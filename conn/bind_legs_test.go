package conn

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeInnerBind stands in for the kernel bind under a LegBind.
type fakeInnerBind struct {
	mu     sync.Mutex
	open   bool
	closed chan struct{}
	sent   []Endpoint
}

func (f *fakeInnerBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.open {
		return nil, 0, ErrBindAlreadyOpen
	}
	f.open = true
	closed := make(chan struct{})
	f.closed = closed
	return []ReceiveFunc{func([]byte) (int, Endpoint, error) {
		<-closed
		return 0, nil, net.ErrClosed
	}}, 4242, nil
}

func (f *fakeInnerBind) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.open {
		close(f.closed)
		f.open = false
	}
	return nil
}

func (f *fakeInnerBind) SetMark(uint32) error { return nil }
func (f *fakeInnerBind) Send(_ []byte, ep Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, ep)
	return nil
}
func (f *fakeInnerBind) ParseEndpoint(s string) (Endpoint, error) {
	return (*StdNetBind)(nil).ParseEndpoint(s)
}
func (f *fakeInnerBind) EnabledAf() EnabledAf { return EnabledAf46 }

// testAgent is a leg agent reduced to a socket, the frame codec and a session.
type testAgent struct {
	t       *testing.T
	id      uint16
	key     *LegKey
	sock    *net.UDPConn
	seq     *LegSequence
	session LegSession
}

func newTestAgent(t *testing.T, id uint16, key *LegKey) *testAgent {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sock.Close() })
	return &testAgent{t: t, id: id, key: key, sock: sock, seq: NewLegSequence()}
}

func (a *testAgent) stateFrame(legs []LegInfo) []byte {
	epoch, counter := a.seq.Next()
	nonce, echo := a.session.Nonces()
	return AppendLegFrame(nil, a.key, LegFrame{Type: LegFrameState, AgentID: a.id, Epoch: epoch, Counter: counter,
		Body: AppendLegState(nil, LegState{Nonce: nonce, Echo: echo, Legs: legs})})
}

func (a *testAgent) sendState(to netip.AddrPort, legs []LegInfo) []byte {
	a.t.Helper()
	frame := a.stateFrame(legs)
	if _, err := a.sock.WriteToUDPAddrPort(frame, to); err != nil {
		a.t.Fatal(err)
	}
	return frame
}

func (a *testAgent) sendData(to netip.AddrPort, legID uint8, from netip.AddrPort, payload []byte) {
	a.t.Helper()
	epoch, counter := a.seq.Next()
	frame := AppendLegFrame(nil, a.key, LegFrame{Type: LegFrameData, AgentID: a.id, LegID: legID, Epoch: epoch, Counter: counter, Addr: from, Body: payload})
	if _, err := a.sock.WriteToUDPAddrPort(frame, to); err != nil {
		a.t.Fatal(err)
	}
}

// read returns the next frame of type kind, skipping others.
func (a *testAgent) read(kind byte) (LegFrame, netip.AddrPort) {
	a.t.Helper()
	frame, from, ok := a.tryRead(kind, 3*time.Second)
	if !ok {
		a.t.Fatal("agent read timed out")
	}
	return frame, from
}

func (a *testAgent) tryRead(kind byte, wait time.Duration) (LegFrame, netip.AddrPort, bool) {
	buf := make([]byte, 65536)
	deadline := time.Now().Add(wait)
	for {
		a.sock.SetReadDeadline(deadline)
		n, from, err := a.sock.ReadFromUDPAddrPort(buf)
		if err != nil {
			return LegFrame{}, netip.AddrPort{}, false
		}
		frame, err := DecodeLegFrame(a.key, buf[:n])
		if err != nil {
			a.t.Fatalf("agent decode: %v", err)
		}
		if frame.Flags&LegFlagFromController == 0 {
			a.t.Fatalf("controller frame without direction flag: %+v", frame)
		}
		if frame.Type == kind {
			frame.Body = append([]byte(nil), frame.Body...)
			return frame, from, true
		}
	}
}

// observe feeds a controller state frame to the agent's session.
func (a *testAgent) observe(frame LegFrame, from netip.AddrPort) (accepted, reply bool) {
	a.t.Helper()
	state, err := ParseLegState(frame.Body)
	if err != nil {
		a.t.Fatal(err)
	}
	return a.session.Observe(frame.Epoch, frame.Counter, state, from, time.Now(), DefaultLegHeartbeatTimeout)
}

// join runs the challenge exchange until the bind lists the agent's legs.
func (a *testAgent) join(bind *LegBind, legs []LegInfo) {
	a.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !a.bindHas(bind, len(legs)) {
		if time.Now().After(deadline) {
			a.t.Fatal("agent never joined")
		}
		a.sendState(bind.LocalAddr(), legs)
		if frame, from, ok := a.tryRead(LegFrameState, 100*time.Millisecond); ok {
			a.observe(frame, from)
		}
	}
}

func (a *testAgent) bindHas(bind *LegBind, legs int) bool {
	n := 0
	for _, leg := range bind.RemoteLegs() {
		if leg.AgentID == a.id {
			n++
		}
	}
	return n == legs && legs > 0 || (legs == 0 && bind.agentOnline(a.id))
}

func (b *LegBind) agentOnline(id uint16) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	agent := b.agents[id]
	return agent != nil && agent.online
}

func (b *LegBind) agentAddr(id uint16) netip.AddrPort {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if agent := b.agents[id]; agent != nil {
		addr, _ := agent.session.Addr()
		return addr
	}
	return netip.AddrPort{}
}

func (a *testAgent) addr() netip.AddrPort {
	return a.sock.LocalAddr().(*net.UDPAddr).AddrPort()
}

type legEventLog struct {
	mu     sync.Mutex
	events []LegEvent
}

func (l *legEventLog) add(event LegEvent) {
	l.mu.Lock()
	l.events = append(l.events, event)
	l.mu.Unlock()
}

func (l *legEventLog) snapshot() []LegEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LegEvent(nil), l.events...)
}

func openTestLegBind(t *testing.T, key *LegKey, peers ...netip.AddrPort) (*LegBind, *fakeInnerBind, ReceiveFunc, *legEventLog) {
	t.Helper()
	inner := &fakeInnerBind{}
	bind := NewLegBind(inner, LegConfig{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Key: *key, Peers: peers})
	events := &legEventLog{}
	bind.SetLegEventHandler(events.add)
	fns, port, err := bind.Open(0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if port != 4242 || len(fns) != 2 {
		t.Fatalf("open returned port %d and %d receive functions", port, len(fns))
	}
	t.Cleanup(func() { bind.Close() })
	return bind, inner, fns[1], events
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// pump runs the leg receive function, which handles state frames inline,
// and forwards data datagrams.
type received struct {
	payload  []byte
	endpoint Endpoint
	err      error
}

func pump(recv ReceiveFunc) chan received {
	out := make(chan received, 16)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, ep, err := recv(buf)
			out <- received{payload: append([]byte(nil), buf[:n]...), endpoint: ep, err: err}
			if err != nil {
				return
			}
		}
	}()
	return out
}

var testLegs = []LegInfo{
	{LegID: 0, Name: "eth0", Addr: netip.MustParseAddrPort("198.51.100.4:16386")},
	{LegID: 1, Name: "wwan0", Addr: netip.MustParseAddrPort("[2001:db8::4]:16386")},
}

func TestLegBindLearnsAgentAndRelays(t *testing.T) {
	key := testLegKey(3)
	bind, inner, recv, events := openTestLegBind(t, key)
	data := pump(recv)
	agent := newTestAgent(t, 9, key)

	// A first frame only earns a challenge.
	agent.sendState(bind.LocalAddr(), testLegs)
	challenge, from := agent.read(LegFrameState)
	if challenge.AgentID != LegControllerID || len(bind.RemoteLegs()) != 0 {
		t.Fatalf("agent trusted before echoing: %+v", bind.RemoteLegs())
	}
	agent.observe(challenge, from)
	agent.join(bind, testLegs)
	legs := bind.RemoteLegs()
	if legs[0].Key() != "9/0" || legs[0].Addr != testLegs[0].Addr || legs[0].Ifindex != LegIfindex(9, 0) {
		t.Fatalf("leg 0: %+v", legs[0])
	}
	waitFor(t, "up events", func() bool { return len(events.snapshot()) == 2 })

	// Outbound: a pinned endpoint on the leg goes to the agent framed.
	ep, err := bind.ParseEndpointFrom("203.0.113.50:7000", testLegs[0].Addr.Addr(), LegIfindex(9, 0))
	if err != nil {
		t.Fatalf("parse endpoint: %v", err)
	}
	legEP, ok := ep.(*RemoteLegEndpoint)
	if !ok || legEP.LegKey() != "9/0" || legEP.SrcToString() != "198.51.100.4" || legEP.DstToString() != "203.0.113.50:7000" {
		t.Fatalf("endpoint: %#v", ep)
	}
	ep.ClearSrc()
	if got := ep.SrcIP().String(); got != "198.51.100.4" {
		t.Fatalf("ClearSrc dropped the leg: src %s", got)
	}
	if err := bind.Send([]byte("hello"), ep); err != nil {
		t.Fatalf("send: %v", err)
	}
	frame, _ := agent.read(LegFrameData)
	if frame.LegID != 0 || frame.AgentID != 9 || frame.Addr.String() != "203.0.113.50:7000" || string(frame.Body) != "hello" {
		t.Fatalf("relayed frame: %+v", frame)
	}
	if len(inner.sent) != 0 {
		t.Fatal("leg datagram went to the inner bind")
	}

	// A family mismatch and an unknown leg fail.
	if _, err := bind.ParseEndpointFrom("[2001:db8::50]:7000", netip.Addr{}, LegIfindex(9, 0)); !errors.Is(err, ErrSourceFamilyMismatch) {
		t.Fatalf("family mismatch: %v", err)
	}
	if _, err := bind.ParseEndpointFrom("203.0.113.50:7000", netip.Addr{}, LegIfindex(9, 7)); !errors.Is(err, ErrLegUnavailable) {
		t.Fatalf("unknown leg: %v", err)
	}

	// Inbound: a relayed datagram surfaces with a leg endpoint.
	agent.sendData(bind.LocalAddr(), 1, netip.MustParseAddrPort("[2001:db8::77]:9000"), []byte("from peer"))
	got := <-data
	if got.err != nil || string(got.payload) != "from peer" {
		t.Fatalf("received %q %v", got.payload, got.err)
	}
	inEP, ok := got.endpoint.(*RemoteLegEndpoint)
	if !ok || inEP.LegKey() != "9/1" || inEP.DstToString() != "[2001:db8::77]:9000" {
		t.Fatalf("inbound endpoint %#v", got.endpoint)
	}

	// Plain endpoints still go to the inner bind.
	plain, _ := bind.ParseEndpoint("192.0.2.1:1")
	if err := bind.Send([]byte("x"), plain); err != nil || len(inner.sent) != 1 {
		t.Fatalf("inner send: %v, %d sent", err, len(inner.sent))
	}
}

func TestLegBindDropsReflectedFrames(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, _ := openTestLegBind(t, key)
	data := pump(recv)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs)

	// A frame the controller built, sent back to it, is dropped.
	ep, _ := bind.ParseEndpointFrom("203.0.113.50:7000", netip.Addr{}, LegIfindex(9, 0))
	bind.Send([]byte("outbound"), ep)
	frame, _ := agent.read(LegFrameData)
	reflected := AppendLegFrame(nil, key, frame)
	agent.sock.WriteToUDPAddrPort(reflected, bind.LocalAddr())
	agent.sendData(bind.LocalAddr(), 0, netip.MustParseAddrPort("203.0.113.50:7000"), []byte("genuine"))
	if got := <-data; string(got.payload) != "genuine" {
		t.Fatalf("reflected frame delivered: %q", got.payload)
	}
}

func TestLegBindIgnoresForgedAndReplayedState(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, _ := openTestLegBind(t, key)
	pump(recv)
	forger := newTestAgent(t, 9, testLegKey(4))
	forger.sendState(bind.LocalAddr(), testLegs)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs[:1])
	recorded := agent.sendState(bind.LocalAddr(), testLegs[:1])

	// A recorded frame replayed from another address does not move the
	// agent there, now or after the agent went silent.
	replayer := newTestAgent(t, 9, key)
	// Challenges are rate limited; the join just used one.
	time.Sleep(2 * legChallengeReplyInterval)
	replayer.sock.WriteToUDPAddrPort(recorded, bind.LocalAddr())
	if _, _, ok := replayer.tryRead(LegFrameState, time.Second); !ok {
		t.Fatal("no challenge for the replayed frame")
	}
	if addr := bind.agentAddr(9); addr != agent.addr() {
		t.Fatalf("agent moved to %v", addr)
	}
	bind.tick(nil, time.Now().Add(DefaultLegHeartbeatTimeout+time.Second))
	if len(bind.RemoteLegs()) != 0 {
		t.Fatal("silent agent still online")
	}
	time.Sleep(2 * legChallengeReplyInterval)
	replayer.sock.WriteToUDPAddrPort(recorded, bind.LocalAddr())
	// The replayer only gets a challenge it cannot answer.
	if _, _, ok := replayer.tryRead(LegFrameState, time.Second); !ok {
		t.Fatal("no challenge for the replayed frame")
	}
	time.Sleep(100 * time.Millisecond)
	if len(bind.RemoteLegs()) != 0 || bind.agentAddr(9) == replayer.addr() {
		t.Fatal("replayed state revived the agent at the replayer's address")
	}
}

func TestLegBindExpiresSilentAgentsAndTakesThemBack(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, events := openTestLegBind(t, key)
	pump(recv)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs)

	bind.tick(nil, time.Now().Add(DefaultLegHeartbeatTimeout+time.Second))
	if n := len(bind.RemoteLegs()); n != 0 {
		t.Fatalf("%d legs after timeout", n)
	}
	if _, err := bind.ParseEndpointFrom("203.0.113.50:7000", netip.Addr{}, LegIfindex(9, 0)); !errors.Is(err, ErrLegUnavailable) {
		t.Fatalf("expired leg: %v", err)
	}
	if err := bind.Send([]byte("x"), &RemoteLegEndpoint{AgentID: 9, LegID: 0, Src: testLegs[0].Addr.Addr(), Dst: netip.MustParseAddrPort("203.0.113.50:7000")}); !errors.Is(err, ErrLegUnavailable) {
		t.Fatalf("send on expired leg: %v", err)
	}
	var downs int
	for _, event := range events.snapshot() {
		if !event.Up {
			downs++
		}
	}
	if downs != 2 {
		t.Fatalf("%d down events", downs)
	}
	// A restarted agent, with a fresh session and sequence, joins again.
	restarted := newTestAgent(t, 9, key)
	restarted.join(bind, testLegs)
	if bind.agentAddr(9) != restarted.addr() {
		t.Fatal("restarted agent not at its new address")
	}
}

func TestLegBindTakesQuicklyRestartedAgentAtNewAddress(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, _ := openTestLegBind(t, key)
	pump(recv)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs)

	// The agent restarts within the timeout, on a new port.
	restarted := newTestAgent(t, 9, key)
	restarted.join(bind, testLegs[:1])
	if bind.agentAddr(9) != restarted.addr() {
		t.Fatalf("agent at %v, want %v", bind.agentAddr(9), restarted.addr())
	}
	waitFor(t, "leg list", func() bool { return len(bind.RemoteLegs()) == 1 })
	ep, _ := bind.ParseEndpointFrom("203.0.113.50:7000", netip.Addr{}, LegIfindex(9, 0))
	bind.Send([]byte("to new"), ep)
	if frame, _ := restarted.read(LegFrameData); string(frame.Body) != "to new" {
		t.Fatalf("relayed %q", frame.Body)
	}
}

func TestLegBindReachesAgentListedInPeers(t *testing.T) {
	// The agent cannot reach the controller first: it knows no address and
	// only answers what arrives.
	key := testLegKey(3)
	agent := newTestAgent(t, 9, key)
	bind, _, recv, _ := openTestLegBind(t, key, agent.addr())
	pump(recv)
	deadline := time.Now().Add(5 * time.Second)
	for len(bind.RemoteLegs()) != len(testLegs) {
		if time.Now().After(deadline) {
			t.Fatal("controller never learned the agent")
		}
		frame, from, ok := agent.tryRead(LegFrameState, 200*time.Millisecond)
		if !ok {
			continue
		}
		if accepted, reply := agent.observe(frame, from); reply || accepted {
			agent.sendState(from, testLegs)
		}
	}
	if bind.agentAddr(9) != agent.addr() {
		t.Fatalf("agent at %v", bind.agentAddr(9))
	}
}

func TestLegBindForgetsLongGoneAgents(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, _ := openTestLegBind(t, key)
	pump(recv)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs)
	bind.tick(nil, time.Now().Add(DefaultLegHeartbeatTimeout+time.Second))
	if !bind.agentAddr(9).IsValid() {
		t.Fatal("offline agent forgotten at once")
	}
	bind.tick(nil, time.Now().Add(legAgentForget+time.Minute))
	if bind.agentAddr(9).IsValid() {
		t.Fatal("long-gone agent still kept")
	}
}

func TestLegBindReportsChangedLegs(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, events := openTestLegBind(t, key)
	pump(recv)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs)
	waitFor(t, "legs", func() bool { return len(events.snapshot()) == 2 })
	moved := []LegInfo{{LegID: 0, Name: "eth0", Addr: netip.MustParseAddrPort("198.51.100.99:16386")}}
	agent.sendState(bind.LocalAddr(), moved)
	waitFor(t, "change events", func() bool { return len(events.snapshot()) == 5 })
	var down, up []string
	for _, event := range events.snapshot()[2:] {
		if event.Up {
			up = append(up, event.Leg.Addr.String())
		} else {
			down = append(down, event.Leg.Addr.String())
		}
	}
	if len(down) != 2 || len(up) != 1 || up[0] != "198.51.100.99:16386" {
		t.Fatalf("down %v up %v", down, up)
	}
}

func TestLegBindRejectsUnusableLegAddresses(t *testing.T) {
	key := testLegKey(3)
	bind, _, recv, _ := openTestLegBind(t, key)
	pump(recv)
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs[:1])
	agent.sendState(bind.LocalAddr(), []LegInfo{
		{LegID: 0, Addr: netip.MustParseAddrPort("0.0.0.0:16386")},
		{LegID: 1, Addr: netip.MustParseAddrPort("198.51.100.4:0")},
		{LegID: 2, Addr: netip.MustParseAddrPort("198.51.100.4:16386")},
	})
	time.Sleep(100 * time.Millisecond)
	legs := bind.RemoteLegs()
	if len(legs) != 1 || legs[0].LegID != 2 {
		t.Fatalf("kept legs %+v", legs)
	}
}

func TestLegBindCloseAndReopenKeepsAgents(t *testing.T) {
	key := testLegKey(3)
	inner := &fakeInnerBind{}
	bind := NewLegBind(inner, LegConfig{Listen: netip.MustParseAddrPort("127.0.0.1:0"), Key: *key})
	fns, _, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	data := pump(fns[1])
	agent := newTestAgent(t, 9, key)
	agent.join(bind, testLegs)
	if err := bind.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := <-data; !errors.Is(got.err, net.ErrClosed) {
		t.Fatalf("receive after close: %v", got.err)
	}
	ep := &RemoteLegEndpoint{AgentID: 9, LegID: 0, Src: testLegs[0].Addr.Addr(), Dst: netip.MustParseAddrPort("203.0.113.50:7000")}
	if err := bind.Send([]byte("x"), ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send while closed: %v", err)
	}
	fns, _, err = bind.Open(0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer bind.Close()
	pump(fns[1])
	if n := len(bind.RemoteLegs()); n != 2 {
		t.Fatalf("%d legs after reopen", n)
	}
	if err := bind.Send([]byte("again"), ep); err != nil {
		t.Fatalf("send after reopen: %v", err)
	}
	if frame, _ := agent.read(LegFrameData); !bytes.Equal(frame.Body, []byte("again")) {
		t.Fatalf("frame body %q", frame.Body)
	}
}

func TestUnwrapBind(t *testing.T) {
	inner := &fakeInnerBind{}
	bind := NewLegBind(inner, LegConfig{})
	if UnwrapBind(bind) != Bind(inner) {
		t.Fatal("UnwrapBind did not reach the inner bind")
	}
	if UnwrapBind(inner) != Bind(inner) {
		t.Fatal("UnwrapBind changed a plain bind")
	}
}
