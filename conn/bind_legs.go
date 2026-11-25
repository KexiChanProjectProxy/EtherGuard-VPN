/* SPDX-License-Identifier: MIT */

package conn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"
)

// BindUnwrapper is implemented by binds that wrap another bind. Code that
// needs the kernel socket type (route checks, the route listener) unwraps
// first.
type BindUnwrapper interface {
	Unwrap() Bind
}

// UnwrapBind returns the innermost bind of a chain of wrappers.
func UnwrapBind(bind Bind) Bind {
	for {
		wrapper, ok := bind.(BindUnwrapper)
		if !ok {
			return bind
		}
		inner := wrapper.Unwrap()
		if inner == nil {
			return bind
		}
		bind = inner
	}
}

// RemoteLeg is an uplink of another machine that this bind can send through.
type RemoteLeg struct {
	AgentID uint16
	LegID   uint8
	Name    string
	// Addr is the uplink's address and the agent's socket port on it.
	Addr netip.AddrPort
	// Ifindex is the synthetic index from LegIfindex.
	Ifindex int
}

// Key identifies the leg in logs and endpoint comparisons.
func (leg RemoteLeg) Key() string {
	return legKey(leg.AgentID, leg.LegID)
}

func legKey(agentID uint16, legID uint8) string {
	return strconv.Itoa(int(agentID)) + "/" + strconv.Itoa(int(legID))
}

// RemoteLegLister is implemented by binds that relay through remote legs.
type RemoteLegLister interface {
	RemoteLegs() []RemoteLeg
}

// LegEndpoint is implemented by endpoints that send through a remote leg.
type LegEndpoint interface {
	Endpoint
	LegKey() string
}

// SourceIfindexer is implemented by endpoints whose pinned interface index is
// meaningful to callers.
type SourceIfindexer interface {
	SrcIfindex() int
}

// LegEvent reports that a remote leg appeared or went away.
type LegEvent struct {
	Leg RemoteLeg
	Up  bool
}

// LegEventSource is implemented by binds that report leg changes.
type LegEventSource interface {
	SetLegEventHandler(func(LegEvent))
}

// RemoteLegEndpoint is a far peer reached through a remote leg.
//
// Its source never clears: a remote leg has no kernel default route to fall
// back to, so ClearSrc keeps the leg. When the leg goes away the bind reports
// it and the device moves peers off it.
type RemoteLegEndpoint struct {
	AgentID uint16
	LegID   uint8
	Src     netip.Addr
	Dst     netip.AddrPort
}

var _ LegEndpoint = (*RemoteLegEndpoint)(nil)
var _ SourceIfindexer = (*RemoteLegEndpoint)(nil)

func (e *RemoteLegEndpoint) ClearSrc()           {}
func (e *RemoteLegEndpoint) SrcToString() string { return e.Src.String() }
func (e *RemoteLegEndpoint) DstToString() string { return e.Dst.String() }
func (e *RemoteLegEndpoint) DstToBytes() []byte {
	addr := e.Dst.Addr().As16()
	out := append([]byte(nil), addr[:]...)
	return append(out, byte(e.Dst.Port()>>8), byte(e.Dst.Port()))
}
func (e *RemoteLegEndpoint) DstIP() net.IP   { return net.IP(e.Dst.Addr().AsSlice()) }
func (e *RemoteLegEndpoint) SrcIP() net.IP   { return net.IP(e.Src.AsSlice()) }
func (e *RemoteLegEndpoint) LegKey() string  { return legKey(e.AgentID, e.LegID) }
func (e *RemoteLegEndpoint) SrcIfindex() int { return LegIfindex(e.AgentID, e.LegID) }

// LegConfig configures the controller side of remote legs.
type LegConfig struct {
	// Listen is the site-network address agents send frames to.
	Listen netip.AddrPort
	Key    LegKey
	// Peers are agent addresses the controller sends state frames to on its
	// own; agents that know the controller are learned from their frames.
	Peers            []netip.AddrPort
	HeartbeatTimeout time.Duration
	// Logf, when set, receives verbose diagnostics.
	Logf func(format string, args ...any)
}

type legAgent struct {
	id      uint16
	session LegSession
	legs    map[uint8]RemoteLeg
	online  bool
}

// legAgentForget is how long the controller keeps an offline agent's state
// and keeps sending it heartbeats.
const legAgentForget = 10 * time.Minute

// LegBind wraps a kernel bind and adds the uplinks of leg agents as remote
// legs. It implements Bind, EndpointSourcePinner, RemoteLegLister and
// LegEventSource.
//
// Agent state survives Close and Open, because the device closes and reopens
// its bind on every listen-port or up/down change.
type LegBind struct {
	inner Bind
	cfg   LegConfig
	seq   *LegSequence

	mu      sync.RWMutex
	agents  map[uint16]*legAgent
	handler func(LegEvent)
	// bootNonce is the challenge in state frames to configured Peers whose
	// agent is not known yet.
	bootNonce uint64
	// emitMu keeps events in the order of the state changes behind them.
	emitMu sync.Mutex
	mark   uint32

	// sock is the site-network socket; nil while closed.
	sockMu sync.RWMutex
	sock   *net.UDPConn
	stop   chan struct{}
	done   sync.WaitGroup

	bufs sync.Pool
}

var _ Bind = (*LegBind)(nil)
var _ EndpointSourcePinner = (*LegBind)(nil)
var _ RemoteLegLister = (*LegBind)(nil)
var _ LegEventSource = (*LegBind)(nil)
var _ BindUnwrapper = (*LegBind)(nil)

// NewLegBind wraps inner.
func NewLegBind(inner Bind, cfg LegConfig) *LegBind {
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = DefaultLegHeartbeatTimeout
	}
	return &LegBind{
		inner:     inner,
		cfg:       cfg,
		seq:       NewLegSequence(),
		agents:    make(map[uint16]*legAgent),
		bootNonce: NewLegNonce(),
		bufs:      sync.Pool{New: func() any { b := make([]byte, 0, 2048); return &b }},
	}
}

func (b *LegBind) Unwrap() Bind { return b.inner }

// LocalAddr returns the bound site-network address, or an invalid address
// while closed.
func (b *LegBind) LocalAddr() netip.AddrPort {
	b.sockMu.RLock()
	defer b.sockMu.RUnlock()
	if b.sock == nil {
		return netip.AddrPort{}
	}
	return b.sock.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (b *LegBind) logf(format string, args ...any) {
	if b.cfg.Logf != nil {
		b.cfg.Logf(format, args...)
	}
}

// SetLegEventHandler sets the callback for leg changes. It runs on the bind's
// own goroutines, in order, and must neither block nor call into the bind:
// Close waits for those goroutines.
func (b *LegBind) SetLegEventHandler(handler func(LegEvent)) {
	b.mu.Lock()
	b.handler = handler
	b.mu.Unlock()
}

// emit delivers events. Callers hold emitMu from before the state change
// that produced them.
func (b *LegBind) emit(events []LegEvent) {
	if len(events) == 0 {
		return
	}
	b.mu.RLock()
	handler := b.handler
	b.mu.RUnlock()
	for _, event := range events {
		if event.Up {
			b.logf("Remote leg up: leg=%s name=%s addr=%s", event.Leg.Key(), event.Leg.Name, event.Leg.Addr)
		} else {
			b.logf("Remote leg down: leg=%s name=%s addr=%s", event.Leg.Key(), event.Leg.Name, event.Leg.Addr)
		}
		if handler != nil {
			handler(event)
		}
	}
}

func (b *LegBind) Open(port uint16) ([]ReceiveFunc, uint16, error) {
	fns, actual, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}
	sock, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(b.cfg.Listen))
	if err != nil {
		b.inner.Close()
		return nil, 0, fmt.Errorf("remote legs listen %s: %w", b.cfg.Listen, err)
	}
	b.mu.RLock()
	mark := b.mark
	b.mu.RUnlock()
	if mark != 0 {
		if err := SetUDPConnMark(sock, mark); err != nil {
			sock.Close()
			b.inner.Close()
			return nil, 0, fmt.Errorf("remote legs fwmark: %w", err)
		}
	}
	stop := make(chan struct{})
	b.sockMu.Lock()
	b.sock = sock
	b.stop = stop
	b.sockMu.Unlock()
	b.done.Add(1)
	go b.heartbeat(sock, stop)
	return append(fns, b.receiveFunc(sock)), actual, nil
}

func (b *LegBind) Close() error {
	b.sockMu.Lock()
	sock, stop := b.sock, b.stop
	b.sock, b.stop = nil, nil
	b.sockMu.Unlock()
	var sockErr error
	if sock != nil {
		close(stop)
		sockErr = sock.Close()
		b.done.Wait()
	}
	return errors.Join(b.inner.Close(), sockErr)
}

// SetMark marks the socket bind and the site-network socket, so policy
// routing that keeps the tunnel's own traffic out of the tunnel covers the
// frames to agents too.
func (b *LegBind) SetMark(mark uint32) error {
	b.mu.Lock()
	b.mark = mark
	b.mu.Unlock()
	err := b.inner.SetMark(mark)
	b.sockMu.RLock()
	defer b.sockMu.RUnlock()
	if b.sock != nil {
		err = errors.Join(err, SetUDPConnMark(b.sock, mark))
	}
	return err
}

func (b *LegBind) ParseEndpoint(s string) (Endpoint, error) { return b.inner.ParseEndpoint(s) }
func (b *LegBind) EnabledAf() EnabledAf                     { return b.inner.EnabledAf() }

// ParseEndpointFrom pins dst to a remote leg when ifindex is a leg index
// (src, when valid, must be that leg's address); otherwise it asks the inner
// bind.
func (b *LegBind) ParseEndpointFrom(dst string, src netip.Addr, ifindex int) (Endpoint, error) {
	if leg, ok := b.findLeg(src, ifindex); ok {
		dstAddr, err := netip.ParseAddrPort(dst)
		if err != nil {
			return nil, err
		}
		dstAddr = netip.AddrPortFrom(dstAddr.Addr().Unmap(), dstAddr.Port())
		if dstAddr.Addr().Is4() != leg.Addr.Addr().Is4() {
			return nil, ErrSourceFamilyMismatch
		}
		return &RemoteLegEndpoint{AgentID: leg.AgentID, LegID: leg.LegID, Src: leg.Addr.Addr(), Dst: dstAddr}, nil
	}
	if IsLegIfindex(ifindex) {
		return nil, ErrLegUnavailable
	}
	pinner, ok := b.inner.(EndpointSourcePinner)
	if !ok {
		return nil, errors.New("bind cannot pin sources")
	}
	return pinner.ParseEndpointFrom(dst, src, ifindex)
}

func (b *LegBind) findLeg(src netip.Addr, ifindex int) (RemoteLeg, bool) {
	src = src.Unmap()
	b.mu.RLock()
	defer b.mu.RUnlock()
	if IsLegIfindex(ifindex) {
		agentID, legID := splitLegIfindex(ifindex)
		agent := b.agents[agentID]
		if agent == nil || !agent.online {
			return RemoteLeg{}, false
		}
		leg, ok := agent.legs[legID]
		if !ok || (src.IsValid() && leg.Addr.Addr() != src) {
			return RemoteLeg{}, false
		}
		return leg, true
	}
	return RemoteLeg{}, false
}

// RemoteLegs lists the legs of every online agent, ordered by agent and leg.
func (b *LegBind) RemoteLegs() []RemoteLeg {
	b.mu.RLock()
	defer b.mu.RUnlock()
	var legs []RemoteLeg
	for _, agent := range b.agents {
		if !agent.online {
			continue
		}
		for _, leg := range agent.legs {
			legs = append(legs, leg)
		}
	}
	sort.Slice(legs, func(i, j int) bool {
		if legs[i].AgentID != legs[j].AgentID {
			return legs[i].AgentID < legs[j].AgentID
		}
		return legs[i].LegID < legs[j].LegID
	})
	return legs
}

func (b *LegBind) Send(buf []byte, endpoint Endpoint) error {
	legEndpoint, ok := endpoint.(*RemoteLegEndpoint)
	if !ok {
		return b.inner.Send(buf, endpoint)
	}
	if len(buf) > 65535-LegFrameOverhead-8-40 {
		return ErrLegPayloadTooBig
	}
	b.mu.RLock()
	agent := b.agents[legEndpoint.AgentID]
	var to netip.AddrPort
	ok = false
	if agent != nil && agent.online {
		addr, known := agent.session.Addr()
		if leg, found := agent.legs[legEndpoint.LegID]; known && found && leg.Addr.Addr() == legEndpoint.Src {
			to, ok = addr, true
		}
	}
	b.mu.RUnlock()
	if !ok {
		return ErrLegUnavailable
	}
	b.sockMu.RLock()
	defer b.sockMu.RUnlock()
	if b.sock == nil {
		return net.ErrClosed
	}
	epoch, counter := b.seq.Next()
	ptr := b.bufs.Get().(*[]byte)
	frame := AppendLegFrame((*ptr)[:0], &b.cfg.Key, LegFrame{
		Type: LegFrameData, Flags: LegFlagFromController, AgentID: legEndpoint.AgentID, LegID: legEndpoint.LegID,
		Epoch: epoch, Counter: counter, Addr: legEndpoint.Dst, Body: buf,
	})
	_, err := b.sock.WriteToUDPAddrPort(frame, to)
	*ptr = frame
	b.bufs.Put(ptr)
	return err
}

// receiveFunc returns datagrams relayed by agents and handles state frames
// in place.
func (b *LegBind) receiveFunc(sock *net.UDPConn) ReceiveFunc {
	return func(buf []byte) (int, Endpoint, error) {
		for {
			n, from, err := sock.ReadFromUDPAddrPort(buf)
			if err != nil {
				return 0, nil, err
			}
			frame, err := DecodeLegFrame(&b.cfg.Key, buf[:n])
			if err != nil {
				b.logf("Remote legs: dropping frame from %s: %v", from, err)
				continue
			}
			if frame.Flags&LegFlagFromController != 0 {
				// One of ours, reflected back.
				continue
			}
			switch frame.Type {
			case LegFrameState:
				b.handleState(sock, frame, from)
			case LegFrameData:
				endpoint := b.dataEndpoint(frame)
				if endpoint == nil {
					continue
				}
				size := copy(buf, frame.Body)
				return size, endpoint, nil
			}
		}
	}
}

func (b *LegBind) dataEndpoint(frame LegFrame) *RemoteLegEndpoint {
	if frame.AgentID == LegControllerID || !frame.Addr.IsValid() {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	agent := b.agents[frame.AgentID]
	if agent == nil || !agent.online {
		return nil
	}
	leg, ok := agent.legs[frame.LegID]
	if !ok {
		return nil
	}
	return &RemoteLegEndpoint{AgentID: leg.AgentID, LegID: leg.LegID, Src: leg.Addr.Addr(), Dst: frame.Addr}
}

func validLegAddr(addr netip.AddrPort) bool {
	ip := addr.Addr()
	return addr.IsValid() && addr.Port() != 0 && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast()
}

func (b *LegBind) handleState(sock *net.UDPConn, frame LegFrame, from netip.AddrPort) {
	if frame.AgentID == LegControllerID {
		return
	}
	state, err := ParseLegState(frame.Body)
	if err != nil {
		b.logf("Remote legs: bad state from agent %d at %s: %v", frame.AgentID, from, err)
		return
	}
	now := time.Now()
	from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
	var events []LegEvent
	b.emitMu.Lock()
	defer b.emitMu.Unlock()
	b.mu.Lock()
	agent := b.agents[frame.AgentID]
	if agent == nil {
		agent = &legAgent{id: frame.AgentID, legs: make(map[uint8]RemoteLeg)}
		agent.session.Bootstrap(b.bootNonce)
		b.agents[frame.AgentID] = agent
	}
	previous, _ := agent.session.Addr()
	usedBoot := state.Echo == b.bootNonce
	accepted, reply := agent.session.Observe(frame.Epoch, frame.Counter, state, from, now, b.cfg.HeartbeatTimeout)
	var answer []byte
	if reply {
		answer = b.stateFrameLocked(agent)
	}
	if !accepted {
		b.mu.Unlock()
		if answer != nil {
			b.logf("Remote legs: challenging agent %d at %s", frame.AgentID, from)
			b.writeState(sock, answer, from)
		}
		return
	}
	if usedBoot {
		// Each bootstrap challenge admits one agent.
		b.bootNonce = NewLegNonce()
	}
	wasOnline := agent.online
	if previous != from {
		b.logf("Remote legs: agent %d at %s", agent.id, from)
	}
	agent.online = true
	next := make(map[uint8]RemoteLeg, len(state.Legs))
	for _, info := range state.Legs {
		addr := netip.AddrPortFrom(info.Addr.Addr().Unmap(), info.Addr.Port())
		if !validLegAddr(addr) {
			b.logf("Remote legs: agent %d announced invalid leg %d address %s", agent.id, info.LegID, info.Addr)
			continue
		}
		next[info.LegID] = RemoteLeg{
			AgentID: agent.id, LegID: info.LegID, Name: info.Name, Addr: addr,
			Ifindex: LegIfindex(agent.id, info.LegID),
		}
	}
	if wasOnline {
		for id, old := range agent.legs {
			if leg, ok := next[id]; !ok || leg.Addr != old.Addr {
				events = append(events, LegEvent{Leg: old, Up: false})
			}
		}
	}
	for id, leg := range next {
		if old, ok := agent.legs[id]; !ok || old.Addr != leg.Addr || !wasOnline {
			events = append(events, LegEvent{Leg: leg, Up: true})
		}
	}
	agent.legs = next
	b.mu.Unlock()
	if answer != nil {
		b.writeState(sock, answer, from)
	}
	b.emit(events)
}

// stateFrameLocked builds the controller's state frame for agent.
func (b *LegBind) stateFrameLocked(agent *legAgent) []byte {
	nonce, echo := agent.session.Nonces()
	return b.stateFrame(nonce, echo)
}

func (b *LegBind) stateFrame(nonce, echo uint64) []byte {
	epoch, counter := b.seq.Next()
	return AppendLegFrame(nil, &b.cfg.Key, LegFrame{
		Type: LegFrameState, Flags: LegFlagFromController, AgentID: LegControllerID,
		Epoch: epoch, Counter: counter,
		Body: AppendLegState(nil, LegState{Nonce: nonce, Echo: echo}),
	})
}

func (b *LegBind) writeState(sock *net.UDPConn, frame []byte, to netip.AddrPort) {
	if sock == nil {
		return
	}
	if _, err := sock.WriteToUDPAddrPort(frame, to); err != nil {
		b.logf("Remote legs: state to %s failed: %v", to, err)
	}
}

func (b *LegBind) heartbeat(sock *net.UDPConn, stop chan struct{}) {
	defer b.done.Done()
	ticker := time.NewTicker(LegHeartbeatInterval)
	defer ticker.Stop()
	for {
		b.tick(sock, time.Now())
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

// tick expires silent agents, forgets long-gone ones, and sends state frames
// to every known agent and configured peer address.
func (b *LegBind) tick(sock *net.UDPConn, now time.Time) {
	type outgoing struct {
		frame []byte
		to    netip.AddrPort
	}
	var sends []outgoing
	covered := make(map[netip.AddrPort]bool)
	var events []LegEvent
	b.emitMu.Lock()
	defer b.emitMu.Unlock()
	b.mu.Lock()
	for id, agent := range b.agents {
		if agent.online && !agent.session.Live(now, b.cfg.HeartbeatTimeout) {
			agent.online = false
			for _, leg := range agent.legs {
				events = append(events, LegEvent{Leg: leg, Up: false})
			}
		}
		addr, known := agent.session.Addr()
		if !agent.online && (!known || now.Sub(agent.session.LastSeen()) > legAgentForget) {
			delete(b.agents, id)
			continue
		}
		if known {
			sends = append(sends, outgoing{b.stateFrameLocked(agent), addr})
			covered[addr] = true
		}
	}
	for _, peer := range b.cfg.Peers {
		if !covered[peer] {
			sends = append(sends, outgoing{b.stateFrame(b.bootNonce, 0), peer})
		}
	}
	b.mu.Unlock()
	b.emit(events)
	for _, send := range sends {
		b.writeState(sock, send.frame, send.to)
	}
}
