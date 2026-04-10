package device

import (
	"bytes"
	"encoding/gob"
	"errors"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/conn/bindtest"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	"golang.org/x/sys/unix"
)

type p2pHarnessNode struct {
	bind   *bindtest.ChannelBind
	device *Device
	recv4  conn.ReceiveFunc
	recv6  conn.ReceiveFunc
	pub    NoisePublicKey
}

type p2pHarness struct {
	t        *testing.T
	topology *bindtest.ChannelTopology
	nodes    []*p2pHarnessNode
}

type reportTestEndpoint struct {
	src  net.IP
	dst  net.IP
	port int
}

type retryLookupTestConn struct {
	remote net.Addr
}

func (e reportTestEndpoint) ClearSrc() {}

func (e reportTestEndpoint) SrcToString() string {
	return (&net.UDPAddr{IP: e.src, Port: e.port}).String()
}

func (e reportTestEndpoint) DstToString() string {
	return (&net.UDPAddr{IP: e.dst, Port: e.port}).String()
}

func (e reportTestEndpoint) SrcToBytes() []byte {
	return append([]byte(nil), e.src...)
}

func (e reportTestEndpoint) DstToBytes() []byte {
	return append([]byte(nil), e.dst...)
}

func (e reportTestEndpoint) DstIP() net.IP {
	return append(net.IP(nil), e.dst...)
}

func (e reportTestEndpoint) SrcIP() net.IP {
	return append(net.IP(nil), e.src...)
}

func (c *retryLookupTestConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (c *retryLookupTestConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *retryLookupTestConn) Close() error                     { return nil }
func (c *retryLookupTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *retryLookupTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c *retryLookupTestConn) SetDeadline(time.Time) error      { return nil }
func (c *retryLookupTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *retryLookupTestConn) SetWriteDeadline(time.Time) error { return nil }

func mustResolveRetryLookupAddr(t *testing.T, network, address string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q, %q): %v", network, address, err)
	}
	return addr
}

func newP2PHarness(t *testing.T, nodeCount int) *p2pHarness {
	t.Helper()

	topology := bindtest.NewChannelTopology(nodeCount)
	harness := &p2pHarness{
		t:        t,
		topology: topology,
		nodes:    make([]*p2pHarnessNode, 0, nodeCount),
	}

	for i := 0; i < nodeCount; i++ {
		tapdev, err := tap.CreateDummyTAP()
		if err != nil {
			t.Fatalf("CreateDummyTAP(%d): %v", i, err)
		}
		select {
		case <-tapdev.Events():
		default:
		}

		graph, err := path.NewGraph(nodeCount, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
		if err != nil {
			t.Fatalf("NewGraph(%d): %v", i, err)
		}

		cfg := &mtypes.EdgeConfig{
			NodeID:     mtypes.Vertex(i + 1),
			DefaultTTL: 1,
			ListenPort: 0,
			AfPrefer:   4,
			LogLevel:   mtypes.LoggerInfo{},
			Interface:  mtypes.InterfaceConf{MTU: DefaultMTU},
			DynamicRoute: mtypes.DynamicRouteInfo{
				PeerAliveTimeout: 5,
				ConnNextTry:      1,
				DupCheckTimeout:  1,
				SuperNode:        mtypes.SuperInfo{},
				P2P: mtypes.P2PInfo{
					UseP2P:           true,
					SendPeerInterval: 60,
				},
			},
		}

		bind := topology.Bind(i)
		recvFns, _, err := bind.Open(0)
		if err != nil {
			t.Fatalf("bind.Open(%d): %v", i, err)
		}
		device := NewDevice(tapdev, cfg.NodeID, bind, NewLogger(LogLevelSilent, "test"), graph, false, "", cfg, nil, nil, "test")
		priv, pub := RandomKeyPair()
		if err := device.SetPrivateKey(priv); err != nil {
			t.Fatalf("SetPrivateKey(%d): %v", i, err)
		}

		harness.nodes = append(harness.nodes, &p2pHarnessNode{
			bind:   bind,
			device: device,
			recv4:  recvFns[0],
			recv6:  recvFns[1],
			pub:    pub,
		})
	}

	return harness
}

func (h *p2pHarness) close() {
	h.t.Helper()
	for i := len(h.nodes) - 1; i >= 0; i-- {
		h.closeNode(i)
	}
}

func (h *p2pHarness) closeNode(node int) {
	h.t.Helper()
	device := h.nodes[node].device
	device.Close()
	select {
	case <-device.Wait():
	case <-time.After(2 * time.Second):
		h.t.Fatalf("device %d did not close", node)
	}
}

func (h *p2pHarness) startNode(node int) {
	h.t.Helper()
	if err := h.nodes[node].device.Up(); err != nil {
		h.t.Fatalf("device %d Up(): %v", node, err)
	}
}

func (h *p2pHarness) addPeer(from, to int, family bindtest.AddressFamily) *Peer {
	h.t.Helper()
	peer, err := h.nodes[from].device.NewPeer(h.nodes[to].pub, h.nodes[to].device.ID, false, 0)
	if err != nil {
		h.t.Fatalf("NewPeer(%d -> %d): %v", from, to, err)
	}
	peer.SetEndpointFromPacket(h.topology.Endpoint(to, family))
	now := time.Now()
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	peer.SingleWayLatency.Push(1)
	return peer
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", desc)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func connectHarnessPeers(t *testing.T, h *p2pHarness, a, b int, family bindtest.AddressFamily) (*Peer, *Peer) {
	t.Helper()

	h.startNode(a)
	h.startNode(b)
	peerAB := h.addPeer(a, b, family)
	peerBA := h.addPeer(b, a, family)

	initiation, err := h.nodes[a].device.CreateMessageInitiation(peerAB)
	if err != nil {
		t.Fatalf("CreateMessageInitiation(%d -> %d): %v", a, b, err)
	}
	consumedPeer := h.nodes[b].device.ConsumeMessageInitiation(initiation)
	if consumedPeer != peerBA {
		t.Fatalf("ConsumeMessageInitiation(%d <- %d) peer mismatch", b, a)
	}
	response, err := h.nodes[b].device.CreateMessageResponse(peerBA)
	if err != nil {
		t.Fatalf("CreateMessageResponse(%d -> %d): %v", b, a, err)
	}
	if err := peerBA.BeginSymmetricSession(); err != nil {
		t.Fatalf("BeginSymmetricSession(%d -> %d): %v", b, a, err)
	}
	consumedPeer = h.nodes[a].device.ConsumeMessageResponse(response)
	if consumedPeer != peerAB {
		t.Fatalf("ConsumeMessageResponse(%d <- %d) peer mismatch", a, b)
	}
	if err := peerAB.BeginSymmetricSession(); err != nil {
		t.Fatalf("BeginSymmetricSession(%d -> %d): %v", a, b, err)
	}

	waitUntil(t, 2*time.Second, "symmetric session establishment", func() bool {
		return peerAB.keypairs.Current() != nil && peerBA.keypairs.loadNext() != nil
	})

	return peerAB, peerBA
}

func sendControlPacket(t *testing.T, sender *p2pHarnessNode, peer *Peer, usage path.Usage, dst mtypes.Vertex, body []byte) {
	t.Helper()

	buf := make([]byte, path.EgHeaderLen+len(body))
	header, err := path.NewEgHeader(buf[:path.EgHeaderLen], sender.device.EdgeConfig.Interface.MTU)
	if err != nil {
		t.Fatalf("NewEgHeader(): %v", err)
	}
	header.SetSrc(sender.device.ID)
	header.SetDst(dst)
	copy(buf[path.EgHeaderLen:], body)
	sender.device.SendPacket(peer, usage, sender.device.EdgeConfig.DefaultTTL, buf, MessageTransportOffsetContent)
}

func gobRouteMismatch(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "gob:") && (strings.Contains(msg, "type mismatch") || strings.Contains(msg, "wrong type") || strings.Contains(msg, "no fields matched") || strings.Contains(msg, "want struct got non-struct"))
}

func TestP2PHarnessSmoke(t *testing.T) {
	h := newP2PHarness(t, 3)
	defer h.close()

	packet, _, _, err := h.nodes[0].device.GeneratePingPacket(h.nodes[0].device.ID, 1)
	if err != nil {
		t.Fatalf("GeneratePingPacket(): %v", err)
	}
	if err := h.nodes[0].bind.Send(packet, h.topology.Endpoint(1, bindtest.IPv4)); err != nil {
		t.Fatalf("Send(): %v", err)
	}

	buf := make([]byte, len(packet)+32)
	n, endpoint, err := h.nodes[1].recv4(buf)
	if err != nil {
		t.Fatalf("recv4(): %v", err)
	}
	if !bytes.Equal(buf[:n], packet) {
		t.Fatalf("received packet mismatch")
	}
	if got, want := endpoint.DstToString(), h.topology.Endpoint(0, bindtest.IPv4).DstToString(); got != want {
		t.Fatalf("recv4 source endpoint = %q, want %q", got, want)
	}

	h.startNode(0)
	h.startNode(1)
	peer := h.addPeer(0, 1, bindtest.IPv4)
	h.nodes[0].device.peers.LocalV4 = h.topology.Endpoint(0, bindtest.IPv4).DstIP()
	h.nodes[0].device.peers.LocalV6 = h.topology.Endpoint(0, bindtest.IPv6).DstIP()

	report := h.nodes[0].device.buildPeerInfoReport()
	if len(report.Pongs) != 1 || report.Pongs[0].Src_nodeID != peer.ID {
		t.Fatalf("unexpected pongs in report: %+v", report.Pongs)
	}
	if _, ok := report.LocalV4s[h.topology.Endpoint(0, bindtest.IPv4).DstToString()]; !ok {
		t.Fatalf("missing local IPv4 report entry: %+v", report.LocalV4s)
	}
	v6ReportAddr := (&net.UDPAddr{IP: h.topology.Endpoint(0, bindtest.IPv6).DstIP(), Port: int(h.nodes[0].device.net.port)}).String()
	if _, ok := report.LocalV6s[v6ReportAddr]; !ok {
		t.Fatalf("missing local IPv6 report entry: %+v", report.LocalV6s)
	}
}

func TestGobIssue13ControlPath(t *testing.T) {
	h := newP2PHarness(t, 2)
	defer h.close()

	peer := h.addPeer(0, 1, bindtest.IPv4)
	pongBody, err := mtypes.GetByte(&mtypes.PongMsg{
		Src_nodeID:  h.nodes[0].device.ID,
		Dst_nodeID:  h.nodes[1].device.ID,
		Timediff:    1,
		TimeToAlive: 5,
	})
	if err != nil {
		t.Fatalf("GetByte(PongMsg): %v", err)
	}
	if err := h.nodes[0].device.process_received(path.BroadcastPeer, peer, pongBody); !gobRouteMismatch(err) {
		t.Fatalf("process_received(BroadcastPeer, PongMsg) error = %v, want gob route mismatch", err)
	}

	broadcastBody, err := mtypes.GetByte(&mtypes.BoardcastPeerMsg{
		Request_ID: 1,
		NodeID:     h.nodes[1].device.ID,
		PubKey:     h.nodes[1].pub,
		ConnURL:    h.topology.Endpoint(1, bindtest.IPv4).DstToString(),
	})
	if err != nil {
		t.Fatalf("GetByte(BoardcastPeerMsg): %v", err)
	}
	if err := h.nodes[0].device.process_received(path.PongPacket, peer, broadcastBody); !gobRouteMismatch(err) {
		t.Fatalf("process_received(PongPacket, BoardcastPeerMsg) error = %v, want gob route mismatch", err)
	}
}

func TestGobIssue13Pong(t *testing.T) {
	h := newP2PHarness(t, 2)
	defer h.close()

	peer01, _ := connectHarnessPeers(t, h, 0, 1, bindtest.IPv4)

	body, err := mtypes.GetByte(&mtypes.PongMsg{
		Src_nodeID:  h.nodes[0].device.ID,
		Dst_nodeID:  h.nodes[1].device.ID,
		Timediff:    1,
		TimeToAlive: h.nodes[1].device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
	})
	if err != nil {
		t.Fatalf("GetByte(PongMsg): %v", err)
	}

	h.topology.SetPacketMutator(func(fromNode, toNode int, family bindtest.AddressFamily, packet []byte) []byte {
		if fromNode == 0 && toNode == 1 && family == bindtest.IPv4 && len(packet) > 0 && path.Usage(packet[0]) == path.PongPacket {
			mutated := append([]byte(nil), packet...)
			mutated[0] = byte(path.BroadcastPeer)
			h.topology.SetPacketMutator(nil)
			return mutated
		}
		return packet
	})

	sendControlPacket(t, h.nodes[0], peer01, path.PongPacket, h.nodes[1].device.ID, body)
	time.Sleep(150 * time.Millisecond)
	if got := h.nodes[1].device.graph.Weight(h.nodes[0].device.ID, h.nodes[1].device.ID, false); got != mtypes.Infinity {
		t.Fatalf("mutated Pong updated graph weight to %v, want Infinity", got)
	}

	sendControlPacket(t, h.nodes[0], peer01, path.PongPacket, h.nodes[1].device.ID, body)
	waitUntil(t, 2*time.Second, "valid Pong processing after removing mutator", func() bool {
		return h.nodes[1].device.graph.Weight(h.nodes[0].device.ID, h.nodes[1].device.ID, false) != mtypes.Infinity
	})
}

func TestGobIssue13BoardcastPeer(t *testing.T) {
	h := newP2PHarness(t, 3)
	defer h.close()

	peer01, _ := connectHarnessPeers(t, h, 0, 1, bindtest.IPv4)
	if got := h.nodes[1].device.LookupPeer(h.nodes[2].pub); got != nil {
		t.Fatalf("unexpected preexisting node-2 peer: %v", got)
	}

	body, err := mtypes.GetByte(&mtypes.BoardcastPeerMsg{
		Request_ID: uint32(h.nodes[0].device.ID),
		NodeID:     h.nodes[2].device.ID,
		PubKey:     h.nodes[2].pub,
		ConnURL:    h.topology.Endpoint(2, bindtest.IPv4).DstToString(),
	})
	if err != nil {
		t.Fatalf("GetByte(BoardcastPeerMsg): %v", err)
	}

	h.topology.SetPacketMutator(func(fromNode, toNode int, family bindtest.AddressFamily, packet []byte) []byte {
		if fromNode == 0 && toNode == 1 && family == bindtest.IPv4 && len(packet) > 0 && path.Usage(packet[0]) == path.BroadcastPeer {
			mutated := append([]byte(nil), packet...)
			mutated[0] = byte(path.PongPacket)
			h.topology.SetPacketMutator(nil)
			return mutated
		}
		return packet
	})

	sendControlPacket(t, h.nodes[0], peer01, path.BroadcastPeer, mtypes.NodeID_Spread, body)
	time.Sleep(150 * time.Millisecond)
	if got := h.nodes[1].device.LookupPeer(h.nodes[2].pub); got != nil {
		t.Fatalf("mutated BoardcastPeer created peer %v, want nil", got)
	}

	body, err = mtypes.GetByte(&mtypes.BoardcastPeerMsg{
		Request_ID: uint32(h.nodes[0].device.ID) + 1,
		NodeID:     h.nodes[2].device.ID,
		PubKey:     h.nodes[2].pub,
		ConnURL:    h.topology.Endpoint(2, bindtest.IPv4).DstToString(),
	})
	if err != nil {
		t.Fatalf("GetByte(BoardcastPeerMsg resend): %v", err)
	}
	sendControlPacket(t, h.nodes[0], peer01, path.BroadcastPeer, mtypes.NodeID_Spread, body)
	waitUntil(t, 2*time.Second, "valid BoardcastPeer processing after removing mutator", func() bool {
		return h.nodes[1].device.LookupPeer(h.nodes[2].pub) != nil
	})
}

func TestGobIssue13DeScope(t *testing.T) {
	first, err := mtypes.GetByte(&mtypes.PongMsg{Src_nodeID: 1, Dst_nodeID: 2})
	if err != nil {
		t.Fatalf("GetByte(first PongMsg): %v", err)
	}
	second, err := mtypes.GetByte(&mtypes.PongMsg{Src_nodeID: 2, Dst_nodeID: 1})
	if err != nil {
		t.Fatalf("GetByte(second PongMsg): %v", err)
	}
	if _, err := mtypes.ParsePongMsg(first); err != nil {
		t.Fatalf("ParsePongMsg(first): %v", err)
	}
	if _, err := mtypes.ParsePongMsg(second); err != nil {
		t.Fatalf("ParsePongMsg(second): %v", err)
	}

	var stream bytes.Buffer
	enc := gob.NewEncoder(&stream)
	dec := gob.NewDecoder(&stream)
	if err := enc.Encode(&mtypes.PongMsg{Src_nodeID: 1, Dst_nodeID: 2}); err != nil {
		t.Fatalf("enc.Encode(first): %v", err)
	}
	var got mtypes.PongMsg
	if err := dec.Decode(&got); err != nil {
		t.Fatalf("dec.Decode(first): %v", err)
	}
	stream.Reset()
	if err := gob.NewEncoder(&stream).Encode(&mtypes.PongMsg{Src_nodeID: 2, Dst_nodeID: 1}); err != nil {
		t.Fatalf("enc.Encode(second stream): %v", err)
	}
	if err := dec.Decode(&got); err == nil || !strings.Contains(err.Error(), "duplicate type received") {
		t.Fatalf("reused decoder error = %v, want duplicate type received", err)
	}
}

func TestP2PSelfAddressReporting(t *testing.T) {
	h := newP2PHarness(t, 2)
	defer h.close()

	h.startNode(0)
	h.startNode(1)
	peer := h.addPeer(0, 1, bindtest.IPv4)

	superPriv, superPub := RandomKeyPair()
	_ = superPriv
	superPeer, err := h.nodes[0].device.NewPeer(superPub, mtypes.NodeID_SuperNode, true, 0)
	if err != nil {
		t.Fatalf("NewPeer(super): %v", err)
	}
	superPeer.SetEndpointFromPacket(reportTestEndpoint{src: net.ParseIP("127.0.0.1"), dst: net.ParseIP("127.0.0.1"), port: 51820})
	superPeer.SetEndpointFromPacket(reportTestEndpoint{src: net.ParseIP("::1"), dst: net.ParseIP("::1"), port: 51820})

	h.nodes[0].device.EdgeConfig.DynamicRoute.SuperNode.AdditionalLocalIP = []string{"127.0.0.2:6000", "[::1]:7000"}

	report := h.nodes[0].device.buildPeerInfoReport()
	port := int(h.nodes[0].device.net.port)
	if len(report.Pongs) != 1 || report.Pongs[0].Src_nodeID != peer.ID {
		t.Fatalf("unexpected pongs in report: %+v", report.Pongs)
	}
	if got := report.LocalV4s[(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}).String()]; got != 100 {
		t.Fatalf("learned local IPv4 weight = %v, want 100; report=%+v", got, report.LocalV4s)
	}
	if got := report.LocalV6s[(&net.UDPAddr{IP: net.ParseIP("::1"), Port: port}).String()]; got != 100 {
		t.Fatalf("learned local IPv6 weight = %v, want 100; report=%+v", got, report.LocalV6s)
	}
	if got := report.LocalV4s["127.0.0.2:6000"]; got != 50 {
		t.Fatalf("configured local IPv4 weight = %v, want 50; report=%+v", got, report.LocalV4s)
	}
	if got := report.LocalV6s["[::1]:7000"]; got != 50 {
		t.Fatalf("configured local IPv6 weight = %v, want 50; report=%+v", got, report.LocalV6s)
	}
}

func TestP2PHarnessOffline(t *testing.T) {
	h := newP2PHarness(t, 3)
	defer h.close()

	h.topology.SetOffline(2, true)
	if !h.topology.IsOffline(2) {
		t.Fatal("node 2 should be offline")
	}
	if err := h.nodes[0].bind.Send([]byte("offline"), h.topology.Endpoint(2, bindtest.IPv4)); err != nil {
		t.Fatalf("Send() to offline peer: %v", err)
	}
	if got := h.topology.Pending(2, bindtest.IPv4); got != 0 {
		t.Fatalf("offline peer queued %d packets, want 0", got)
	}

	h.startNode(2)
	h.closeNode(2)
}

func TestP2PHarnessIPv6NoRoute(t *testing.T) {
	h := newP2PHarness(t, 2)
	defer h.close()

	h.topology.SetIPv6NoRoute(0, true)
	err := h.nodes[0].bind.Send([]byte("v6"), h.topology.Endpoint(1, bindtest.IPv6))
	if err == nil {
		t.Fatal("expected IPv6 no-route error")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("expected net.OpError, got %T", err)
	}
	if opErr.Net != "udp6" {
		t.Fatalf("error network = %q, want udp6", opErr.Net)
	}
	if !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("error = %v, want ENETUNREACH", err)
	}
	if got := h.topology.Pending(1, bindtest.IPv6); got != 0 {
		t.Fatalf("IPv6 no-route queued %d packets, want 0", got)
	}

	h.topology.SetIPv6NoRoute(0, false)
	if err := h.nodes[0].bind.Send([]byte("v4-ok"), h.topology.Endpoint(1, bindtest.IPv4)); err != nil {
		t.Fatalf("IPv4 send after IPv6 failure: %v", err)
	}
	buf := make([]byte, 64)
	n, endpoint, err := h.nodes[1].recv4(buf)
	if err != nil {
		t.Fatalf("recv4(): %v", err)
	}
	if got := string(buf[:n]); got != "v4-ok" {
		t.Fatalf("recv4 payload = %q, want %q", got, "v4-ok")
	}
	if got, want := endpoint.DstToString(), h.topology.Endpoint(0, bindtest.IPv4).DstToString(); got != want {
		t.Fatalf("recv4 source endpoint = %q, want %q", got, want)
	}

	if err := h.nodes[0].bind.Send([]byte("v6-ok"), h.topology.Endpoint(1, bindtest.IPv6)); err != nil {
		t.Fatalf("IPv6 send after clearing no-route: %v", err)
	}
	n, endpoint, err = h.nodes[1].recv6(buf)
	if err != nil {
		t.Fatalf("recv6(): %v", err)
	}
	if got := string(buf[:n]); got != "v6-ok" {
		t.Fatalf("recv6 payload = %q, want %q", got, "v6-ok")
	}
	if got, want := endpoint.DstToString(), h.topology.Endpoint(0, bindtest.IPv6).DstToString(); got != want {
		t.Fatalf("recv6 source endpoint = %q, want %q", got, want)
	}
}

func TestEndpointTrylistConcurrentRotation(t *testing.T) {
	h := newP2PHarness(t, 5)
	defer h.close()

	peer := h.addPeer(0, 1, bindtest.IPv4)
	trylist := peer.endpoint_trylist
	trylist.timeout = 50 * time.Millisecond

	superA := h.topology.Endpoint(1, bindtest.IPv4).DstToString()
	superB := h.topology.Endpoint(2, bindtest.IPv4).DstToString()
	p2pLive := h.topology.Endpoint(3, bindtest.IPv4).DstToString()
	p2pStale := h.topology.Endpoint(4, bindtest.IPv4).DstToString()
	now := time.Now()

	trylist.Lock()
	trylist.trymap_super = map[string]*endpoint_tryitem{
		superA: {URL: superA, lastTry: now.Add(-4 * time.Second)},
		superB: {URL: superB, lastTry: now.Add(-3 * time.Second)},
	}
	trylist.trymap_p2p = map[string]*endpoint_tryitem{
		p2pLive:  {URL: p2pLive, lastTry: now.Add(-2 * time.Second)},
		p2pStale: {URL: p2pStale, lastTry: now.Add(-5 * time.Second), firstTry: now.Add(-200 * time.Millisecond)},
	}
	trylist.Unlock()

	rotation := []string{superA, superB, p2pLive}
	for i, want := range rotation {
		fast, got := trylist.GetNextTry()
		if !fast {
			t.Fatalf("rotation %d returned slow retry for %q", i, got)
		}
		if got != want {
			t.Fatalf("rotation %d got %q, want %q", i, got, want)
		}
	}

	trylist.RLock()
	if _, ok := trylist.trymap_p2p[p2pStale]; ok {
		trylist.RUnlock()
		t.Fatalf("stale P2P candidate %q was not pruned", p2pStale)
	}
	trylist.RUnlock()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				if _, got := trylist.GetNextTry(); got == "" {
					t.Error("GetNextTry returned empty URL")
					return
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for j := 0; j < 50; j++ {
				trylist.UpdateP2P(p2pLive)
			}
		}()
	}
	close(start)
	wg.Wait()

	trylist.RLock()
	if _, ok := trylist.trymap_p2p[p2pStale]; ok {
		trylist.RUnlock()
		t.Fatalf("stale P2P candidate %q reappeared after concurrent rotation", p2pStale)
	}
	trylist.RUnlock()
}

func TestP2POfflinePeerChurnDoesNotLeakOrStall(t *testing.T) {
	h := newP2PHarness(t, 3)
	defer h.close()

	h.startNode(0)
	device := h.nodes[0].device
	device.EdgeConfig.DynamicRoute.ConnNextTry = 1

	deadPeer := h.addPeer(0, 1, bindtest.IPv4)
	alivePeer := h.addPeer(0, 2, bindtest.IPv4)
	stale := time.Now().Add(-10 * time.Second)
	deadPeer.LastPacketReceivedAdd1Sec.Store(&stale)

	go device.RoutineTryReceivedEndpoint()
	baselineGoroutines := runtime.NumGoroutine()

	churn := mtypes.BoardcastPeerMsg{
		Request_ID: 0,
		NodeID:     deadPeer.ID,
		PubKey:     deadPeer.handshake.remoteStatic,
		ConnURL:    h.topology.Endpoint(1, bindtest.IPv4).DstToString(),
	}
	for i := 0; i < 128; i++ {
		if err := device.process_BoardcastPeerMsg(alivePeer, churn); err != nil {
			t.Fatalf("process_BoardcastPeerMsg(%d): %v", i, err)
		}
	}

	waitUntil(t, time.Second, "dead peer hole punch start", func() bool {
		return deadPeer.retry.holePunching.Get()
	})

	time.Sleep(100 * time.Millisecond)
	if got := runtime.NumGoroutine() - baselineGoroutines; got > 12 {
		t.Fatalf("dead peer retry pressure spawned %d extra goroutines, want <= 12", got)
	}
	if got := len(device.event_tryendpoint); got > 1 {
		t.Fatalf("event_tryendpoint backlog = %d, want <= 1", got)
	}

	aliveMsg := mtypes.BoardcastPeerMsg{
		Request_ID: 0,
		NodeID:     alivePeer.ID,
		PubKey:     alivePeer.handshake.remoteStatic,
		ConnURL:    h.topology.Endpoint(2, bindtest.IPv4).DstToString(),
	}
	done := make(chan error, 1)
	go func() {
		done <- device.process_BoardcastPeerMsg(deadPeer, aliveMsg)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("alive peer broadcast failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("alive peer broadcast stalled under dead peer churn")
	}
}

func TestIPv6NoRouteRetriesWithoutPeerExit(t *testing.T) {
	h := newP2PHarness(t, 2)
	defer h.close()

	h.startNode(0)
	device := h.nodes[0].device
	device.EdgeConfig.DynamicRoute.ConnNextTry = 0.05
	peer, err := device.NewPeer(h.nodes[1].pub, h.nodes[1].device.ID, false, 0)
	if err != nil {
		t.Fatalf("NewPeer(): %v", err)
	}

	v4URL := h.topology.Endpoint(1, bindtest.IPv4).DstToString()
	v6URL := h.topology.Endpoint(1, bindtest.IPv6).DstToString()
	now := time.Now()
	peer.endpoint_trylist.Lock()
	peer.endpoint_trylist.trymap_super = map[string]*endpoint_tryitem{
		v6URL: {URL: v6URL, lastTry: now.Add(-2 * time.Second)},
		v4URL: {URL: v4URL, lastTry: now.Add(-1 * time.Second)},
	}
	peer.endpoint_trylist.trymap_p2p = map[string]*endpoint_tryitem{}
	peer.endpoint_trylist.Unlock()

	noRouteIPv6 := true
	restore := conn.SetLookupIPDialForTest(func(network, address string) (net.Conn, error) {
		switch address {
		case v6URL:
			switch network {
			case "udp6", "udp":
				if noRouteIPv6 {
					return nil, bindtest.NewIPv6NoRouteError(h.topology.Endpoint(1, bindtest.IPv6).DstIP().String())
				}
				return &retryLookupTestConn{remote: mustResolveRetryLookupAddr(t, network, address)}, nil
			default:
				return nil, &net.AddrError{Err: "no suitable address found", Addr: address}
			}
		case v4URL:
			switch network {
			case "udp4", "udp":
				return &retryLookupTestConn{remote: mustResolveRetryLookupAddr(t, network, address)}, nil
			default:
				return nil, &net.AddrError{Err: "no suitable address found", Addr: address}
			}
		default:
			return nil, &net.AddrError{Err: "unexpected address", Addr: address}
		}
	})
	defer restore()

	go device.RoutineTryReceivedEndpoint()
	device.signalTryEndpoint()

	waitUntil(t, 2*time.Second, "IPv4 fallback endpoint after transient IPv6 failure", func() bool {
		return peer.GetEndpointDstStr() == v4URL
	})
	if device.isClosed() {
		t.Fatal("device closed after transient IPv6 route failure")
	}
	peer.endpoint_trylist.RLock()
	_, hasIPv6Candidate := peer.endpoint_trylist.trymap_super[v6URL]
	peer.endpoint_trylist.RUnlock()
	if !hasIPv6Candidate {
		t.Fatalf("transient IPv6 candidate %q was deleted", v6URL)
	}

	noRouteIPv6 = false
	peer.endpoint_trylist.Lock()
	delete(peer.endpoint_trylist.trymap_super, v4URL)
	if item := peer.endpoint_trylist.trymap_super[v6URL]; item != nil {
		item.lastTry = time.Now().Add(-2 * time.Second)
		item.firstTry = time.Time{}
	}
	peer.endpoint_trylist.Unlock()
	stale := time.Now().Add(-10 * time.Second)
	peer.LastPacketReceivedAdd1Sec.Store(&stale)
	device.signalTryEndpoint()

	waitUntil(t, 2*time.Second, "retained IPv6 candidate retry after route recovery", func() bool {
		return peer.GetEndpointDstStr() == v6URL
	})
}
