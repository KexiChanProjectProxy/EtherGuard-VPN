package device

import (
	"math"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
)

type pureSent struct {
	peer  *Peer
	usage path.Usage
	dst   mtypes.Vertex
}

func newPureP2PTestDevice(t *testing.T) *Device {
	t.Helper()
	graph, err := path.NewGraph(0, false, mtypes.GraphRecalculateSetting{TimeoutCheckInterval: 1}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	device := &Device{
		ID:    1,
		log:   NewLogger(LogLevelSilent, "purep2p-test"),
		graph: graph,
		EdgeConfig: &mtypes.EdgeConfig{
			Interface:  mtypes.InterfaceConf{MTU: 1400},
			DefaultTTL: 200,
			DynamicRoute: mtypes.DynamicRouteInfo{
				SendPingInterval: 16,
				PeerAliveTimeout: 70,
				P2P:              mtypes.P2PInfo{UseP2P: true, PureP2P: true},
			},
		},
		chan_send_packet: make(chan *packet_send_params, 32),
	}
	device.PopulatePools()
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	t.Cleanup(func() { drainPureSent(t, device) })
	return device
}

func addTestPeer(device *Device, id mtypes.Vertex, alive bool) *Peer {
	peer := &Peer{ID: id, device: device, endpoint: reliabilityTestEndpoint{}}
	peer.SingleWayLatency.device = device
	peer.RawOneWay.device = device
	last := time.Now()
	if !alive {
		last = last.Add(-time.Hour)
	}
	peer.LastPacketReceivedAdd1Sec.Store(&last)
	device.peers.IDMap[id] = peer
	return peer
}

// drainPureSent returns every queued packet and releases the queued elements.
func drainPureSent(t *testing.T, device *Device) []pureSent {
	t.Helper()
	var sent []pureSent
	for {
		select {
		case params := <-device.chan_send_packet:
			header, err := path.NewEgHeader(params.elem.packet[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
			if err != nil {
				t.Fatalf("parse header: %v", err)
			}
			sent = append(sent, pureSent{peer: params.peer, usage: params.elem.Type, dst: header.GetDst()})
			device.PutMessageBuffer(params.elem.buffer)
			device.PutOutboundElement(params.elem)
		default:
			return sent
		}
	}
}

func dataFrame(dst mtypes.Vertex) []byte {
	packet := make([]byte, path.EgHeaderLen+60)
	header, _ := path.NewEgHeader(packet[:path.EgHeaderLen], 1400)
	header.SetSrc(1)
	header.SetDst(dst)
	return packet
}

func assertGraphEmpty(t *testing.T, device *Device) {
	t.Helper()
	if vertices := device.graph.Vertices(); len(vertices) != 0 {
		t.Fatalf("graph vertices = %v, want none in PureP2P", vertices)
	}
}

func TestPureP2PRequiresUseP2P(t *testing.T) {
	if (mtypes.P2PInfo{PureP2P: true}).IsPure() {
		t.Fatal("PureP2P without UseP2P reported as pure")
	}
	if !(mtypes.P2PInfo{UseP2P: true, PureP2P: true}).IsPure() {
		t.Fatal("UseP2P+PureP2P not reported as pure")
	}
}

func TestPureP2PDirectAlivePeer(t *testing.T) {
	device := newPureP2PTestDevice(t)
	alive := addTestPeer(device, 2, true)
	addTestPeer(device, 3, false)

	if got := device.directAlivePeer(9); got != nil {
		t.Fatalf("unknown node = %v, want nil", got.ID)
	}
	if got := device.directAlivePeer(3); got != nil {
		t.Fatal("dead peer returned")
	}
	if got := device.directAlivePeer(mtypes.NodeID_Broadcast); got != nil {
		t.Fatal("special id returned a peer")
	}
	if got := device.directAlivePeer(2); got != alive {
		t.Fatalf("alive peer = %v, want peer 2", got)
	}
	assertGraphEmpty(t, device)
}

func TestPureP2PBoardcastPacketSendsToAlivePeersOnly(t *testing.T) {
	device := newPureP2PTestDevice(t)
	addTestPeer(device, 2, true)
	addTestPeer(device, 3, false)
	addTestPeer(device, 4, true)

	device.BoardcastPacket(map[mtypes.Vertex]bool{4: true}, path.NormalPacket, 200, dataFrame(mtypes.NodeID_Broadcast), MessageTransportOffsetContent)

	sent := drainPureSent(t, device)
	if len(sent) != 1 || sent[0].peer.ID != 2 {
		t.Fatalf("sent = %+v, want only peer 2", sent)
	}
	if list := device.graph.GetBoardcastList(device.ID); len(list) != 0 {
		t.Fatalf("broadcast list = %v, want empty", list)
	}
}

func TestPureP2PTransitBoardcastPacketIsNoop(t *testing.T) {
	device := newPureP2PTestDevice(t)
	addTestPeer(device, 2, true)
	addTestPeer(device, 3, true)

	device.TransitBoardcastPacket(2, 2, path.NormalPacket, 199, dataFrame(mtypes.NodeID_Broadcast), MessageTransportOffsetContent)

	if sent := drainPureSent(t, device); len(sent) != 0 {
		t.Fatalf("relayed broadcast: %+v", sent)
	}
}

func TestPureP2PProcessPingRepliesDirectly(t *testing.T) {
	device := newPureP2PTestDevice(t)
	pinger := addTestPeer(device, 2, true)
	addTestPeer(device, 3, true)

	if err := device.process_ping(pinger, mtypes.PingMsg{Src_nodeID: 2, Time: time.Now()}, nil); err != nil {
		t.Fatalf("process_ping: %v", err)
	}

	var pongs []pureSent
	for _, packet := range drainPureSent(t, device) {
		if packet.usage == path.PongPacket {
			pongs = append(pongs, packet)
		}
	}
	if len(pongs) != 1 || pongs[0].peer != pinger || pongs[0].dst != 2 {
		t.Fatalf("pongs = %+v, want one unicast pong to node 2", pongs)
	}
	assertGraphEmpty(t, device)
}

func TestPureP2PProcessPongSendsQueryPeerOnce(t *testing.T) {
	device := newPureP2PTestDevice(t)
	peer := addTestPeer(device, 2, true)

	// A pong for one of our pings asks for neighbours, even without a
	// usable latency sample.
	if err := device.process_pong(peer, mtypes.PongMsg{Src_nodeID: 1, Dst_nodeID: 2, Timediff: math.NaN()}); err != nil {
		t.Fatalf("process_pong: %v", err)
	}
	sent := drainPureSent(t, device)
	if len(sent) != 1 || sent[0].usage != path.QueryPeer || sent[0].peer != peer || sent[0].dst != mtypes.NodeID_Spread {
		t.Fatalf("sent = %+v, want one QueryPeer to peer 2", sent)
	}

	// A pong for someone else's ping is ignored.
	if err := device.process_pong(peer, mtypes.PongMsg{Src_nodeID: 5, Dst_nodeID: 2, Timediff: 0.01}); err != nil {
		t.Fatalf("process_pong: %v", err)
	}
	if sent := drainPureSent(t, device); len(sent) != 0 {
		t.Fatalf("foreign pong sent %+v", sent)
	}

	// Once the peer answered, no more queries.
	peer.AskedForNeighbor = true
	if err := device.process_pong(peer, mtypes.PongMsg{Src_nodeID: 1, Dst_nodeID: 2, Timediff: 0.01}); err != nil {
		t.Fatalf("process_pong: %v", err)
	}
	if sent := drainPureSent(t, device); len(sent) != 0 {
		t.Fatalf("answered peer queried again: %+v", sent)
	}
	assertGraphEmpty(t, device)
}

func TestPureP2PProbePongStillReachesProber(t *testing.T) {
	device := newPureP2PTestDevice(t)
	peer := addTestPeer(device, 2, true)
	peer.prober.rebuild([]*probePair{{key: "a", rtt: math.Inf(1)}})
	id := peer.prober.register("a", time.Now())

	if err := device.process_pong(peer, mtypes.PongMsg{RequestID: id, Src_nodeID: 1, Dst_nodeID: 2}); err != nil {
		t.Fatalf("process_pong: %v", err)
	}

	if pair := peer.prober.snapshot()[0]; pair.samples != 1 {
		t.Fatalf("probe pair = %+v, want one sample", pair)
	}
}

func TestRoutineRecalculateNhTableReturnsInPureP2P(t *testing.T) {
	device := newPureP2PTestDevice(t)
	done := make(chan struct{})
	go func() {
		device.RoutineRecalculateNhTable()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RoutineRecalculateNhTable kept running in PureP2P")
	}
}

func TestPureP2PBoardcastPeerMsgAddsPeerWithoutGraph(t *testing.T) {
	tapDevice, err := tap.CreateDummyTAP()
	if err != nil {
		t.Fatalf("dummy tap: %v", err)
	}
	graph, err := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	config := &mtypes.EdgeConfig{
		NodeID:     1,
		DefaultTTL: 64,
		Interface:  mtypes.InterfaceConf{MTU: 1400},
		DynamicRoute: mtypes.DynamicRouteInfo{
			PeerAliveTimeout: 70,
			DupCheckTimeout:  1,
			P2P:              mtypes.P2PInfo{UseP2P: true, PureP2P: true},
		},
	}
	device := NewDevice(tapDevice, 1, &endpointBlacklistTestBind{}, NewLogger(LogLevelSilent, "purep2p-test"), graph, "", config, "test")
	t.Cleanup(device.Close)
	_, fromKey := RandomKeyPair()
	from, err := device.NewPeer(fromKey, 2, false, 0)
	if err != nil {
		t.Fatalf("new peer: %v", err)
	}
	_, newKey := RandomKeyPair()

	err = device.process_BoardcastPeerMsg(from, mtypes.BoardcastPeerMsg{NodeID: 3, PubKey: newKey, ConnURL: "203.0.113.3:51820"})
	if err != nil {
		t.Fatalf("process_BoardcastPeerMsg: %v", err)
	}

	if device.LookupPeer(newKey) == nil {
		t.Fatal("advertised peer was not added")
	}
	if len(device.event_tryendpoint) == 0 {
		t.Fatal("no endpoint retry signalled for the new peer")
	}
	assertGraphEmpty(t, device)
}
