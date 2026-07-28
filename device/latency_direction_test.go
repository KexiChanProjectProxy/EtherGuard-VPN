package device

import (
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func TestProcessPingSuperModeEmitsPongToPinger(t *testing.T) {
	// Given
	graph, err := path.NewGraph(0, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	device := &Device{
		ID:    1,
		graph: graph,
		EdgeConfig: &mtypes.EdgeConfig{
			Interface: mtypes.InterfaceConf{MTU: 1400},
			DynamicRoute: mtypes.DynamicRouteInfo{
				PeerAliveTimeout: 60,
				P2P:              mtypes.P2PInfo{UseP2P: false},
			},
		},
		chan_send_packet: make(chan *packet_send_params, 1),
	}
	device.PopulatePools()
	peer := &Peer{ID: 2, device: device, endpoint: reliabilityTestEndpoint{}}
	peer.SingleWayLatency.device = device
	content := mtypes.PingMsg{
		Src_nodeID:   peer.ID,
		Time:         device.graph.GetCurrentTime().Add(-10 * time.Millisecond),
		RequestReply: 0,
	}

	// When
	if err := device.process_ping(peer, content); err != nil {
		t.Fatalf("process_ping: %v", err)
	}

	// Then
	select {
	case params := <-device.chan_send_packet:
		t.Cleanup(func() {
			device.PutMessageBuffer(params.elem.buffer)
			device.PutOutboundElement(params.elem)
		})
		if params.peer != peer {
			t.Fatalf("pong queued for peer %v, want pinger %v", params.peer.ID, peer.ID)
		}
		if params.elem.Type != path.PongPacket {
			t.Fatalf("queued packet type = %v, want PongPacket", params.elem.Type)
		}
		header, err := path.NewEgHeader(params.elem.packet[:path.EgHeaderLen], device.EdgeConfig.Interface.MTU)
		if err != nil {
			t.Fatalf("parse PongPacket header: %v", err)
		}
		if header.GetSrc() != device.ID || header.GetDst() != peer.ID {
			t.Fatalf("PongPacket route = %v -> %v, want %v -> %v", header.GetSrc(), header.GetDst(), device.ID, peer.ID)
		}
	case <-time.After(time.Second):
		t.Fatal("super-mode process_ping emitted no PongPacket")
	}
}

func TestProcessPongSuperModeAddsOutboundRoute(t *testing.T) {
	// Given
	device, peer := newSuperLatencyTestDevice(t)
	content := mtypes.PongMsg{
		Src_nodeID:  device.ID,
		Dst_nodeID:  peer.ID,
		Timediff:    0.012,
		TimeToAlive: device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
	}

	// When
	if err := device.process_pong(peer, content); err != nil {
		t.Fatalf("process_pong: %v", err)
	}

	// Then
	if next := device.graph.Next(device.ID, peer.ID); next != peer.ID {
		t.Fatalf("next hop self=%v peer=%v, want direct peer; graph edge was not recorded", device.ID, next)
	}
}

func newSuperLatencyTestDevice(t *testing.T) (*Device, *Peer) {
	t.Helper()
	graph, err := path.NewGraph(0, true, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	now := time.Now()
	device := &Device{
		ID:    1,
		log:   NewLogger(LogLevelSilent, "super-latency-test"),
		graph: graph,
		EdgeConfig: &mtypes.EdgeConfig{
			DynamicRoute: mtypes.DynamicRouteInfo{
				PeerAliveTimeout: 60,
				P2P:              mtypes.P2PInfo{UseP2P: false},
			},
		},
	}
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	peer := &Peer{ID: 2, device: device, endpoint: runtimeTestEndpoint{}}
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	peer.SingleWayLatency.device = device
	peer.SingleWayLatency.Push(0.250)
	peer.OutboundLatency.device = device
	peer.OutboundLatency.Push(mtypes.Infinity)
	device.peers.IDMap[peer.ID] = peer
	return device, peer
}
