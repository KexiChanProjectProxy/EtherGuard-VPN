package device

import (
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

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
