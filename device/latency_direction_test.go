package device

import (
	"math"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func TestProcessPingSuperModeEmitsPongToPinger(t *testing.T) {
	// Given
	device, peer := newSuperPingTestDevice(t)
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
		pong, err := mtypes.ParsePongMsg(params.elem.packet[path.EgHeaderLen:])
		if err != nil {
			t.Fatalf("parse PongPacket: %v", err)
		}
		if !pong.PingTime.Equal(content.Time) {
			t.Fatalf("echoed ping time = %v, want %v", pong.PingTime, content.Time)
		}
	case <-time.After(time.Second):
		t.Fatal("super-mode process_ping emitted no PongPacket")
	}
}

func TestProcessPingSuperModeClampsNegativeLegacyLatencyAndEchoesTimestamp(t *testing.T) {
	// Given
	device, peer := newSuperPingTestDevice(t)
	content := mtypes.PingMsg{
		Src_nodeID:   peer.ID,
		Time:         device.graph.GetCurrentTime().Add(time.Second),
		RequestReply: 0,
	}
	if rawDelta := device.graph.GetCurrentTime().Sub(content.Time).Seconds(); rawDelta >= 0 {
		t.Fatalf("raw receiver-clock delta = %f, want negative", rawDelta)
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
		pong, err := mtypes.ParsePongMsg(params.elem.packet[path.EgHeaderLen:])
		if err != nil {
			t.Fatalf("parse PongPacket: %v", err)
		}
		if !pong.PingTime.Equal(content.Time) {
			t.Fatalf("echoed ping time = %v, want %v", pong.PingTime, content.Time)
		}
		if pong.Timediff != 0 {
			t.Fatalf("legacy timediff = %f, want 0 after negative raw delta", pong.Timediff)
		}
	case <-time.After(time.Second):
		t.Fatal("super-mode process_ping emitted no PongPacket")
	}
}

func TestProcessPingSuperModeCarriesEffectiveRelayCost(t *testing.T) {
	// Given
	device, peer := newSuperPingTestDevice(t)
	device.EdgeConfig.SuperNodeV2Enabled = true
	relayCost := 125.5
	device.superHTTP = NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{NodeID: device.ID, RelayCostMS: &relayCost})
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
		pong, err := mtypes.ParsePongMsg(params.elem.packet[path.EgHeaderLen:])
		if err != nil {
			t.Fatalf("parse PongPacket: %v", err)
		}
		if pong.AdditionalCost != relayCost {
			t.Fatalf("pong additional cost = %f, want %f", pong.AdditionalCost, relayCost)
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
		PingTime:    time.Time{},
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

func TestProcessPongSuperModeUsesLocalRTTHalfWhenPingTimeEchoed(t *testing.T) {
	// Given
	device, peer := newSuperLatencyTestDevice(t)
	pingTime := device.graph.GetCurrentTime().Add(-40 * time.Millisecond)
	content := mtypes.PongMsg{
		Src_nodeID:  device.ID,
		Dst_nodeID:  peer.ID,
		Timediff:    -0.250,
		PingTime:    pingTime,
		TimeToAlive: device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
	}

	// When
	if err := device.process_pong(peer, content); err != nil {
		t.Fatalf("process_pong: %v", err)
	}

	// Then
	want := device.graph.GetCurrentTime().Sub(pingTime).Seconds() / 2
	got := device.graph.Weight(device.ID, peer.ID, false)
	if got <= 0 || math.Abs(got-want) > 0.01 {
		t.Fatalf("outbound graph latency = %f seconds, want local RTT/2 near %f seconds", got, want)
	}
	if outbound := peer.OutboundLatency.GetVal(); outbound <= 0 || math.Abs(outbound-want) > 0.01 {
		t.Fatalf("outbound latency = %f seconds, want local RTT/2 near %f seconds", outbound, want)
	}
}

func TestProcessPongSuperModeClampsNegativeAdditionalCost(t *testing.T) {
	// Given
	device, peer := newSuperLatencyTestDevice(t)
	content := mtypes.PongMsg{
		Src_nodeID:     device.ID,
		Dst_nodeID:     peer.ID,
		Timediff:       0.012,
		TimeToAlive:    device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
		AdditionalCost: -50,
	}

	// When
	if err := device.process_pong(peer, content); err != nil {
		t.Fatalf("process_pong: %v", err)
	}

	// Then
	if got := device.graph.Weight(device.ID, peer.ID, true); math.Abs(got-0.012) > 0.000001 {
		t.Fatalf("negative additional cost changed weighted latency to %f, want 0.012", got)
	}
}

func TestProcessPongSuperModeSkipsInvalidLegacyLatency(t *testing.T) {
	for _, sample := range []struct {
		name  string
		value float64
	}{
		{name: "negative", value: -0.012},
		{name: "not a number", value: math.NaN()},
		{name: "infinite", value: math.Inf(1)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			// Given
			device, peer := newSuperLatencyTestDevice(t)
			content := mtypes.PongMsg{
				Src_nodeID:  device.ID,
				Dst_nodeID:  peer.ID,
				Timediff:    sample.value,
				PingTime:    time.Time{},
				TimeToAlive: device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
			}

			// When
			if err := device.process_pong(peer, content); err != nil {
				t.Fatalf("process_pong: %v", err)
			}

			// Then
			if got := device.graph.Weight(device.ID, peer.ID, false); got != mtypes.Infinity {
				t.Fatalf("legacy invalid latency produced graph edge %f, want no edge", got)
			}
			if got := peer.OutboundLatency.GetVal(); got != mtypes.Infinity {
				t.Fatalf("legacy invalid latency produced outbound sample %f, want no sample", got)
			}
			if reports := device.superHTTPPongs(); len(reports) != 0 {
				t.Fatalf("legacy invalid latency produced %d report entries, want 0", len(reports))
			}
		})
	}
}

func newSuperPingTestDevice(t *testing.T) (*Device, *Peer) {
	t.Helper()
	graph, err := path.NewGraph(0, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	device := &Device{
		ID:    1,
		log:   NewLogger(LogLevelSilent, "super-ping-test"),
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
	return device, peer
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
