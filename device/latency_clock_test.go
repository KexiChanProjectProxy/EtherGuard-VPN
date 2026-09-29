package device

import (
	"math"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func TestSentPingRegistryKeepsEntriesForEveryResponder(t *testing.T) {
	var registry sentPingRegistry
	mono := time.Now()
	wall := mono.Round(0)
	registry.record(wall, mono, time.Minute)
	for i := 0; i < 3; i++ {
		if got, ok := registry.lookup(wall); !ok || !got.Equal(mono) {
			t.Fatalf("lookup %d = %v %v", i, got, ok)
		}
	}
}

func TestSentPingRegistryEvictsByAgeAndCap(t *testing.T) {
	var registry sentPingRegistry
	base := time.Now()
	// Given an old entry, then a new one past the TTL
	registry.record(base.Round(0), base, time.Minute)
	later := base.Add(2 * time.Minute)
	registry.record(later.Round(0), later, time.Minute)
	if _, ok := registry.lookup(base.Round(0)); ok {
		t.Fatal("entry older than the TTL survived")
	}
	// When more than the cap are recorded within the TTL
	for i := 1; i <= sentPingRegistryCap+10; i++ {
		at := later.Add(time.Duration(i) * time.Millisecond)
		registry.record(at.Round(0), at, time.Minute)
	}
	// Then only the newest cap entries remain
	if registry.len() != sentPingRegistryCap {
		t.Fatalf("entries = %d, want %d", registry.len(), sentPingRegistryCap)
	}
	if _, ok := registry.lookup(later.Round(0)); ok {
		t.Fatal("oldest entry survived the cap")
	}
}

func TestGeneratePingPacketRegistersOnlyOwnRoutingPings(t *testing.T) {
	device, _ := newSuperLatencyTestDevice(t)
	device.EdgeConfig.Interface.MTU = 1400

	packet, _, _, err := device.GeneratePingPacket(device.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	ping, err := mtypes.ParsePingMsg(packet[path.EgHeaderLen:])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := device.sentPings.lookup(ping.Time); !ok {
		t.Fatal("routing ping was not registered under its gob-decoded stamp")
	}
	if _, _, _, err := device.GeneratePingPacketWithRequestID(device.ID, 0, 7); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := device.GeneratePingPacket(device.ID+1, 0); err != nil {
		t.Fatal(err)
	}
	if device.sentPings.len() != 1 {
		t.Fatalf("registered = %d, want only the routing ping", device.sentPings.len())
	}
}

func TestProcessPongSuperModeUsesMonotonicRoundTrip(t *testing.T) {
	// Given a ping stamped 10 s ahead (as after an NTP step) but built 40 ms ago
	device, peer := newSuperLatencyTestDevice(t)
	pingTime := device.graph.GetCurrentTime().Add(10 * time.Second)
	device.sentPings.record(pingTime, time.Now().Add(-40*time.Millisecond), time.Minute)
	content := mtypes.PongMsg{
		Src_nodeID:  device.ID,
		Dst_nodeID:  peer.ID,
		PingTime:    pingTime,
		TimeToAlive: device.EdgeConfig.DynamicRoute.PeerAliveTimeout,
	}

	// When
	if err := device.process_pong(peer, content); err != nil {
		t.Fatalf("process_pong: %v", err)
	}

	// Then the wall clocks are ignored: the edge gets RTT/2 of about 20 ms
	if got := device.graph.Weight(device.ID, peer.ID, false); math.Abs(got-0.020) > 0.005 {
		t.Fatalf("outbound graph latency = %f s, want about 0.020", got)
	}
	if got := peer.OutboundLatency.GetVal(); math.Abs(got-0.020) > 0.005 {
		t.Fatalf("outbound latency = %f s, want about 0.020", got)
	}
}
