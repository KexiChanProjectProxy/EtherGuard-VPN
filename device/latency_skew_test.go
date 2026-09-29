package device

import (
	"math"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func newP2PPingTestDevice(t *testing.T) (*Device, *Peer, *recordingLogger) {
	t.Helper()
	graph, err := path.NewGraph(0, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	logs := &recordingLogger{}
	device := &Device{
		ID:    1,
		log:   logs.logger(),
		graph: graph,
		EdgeConfig: &mtypes.EdgeConfig{
			Interface:  mtypes.InterfaceConf{MTU: 1400},
			DefaultTTL: 200,
			DynamicRoute: mtypes.DynamicRouteInfo{
				SendPingInterval: 16,
				PeerAliveTimeout: 70,
				P2P:              mtypes.P2PInfo{UseP2P: true},
			},
		},
		chan_send_packet: make(chan *packet_send_params, 8),
	}
	device.PopulatePools()
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	peer := &Peer{ID: 2, device: device, endpoint: reliabilityTestEndpoint{}}
	peer.SingleWayLatency.device = device
	peer.RawOneWay.device = device
	device.peers.IDMap[peer.ID] = peer
	t.Cleanup(func() { drainPongs(t, device) })
	return device, peer, logs
}

// drainPongs returns every queued pong and releases the queued elements.
func drainPongs(t *testing.T, device *Device) []mtypes.PongMsg {
	t.Helper()
	var pongs []mtypes.PongMsg
	for {
		select {
		case params := <-device.chan_send_packet:
			if params.elem.Type == path.PongPacket {
				pong, err := mtypes.ParsePongMsg(params.elem.packet[path.EgHeaderLen:])
				if err != nil {
					t.Fatalf("parse pong: %v", err)
				}
				pongs = append(pongs, pong)
			}
			device.PutMessageBuffer(params.elem.buffer)
			device.PutOutboundElement(params.elem)
		default:
			return pongs
		}
	}
}

// pingFrom sends a ping from peer whose stamp makes the raw delta rawDelta.
func pingFrom(t *testing.T, device *Device, peer *Peer, rawDelta time.Duration) mtypes.PongMsg {
	t.Helper()
	content := mtypes.PingMsg{Src_nodeID: peer.ID, Time: device.graph.GetCurrentTime().Add(-rawDelta)}
	if err := device.process_ping(peer, content); err != nil {
		t.Fatalf("process_ping: %v", err)
	}
	pongs := drainPongs(t, device)
	if len(pongs) == 0 {
		t.Fatal("process_ping emitted no pong")
	}
	return pongs[0]
}

func TestProcessPingCancelsClockSkewWithReverseSample(t *testing.T) {
	// Given the peer's clock runs 40 ms ahead: its ping looks like -20 ms,
	// and it measured +60 ms for this node's ping; the true one-way is 20 ms
	device, peer, logs := newP2PPingTestDevice(t)
	peer.reverseRaw.Store(&oneWaySample{raw: 0.060, at: time.Now()})

	// When
	pong := pingFrom(t, device, peer, -20*time.Millisecond)

	// Then the reported and local latency are the offset-cancelled 20 ms
	if math.Abs(pong.Timediff-0.020) > 0.003 {
		t.Fatalf("Timediff = %f, want about 0.020", pong.Timediff)
	}
	if !pong.HasRawTimediff || math.Abs(pong.RawTimediff+0.020) > 0.003 {
		t.Fatalf("RawTimediff = %f (has=%v), want about -0.020", pong.RawTimediff, pong.HasRawTimediff)
	}
	if got := device.graph.Weight(peer.ID, device.ID, false); math.Abs(got-0.020) > 0.003 {
		t.Fatalf("graph edge = %f, want about 0.020", got)
	}
	if len(logs.errors) != 0 {
		t.Fatalf("unexpected errors: %v", logs.errors)
	}
	if logs.count(verboseLines, "corrected=true") != 1 {
		t.Fatalf("missing verbose sample line: %v", logs.verbose)
	}
}

func TestProcessPingReportsLargeSkewOncePerInterval(t *testing.T) {
	// Given the peer runs 140 ms ahead (raw -20 ms, reverse +260 ms)
	device, peer, logs := newP2PPingTestDevice(t)
	peer.reverseRaw.Store(&oneWaySample{raw: 0.260, at: time.Now()})

	// When the peer pings three times
	for i := 0; i < 3; i++ {
		pong := pingFrom(t, device, peer, -20*time.Millisecond)
		if math.Abs(pong.Timediff-0.120) > 0.003 {
			t.Fatalf("Timediff = %f, want about 0.120", pong.Timediff)
		}
	}

	// Then the skew is reported once
	if got := logs.count(errorLines, "clock skew between node 1 and node 2 is about -140.0 ms"); got != 1 {
		t.Fatalf("skew errors = %d, want 1: %v", got, logs.errors)
	}
}

func TestProcessPingClampsNegativeRawWithoutReverseSample(t *testing.T) {
	device, peer, logs := newP2PPingTestDevice(t)

	// When three pings arrive with a negative raw delta and no reverse sample
	for i := 0; i < 3; i++ {
		pong := pingFrom(t, device, peer, -20*time.Millisecond)
		if pong.Timediff != 0 {
			t.Fatalf("Timediff = %f, want 0", pong.Timediff)
		}
		if !pong.HasRawTimediff || pong.RawTimediff >= 0 {
			t.Fatalf("RawTimediff = %f (has=%v), want the negative raw delta", pong.RawTimediff, pong.HasRawTimediff)
		}
	}
	// Then one rate-limited error is logged
	if got := logs.count(errorLines, "negative raw one-way latency source=2 destination=1"); got != 1 {
		t.Fatalf("errors = %d, want 1: %v", got, logs.errors)
	}

	// When the interval has passed
	peer.clockWarn.last.Store(time.Now().Add(-clockWarnInterval - time.Second).UnixNano())
	pingFrom(t, device, peer, -20*time.Millisecond)
	if got := logs.count(errorLines, "negative raw one-way latency"); got != 2 {
		t.Fatalf("errors = %d, want 2 after the interval", got)
	}
}

func TestProcessPingIgnoresStaleReverseSample(t *testing.T) {
	device, peer, _ := newP2PPingTestDevice(t)
	peer.reverseRaw.Store(&oneWaySample{raw: 0.060, at: time.Now().Add(-2 * device.reverseSampleMaxAge())})
	if pong := pingFrom(t, device, peer, -20*time.Millisecond); pong.Timediff != 0 {
		t.Fatalf("Timediff = %f, want the clamped 0", pong.Timediff)
	}
}

func TestProcessPongStoresReverseSampleOnPongAuthor(t *testing.T) {
	device, author, _ := newP2PPingTestDevice(t)
	relay := &Peer{ID: 3, device: device, endpoint: reliabilityTestEndpoint{}}
	relay.SingleWayLatency.device = device
	device.peers.IDMap[relay.ID] = relay

	// A legacy pong leaves no sample
	legacy := mtypes.PongMsg{Src_nodeID: device.ID, Dst_nodeID: author.ID, Timediff: 0.01, TimeToAlive: 70}
	if err := device.process_pong(relay, legacy); err != nil {
		t.Fatal(err)
	}
	if author.reverseRaw.Load() != nil {
		t.Fatal("legacy pong set a reverse sample")
	}

	// A pong about another pair leaves no sample
	other := mtypes.PongMsg{Src_nodeID: relay.ID, Dst_nodeID: author.ID, Timediff: 0.01, TimeToAlive: 70, RawTimediff: 0.05, HasRawTimediff: true}
	if err := device.process_pong(relay, other); err != nil {
		t.Fatal(err)
	}
	if author.reverseRaw.Load() != nil {
		t.Fatal("pong for another pinger set a reverse sample")
	}

	// A pong for this node's ping relayed by another peer is stored on its author
	mine := mtypes.PongMsg{Src_nodeID: device.ID, Dst_nodeID: author.ID, Timediff: 0.01, TimeToAlive: 70, RawTimediff: -0.03, HasRawTimediff: true}
	if err := device.process_pong(relay, mine); err != nil {
		t.Fatal(err)
	}
	if sample := author.reverseRaw.Load(); sample == nil || sample.raw != -0.03 {
		t.Fatalf("author sample = %+v, want raw -0.03", sample)
	}
	if relay.reverseRaw.Load() != nil {
		t.Fatal("sample stored on the relay")
	}
}

func TestCorrectOneWay(t *testing.T) {
	now := time.Now()
	fresh := func(raw float64) *oneWaySample { return &oneWaySample{raw: raw, at: now.Add(-time.Second)} }
	cases := []struct {
		name          string
		raw           float64
		reverse       *oneWaySample
		wantOneWay    float64
		wantSkew      float64
		wantCorrected bool
	}{
		{"no reverse, positive", 0.03, nil, 0.03, 0, false},
		{"no reverse, negative", -0.03, nil, 0, 0, false},
		{"stale reverse", -0.03, &oneWaySample{raw: 0.07, at: now.Add(-time.Hour)}, 0, 0, false},
		{"non-finite reverse", -0.03, fresh(math.Inf(1)), 0, 0, false},
		{"this node ahead", 0.07, fresh(-0.03), 0.02, 0.05, true},
		{"peer ahead", -0.03, fresh(0.07), 0.02, -0.05, true},
		{"negative after correction", -0.05, fresh(0.01), -0.02, -0.03, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oneWay, skew, corrected := correctOneWay(tc.raw, tc.reverse, now, time.Minute)
			if corrected != tc.wantCorrected || math.Abs(oneWay-tc.wantOneWay) > 1e-9 || math.Abs(skew-tc.wantSkew) > 1e-9 {
				t.Fatalf("got (%f, %f, %v), want (%f, %f, %v)", oneWay, skew, corrected, tc.wantOneWay, tc.wantSkew, tc.wantCorrected)
			}
		})
	}
}

func TestReverseSampleMaxAge(t *testing.T) {
	device := &Device{EdgeConfig: &mtypes.EdgeConfig{}}
	for _, tc := range []struct {
		interval, alive float64
		want            time.Duration
	}{
		{16, 70, 48 * time.Second},
		{30, 70, 70 * time.Second},
		{0, 70, 70 * time.Second},
		{16, 0, 48 * time.Second},
	} {
		device.EdgeConfig.DynamicRoute.SendPingInterval = tc.interval
		device.EdgeConfig.DynamicRoute.PeerAliveTimeout = tc.alive
		if got := device.reverseSampleMaxAge(); got != tc.want {
			t.Fatalf("interval %v alive %v: got %v, want %v", tc.interval, tc.alive, got, tc.want)
		}
	}
}
