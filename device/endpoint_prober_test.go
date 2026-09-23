package device

import (
	"math"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

var testSelection = endpointSelectionSettings{
	enabled:    true,
	interval:   time.Second,
	minMargin:  5 * time.Millisecond,
	marginFrac: 0.15,
	rounds:     3,
}

func TestSelectEndpointPair(t *testing.T) {
	ms := func(v float64) float64 { return v / 1000 }
	cases := []struct {
		name       string
		pairs      []pairStats
		current    string
		wantKey    string
		wantSwitch bool
	}{
		{"faster by margin", []pairStats{{"a", ms(80), 3}, {"b", ms(20), 3}}, "a", "b", true},
		{"within absolute margin", []pairStats{{"a", ms(24), 3}, {"b", ms(20), 3}}, "a", "b", false},
		{"within relative margin", []pairStats{{"a", ms(200), 3}, {"b", ms(180), 3}}, "a", "b", false},
		{"current is best", []pairStats{{"a", ms(10), 3}, {"b", ms(20), 3}}, "a", "", false},
		{"unmeasured current is replaceable", []pairStats{{"a", math.Inf(1), 0}, {"b", ms(50), 3}}, "a", "b", true},
		{"too few samples", []pairStats{{"a", ms(80), 3}, {"b", ms(10), 2}}, "a", "", false},
		{"nothing measured", []pairStats{{"a", math.Inf(1), 0}, {"b", math.Inf(1), 0}}, "a", "", false},
		{"tie breaks by key", []pairStats{{"c", ms(90), 3}, {"b", ms(10), 3}, {"a", ms(10), 3}}, "c", "a", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, switchable := selectEndpointPair(tc.pairs, tc.current, 5*time.Millisecond, 0.15, 3)
			if key != tc.wantKey || switchable != tc.wantSwitch {
				t.Fatalf("got (%q, %v), want (%q, %v)", key, switchable, tc.wantKey, tc.wantSwitch)
			}
		})
	}
}

func pairKeys(pairs []*probePair) string {
	keys := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		keys = append(keys, pair.key)
	}
	return strings.Join(keys, ",")
}

func TestBuildProbePairsSingleHomedSingleCandidateBuildsNothing(t *testing.T) {
	pairs := buildProbePairs("198.51.100.7:3001", []trylistCandidate{{address: "198.51.100.7:3001"}}, nil, false, nil)
	if pairs != nil {
		t.Fatalf("pairs = %s, want none", pairKeys(pairs))
	}
}

func TestBuildProbePairsOrdersCurrentFirstMatchesFamiliesAndCaps(t *testing.T) {
	// Given two v4 uplinks, one v6 uplink and mixed-family remote candidates
	sources := []stunSource{wan1Source, wan1V6, wan2Source}
	candidates := []trylistCandidate{
		{address: "203.0.113.20:3001", cost: 0},
		{address: "[2001:db8::20]:3001", cost: 25000},
		{address: "203.0.113.21:3001", cost: 20000},
	}

	// When
	pairs := buildProbePairs("203.0.113.21:3001", candidates, sources, true, nil)

	// Then the current remote leads and pinned sources only pair with their family
	want := strings.Join([]string{
		"default|203.0.113.21:3001", "192.0.2.2#3|203.0.113.21:3001", "198.51.100.2#4|203.0.113.21:3001",
		"default|203.0.113.20:3001", "192.0.2.2#3|203.0.113.20:3001", "198.51.100.2#4|203.0.113.20:3001",
		"default|[2001:db8::20]:3001", "2001:db8:1::2#3|[2001:db8::20]:3001",
	}, ",")
	if got := pairKeys(pairs); got != want {
		t.Fatalf("pairs =\n%s\nwant\n%s", got, want)
	}
	if len(pairs) != endpointProbeMaxPairs {
		t.Fatalf("pair count = %d, want cap %d", len(pairs), endpointProbeMaxPairs)
	}
}

func TestBuildProbePairsDropsDisallowedRemotes(t *testing.T) {
	candidates := []trylistCandidate{{address: "203.0.113.20:3001"}, {address: "203.0.113.66:3001"}, {address: "203.0.113.21:3001"}}
	blocked := func(addrPort netip.AddrPort) bool { return addrPort.Addr() != netip.MustParseAddr("203.0.113.66") }
	pairs := buildProbePairs("", candidates, nil, false, blocked)
	if got := pairKeys(pairs); got != "default|203.0.113.20:3001,default|203.0.113.21:3001" {
		t.Fatalf("pairs = %s", got)
	}
}

func TestEndpointProberSmoothsRTTAndMarksMissesUnreachable(t *testing.T) {
	// Given
	var prober endpointProber
	prober.rebuild([]*probePair{{key: "a", rtt: math.Inf(1)}, {key: "b", rtt: math.Inf(1)}})
	base := time.Now()

	// When a first then second sample arrive for "a"
	id := prober.register("a", base)
	prober.onPong(id, base.Add(100*time.Millisecond))
	id = prober.register("a", base)
	prober.onPong(id, base.Add(200*time.Millisecond))

	// Then the second sample is blended with alpha 0.3
	pairs := prober.snapshot()
	if got := pairs[0].rtt; math.Abs(got-0.13) > 1e-9 || pairs[0].samples != 2 {
		t.Fatalf("rtt = %v samples = %d, want 0.13 and 2", got, pairs[0].samples)
	}

	// When "a" misses twice
	prober.register("a", base)
	prober.expire(base.Add(2*time.Second), time.Second)
	prober.register("a", base)
	prober.expire(base.Add(2*time.Second), time.Second)

	// Then it is unreachable
	if pair := prober.snapshot()[0]; !math.IsInf(pair.rtt, 1) || pair.samples != 0 {
		t.Fatalf("after misses rtt = %v samples = %d", pair.rtt, pair.samples)
	}
}

func TestEndpointProberIgnoresUnknownAndDuplicatePongs(t *testing.T) {
	var prober endpointProber
	prober.rebuild([]*probePair{{key: "a", rtt: math.Inf(1)}, {key: "b", rtt: math.Inf(1)}})
	now := time.Now()
	id := prober.register("a", now)
	prober.onPong(id+1000, now.Add(time.Millisecond))
	prober.onPong(id, now.Add(10*time.Millisecond))
	prober.onPong(id, now.Add(500*time.Millisecond))
	if pair := prober.snapshot()[0]; pair.samples != 1 || math.Abs(pair.rtt-0.01) > 1e-9 {
		t.Fatalf("pair = %+v, want one 10ms sample", pair)
	}
}

func TestEndpointProberRequestIDsAreNonZeroAndDistinct(t *testing.T) {
	var prober endpointProber
	prober.nextID = math.MaxUint32
	seen := make(map[uint32]bool)
	for i := 0; i < 4; i++ {
		id := prober.register("a", time.Now())
		if id == 0 || seen[id] {
			t.Fatalf("id %d reused or zero", id)
		}
		seen[id] = true
	}
}

func TestEndpointProberHysteresisNeedsConsecutiveRounds(t *testing.T) {
	// Given b is clearly faster than current a
	var prober endpointProber
	prober.rebuild([]*probePair{{key: "a", rtt: 0.08, samples: 3}, {key: "b", rtt: 0.02, samples: 3}})

	// When / Then: rounds 1 and 2 only build the streak
	for round := 1; round < testSelection.rounds; round++ {
		if target := prober.decide("a", testSelection); target != nil {
			t.Fatalf("switched after %d rounds", round)
		}
	}
	// A round where b is no longer clearly better resets the streak
	prober.pairs[1].rtt = 0.079
	if prober.decide("a", testSelection) != nil {
		t.Fatal("switched without a margin")
	}
	prober.pairs[1].rtt = 0.02
	for round := 1; round < testSelection.rounds; round++ {
		if prober.decide("a", testSelection) != nil {
			t.Fatalf("streak was not reset; switched after %d rounds", round)
		}
	}
	if target := prober.decide("a", testSelection); target == nil || target.key != "b" {
		t.Fatalf("target = %+v, want b", target)
	}
}

func TestEndpointProberRebuildKeepsMeasurementsOfSurvivingPairs(t *testing.T) {
	var prober endpointProber
	prober.rebuild([]*probePair{{key: "a", rtt: 0.05, samples: 4}, {key: "b", rtt: 0.07, samples: 4}})
	prober.rebuild([]*probePair{{key: "a", rtt: math.Inf(1)}, {key: "c", rtt: math.Inf(1)}})
	pairs := prober.snapshot()
	if pairs[0].rtt != 0.05 || pairs[0].samples != 4 || !math.IsInf(pairs[1].rtt, 1) {
		t.Fatalf("pairs = %+v %+v", pairs[0], pairs[1])
	}
}

// --- probe rounds against a device ---

func newProberTestDevice(t *testing.T, bind conn.Bind) (*Device, *Peer) {
	t.Helper()
	graph, err := path.NewGraph(0, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	device := &Device{
		ID:    1,
		log:   NewLogger(LogLevelSilent, "prober-test"),
		graph: graph,
		EdgeConfig: &mtypes.EdgeConfig{
			Interface:          mtypes.InterfaceConf{MTU: 1400},
			SuperNodeV2Enabled: true,
			DynamicRoute: mtypes.DynamicRouteInfo{
				PeerAliveTimeout: 60,
				SendPingInterval: 1,
			},
		},
		chan_send_packet: make(chan *packet_send_params, 64),
		enabledAf:        conn.EnabledAf46,
	}
	device.net.bind = bind
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	device.PopulatePools()
	peer := &Peer{ID: 2, device: device}
	peer.endpoint_trylist = NewEndpoint_trylist(peer, time.Minute, conn.EnabledAf46)
	peer.isRunning.Set(true)
	peer.SingleWayLatency.device = device
	now := time.Now()
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	device.peers.IDMap[peer.ID] = peer
	t.Cleanup(func() { drainProbes(device) })
	return device, peer
}

func setTrylist(peer *Peer, addresses ...string) {
	peer.endpoint_trylist.Lock()
	defer peer.endpoint_trylist.Unlock()
	for i, address := range addresses {
		host, _, _ := net.SplitHostPort(address)
		peer.endpoint_trylist.trymap_super[address] = &endpoint_tryitem{URL: address, cost: i, ip: net.ParseIP(host)}
	}
	peer.endpoint_trylist.generation++
}

type sentProbe struct {
	requestID uint32
	endpoint  conn.Endpoint
	pairKey   string
}

func drainProbes(device *Device) []sentProbe {
	var probes []sentProbe
	for {
		select {
		case params := <-device.chan_send_packet:
			ping, err := mtypes.ParsePingMsg(params.elem.packet[path.EgHeaderLen:])
			if err == nil {
				probes = append(probes, sentProbe{requestID: ping.RequestID, endpoint: params.elem.endpoint})
			}
			device.PutMessageBuffer(params.elem.buffer)
			device.PutOutboundElement(params.elem)
		default:
			return probes
		}
	}
}

// answerProbes replies to every probe with the RTT that rtt() assigns to the
// probe's endpoint.
func answerProbes(peer *Peer, probes []sentProbe, rtt func(conn.Endpoint) time.Duration) {
	for _, probe := range probes {
		peer.prober.mu.Lock()
		pending, ok := peer.prober.pending[probe.requestID]
		peer.prober.mu.Unlock()
		if !ok {
			continue
		}
		peer.prober.onPong(probe.requestID, pending.sentAt.Add(rtt(probe.endpoint)))
	}
}

func TestProbeRoundEmitsOneProbePerPairWithExplicitEndpoints(t *testing.T) {
	// Given a peer with two remote candidates and an edge with two uplinks
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")
	sources := []stunSource{wan1Source, wan2Source}

	// When
	device.probePeerEndpoints(peer, bind, sources, true, testSelection, time.Now())

	// Then 2 remotes x (default + 2 uplinks) probes go out, each to its own endpoint
	probes := drainProbes(device)
	if len(probes) != 6 {
		t.Fatalf("probes = %d, want 6", len(probes))
	}
	seenIDs := make(map[uint32]bool)
	seenPaths := make(map[string]bool)
	for _, probe := range probes {
		if probe.requestID == 0 || seenIDs[probe.requestID] {
			t.Fatalf("bad request id %d", probe.requestID)
		}
		seenIDs[probe.requestID] = true
		if probe.endpoint == nil {
			t.Fatal("probe without explicit endpoint")
		}
		seenPaths[probe.endpoint.SrcToString()+">"+probe.endpoint.DstToString()] = true
	}
	for _, want := range []string{"invalid IP>203.0.113.21:3001", "198.51.100.2>203.0.113.21:3001", "192.0.2.2>203.0.113.20:3001"} {
		if !seenPaths[want] {
			t.Fatalf("missing probe path %s in %v", want, seenPaths)
		}
	}
}

func TestProbeRoundSendsNothingForSingleHomedSingleCandidatePeer(t *testing.T) {
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001")
	device.probePeerEndpoints(peer, bind, nil, true, testSelection, time.Now())
	if probes := drainProbes(device); len(probes) != 0 {
		t.Fatalf("probes = %d, want 0", len(probes))
	}
}

func TestProbeRoundsSwitchToLowestLatencyPairAndPinIt(t *testing.T) {
	// Given the current path is slow and wan2 -> .21 is fast
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")
	sources := []stunSource{wan1Source, wan2Source}
	rtt := func(endpoint conn.Endpoint) time.Duration {
		if endpoint.SrcToString() == "198.51.100.2" && endpoint.DstToString() == "203.0.113.21:3001" {
			return 12 * time.Millisecond
		}
		return 90 * time.Millisecond
	}

	// When rounds run until the prober decides
	switched := false
	for round := 0; round < 10 && !switched; round++ {
		device.probePeerEndpoints(peer, bind, sources, true, testSelection, time.Now())
		answerProbes(peer, drainProbes(device), rtt)
		peer.RLock()
		switched = peer.endpoint.DstToString() == "203.0.113.21:3001"
		peer.RUnlock()
	}

	// Then the peer uses the fast pair, pinned to wan2, and is held briefly
	if !switched {
		t.Fatal("peer never switched to the lowest-latency pair")
	}
	peer.RLock()
	src := peer.endpoint.SrcToString()
	peer.RUnlock()
	if src != "198.51.100.2" {
		t.Fatalf("switched endpoint source = %s, want wan2", src)
	}
	if !peer.endpointPinned.Load() || !peerEndpointRetryHeld(peer) {
		t.Fatal("switched endpoint is not pinned and held")
	}
}

func TestProbeRoundsKeepCurrentPathWhenNothingIsClearlyFaster(t *testing.T) {
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")
	rtt := func(endpoint conn.Endpoint) time.Duration {
		if endpoint.DstToString() == "203.0.113.21:3001" {
			return 48 * time.Millisecond
		}
		return 50 * time.Millisecond
	}
	for round := 0; round < 10; round++ {
		device.probePeerEndpoints(peer, bind, nil, true, testSelection, time.Now())
		answerProbes(peer, drainProbes(device), rtt)
	}
	if got := peer.endpoint.DstToString(); got != "203.0.113.20:3001" {
		t.Fatalf("endpoint = %s, want unchanged", got)
	}
}

func TestProbeRoundSkipsIneligiblePeers(t *testing.T) {
	cases := map[string]func(*Peer){
		"static":           func(peer *Peer) { peer.StaticConn = true },
		"roaming disabled": func(peer *Peer) { peer.disableRoaming = true },
		"special node":     func(peer *Peer) { peer.ID = mtypes.NodeID_SuperNode },
		"dead": func(peer *Peer) {
			old := time.Now().Add(-time.Hour)
			peer.LastPacketReceivedAdd1Sec.Store(&old)
			peer.endpointPinned.Store(true)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bind := newPinningSTUNFake(3001)
			device, peer := newProberTestDevice(t, bind)
			peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
			setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")
			mutate(peer)
			device.probePeerEndpoints(peer, bind, nil, true, testSelection, time.Now())
			if probes := drainProbes(device); len(probes) != 0 {
				t.Fatalf("probes = %d, want 0", len(probes))
			}
			if name == "dead" && peer.endpointPinned.Load() {
				t.Fatal("dead peer kept its probe pin")
			}
		})
	}
}

func TestProbeRoundDiscardsPairWhosePinWasDropped(t *testing.T) {
	// Given a pinned pair with good measurements
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")
	sources := []stunSource{wan1Source}
	device.probePeerEndpoints(peer, bind, sources, true, testSelection, time.Now())
	probes := drainProbes(device)
	answerProbes(peer, probes, func(conn.Endpoint) time.Duration { return 10 * time.Millisecond })

	// When the kernel dropped the pin of wan1's probes
	for _, probe := range probes {
		if probe.endpoint.SrcToString() == wan1Source.ip.String() {
			probe.endpoint.ClearSrc()
		}
	}
	device.probePeerEndpoints(peer, bind, sources, true, testSelection, time.Now())
	drainProbes(device)

	// Then the pinned pairs lost their measurements, default pairs kept theirs
	for _, pair := range peer.prober.snapshot() {
		if pair.local != nil && pair.samples != 0 {
			t.Fatalf("pinned pair %s kept %d samples after pin drop", pair.key, pair.samples)
		}
		if pair.local == nil && pair.samples != 1 {
			t.Fatalf("default pair %s samples = %d, want 1", pair.key, pair.samples)
		}
	}
}

func TestEndpointSelectionSettingsDefaultsAndDisable(t *testing.T) {
	device := &Device{EdgeConfig: &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{SendPingInterval: 16}}}
	got := device.endpointSelectionSettings()
	if !got.enabled || got.interval != 16*time.Second || got.minMargin != 5*time.Millisecond || got.marginFrac != 0.15 || got.rounds != 3 {
		t.Fatalf("defaults = %+v", got)
	}
	device.EdgeConfig.DynamicRoute = mtypes.DynamicRouteInfo{SendPingInterval: 16, EndpointProbeInterval: 4, EndpointSwitchMarginMS: 20, EndpointSwitchMarginPercent: 30, EndpointSwitchRounds: 5}
	got = device.endpointSelectionSettings()
	if got.interval != 4*time.Second || got.minMargin != 20*time.Millisecond || got.marginFrac != 0.3 || got.rounds != 5 {
		t.Fatalf("explicit = %+v", got)
	}
	device.EdgeConfig.DynamicRoute.DisableEndpointSelection = true
	if device.endpointSelectionSettings().enabled {
		t.Fatal("DisableEndpointSelection did not disable")
	}
	device.EdgeConfig.DynamicRoute = mtypes.DynamicRouteInfo{}
	if device.endpointSelectionSettings().enabled {
		t.Fatal("selection enabled without any probe interval")
	}
}

// --- ping/pong probe handling ---

func TestProcessProbePingEchoesRequestIDWithoutTouchingLatency(t *testing.T) {
	for _, p2p := range []bool{false, true} {
		// Given
		device, peer := newSuperPingTestDevice(t)
		device.EdgeConfig.DynamicRoute.P2P.UseP2P = p2p
		device.chan_send_packet = make(chan *packet_send_params, 8)
		before := peer.SingleWayLatency.GetVal()

		// When
		err := device.process_ping(peer, mtypes.PingMsg{RequestID: 77, Src_nodeID: peer.ID, Time: device.graph.GetCurrentTime(), RequestReply: 3})
		if err != nil {
			t.Fatalf("process_ping: %v", err)
		}

		// Then exactly one pong goes straight back, echoing the id
		if len(device.chan_send_packet) != 1 {
			t.Fatalf("p2p=%v queued %d packets, want 1 direct pong and no ping-back", p2p, len(device.chan_send_packet))
		}
		params := <-device.chan_send_packet
		if params.peer != peer || params.elem.Type != path.PongPacket {
			t.Fatalf("p2p=%v queued %v to %v", p2p, params.elem.Type, params.peer.ID)
		}
		header, _ := path.NewEgHeader(params.elem.packet[:path.EgHeaderLen], 1400)
		if header.GetDst() != peer.ID {
			t.Fatalf("p2p=%v pong dst = %v, want direct to %v", p2p, header.GetDst(), peer.ID)
		}
		pong, err := mtypes.ParsePongMsg(params.elem.packet[path.EgHeaderLen:])
		if err != nil || pong.RequestID != 77 {
			t.Fatalf("p2p=%v pong = %+v err=%v", p2p, pong, err)
		}
		if after := peer.SingleWayLatency.GetVal(); after != before {
			t.Fatalf("p2p=%v SingleWayLatency changed %v -> %v", p2p, before, after)
		}
		device.PutMessageBuffer(params.elem.buffer)
		device.PutOutboundElement(params.elem)
	}
}

func TestProcessProbePongFeedsProberNotGraph(t *testing.T) {
	// Given a pending probe to peer 2
	device, peer := newSuperLatencyTestDevice(t)
	peer.prober.rebuild([]*probePair{{key: "a", rtt: math.Inf(1)}, {key: "b", rtt: math.Inf(1)}})
	id := peer.prober.register("a", time.Now().Add(-20*time.Millisecond))
	before := peer.OutboundLatency.GetVal()

	// When
	err := device.process_pong(peer, mtypes.PongMsg{RequestID: id, Src_nodeID: device.ID, Dst_nodeID: peer.ID, Timediff: 0.001, PingTime: device.graph.GetCurrentTime()})
	if err != nil {
		t.Fatalf("process_pong: %v", err)
	}

	// Then the prober has a sample and routing state is untouched
	if pair := peer.prober.snapshot()[0]; pair.samples != 1 {
		t.Fatalf("prober samples = %d, want 1", pair.samples)
	}
	if after := peer.OutboundLatency.GetVal(); after != before {
		t.Fatalf("OutboundLatency changed %v -> %v", before, after)
	}
	if next := device.graph.Next(device.ID, peer.ID); next != mtypes.NodeID_Invalid {
		t.Fatalf("graph learned a route from a probe pong: next = %v", next)
	}
}

// --- pinning and roaming guard ---

func TestApplyProbedEndpointPinsAgainstInboundRoaming(t *testing.T) {
	// Given a live peer
	now := time.Now()
	current := staticTestEndpoint{dst: net.ParseIP("192.0.2.10"), src: net.ParseIP("192.0.2.1")}
	chosen := staticTestEndpoint{dst: net.ParseIP("192.0.2.20"), src: net.ParseIP("198.51.100.1")}
	peer := &Peer{device: &Device{EdgeConfig: &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{PeerAliveTimeout: 70}}}}
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	peer.endpoint = current

	// When the prober switches to a different remote IP and local source
	if !peer.applyProbedEndpoint(chosen, "old", &probePair{key: "new", remote: "192.0.2.20:51820"}) {
		t.Fatal("applyProbedEndpoint refused")
	}
	// and an inbound packet arrives from the same remote IP on another uplink
	peer.SetEndpointFromPacket(staticTestEndpoint{dst: net.ParseIP("192.0.2.20"), src: net.ParseIP("192.0.2.1")})

	// Then the chosen endpoint survives
	if got := peer.endpoint.SrcIP(); !got.Equal(chosen.src) {
		t.Fatalf("endpoint source = %v, want prober choice %v", got, chosen.src)
	}

	// When the retry path sets a URL explicitly
	peer.endpointPinned.Store(true)
	peer.device.net.bind = newPinningSTUNFake(1)
	_ = peer.SetEndpointFromConnURL("192.0.2.30:51820", conn.EnabledAf4, 0, false)
	if peer.endpointPinned.Load() {
		t.Fatal("SetEndpointFromConnURL did not clear the probe pin")
	}
}

// --- off-path sends ---

type recordingBind struct {
	*pinningSTUNFake
	sent []string
}

func (b *recordingBind) Send(_ []byte, endpoint conn.Endpoint) error {
	b.sent = append(b.sent, endpoint.DstToString())
	return nil
}

func TestTransmitOutboundOffPathLeavesKeepaliveTimersAlone(t *testing.T) {
	// Given an up device and a running peer with a pending keepalive
	bind := &recordingBind{pinningSTUNFake: newPinningSTUNFake(1)}
	device := &Device{log: NewLogger(LogLevelSilent, "tx-test"), EdgeConfig: &mtypes.EdgeConfig{}}
	device.net.bind = bind
	device.state.state = uint32(deviceStateUp)
	device.closed = make(chan int)
	device.PopulatePools()
	peer := &Peer{device: device}
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	peer.timersInit()
	peer.isRunning.Set(true)
	peer.timers.sendKeepalive.Mod(time.Hour)
	defer peer.timers.sendKeepalive.Del()
	defer peer.timers.newHandshake.Del()
	probeEndpoint, _ := bind.ParseEndpoint("203.0.113.21:3001")
	elem := device.NewOutboundElement()
	elem.packet = elem.buffer[:40]
	elem.endpoint = probeEndpoint

	// When
	if err := peer.transmitOutbound(elem); err != nil {
		t.Fatalf("transmitOutbound: %v", err)
	}

	// Then the datagram went to the probe endpoint and no timer moved
	if len(bind.sent) != 1 || bind.sent[0] != "203.0.113.21:3001" {
		t.Fatalf("sent = %v", bind.sent)
	}
	if !peer.timers.sendKeepalive.IsPending() {
		t.Fatal("off-path probe cancelled the pending keepalive")
	}
	if peer.timers.newHandshake.IsPending() {
		t.Fatal("off-path probe armed a new handshake")
	}

	// When an on-path element is sent
	elem.endpoint = nil
	if err := peer.transmitOutbound(elem); err != nil {
		t.Fatalf("transmitOutbound: %v", err)
	}
	// Then it uses the peer endpoint and the usual timer bookkeeping
	if bind.sent[1] != "203.0.113.20:3001" || peer.timers.sendKeepalive.IsPending() {
		t.Fatalf("on-path send = %v keepalive pending = %v", bind.sent, peer.timers.sendKeepalive.IsPending())
	}
	device.PutMessageBuffer(elem.buffer)
	device.PutOutboundElement(elem)
}
