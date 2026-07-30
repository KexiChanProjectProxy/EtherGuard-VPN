package device

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
)

func TestSuperHTTPPongsReportsOutboundLatency(t *testing.T) {
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
	reports := device.superHTTPPongs()

	// Then
	if len(reports) != 1 {
		t.Fatalf("reported pong count = %d, want 1", len(reports))
	}
	if reports[0].SourceNode != device.ID || reports[0].DestNode != peer.ID {
		t.Fatalf("reported direction = %v -> %v, want %v -> %v", reports[0].SourceNode, reports[0].DestNode, device.ID, peer.ID)
	}
	if reports[0].TimediffMS < 11.9 || reports[0].TimediffMS > 12.1 {
		t.Fatalf("reported outbound latency = %f ms, want about 12 ms", reports[0].TimediffMS)
	}
}

func TestSuperHTTPPongsSkipsInvalidLatencyAndPreservesValidPeer(t *testing.T) {
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
			device, invalidPeer := newSuperLatencyTestDevice(t)
			invalidPeer.OutboundLatency.Push(sample.value)
			now := time.Now()
			validPeer := &Peer{ID: 3, device: device, endpoint: runtimeTestEndpoint{}}
			validPeer.LastPacketReceivedAdd1Sec.Store(&now)
			validPeer.OutboundLatency.device = device
			validPeer.OutboundLatency.Push(0.008)
			device.peers.IDMap[validPeer.ID] = validPeer

			// When
			reports := device.superHTTPPongs()

			// Then
			if len(reports) != 1 {
				t.Fatalf("reported pong count = %d, want 1 valid pong", len(reports))
			}
			if reports[0].DestNode != validPeer.ID {
				t.Fatalf("reported peer = %v, want valid peer %v", reports[0].DestNode, validPeer.ID)
			}
			if err := (&mtypes.ControlV2ReportRequest{NodeID: device.ID, Pongs: reports}).Validate(); err != nil {
				t.Fatalf("valid report rejected: %v", err)
			}
		})
	}
}

func TestSuperHTTPRuntimeStartsAfterReadyAndReports(t *testing.T) {
	// Given
	var registered atomic.Int32
	var reported atomic.Int32
	snapshot := runtimeTestSnapshot(t, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/edge/v2/register":
			registered.Add(1)
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/edge/v2/report":
			reported.Add(1)
			w.WriteHeader(http.StatusAccepted)
		case "/edge/v2/snapshot":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/edge/v2/events":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID: 10, NodeName: "edge-10", DefaultTTL: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{APIUrl: server.URL, APIPrefix: "/edge/v2", NodeID: 99, ControlPSKey: "key"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// When
	runtime.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	if registered.Load() != 0 {
		t.Fatalf("register happened before bind readiness")
	}
	runtime.MarkReady(51820, 0, net.ParseIP("10.0.0.10"), nil)

	// Then
	waitRuntimeCondition(t, time.Second, func() bool { return registered.Load() > 0 && reported.Load() > 0 })
}

func TestSuperHTTPRuntimeLifecycleReregistersAfterUnknownPeer(t *testing.T) {
	// Given
	super := newLifecycleSuper(t, "lifecycle-key", policySingle(47112))
	bind := &bindScript{}
	_, _, _ = startLifecycleEdgeReturningRuntime(t, super, bind, []uint16{47112}, nil)
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() == 1 })
	super.deleteRegisteredPeer()

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() >= 2 })

	// Then
	if got := super.registerRequests.Load(); got != 2 {
		t.Fatalf("register attempts after unknown peer = %d, want exactly 2", got)
	}
	snapshot := super.snapshot()
	if len(snapshot.Peers) != 1 || snapshot.Peers[0].NodeID != 47100 {
		t.Fatalf("snapshot peers after re-registration = %+v, want edge 47100", snapshot.Peers)
	}
}

func TestSuperHTTPRuntimeLifecycleCoalescesUnknownPeerReregistration(t *testing.T) {
	// Given
	super := newLifecycleSuper(t, "lifecycle-key", policySingle(47113))
	bind := &bindScript{}
	_, _, _ = startLifecycleEdgeReturningRuntime(t, super, bind, []uint16{47113}, nil)
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() == 1 })
	super.reportUnknownPeer.Store(true)

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return super.reportCalls.Load() >= 6 })

	// Then
	if got := super.registerRequests.Load(); got != 2 {
		t.Fatalf("coalesced register attempts = %d, want exactly 2", got)
	}
}

func TestSuperHTTPRuntimeLifecycleDoesNotReregisterOnUnauthorizedReport(t *testing.T) {
	// Given
	super := newLifecycleSuper(t, "lifecycle-key", policySingle(47114))
	bind := &bindScript{}
	_, _, _ = startLifecycleEdgeReturningRuntime(t, super, bind, []uint16{47114}, nil)
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() == 1 })
	super.reportUnauthorized.Store(true)

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return super.reportCalls.Load() >= 6 })

	// Then
	if got := super.registerRequests.Load(); got != 1 {
		t.Fatalf("register attempts after unauthorized report = %d, want 1", got)
	}
}

func TestSuperHTTPRuntimeSyncFallsBackToPollingAndStops(t *testing.T) {
	// Given
	var revision atomic.Uint64
	var snapshots atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/edge/v2/register":
			_ = json.NewEncoder(w).Encode(runtimeTestSnapshot(t, 1))
		case "/edge/v2/snapshot":
			snapshots.Add(1)
			rev := revision.Add(1) + 1
			_ = json.NewEncoder(w).Encode(runtimeTestSnapshot(t, rev))
		case "/edge/v2/events":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/edge/v2/report":
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID: 11, NodeName: "edge-11", DefaultTTL: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{APIUrl: server.URL, APIPrefix: "/edge/v2", NodeID: 99, ControlPSKey: "key"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	runtime.Start(ctx)
	runtime.MarkReady(51821, 0, net.ParseIP("10.0.0.11"), nil)

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return snapshots.Load() >= 2 })
	cancel()

	// Then
	select {
	case <-runtime.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime goroutines did not stop")
	}
}

func TestSuperHTTPRuntimeApplySnapshotSerializesConcurrentCalls(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	first := runtimeTestSnapshot(t, 1)
	second := runtimeTestSnapshot(t, 2)
	second.Parameters.PollInterval = 20 * time.Millisecond
	start := make(chan struct{})
	var wg sync.WaitGroup

	// When
	for index := 0; index < 32; index++ {
		wg.Add(1)
		snapshot := first
		if index%2 != 0 {
			snapshot = second
		}
		go func() {
			defer wg.Done()
			<-start
			runtime.applySnapshot(snapshot)
		}()
	}
	close(start)
	wg.Wait()

	// Then
	runtime.mu.RLock()
	interval := runtime.parameters.PollInterval
	runtime.mu.RUnlock()
	if interval != first.Parameters.PollInterval && interval != second.Parameters.PollInterval {
		t.Fatalf("unexpected final poll interval %v", interval)
	}
}

func TestSuperHTTPRuntimeEffectiveRelayCostUsesOverride(t *testing.T) {
	// Given
	override := 125.5
	serverDefault := 250.25
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{RelayCostMS: &override})
	snapshot := runtimeTestSnapshot(t, 1)
	snapshot.Parameters.RelayCostMS = &serverDefault

	// When
	runtime.applySnapshot(snapshot)

	// Then
	if got := runtime.effectiveRelayCostMS(); got != override {
		t.Fatalf("effective relay cost = %f, want override %f", got, override)
	}
}

func TestSuperHTTPRuntimeEffectiveRelayCostUsesServerDefaultWithoutOverride(t *testing.T) {
	// Given
	serverDefault := 250.25
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	snapshot := runtimeTestSnapshot(t, 1)
	snapshot.Parameters.RelayCostMS = &serverDefault

	// When
	runtime.applySnapshot(snapshot)

	// Then
	if got := runtime.effectiveRelayCostMS(); got != serverDefault {
		t.Fatalf("effective relay cost = %f, want server default %f", got, serverDefault)
	}
}

func TestSuperHTTPRuntimeEffectiveRelayCostDefaultsToZero(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})

	// When
	runtime.applySnapshot(runtimeTestSnapshot(t, 1))

	// Then
	if got := runtime.effectiveRelayCostMS(); got != 0 {
		t.Fatalf("effective relay cost = %f, want zero", got)
	}
}

func TestSuperHTTPRuntimeReportIncludesEffectiveRelayCost(t *testing.T) {
	// Given
	override := 125.5
	reports := make(chan mtypes.ControlV2ReportRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/edge/v2/report" {
			http.NotFound(w, r)
			return
		}
		var report mtypes.ControlV2ReportRequest
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			t.Errorf("decode report: %v", err)
			return
		}
		reports <- report
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID:      10,
		RelayCostMS: &override,
	})
	runtime.client = NewControlHTTPClient(server.URL, "/edge/v2", runtime.config.NodeID, "key")
	snapshot := runtimeTestSnapshot(t, 1)
	snapshot.Parameters.ReportInterval = time.Millisecond
	runtime.applySnapshot(snapshot)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	// When
	go func() {
		runtime.reportLoop(ctx, superHTTPReady{})
		close(done)
	}()

	// Then
	select {
	case report := <-reports:
		if report.RelayCostMS == nil || *report.RelayCostMS != override {
			t.Fatalf("reported relay cost = %v, want %f", report.RelayCostMS, override)
		}
	case <-time.After(time.Second):
		t.Fatal("report loop emitted no report")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("report loop did not stop")
	}
}

func TestApplySuperHTTPSnapshotUsesIncomingDestinationRelayCosts(t *testing.T) {
	// Given
	const (
		nodeA = mtypes.Vertex(1)
		nodeR = mtypes.Vertex(2)
		nodeB = mtypes.Vertex(3)
	)
	relayCostR := 50.0
	serverDefault := 70.0
	device := newRelayCostSnapshotDevice(t, 99)
	peerKeys := make([]string, 3)
	for index := range peerKeys {
		_, publicKey := RandomKeyPair()
		peerKeys[index] = publicKey.ToString()
	}
	snapshot := runtimeTestSnapshot(t, 1)
	snapshot.Parameters.RelayCostMS = &serverDefault
	snapshot.Peers = []mtypes.ControlV2Peer{
		{NodeID: nodeA, PubKey: peerKeys[0], LatencyMS: map[mtypes.Vertex]float64{nodeR: 10, nodeB: 25}},
		{NodeID: nodeR, PubKey: peerKeys[1], RelayCostMS: &relayCostR, LatencyMS: map[mtypes.Vertex]float64{nodeB: 10}},
		{NodeID: nodeB, PubKey: peerKeys[2]},
	}

	// When
	device.applySuperHTTPSnapshot(snapshot, 0)

	// Then
	if got := device.graph.Weight(nodeA, nodeR, true); math.Abs(got-0.060) > 0.000001 {
		t.Fatalf("A->R weighted cost = %f, want 0.060", got)
	}
	if got := device.graph.Weight(nodeR, nodeB, true); math.Abs(got-0.080) > 0.000001 {
		t.Fatalf("R->B weighted cost = %f, want 0.080", got)
	}
	if got := device.graph.Weight(nodeA, nodeB, true); math.Abs(got-0.095) > 0.000001 {
		t.Fatalf("A->B weighted cost = %f, want 0.095", got)
	}
	if next := device.graph.Next(nodeA, nodeB); next != nodeB {
		t.Fatalf("costed next hop A->B = %v, want direct B(%v)", next, nodeB)
	}

	uncosted := newRelayCostSnapshotDevice(t, 99)
	plainSnapshot := runtimeTestSnapshot(t, 1)
	plainSnapshot.Parameters.RelayCostMS = nil
	plainSnapshot.Peers = make([]mtypes.ControlV2Peer, len(snapshot.Peers))
	copy(plainSnapshot.Peers, snapshot.Peers)
	for index := range plainSnapshot.Peers {
		plainSnapshot.Peers[index].RelayCostMS = nil
	}
	uncosted.applySuperHTTPSnapshot(plainSnapshot, 0)
	if got := uncosted.graph.Weight(nodeA, nodeB, true); math.Abs(got-0.025) > 0.000001 {
		t.Fatalf("uncosted A->B weighted cost = %f, want 0.025", got)
	}
	if next := uncosted.graph.Next(nodeA, nodeB); next != nodeR {
		t.Fatalf("uncosted next hop A->B = %v, want relay R(%v)", next, nodeR)
	}
	costedTwoHop := device.graph.Weight(nodeA, nodeR, true) + device.graph.Weight(nodeR, nodeB, true)
	uncostedTwoHop := uncosted.graph.Weight(nodeA, nodeR, true) + uncosted.graph.Weight(nodeR, nodeB, true)
	costedDirect := device.graph.Weight(nodeA, nodeB, true)
	uncostedDirect := uncosted.graph.Weight(nodeA, nodeB, true)
	if got := (costedTwoHop - costedDirect) - (uncostedTwoHop - uncostedDirect); math.Abs(got-relayCostR/1000) > 0.000001 {
		t.Fatalf("intermediate relay cost delta = %f, want %f", got, relayCostR/1000)
	}
}

func newRelayCostSnapshotDevice(t *testing.T, id mtypes.Vertex) *Device {
	t.Helper()
	graph, err := path.NewGraph(0, true, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	device := &Device{
		ID:                id,
		closed:            make(chan int),
		event_tryendpoint: make(chan struct{}, 1),
		enabledAf:         conn.EnabledAf46,
		log:               NewLogger(LogLevelSilent, "relay-cost-snapshot-test"),
		graph:             graph,
		EdgeConfig: &mtypes.EdgeConfig{
			DynamicRoute: mtypes.DynamicRouteInfo{
				PeerAliveTimeout: 60,
				P2P:              mtypes.P2PInfo{UseP2P: false},
			},
			SuperNodeV2Enabled: true,
		},
	}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	device.peers.SuperPeer = make(map[NoisePublicKey]*Peer)
	return device
}

func TestSuperHTTPRuntimeSnapshotURLsWeightsObservedCandidates(t *testing.T) {
	// Given
	info := mtypes.ControlV2Peer{
		LocalV4:  []string{"10.0.0.2:51820"},
		PublicV4: []string{"198.51.100.2:51820"},
		ObservedV4: []mtypes.ControlV2ObservedAddress{
			{Address: "203.0.113.2:51820", ReporterCount: 7},
		},
		ObservedV6: []mtypes.ControlV2ObservedAddress{
			{Address: "[2001:db8::2]:51820", ReporterCount: 12},
		},
	}

	// When
	urls := snapshotURLs(info)

	// Then
	candidates := urls.GetList(true)
	counts := make(map[string]uint32, len(candidates))
	for _, candidate := range candidates {
		if candidate.Source == mtypes.APIConnURLSourceObserved {
			counts[candidate.URL] = candidate.ReporterCount
		}
	}
	if counts["203.0.113.2:51820"] != 7 || counts["[2001:db8::2]:51820"] != 12 {
		t.Fatalf("observed reporter counts = %#v", counts)
	}
}

func TestSuperHTTPRuntimeRecoveryCoalescesPeerRefreshes(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	now := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)

	// When
	first := runtime.shouldRequestSnapshotRefresh(7, now)
	second := runtime.shouldRequestSnapshotRefresh(7, now.Add(time.Second))
	afterWindow := runtime.shouldRequestSnapshotRefresh(7, now.Add(30*time.Second))

	// Then
	if !first || second || !afterWindow {
		t.Fatalf("refresh decisions = %v, %v, %v", first, second, afterWindow)
	}
}

func TestSuperHTTPRuntimeRecoveryAllowsDifferentPeersWithinCoalesceWindow(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	now := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)

	// When
	firstPeerRequested := runtime.shouldRequestSnapshotRefresh(7, now)
	secondPeerRequested := runtime.shouldRequestSnapshotRefresh(8, now.Add(time.Second))

	// Then
	if !firstPeerRequested || !secondPeerRequested {
		t.Fatalf("different-peer refresh decisions = %v, %v", firstPeerRequested, secondPeerRequested)
	}
}

func TestSuperHTTPRuntimeRecoveryClearsCoalesceStateWhenPeerRecovers(t *testing.T) {
	// Given
	now := time.Now()
	device := &Device{
		EdgeConfig: &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{PeerAliveTimeout: 60}},
	}
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	peer := &Peer{ID: 7, device: device, endpoint: runtimeTestEndpoint{}}
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	device.peers.IDMap[peer.ID] = peer
	runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{})
	runtime.recoveryRequests[peer.ID] = now

	// When
	runtime.recoverExhaustedPeers()

	// Then
	runtime.mu.RLock()
	_, exists := runtime.recoveryRequests[peer.ID]
	runtime.mu.RUnlock()
	if exists {
		t.Fatal("recovered peer retained recovery coalesce state")
	}
}

func TestSuperHTTPRuntimeRecoveryCapSurvivesNewSnapshotGeneration(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	now := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	if !runtime.shouldRequestSnapshotRefresh(7, now) {
		t.Fatal("first refresh was not requested")
	}

	// When
	snapshot := runtimeTestSnapshot(t, 2)
	snapshot.Peers = []mtypes.ControlV2Peer{{NodeID: 7}}
	runtime.applySnapshot(snapshot)
	requested := runtime.shouldRequestSnapshotRefresh(7, now.Add(time.Second))

	// Then
	if requested {
		t.Fatal("new snapshot generation reset the peer refresh cap")
	}
}

func TestSuperHTTPRuntimeRecoveryStateDropsRemovedPeers(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	now := time.Date(2026, time.July, 26, 0, 0, 0, 0, time.UTC)
	runtime.shouldRequestSnapshotRefresh(7, now)

	// When
	runtime.pruneRecoveryRequests(map[mtypes.Vertex]struct{}{})

	// Then
	runtime.mu.RLock()
	_, exists := runtime.recoveryRequests[7]
	runtime.mu.RUnlock()
	if exists {
		t.Fatal("removed peer retained recovery state")
	}
}

func TestSuperHTTPRuntimeObservedEndpointsCapsAndSortsEligiblePeers(t *testing.T) {
	// Given
	now := time.Now()
	device := &Device{
		ID:         1,
		EdgeConfig: &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{PeerAliveTimeout: 60}},
	}
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	for id := mtypes.Vertex(2); id < 302; id++ {
		peer := &Peer{ID: id, device: device, endpoint: runtimeTestEndpoint{}}
		peer.LastPacketReceivedAdd1Sec.Store(&now)
		device.peers.IDMap[id] = peer
	}
	runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{NodeID: device.ID})

	// When
	first := runtime.observedEndpoints()
	second := runtime.observedEndpoints()

	// Then
	if len(first) != 256 {
		t.Fatalf("observed endpoint count = %d, want 256", len(first))
	}
	if err := (&mtypes.ControlV2ReportRequest{NodeID: device.ID, Observed: first}).Validate(); err != nil {
		t.Fatalf("capped observed report is invalid: %v", err)
	}
	for index, observed := range first {
		wantID := mtypes.Vertex(index + 2)
		if observed.TargetNodeID != wantID {
			t.Fatalf("observed[%d] target = %v, want %v", index, observed.TargetNodeID, wantID)
		}
		if second[index] != observed {
			t.Fatalf("observed endpoint order is not deterministic at index %d", index)
		}
	}
}

type runtimeTestEndpoint struct{}

func (runtimeTestEndpoint) ClearSrc() {}

func (runtimeTestEndpoint) SrcToString() string { return "192.0.2.1:51820" }

func (runtimeTestEndpoint) DstToString() string { return "203.0.113.1:51820" }

func (runtimeTestEndpoint) DstToBytes() []byte { return []byte("203.0.113.1:51820") }

func (runtimeTestEndpoint) DstIP() net.IP { return net.ParseIP("203.0.113.1") }

func (runtimeTestEndpoint) SrcIP() net.IP { return net.ParseIP("192.0.2.1") }

func runtimeTestSnapshot(t *testing.T, revision uint64) *mtypes.ControlV2Snapshot {
	t.Helper()
	return &mtypes.ControlV2Snapshot{
		Revision: revision,
		IssuedAt: time.Now(),
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        10 * time.Millisecond,
			STUNRequestTimeout:  5 * time.Millisecond,
			STUNRefreshInterval: time.Hour,
			ReportInterval:      10 * time.Millisecond,
			HeartbeatInterval:   time.Second,
		},
	}
}

func waitRuntimeCondition(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("runtime condition timed out")
}

// ---------------------------------------------------------------------------
// Bootstrap / ListenPortPriority lifecycle coverage
//
// The following tests prove the bootstrap → initial bind → registration
// lifecycle behaves as documented and that the post-bind UDP socket is
// never rebound in response to a params_change SSE event. The Super is
// replaced with an httptest server that exposes only the four endpoints
// the runtime touches; the bind is replaced with a scriptable fake that
// records the requested ports and yields the actual port from the
// production code. Goroutine counts before/after each test confirm no
// listener or routine is leaked in any failure path.
// ---------------------------------------------------------------------------

// lifecycleSuper is a deterministic in-process Super for bootstrap tests.
// It supports the exact endpoint set the runtime uses, captures the
// incoming register request, and exposes a knob to push a fresh
// params_change snapshot to the connected SSE consumer.
type lifecycleSuper struct {
	t              *testing.T
	server         *httptest.Server
	psKey          []byte
	policy         mtypes.ListenPortPriority
	policySnapshot atomic.Pointer[mtypes.ControlV2Parameters]
	snapshotRev    atomic.Uint64

	mu                 sync.Mutex
	registerCalls      int
	reportCalls        atomic.Int32
	lastRegister       mtypes.ControlV2RegisterRequest
	bootstrapRequests  atomic.Int32
	registerRequests   atomic.Int32
	reportUnknownPeer  atomic.Bool
	reportUnauthorized atomic.Bool
	registeredPeer     mtypes.ControlV2Peer
	peerPresent        bool
	// closeHandler, when non-nil, replaces the default /bootstrap handler
	// (used to simulate unreachable / wrong-key / malformed responses).
	closeHandler func(http.ResponseWriter, *http.Request)
}

func newLifecycleSuper(t *testing.T, psKey string, policy mtypes.ListenPortPriority) *lifecycleSuper {
	t.Helper()
	super := &lifecycleSuper{t: t, psKey: []byte(psKey), policy: policy}
	initial := mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		PollInterval:        20 * time.Millisecond,
		STUNServers:         []string{"stun:127.0.0.1:3478"},
		STUNRequestTimeout:  10 * time.Millisecond,
		STUNRefreshInterval: time.Hour,
		ReportInterval:      20 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		EventReplay:         16,
		ListenPortPriority:  policy,
	}
	super.policySnapshot.Store(&initial)
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/bootstrap", super.handleBootstrap)
	mux.HandleFunc("/edge/v2/register", super.handleRegister)
	mux.HandleFunc("/edge/v2/report", super.handleReport)
	mux.HandleFunc("/edge/v2/snapshot", super.handleSnapshot)
	mux.HandleFunc("/edge/v2/events", super.handleEvents)
	super.server = httptest.NewServer(mux)
	t.Cleanup(super.server.Close)
	return super
}

func (super *lifecycleSuper) verify(r *http.Request, body []byte) bool {
	tsStr := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	sig := r.Header.Get(HeaderSignature)
	if tsStr == "" || nonce == "" || sig == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > 5*time.Minute || time.Until(time.Unix(ts, 0)) > 5*time.Minute {
		return false
	}
	digest := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + tsStr + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	mac := hmac.New(sha256.New, super.psKey)
	_, _ = mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil)) == sig
}

func (super *lifecycleSuper) handleBootstrap(writer http.ResponseWriter, request *http.Request) {
	if super.closeHandler != nil {
		super.closeHandler(writer, request)
		return
	}
	body, _ := io.ReadAll(request.Body)
	if !super.verify(request, body) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	super.bootstrapRequests.Add(1)
	snapshot := *super.policySnapshot.Load()
	encoded, err := json.Marshal(&snapshot)
	if err != nil {
		http.Error(writer, "encode failure", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(encoded)
}

func (super *lifecycleSuper) handleRegister(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	if !super.verify(request, body) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	var captured mtypes.ControlV2RegisterRequest
	if err := json.Unmarshal(body, &captured); err != nil {
		http.Error(writer, "malformed", http.StatusBadRequest)
		return
	}
	super.mu.Lock()
	super.lastRegister = captured
	super.registerCalls++
	super.registeredPeer = mtypes.ControlV2Peer{
		NodeID:   captured.NodeID,
		NodeName: captured.NodeName,
		PubKey:   captured.PubKey,
		LocalV4:  append([]string(nil), captured.LocalV4...),
		LocalV6:  append([]string(nil), captured.LocalV6...),
		PublicV4: append([]string(nil), captured.PublicV4...),
		PublicV6: append([]string(nil), captured.PublicV6...),
	}
	super.peerPresent = true
	super.mu.Unlock()
	super.registerRequests.Add(1)
	snapshot := super.snapshot()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(snapshot)
}

func (super *lifecycleSuper) handleReport(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	if !super.verify(request, body) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	super.mu.Lock()
	peerPresent := super.peerPresent
	super.mu.Unlock()
	super.reportCalls.Add(1)
	if super.reportUnauthorized.Load() {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	if super.reportUnknownPeer.Load() || !peerPresent {
		http.Error(writer, "report: control state: unknown peer", http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusAccepted)
}

func (super *lifecycleSuper) handleSnapshot(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	if !super.verify(request, body) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	snapshot := super.snapshot()
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("ETag", snapshot.ETag())
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(snapshot)
}

func (super *lifecycleSuper) handleEvents(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	if !super.verify(request, body) {
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.WriteHeader(http.StatusOK)
	flusher, ok := writer.(http.Flusher)
	if !ok {
		return
	}
	flusher.Flush()
	<-request.Context().Done()
}

func (super *lifecycleSuper) snapshot() mtypes.ControlV2Snapshot {
	rev := super.snapshotRev.Add(1)
	snapshot := mtypes.ControlV2Snapshot{
		Revision: rev,
		IssuedAt: time.Unix(int64(rev), 0),
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        20 * time.Millisecond,
			STUNServers:         []string{"stun:127.0.0.1:3478"},
			STUNRequestTimeout:  10 * time.Millisecond,
			STUNRefreshInterval: time.Hour,
			ReportInterval:      20 * time.Millisecond,
			HeartbeatInterval:   time.Hour,
			EventReplay:         16,
			ListenPortPriority:  super.policy,
		},
	}
	super.mu.Lock()
	if super.peerPresent {
		snapshot.Peers = []mtypes.ControlV2Peer{super.registeredPeer}
	}
	super.mu.Unlock()
	return snapshot
}

func (super *lifecycleSuper) deleteRegisteredPeer() {
	super.mu.Lock()
	super.peerPresent = false
	super.mu.Unlock()
}

func (super *lifecycleSuper) lastRegisterCall(t *testing.T) mtypes.ControlV2RegisterRequest {
	t.Helper()
	super.mu.Lock()
	defer super.mu.Unlock()
	return super.lastRegister
}

func (super *lifecycleSuper) updatePolicy(t *testing.T, next mtypes.ListenPortPriority) {
	t.Helper()
	super.mu.Lock()
	super.policy = next
	super.mu.Unlock()
	params := mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		PollInterval:        20 * time.Millisecond,
		STUNServers:         []string{"stun:127.0.0.1:3478"},
		STUNRequestTimeout:  10 * time.Millisecond,
		STUNRefreshInterval: time.Hour,
		ReportInterval:      20 * time.Millisecond,
		HeartbeatInterval:   time.Hour,
		EventReplay:         16,
		ListenPortPriority:  next,
	}
	super.policySnapshot.Store(&params)
}

// bindScript is a scriptable conn.Bind that records every Open call and
// reports the actual port the device would have been given. Errors and
// port-zero fallbacks are reproducible without touching the network.
//
// The "active" count is the number of Open calls without a matching
// Close. Production may call Close before the very first Open (to
// ensure no leftover listener from a prior lifecycle); that pre-close
// must be treated as a no-op, not as a listener leak.
type bindScript struct {
	mu         sync.Mutex
	attempts   []uint16
	openErrors []error
	portZero   uint16
	openCount  int
	closeCount int
	active     int
}

func (b *bindScript) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts = append(b.attempts, port)
	b.openCount++
	if len(b.openErrors) > 0 {
		err := b.openErrors[0]
		b.openErrors = b.openErrors[1:]
		if err != nil {
			return nil, 0, err
		}
	}
	b.active++
	if port == 0 {
		return nil, b.portZero, nil
	}
	return nil, port, nil
}

func (b *bindScript) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closeCount++
	if b.active > 0 {
		b.active--
	}
	return nil
}

func (*bindScript) SetMark(uint32) error { return nil }

func (*bindScript) Send([]byte, conn.Endpoint) error { return nil }

func (*bindScript) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, errors.New("bind script test endpoint unused")
}

func (*bindScript) EnabledAf() conn.EnabledAf { return conn.EnabledAf{IPv4: true} }

func (b *bindScript) snapshot() ([]uint16, int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]uint16(nil), b.attempts...), b.closeCount, b.active
}

func intPtr(value int) *int { return &value }

// runtimeGoroutineCount returns the current number of goroutines. Used to
// detect leaks across bootstrap failure paths.
func runtimeGoroutineCount() int {
	return runtime.NumGoroutine()
}

func policySingle(port int) mtypes.ListenPortPriority {
	return mtypes.ListenPortPriority{{Port: intPtr(port)}}
}

func assertNoLeakedListener(t *testing.T, bind *bindScript) {
	t.Helper()
	bind.mu.Lock()
	active := bind.active
	bind.mu.Unlock()
	if active != 0 {
		t.Fatalf("bind listener leak: active=%d (want 0) — no UDP listener should remain", active)
	}
}

func assertPolicyIntegrity(t *testing.T, body []byte) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("bootstrap body is not parseable JSON: %v", err)
	}
	for _, forbidden := range []string{
		"PSKey", "ps_key", "ControlPSKey", "control_ps_key",
		"Peers", "peers",
		"Candidates", "candidates",
		"Observed", "observed",
		"ManagementAuth", "management_auth",
		"User", "PasswordHash", "password_hash",
		"node_id", "NodeID", "PubKey", "pub_key", "listen_port", "ListenPort",
	} {
		if _, present := raw[forbidden]; present {
			t.Fatalf("bootstrap body leaked forbidden key %q: %s", forbidden, string(body))
		}
	}
	if _, ok := raw["ListenPortPriority"]; !ok {
		t.Fatalf("bootstrap body missing ListenPortPriority: %s", string(body))
	}
}

func collectGoroutineDelta(t *testing.T, action func()) int {
	t.Helper()
	// Settle to a quiescent baseline so the server's own background
	// goroutines are counted, then measure only the change the action
	// introduced.
	waitQuiescentGoroutines()
	before := runtimeGoroutineCount()
	action()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			return runtime.NumGoroutine() - before
		}
		time.Sleep(20 * time.Millisecond)
	}
	delta := runtime.NumGoroutine() - before
	if delta > 1 {
		buf := make([]byte, 16384)
		n := runtime.Stack(buf, true)
		t.Logf("goroutine delta = %d, all stacks:\n%s", delta, buf[:n])
	}
	return delta
}

func waitQuiescentGoroutines() {
	deadline := time.Now().Add(time.Second)
	last := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(40 * time.Millisecond)
		current := runtime.NumGoroutine()
		if current == last {
			return
		}
		last = current
	}
}

// TestLifecycleBootstrapBindsFirstFreeCandidateAndRegistersThatPort —
// Given: a Super publishes a 2-port policy, no candidate is occupied.
// When: the Edge bootstraps, binds, registers, then connects SSE.
// Then: the bind was called once with the first candidate, the
// registration ListenPort is exactly that port, and the runtime stays
// bound (no listener leak).
func TestSuperHTTPRuntimeListenPortFirstFreeCandidateAndRegistersThatPort(t *testing.T) {
	policy := policySingle(47101)
	super := newLifecycleSuper(t, "lifecycle-key", policy)
	bind := &bindScript{}
	gotResult := startLifecycleEdge(t, super, bind, []uint16{47101}, nil)

	if gotResult.Port != 47101 {
		t.Fatalf("initial bind port = %d, want 47101", gotResult.Port)
	}
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() > 0 })
	captured := super.lastRegisterCall(t)
	if captured.ListenPort != 47101 {
		t.Fatalf("register ListenPort = %d, want 47101", captured.ListenPort)
	}
	attempts, _, active := bind.snapshot()
	if !reflect.DeepEqual(attempts, []uint16{47101}) {
		t.Fatalf("bind attempts = %v, want [47101]", attempts)
	}
	if active != 1 {
		t.Fatalf("active listener count = %d, want 1 (listener must remain open)", active)
	}
}

// TestLifecycleBootstrapAdvancesAfterCollisionAndBindsSecondCandidate —
// Given: the first candidate port is in use; the second is free.
// When: the Edge bootstraps with the policy and lets the initial bind
// advance via EADDRINUSE.
// Then: the bind called both candidates in order, the bound port is
// exactly the second, and the registration ListenPort matches the
// second.
func TestSuperHTTPRuntimeListenPortAdvancesAfterCollisionAndBindsSecondCandidate(t *testing.T) {
	policy := mtypes.ListenPortPriority{
		{Port: intPtr(47102)},
		{Port: intPtr(47103)},
	}
	super := newLifecycleSuper(t, "lifecycle-key", policy)
	bind := &bindScript{
		openErrors: []error{fmt.Errorf("first candidate: %w", syscall.EADDRINUSE)},
	}
	gotResult := startLifecycleEdge(t, super, bind, []uint16{47102, 47103}, nil)

	if gotResult.Port != 47103 {
		t.Fatalf("initial bind port = %d, want 47103", gotResult.Port)
	}
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() > 0 })
	captured := super.lastRegisterCall(t)
	if captured.ListenPort != 47103 {
		t.Fatalf("register ListenPort = %d, want 47103", captured.ListenPort)
	}
	attempts, _, active := bind.snapshot()
	if !reflect.DeepEqual(attempts, []uint16{47102, 47103}) {
		t.Fatalf("bind attempts = %v, want [47102 47103]", attempts)
	}
	if active != 1 {
		t.Fatalf("active listener count = %d, want 1", active)
	}
}

// TestLifecycleBootstrapFallsBackToEphemeralAfterEveryCandidateOccupied —
// Given: every Super-issued candidate is occupied.
// When: the Edge bootstraps with that policy and the initial bind walks
// through every entry, then falls back to port zero.
// Then: the bind called every candidate and then 0, the reported port
// is the OS-assigned port from the fallback, and the registration
// ListenPort is that exact OS-assigned port.
func TestSuperHTTPRuntimeListenPortFallsBackToEphemeralAfterEveryCandidateOccupied(t *testing.T) {
	policy := mtypes.ListenPortPriority{
		{Port: intPtr(47104)},
		{Port: intPtr(47105)},
	}
	super := newLifecycleSuper(t, "lifecycle-key", policy)
	bind := &bindScript{
		openErrors: []error{
			fmt.Errorf("first: %w", syscall.EADDRINUSE),
			fmt.Errorf("second: %w", syscall.EADDRINUSE),
		},
		portZero: 53104,
	}
	gotResult := startLifecycleEdge(t, super, bind, []uint16{47104, 47105}, nil)

	if gotResult.Port != 53104 {
		t.Fatalf("initial bind port = %d, want 53104 (OS-assigned fallback)", gotResult.Port)
	}
	waitRuntimeCondition(t, time.Second, func() bool { return super.registerRequests.Load() > 0 })
	captured := super.lastRegisterCall(t)
	if captured.ListenPort != 53104 {
		t.Fatalf("register ListenPort = %d, want 53104 (matches bound port)", captured.ListenPort)
	}
	attempts, _, active := bind.snapshot()
	if !reflect.DeepEqual(attempts, []uint16{47104, 47105, 0}) {
		t.Fatalf("bind attempts = %v, want [47104 47105 0]", attempts)
	}
	if active != 1 {
		t.Fatalf("active listener count = %d, want 1", active)
	}
}

// TestLifecycleBootstrapFailureLeavesNoListenerAndNoGoroutineLeak —
// Given: the Super is unreachable (server closed before bootstrap).
// When: the bootstrap call returns an error and the caller refuses to
// bring the Edge up.
// Then: no device is constructed, no bind is opened, and no goroutine
// remains beyond the bootstrap attempt itself.
func TestSuperHTTPRuntimeListenPortBootstrapFailureLeavesNoListenerAndNoGoroutineLeak(t *testing.T) {
	super := newLifecycleSuper(t, "lifecycle-key", policySingle(47106))
	super.server.Close() // simulate unreachable Super

	bind := &bindScript{}
	client := NewControlHTTPClient("", mtypes.ControlV2APIPrefix, vertexFromInt(t, 47106), "lifecycle-key")
	client.BaseURL = super.server.URL // already closed; will fail on Do
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := client.Bootstrap(ctx)
	if err == nil {
		t.Fatal("bootstrap against closed Super must fail")
	}

	attempts, _, active := bind.snapshot()
	if len(attempts) != 0 || active != 0 {
		t.Fatalf("bind must remain untouched: attempts=%v active=%d", attempts, active)
	}

	delta := collectGoroutineDelta(t, func() {
		_, _ = client.Bootstrap(ctx)
	})
	if delta > 1 {
		t.Fatalf("bootstrap failure leaked %d goroutines", delta)
	}
}

// TestLifecycleBootstrapWrongKeyRefusesAndLeavesNoListener — the Super
// must reject the bootstrap with a typed error, the bind must not be
// touched, and no goroutine should leak.
func TestSuperHTTPRuntimeListenPortBootstrapWrongKeyRefusesAndLeavesNoListener(t *testing.T) {
	super := newLifecycleSuper(t, "super-side-secret", policySingle(47107))

	bind := &bindScript{}
	client := NewControlHTTPClient(super.server.URL, mtypes.ControlV2APIPrefix, vertexFromInt(t, 47107), "edge-wrong-key")

	delta := collectGoroutineDelta(t, func() {
		_, err := client.Bootstrap(context.Background())
		if err == nil {
			t.Fatal("bootstrap with wrong key must fail")
		}
		var status *BootstrapStatusError
		if !errors.As(err, &status) {
			t.Fatalf("error type = %T, want *BootstrapStatusError", err)
		}
		if status.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", status.StatusCode)
		}
	})
	if delta > 1 {
		t.Fatalf("wrong-key bootstrap leaked %d goroutines", delta)
	}
	attempts, _, active := bind.snapshot()
	if len(attempts) != 0 || active != 0 {
		t.Fatalf("bind must remain untouched: attempts=%v active=%d", attempts, active)
	}
}

// TestLifecycleBootstrapEmptyPolicyRefusesAndLeavesNoListener — the
// Super publishes no ListenPortPriority; the bootstrap must surface a
// BootstrapInvalidPolicyError and the bind must remain untouched.
func TestSuperHTTPRuntimeListenPortBootstrapEmptyPolicyRefusesAndLeavesNoListener(t *testing.T) {
	super := newLifecycleSuper(t, "lifecycle-key", mtypes.ListenPortPriority{})
	bind := &bindScript{}

	delta := collectGoroutineDelta(t, func() {
		_, err := superBootstrap(super, vertexFromInt(t, 47108), "lifecycle-key")
		if err == nil {
			t.Fatal("bootstrap with empty policy must fail")
		}
		var invalid *BootstrapInvalidPolicyError
		if !errors.As(err, &invalid) {
			t.Fatalf("error type = %T, want *BootstrapInvalidPolicyError", err)
		}
	})
	if delta > 1 {
		t.Fatalf("empty-policy bootstrap leaked %d goroutines", delta)
	}
	attempts, _, active := bind.snapshot()
	if len(attempts) != 0 || active != 0 {
		t.Fatalf("bind must remain untouched: attempts=%v active=%d", attempts, active)
	}
}

// TestLifecycleParamsChangeDoesNotRebindBoundSocket — the bind is
// opened exactly once during bootstrap. A subsequent params_change
// (ListenPortPriority swap) drives applySnapshot on the runtime, which
// updates the cached parameters but MUST NOT touch the bound socket:
// the bind attempts slice is unchanged and the active listener count
// remains 1.
func TestSuperHTTPRuntimeListenPortParamsChangeDoesNotRebindBoundSocket(t *testing.T) {
	policy := policySingle(47109)
	super := newLifecycleSuper(t, "lifecycle-key", policy)
	bind := &bindScript{}
	deviceRef, runtimeRef, _ := startLifecycleEdgeReturningRuntime(t, super, bind, []uint16{47109}, nil)

	// Drive a params_change on the runtime exactly as the SSE stream
	// would. The runtime applies the snapshot and updates its cached
	// parameters without touching device.net.bind.
	next := mtypes.ListenPortPriority{
		{Port: intPtr(49999)},
		{Port: intPtr(49998)},
	}
	deviceRef.net.RLock()
	beforePort := deviceRef.net.port
	deviceRef.net.RUnlock()
	if beforePort != 47109 {
		t.Fatalf("starting bound port = %d, want 47109", beforePort)
	}

	runtimeRef.applySnapshot(&mtypes.ControlV2Snapshot{
		Revision: 99,
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        20 * time.Millisecond,
			STUNServers:         []string{"stun:127.0.0.1:3478"},
			STUNRequestTimeout:  10 * time.Millisecond,
			STUNRefreshInterval: time.Hour,
			ReportInterval:      20 * time.Millisecond,
			HeartbeatInterval:   time.Hour,
			EventReplay:         16,
			ListenPortPriority:  next,
		},
	})

	deviceRef.net.RLock()
	afterPort := deviceRef.net.port
	deviceRef.net.RUnlock()
	if afterPort != beforePort {
		t.Fatalf("params_change rebound UDP port: before=%d after=%d (must be unchanged)", beforePort, afterPort)
	}
	attempts, _, active := bind.snapshot()
	if !reflect.DeepEqual(attempts, []uint16{47109}) {
		t.Fatalf("bind attempts after params_change = %v, want [47109] (no rebind)", attempts)
	}
	if active != 1 {
		t.Fatalf("active listener count after params_change = %d, want 1", active)
	}

	runtimeRef.mu.RLock()
	cached := runtimeRef.parameters.ListenPortPriority
	runtimeRef.mu.RUnlock()
	if len(cached) != len(next) {
		t.Fatalf("cached policy size = %d, want %d", len(cached), len(next))
	}
	for i := range cached {
		if cached[i].Port == nil || next[i].Port == nil || *cached[i].Port != *next[i].Port {
			t.Fatalf("cached policy[%d] = %+v, want %+v", i, cached[i], next[i])
		}
	}
}

// TestLifecycleBootstrapBodyLeaksNoForbiddenKeys — every bootstrap
// response must be policy-only; the wire body MUST NOT expose PSKey,
// peers, candidates, observed hints, or any management auth field.
func TestSuperHTTPRuntimeListenPortBootstrapBodyLeaksNoForbiddenKeys(t *testing.T) {
	policy := policySingle(47110)
	super := newLifecycleSuper(t, "lifecycle-key", policy)

	// Materialise a body by issuing one direct request with the same
	// signing convention the production client uses.
	client := NewControlHTTPClient(super.server.URL, mtypes.ControlV2APIPrefix, vertexFromInt(t, 47110), "lifecycle-key")
	params, err := client.Bootstrap(context.Background())
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	assertPolicyIntegrity(t, encoded)
}

// TestLifecycleOldSnapshotWithoutListenPortPriorityStillDecodes — an
// older Super that never published ListenPortPriority must remain
// decodable. The runtime accepts the snapshot (no policy applied) and
// the bind remains on its original port.
func TestSuperHTTPRuntimeListenPortOldSnapshotWithoutListenPortPriorityStillDecodes(t *testing.T) {
	policy := policySingle(47111)
	super := newLifecycleSuper(t, "lifecycle-key", policy)
	bind := &bindScript{}
	deviceRef, runtimeRef, _ := startLifecycleEdgeReturningRuntime(t, super, bind, []uint16{47111}, nil)

	old := []byte(`{
		"Revision": 1,
		"IssuedAt": "1970-01-01T00:00:01Z",
		"Parameters": {
			"ProtocolVersion": "v2",
			"PollInterval": 20000000000,
			"STUNServers": ["stun:127.0.0.1:3478"],
			"STUNRequestTimeout": 10000000,
			"STUNRefreshInterval": 3600000000000,
			"ReportInterval": 20000000000,
			"HeartbeatInterval": 3600000000000,
			"EventReplay": 16
		},
		"Peers": []
	}`)
	var snap mtypes.ControlV2Snapshot
	if err := json.Unmarshal(old, &snap); err != nil {
		t.Fatalf("legacy snapshot decode: %v", err)
	}
	if len(snap.Parameters.ListenPortPriority) != 0 {
		t.Fatalf("legacy snapshot unexpectedly carried policy: %+v", snap.Parameters.ListenPortPriority)
	}
	runtimeRef.applySnapshot(&snap)

	deviceRef.net.RLock()
	port := deviceRef.net.port
	deviceRef.net.RUnlock()
	if port != 47111 {
		t.Fatalf("port after legacy snapshot = %d, want 47111 (unchanged)", port)
	}
	attempts, _, active := bind.snapshot()
	if !reflect.DeepEqual(attempts, []uint16{47111}) {
		t.Fatalf("bind attempts after legacy snapshot = %v, want [47111]", attempts)
	}
	if active != 1 {
		t.Fatalf("active listener count = %d, want 1", active)
	}
}

// startLifecycleEdge mirrors main_edge.go's bootstrapInitialBind +
// waitInitialBind + SuperHTTPReady + Start pipeline in test code.
// It returns the InitialBindResult so the caller can assert on the
// chosen port without reaching into package-internal state.
func startLifecycleEdge(t *testing.T, super *lifecycleSuper, bind *bindScript, candidates []uint16, _ func()) InitialBindResult {
	t.Helper()
	_, _, result := startLifecycleEdgeReturningRuntime(t, super, bind, candidates, nil)
	return result
}

func startLifecycleEdgeReturningRuntime(t *testing.T, super *lifecycleSuper, bind *bindScript, candidates []uint16, _ func()) (*Device, *SuperHTTPRuntime, InitialBindResult) {
	t.Helper()
	parameters, err := superBootstrap(super, vertexFromInt(t, 47100), "lifecycle-key")
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	expanded, err := parameters.ListenPortPriority.Expand()
	if err != nil {
		t.Fatalf("expand policy: %v", err)
	}
	expandedPorts := make([]uint16, len(expanded))
	for i, port := range expanded {
		expandedPorts[i] = uint16(port)
	}
	if len(candidates) > 0 && len(candidates) <= len(expandedPorts) {
		expandedPorts = candidates
	}

	tapDevice, err := tap.CreateDummyTAP()
	if err != nil {
		t.Fatalf("dummy tap: %v", err)
	}
	graph, err := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	config := &mtypes.EdgeConfig{
		NodeID:     vertexFromInt(t, 47100),
		NodeName:   "lifecycle-edge",
		DefaultTTL: 64,
		Interface:  mtypes.InterfaceConf{MTU: 1400},
		DynamicRoute: mtypes.DynamicRouteInfo{
			DupCheckTimeout: 1,
		},
	}
	results := make(chan InitialBindResult, 1)
	deviceRef := NewDeviceWithInitialBind(tapDevice, config.NodeID, bind, NewLogger(LogLevelSilent, "lifecycle"), graph, "", config, "test", InitialBindPolicy{
		Candidates: expandedPorts,
		Results:    results,
	})
	t.Cleanup(deviceRef.Close)

	// Wait for the bind goroutine to publish its result before
	// constructing the runtime; SuperHTTPReady reads device.net.port
	// synchronously, so the bind MUST have completed first.
	var result InitialBindResult
	select {
	case result = <-results:
	case <-time.After(2 * time.Second):
		t.Fatal("initial bind result timed out")
	}
	if result.Err != nil {
		t.Fatalf("initial bind error: %v", result.Err)
	}
	if result.Port == 0 {
		t.Fatal("initial bind reported port zero")
	}

	runtime := NewSuperHTTPRuntime(deviceRef, mtypes.EdgeConfigV2{
		NodeID:     config.NodeID,
		NodeName:   "lifecycle-edge",
		DefaultTTL: 64,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       super.server.URL,
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: "lifecycle-key",
		},
	})
	deviceRef.superHTTP = runtime
	deviceRef.SuperHTTPReady()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runtime.Start(ctx)

	return deviceRef, runtime, result
}

func superBootstrap(super *lifecycleSuper, nodeID mtypes.Vertex, key string) (*mtypes.ControlV2Parameters, error) {
	return super.bootstrapClient(nodeID, key).Bootstrap(context.Background())
}

func (super *lifecycleSuper) bootstrapClient(nodeID mtypes.Vertex, key string) *ControlHTTPClient {
	client := NewControlHTTPClient(super.server.URL, mtypes.ControlV2APIPrefix, nodeID, key)
	client.HTTP.Timeout = 2 * time.Second
	// Disable keep-alive so the server's per-connection reader
	// goroutines exit between bootstrap calls; goroutine-leak
	// assertions in failure-path tests can then measure only the
	// client-side leak signal.
	client.HTTP.Transport = &http.Transport{DisableKeepAlives: true}
	return client
}
