package main

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func TestHTTPOnlySuperEndToEnd(t *testing.T) {
	// Given an HTTP-only Super with two real Edge devices on bindtest links.
	topology := newE2ETopology(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := topology.shutdown(ctx); err != nil {
			t.Errorf("topology shutdown: %v", err)
		}
	})

	if topology.edgeListener.Addr().Network() != "tcp" || topology.manageListener.Addr().Network() != "tcp" {
		t.Fatal("HTTP-only Super exposed a non-TCP control listener")
	}
	if topology.runtime.State() == nil || topology.runtime.Hub() == nil || topology.runtime.Auth() == nil || topology.runtime.Manage() == nil {
		t.Fatal("HTTP-only Super did not expose its control-plane runtime services")
	}

	wrongIdentity := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 102, topology.keyA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	t.Logf("cap counter after topology start: 304=%d snapshots=%d", topology.forcedCNotModified.Load(), topology.forcedCSnapshots.Load())
	if _, _, err := wrongIdentity.Snapshot(ctx); err == nil {
		t.Fatal("Edge A control key authenticated as Edge B")
	}

	// When both runtimes register and report their same-bind STUN candidates.
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, err := topology.snapshot(ctx, 102, topology.keyB)
		if err != nil {
			return false
		}
		peer, found := e2ePeer(snapshot, 101)
		return found && len(peer.LocalV4) == 1 && len(peer.PublicV4) == 1
	})

	// Then the peer-safe HTTP snapshot exposes the other Edge's same-bind
	// candidates and WireGuard identity, never the control key.
	snapshotB, err := topology.snapshot(ctx, 102, topology.keyB)
	if err != nil {
		t.Fatalf("Edge B snapshot: %v", err)
	}
	peerA, found := e2ePeer(snapshotB, 101)
	if !found {
		t.Fatal("Edge B snapshot omitted registered Edge A")
	}
	if peerA.PubKey != topology.pubA.ToString() {
		t.Fatalf("Edge A public key in snapshot = %q, want %q", peerA.PubKey, topology.pubA.ToString())
	}
	if peerA.PSKey != "" {
		t.Fatal("Edge B snapshot exposed Edge A control key")
	}
	assertSameBindCandidate(t, peerA.LocalV4[0], peerA.PublicV4[0], "198.51.100.101")

	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeA.LookupPeer(topology.pubB) != nil && topology.edgeB.LookupPeer(topology.pubA) != nil &&
			topology.edgeA.GetConnurl(102) != "" && topology.edgeB.GetConnurl(101) != ""
	})
	peerToB := topology.edgeA.LookupPeer(topology.pubB)
	if err := peerToB.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("start direct Edge handshake: %v", err)
	}
	payload := e2eNormalPacket(t, 101, 102)
	topology.edgeA.SendPacket(peerToB, path.NormalPacket, 64, payload, device.MessageTransportOffsetContent)
	select {
	case <-topology.bindA.responses:
	case <-ctx.Done():
		t.Fatal("direct Edge handshake response did not arrive before deadline")
	}
	select {
	case usage := <-topology.bindB.transports:
		if usage != path.NormalPacket {
			t.Fatalf("direct Edge transport usage = %v, want %v", usage, path.NormalPacket)
		}
	case <-ctx.Done():
		t.Fatal("direct Edge transport packet did not cross the bind topology before deadline")
	}

	// When a real report changes latency, the Super publishes an SSE
	// invalidation and recalculates the direct next hop.
	before := snapshotB.Revision
	subscriber, err := topology.runtime.Hub().Subscribe(ctx, "")
	if err != nil {
		t.Fatalf("subscribe to Super event hub: %v", err)
	}
	t.Cleanup(subscriber.Close)
	topology.clock.Advance(time.Millisecond)
	reporter := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 101, topology.keyA)
	if err := reporter.Report(ctx, &mtypes.ControlV2ReportRequest{
		NodeID:     101,
		Candidates: e2eCandidates(peerA),
		Pongs: []mtypes.ControlV2Pong{{
			SourceNode:   101,
			DestNode:     102,
			LatencyMS:    4.5,
			AliveSeconds: 5,
		}},
		ReportedAt: topology.clock.Now(),
	}); err != nil {
		t.Fatalf("report latency: %v", err)
	}
	awaitSSERevision(t, ctx, subscriber.Events(), before)
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, snapshotErr := topology.snapshot(ctx, 102, topology.keyB)
		peer, exists := e2ePeer(snapshot, 101)
		return snapshotErr == nil && exists && peer.LatencyMS[102] == 4.5 && topology.runtime.graph.Next(101, 102) == 102
	})

	// When SSE is forcibly unavailable, polling still removes a deleted peer.
	topology.runtime.Hub().Close()
	if err := topology.runtime.Manage().DeletePeer(ctx, ManageDeletePeerRequest{NodeID: 101}); err != nil {
		t.Fatalf("delete Edge A: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, snapshotErr := topology.snapshot(ctx, 102, topology.keyB)
		_, exists := e2ePeer(snapshot, 101)
		return snapshotErr == nil && !exists && topology.edgeB.LookupPeer(topology.pubA) == nil
	})

	// Then every runtime stops through its documented lifecycle.
	shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopShutdown()
	if err := topology.shutdown(shutdownCtx); err != nil {
		t.Fatalf("clean topology shutdown: %v", err)
	}
	for _, edge := range []struct {
		name string
		done <-chan int
	}{
		{name: "A", done: topology.edgeA.Wait()},
		{name: "B", done: topology.edgeB.Wait()},
		{name: "C", done: topology.edgeC.Wait()},
	} {
		edgeCloseCtx, stopEdgeClose := context.WithTimeout(context.Background(), 3*time.Second)
		select {
		case <-edge.done:
		case <-edgeCloseCtx.Done():
			t.Fatalf("Edge %s did not close", edge.name)
		}
		stopEdgeClose()
	}
}

func TestHTTPOnlySuperEndToEndObservedFallback(t *testing.T) {
	// Given three registered Edges connected only through the in-process fabric.
	topology := newE2ETopology(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := topology.shutdown(ctx); err != nil {
			t.Errorf("topology shutdown: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeA.LookupPeer(topology.pubB) != nil &&
			topology.edgeB.LookupPeer(topology.pubA) != nil &&
			topology.edgeC.LookupPeer(topology.pubB) != nil
	})

	// When A receives authenticated traffic from B's alternate public source.
	topology.bindB.dropInitiation.Store(false)
	if err := topology.edgeB.LookupPeer(topology.pubA).SendHandshakeInitiation(false); err != nil {
		t.Fatalf("start B-to-A handshake: %v", err)
	}
	select {
	case <-topology.bindB.responses:
	case <-ctx.Done():
		t.Fatal("B-to-A handshake response did not arrive before deadline")
	}
	topology.edgeB.SendPacket(topology.edgeB.LookupPeer(topology.pubA), path.NormalPacket, 64, e2eNormalPacket(t, 102, 101), device.MessageTransportOffsetContent)
	select {
	case <-topology.bindA.transports:
	case <-ctx.Done():
		t.Fatal("B-to-A authenticated transport did not arrive before deadline")
	}

	// Then C receives B's anonymous, count-ranked observed fallback hint.
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, err := topology.snapshot(ctx, 103, topology.keyC)
		if err != nil {
			return false
		}
		peerB, found := e2ePeer(snapshot, 102)
		return found && len(peerB.ObservedV4) == 1 && peerB.ObservedV4[0].Address == "203.0.113.102:102" && peerB.ObservedV4[0].ReporterCount == 1
	})
	snapshotC, err := topology.snapshot(ctx, 103, topology.keyC)
	if err != nil {
		t.Fatalf("C snapshot with observed hint: %v", err)
	}
	encoded, err := json.Marshal(snapshotC)
	if err != nil {
		t.Fatalf("marshal C snapshot: %v", err)
	}
	for _, forbidden := range []string{"observer", "received_at", topology.keyA} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("snapshot JSON leaked %q: %s", forbidden, encoded)
		}
	}

	// When B withdraws its self candidates, C applies only the observed fallback.
	topology.cancelB()
	select {
	case <-topology.runtimeB.Done():
	case <-ctx.Done():
		t.Fatal("B runtime did not stop before withdrawal")
	}
	reporterB := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 102, topology.keyB)
	reporterB.Now = topology.clock.Now
	if err := reporterB.Report(ctx, &mtypes.ControlV2ReportRequest{NodeID: 102, ReportedAt: topology.clock.Now()}); err != nil {
		t.Fatalf("withdraw B self candidates: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, snapshotErr := topology.snapshot(ctx, 103, topology.keyC)
		peerB, found := e2ePeer(snapshot, 102)
		return snapshotErr == nil && found && len(peerB.LocalV4) == 0 && len(peerB.PublicV4) == 0 && len(peerB.ObservedV4) == 1
	})

	topology.cancelC()
	select {
	case <-topology.runtimeC.Done():
	case <-ctx.Done():
		t.Fatal("C runtime did not apply fallback before shutdown")
	}
	peerToB := topology.edgeC.LookupPeer(topology.pubB)
	if err := peerToB.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("start C-to-B recovery handshake: %v", err)
	}
	select {
	case <-topology.bindC.responses:
	case <-ctx.Done():
		t.Fatal("C did not rotate to B's observed fallback")
	}

	// When the only observer expires, the revision exposes stale-hint removal.
	beforeExpiry, err := topology.snapshot(ctx, 103, topology.keyC)
	if err != nil {
		t.Fatalf("snapshot before observer expiry: %v", err)
	}
	topology.cancelA()
	select {
	case <-topology.runtimeA.Done():
	case <-ctx.Done():
		t.Fatal("A runtime did not stop before expiry")
	}
	topology.clock.Advance(30 * time.Minute)
	if err := reporterB.Report(ctx, &mtypes.ControlV2ReportRequest{NodeID: 102, ReportedAt: topology.clock.Now()}); err != nil {
		t.Fatalf("keep B live while expiring observer: %v", err)
	}
	reporterC := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 103, topology.keyC)
	reporterC.Now = topology.clock.Now
	if err := reporterC.Report(ctx, &mtypes.ControlV2ReportRequest{NodeID: 103, ReportedAt: topology.clock.Now()}); err != nil {
		t.Fatalf("keep C live while expiring observer: %v", err)
	}
	topology.clock.Advance(31 * time.Minute)
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, snapshotErr := topology.snapshot(ctx, 103, topology.keyC)
		peerB, found := e2ePeer(snapshot, 102)
		return snapshotErr == nil && found && snapshot.Revision > beforeExpiry.Revision && len(peerB.ObservedV4) == 0
	})
}

func TestHTTPOnlySuperEndToEndForcedRefreshCap(t *testing.T) {
	// Given C receives normal SSE snapshots and retries dynamic peers rapidly.
	topology := newE2ETopologyWithOptions(t, e2eTopologyOptions{
		pollIntervalSeconds: 30,
		reportInterval:      3 * time.Second,
		edgeCRetry: e2eRetryConfig{
			peerAliveTimeout:     0,
			connNextTry:          0.01,
			timeoutCheckInterval: 0.01,
		},
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := topology.shutdown(ctx); err != nil {
			t.Errorf("topology shutdown: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	reporterC := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 103, topology.keyC)
	reporterC.Now = topology.clock.Now
	if err := reporterC.Report(ctx, &mtypes.ControlV2ReportRequest{
		NodeID: 103,
		Candidates: []mtypes.ControlV2Candidate{
			{Address: "127.0.0.1:103", Source: mtypes.ControlV2CandidateLocal},
			{Address: "198.51.100.103:103", Source: mtypes.ControlV2CandidateSTUN},
		},
		ReportedAt: topology.clock.Now(),
	}); err != nil {
		t.Fatalf("publish C candidates before cap observation: %v", err)
	}
	awaitStableSnapshotCount(t, topology.forcedCSnapshots, time.Second, 500*time.Millisecond)
	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeC.LookupPeer(topology.pubA) != nil && topology.edgeC.LookupPeer(topology.pubB) != nil
	})

	// Remove A to leave C with exactly B. Setup retries may already have
	// exhausted B, but B's removal below prunes that stale coalesce entry.
	if err := topology.runtime.Manage().DeletePeer(ctx, ManageDeletePeerRequest{NodeID: 101}); err != nil {
		t.Fatalf("delete Edge A before cap observation: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeC.LookupPeer(topology.pubA) == nil
	})

	// Rebirth B: removal prunes C's setup-era recovery state, and Register
	// creates a new, dead Super peer with a fresh trylist generation.
	topology.bindB.dropOutbound.Store(true)
	if err := topology.runtime.Manage().DeletePeer(ctx, ManageDeletePeerRequest{NodeID: 102}); err != nil {
		t.Fatalf("delete Edge B for rebirth: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeC.LookupPeer(topology.pubB) == nil
	})
	addedB, err := topology.runtime.Manage().AddPeer(ctx, ManageAddPeerRequest{NodeID: 102, NodeName: "edge-b"})
	if err != nil {
		t.Fatalf("add B authorization for rebirth: %v", err)
	}
	rebornB := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 102, addedB.SuperPeer.ControlPSKey)
	rebornB.Now = topology.clock.Now
	if _, err := rebornB.Register(ctx, &mtypes.ControlV2RegisterRequest{
		NodeID:         102,
		NodeName:       "edge-b",
		PubKey:         topology.pubB.ToString(),
		Version:        mtypes.ControlV2ProtocolVersion,
		ListenPort:     102,
		PublicV4:       []string{"203.0.113.202:102"},
		DesiredTTL:     64,
		RequestedAt:    topology.clock.Now(),
		Implementation: "etherguard",
	}); err != nil {
		t.Fatalf("re-register B with fresh candidates: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeC.LookupPeer(topology.pubB) != nil && topology.edgeC.GetConnurl(102) == "203.0.113.202:102"
	})

	// The SSE-driven delete/re-add fetches must settle before measuring the
	// exhaustion-triggered Sync refresh.
	topology.runtime.Hub().Close()
	before := awaitStableSnapshotCount(t, topology.forcedCSnapshots, 3*time.Second, 100*time.Millisecond)

	// When C exhausts its fresh, dead B generation, the ETag-aware recovery
	// requests exactly one snapshot. B cannot reply to C's probes.
	awaitE2E(t, 5*time.Second, func() bool {
		return topology.forcedCSnapshots.Load() == before+1
	})
	awaitStableSnapshotCount(t, topology.forcedCSnapshots, time.Second, 400*time.Millisecond)
	// Then the single peer causes one ETag-aware fetch, never a retry storm within 30 seconds.
	if got := topology.forcedCSnapshots.Load() - before; got != 1 {
		t.Fatalf("forced snapshot requests for C->B = %d, want 1 within 30 seconds", got)
	}
}

func (topology *e2eTopology) snapshot(ctx context.Context, nodeID mtypes.Vertex, key string) (*mtypes.ControlV2Snapshot, error) {
	client := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, nodeID, key)
	client.Now = topology.clock.Now
	snapshot, _, err := client.Snapshot(ctx)
	return snapshot, err
}

func awaitE2E(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-timeoutTimer.C:
			t.Fatal("end-to-end condition did not converge")
		}
	}
}

func awaitStableSnapshotCount(t *testing.T, counter *atomic.Int64, timeout, quiet time.Duration) int64 {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	last := counter.Load()
	quietUntil := time.Now().Add(quiet)
	for {
		select {
		case <-ticker.C:
			if current := counter.Load(); current != last {
				last = current
				quietUntil = time.Now().Add(quiet)
			}
			if !time.Now().Before(quietUntil) {
				return last
			}
		case <-deadline.C:
			t.Fatal("C snapshot traffic did not settle before cap observation")
		}
	}
}

func e2ePeer(snapshot *mtypes.ControlV2Snapshot, nodeID mtypes.Vertex) (mtypes.ControlV2Peer, bool) {
	if snapshot == nil {
		return mtypes.ControlV2Peer{}, false
	}
	for _, peer := range snapshot.Peers {
		if peer.NodeID == nodeID {
			return peer, true
		}
	}
	return mtypes.ControlV2Peer{}, false
}

func assertSameBindCandidate(t *testing.T, local, mapped, wantIP string) {
	t.Helper()
	_, localPort, err := net.SplitHostPort(local)
	if err != nil {
		t.Fatalf("local candidate %q: %v", local, err)
	}
	mappedIP, mappedPort, err := net.SplitHostPort(mapped)
	if err != nil {
		t.Fatalf("mapped candidate %q: %v", mapped, err)
	}
	if mappedIP != wantIP || mappedPort != localPort {
		t.Fatalf("mapped candidate = %s, want %s with active bind port %s", mapped, wantIP, localPort)
	}
}

func e2eNormalPacket(t *testing.T, source, destination mtypes.Vertex) []byte {
	t.Helper()
	packet := make([]byte, path.EgHeaderLen+14)
	header, err := path.NewEgHeader(packet[:path.EgHeaderLen], 1400)
	if err != nil {
		t.Fatalf("create EtherGuard header: %v", err)
	}
	header.SetSrc(source)
	header.SetDst(destination)
	copy(packet[path.EgHeaderLen:], []byte{0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00})
	return packet
}

func e2eCandidates(peer mtypes.ControlV2Peer) []mtypes.ControlV2Candidate {
	candidates := make([]mtypes.ControlV2Candidate, 0, len(peer.LocalV4)+len(peer.PublicV4))
	for _, address := range peer.LocalV4 {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: address, Source: mtypes.ControlV2CandidateLocal})
	}
	for _, address := range peer.PublicV4 {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: address, Source: mtypes.ControlV2CandidateSTUN})
	}
	return candidates
}

func awaitSSERevision(t *testing.T, ctx context.Context, events <-chan mtypes.ControlV2Event, revision uint64) {
	t.Helper()
	for {
		select {
		case event := <-events:
			if event.Type == mtypes.ControlV2EventPeerChange && event.Revision > revision {
				return
			}
		case <-ctx.Done():
			t.Fatal("SSE invalidation did not arrive before deadline")
		}
	}
}
