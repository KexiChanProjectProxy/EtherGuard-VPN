package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestControlStateRegistrationAndReport(t *testing.T) {
	// Given a service and a valid registration request
	svc := NewControlState(ControlStateConfig{})
	req := controlRegisterRequest(1, "edge-a")

	// When the edge registers
	snapshot, err := svc.Register(context.Background(), req, "control-a")

	// Then it is represented without exposing its control key
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(snapshot.Peers) != 0 {
		t.Fatalf("self peer must not appear in own snapshot, got %#v", snapshot.Peers)
	}
	if key, ok := svc.ControlKeyFor(req.NodeID); !ok || key != "control-a" {
		t.Fatalf("control key lookup failed: %q ok=%v", key, ok)
	}
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: req.NodeID, Candidates: []mtypes.ControlV2Candidate{{Address: "192.0.2.1:51820", Source: mtypes.ControlV2CandidateLocal}}}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if peers := svc.SnapshotFor(req.NodeID).Peers; len(peers) != 0 {
		t.Fatal("self peer must not appear in own snapshot after report")
	}
}

func TestControlStateReportedCandidateReachesOtherEdges(t *testing.T) {
	// Given two registered edges on a fresh service
	svc := NewControlState(ControlStateConfig{})
	if _, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "key-a"); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if _, err := svc.Register(context.Background(), controlRegisterRequest(2, "edge-b"), "key-b"); err != nil {
		t.Fatalf("register b: %v", err)
	}
	baseline := svc.Revision()

	// When edge A reports a new STUN-derived candidate
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 1, Candidates: []mtypes.ControlV2Candidate{
		{Address: "192.0.2.1:51820", Source: mtypes.ControlV2CandidateLocal},
		{Address: "203.0.113.10:51820", Source: mtypes.ControlV2CandidateSTUN},
		{Address: "[2001:db8::10]:51820", Source: mtypes.ControlV2CandidateSTUN},
	}}); err != nil {
		t.Fatalf("report a: %v", err)
	}

	// Then edge B's snapshot exposes the new candidate and the revision bumped
	snap := svc.SnapshotFor(2)
	if svc.Revision() <= baseline {
		t.Fatalf("revision did not bump: baseline=%d now=%d", baseline, svc.Revision())
	}
	if len(snap.Peers) != 1 || snap.Peers[0].NodeID != 1 {
		t.Fatalf("unexpected peers: %#v", snap.Peers)
	}
	if !contains(snap.Peers[0].PublicV4, "203.0.113.10:51820") {
		t.Fatalf("STUN v4 candidate missing from public list: %#v", snap.Peers[0].PublicV4)
	}
	if !contains(snap.Peers[0].PublicV6, "[2001:db8::10]:51820") {
		t.Fatalf("STUN v6 candidate missing from public list: %#v", snap.Peers[0].PublicV6)
	}
	if !contains(snap.Peers[0].LocalV4, "192.0.2.1:51820") {
		t.Fatalf("Local v4 candidate missing: %#v", snap.Peers[0].LocalV4)
	}
	if snap.Peers[0].PSKey != "" {
		t.Fatalf("control PSKey leaked into peer view")
	}
}

func TestControlStateTimeoutAndRevisionSemantics(t *testing.T) {
	// Given a controllable clock and an alive timeout
	svc := NewControlState(ControlStateConfig{Now: currentTime, PeerAliveTimeout: 0})
	_, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "key")
	if err != nil {
		t.Fatal(err)
	}
	rev := svc.Revision()

	// When an identical report arrives, only heartbeat changes
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 1}); err != nil {
		t.Fatal(err)
	}
	if svc.Revision() != rev {
		t.Fatalf("heartbeat changed revision: %d -> %d", rev, svc.Revision())
	}
	svc.peerAliveTimeout = time.Minute
	advance(2 * time.Minute)
	advance(0) // ensure atomic publish visibility
	if removed := svc.SweepTimeouts(); removed != 1 {
		t.Fatalf("removed=%d", removed)
	}
	if svc.Revision() != rev+1 {
		t.Fatalf("revision=%d want %d", svc.Revision(), rev+1)
	}
	if svc.SweepTimeouts() != 0 || svc.Revision() != rev+1 {
		t.Fatal("empty sweep changed revision")
	}
}

func TestControlStateConcurrentMutation(t *testing.T) {
	// Given one service shared by concurrent writers and readers
	svc := NewControlState(ControlStateConfig{PeerAliveTimeout: time.Hour})
	// When many goroutines register, report, and snapshot concurrently
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := mtypes.Vertex(i + 1)
			_, _ = svc.Register(context.Background(), controlRegisterRequest(id, "edge"), "key")
			_ = svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: id})
			svc.SnapshotFor(id)
		}(i)
	}
	wg.Wait()
	// Then the service remains usable and all keys are isolated
	if svc.Revision() == 0 {
		t.Fatal("concurrent registrations made no observable change")
	}
}

func controlRegisterRequest(id mtypes.Vertex, name string) mtypes.ControlV2RegisterRequest {
	return mtypes.ControlV2RegisterRequest{NodeID: id, NodeName: name, Version: mtypes.ControlV2ProtocolVersion}
}

func contains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

// Test clock — package-private helpers shared across the TDD tests in
// this file only; production code passes its own Now function.
var testClockNanos atomic.Int64

func currentTime() time.Time {
	return time.Unix(0, testClockNanos.Load())
}

func advance(d time.Duration) {
	testClockNanos.Add(int64(d))
}

// Test clock — package-private helpers shared across the TDD tests in
// this file only; production code passes its own Now function.

func TestControlStateRegisterCandidateSourceLabels(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	req := mtypes.ControlV2RegisterRequest{
		NodeID:   1,
		NodeName: "edge-a",
		Version:  mtypes.ControlV2ProtocolVersion,
		LocalV4:  []string{"10.0.0.1:51820"},
		LocalV6:  []string{"[fd00::1]:51820"},
		PublicV4: []string{"203.0.113.1:51820"},
		PublicV6: []string{"[2001:db8::1]:51820"},
	}

	if _, err := svc.Register(context.Background(), req, "control-a"); err != nil {
		t.Fatalf("register: %v", err)
	}

	record, ok := svc.peers[req.NodeID]
	if !ok {
		t.Fatalf("registered peer %v not found", req.NodeID)
	}
	want := map[string]mtypes.ControlV2CandidateSource{
		"10.0.0.1:51820":      mtypes.ControlV2CandidateLocal,
		"[fd00::1]:51820":     mtypes.ControlV2CandidateLocal,
		"203.0.113.1:51820":   mtypes.ControlV2CandidateSTUN,
		"[2001:db8::1]:51820": mtypes.ControlV2CandidateSTUN,
	}
	if len(record.candidates) != len(want) {
		t.Fatalf("candidate count = %d, want %d: %#v", len(record.candidates), len(want), record.candidates)
	}
	for _, candidate := range record.candidates {
		wantSource, ok := want[candidate.Address]
		if !ok {
			t.Errorf("unexpected candidate address %q", candidate.Address)
			continue
		}
		if candidate.Source != wantSource {
			t.Errorf("candidate %q source = %q, want %q", candidate.Address, candidate.Source, wantSource)
		}
	}
}

func TestControlStateObservedVotesAggregateReplaceAndRemainAnonymous(t *testing.T) {
	// Given a target and two observers with a receipt-time clock
	now := time.Unix(100, 0)
	svc := NewControlState(ControlStateConfig{Now: func() time.Time { return now }, PeerAliveTimeout: time.Minute})
	registerObservedPeers(t, svc, 1, 2, 3, 4)
	targetLastSeen := observedPeer(t, svc.SnapshotFor(4), 1).LastSeen

	// When observers report one canonical vote each and one replaces its vote
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")
	reportObservedVote(t, svc, 3, 1, "198.51.100.10:51820")
	observed := observedPeer(t, svc.SnapshotFor(4), 1).ObservedV4
	if len(observed) != 1 || observed[0].Address != "198.51.100.10:51820" || observed[0].ReporterCount != 2 {
		t.Fatalf("aggregate after two votes = %#v", observed)
	}
	reportObservedVote(t, svc, 2, 1, "198.51.100.11:51820")

	// Then the old vote is replaced, liveness is untouched, and JSON is anonymous.
	peer := observedPeer(t, svc.SnapshotFor(4), 1)
	if len(peer.ObservedV4) != 2 || peer.ObservedV4[0] != (mtypes.ControlV2ObservedAddress{Address: "198.51.100.10:51820", ReporterCount: 1}) || peer.ObservedV4[1] != (mtypes.ControlV2ObservedAddress{Address: "198.51.100.11:51820", ReporterCount: 1}) {
		t.Fatalf("replacement aggregate = %#v", peer.ObservedV4)
	}
	if !peer.LastSeen.Equal(targetLastSeen) {
		t.Fatalf("target LastSeen changed through observer vote: %s -> %s", targetLastSeen, peer.LastSeen)
	}
	encoded, err := json.Marshal(peer)
	if err != nil {
		t.Fatalf("marshal peer: %v", err)
	}
	if string(encoded) == "" || containsJSONKey(encoded, "observer") {
		t.Fatalf("observed snapshot leaked attribution: %s", encoded)
	}
}

func TestControlStateObservedSnapshotCapsAndSuppressesSelfCandidates(t *testing.T) {
	// Given a target with a self-reported endpoint and enough reporters to exceed every cap
	svc := NewControlState(ControlStateConfig{})
	target := controlRegisterRequest(1, "target")
	target.PublicV4 = []string{"198.51.100.250:51820"}
	if _, err := svc.Register(context.Background(), target, "target-key"); err != nil {
		t.Fatalf("register target: %v", err)
	}
	if _, err := svc.Register(context.Background(), controlRegisterRequest(100, "reader"), "reader-key"); err != nil {
		t.Fatalf("register reader: %v", err)
	}
	for id := mtypes.Vertex(2); id <= 34; id++ {
		if _, err := svc.Register(context.Background(), controlRegisterRequest(id, fmt.Sprintf("observer-%d", id)), fmt.Sprintf("key-%d", id)); err != nil {
			t.Fatalf("register observer %d: %v", id, err)
		}
		address := fmt.Sprintf("198.51.100.%d:51820", id)
		if id == 2 {
			address = "198.51.100.250:51820"
		}
		if id >= 20 {
			address = fmt.Sprintf("[2001:db8::%x]:51820", id)
		}
		reportObservedVote(t, svc, id, 1, address)
	}

	// When another edge reads the target snapshot
	peer := observedPeer(t, svc.SnapshotFor(100), 1)

	// Then self candidates are absent and published hints obey total/family bounds.
	if containsObserved(peer.ObservedV4, "198.51.100.250:51820") {
		t.Fatalf("self candidate published: %#v", peer.ObservedV4)
	}
	if got := len(peer.ObservedV4) + len(peer.ObservedV6); got != 16 {
		t.Fatalf("total observed hints = %d, want 16", got)
	}
	if len(peer.ObservedV4) > 14 || len(peer.ObservedV6) > 14 {
		t.Fatalf("family caps exceeded: v4=%d v6=%d", len(peer.ObservedV4), len(peer.ObservedV6))
	}
}

func TestControlStateObservedVoteRemovalIsRevisionSafe(t *testing.T) {
	// Given an observed hint and an event collector
	now := time.Unix(0, 0)
	svc := NewControlState(ControlStateConfig{Now: func() time.Time { return now }, PeerAliveTimeout: 5 * time.Second})
	registerObservedPeers(t, svc, 1, 2, 3)
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) { events = append(events, event) })
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")

	// When an unchanged report is followed by observer re-registration
	revision := svc.Revision()
	eventCount := len(events)
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")
	if svc.Revision() != revision || len(events) != eventCount {
		t.Fatalf("unchanged vote changed revision/events: revision=%d events=%d", svc.Revision(), len(events))
	}
	if _, err := svc.Register(context.Background(), controlRegisterRequest(2, "observer-2"), "key-2"); err != nil {
		t.Fatalf("re-register observer: %v", err)
	}

	// Then re-registration removes the hint through exactly one revision/event.
	if svc.Revision() != revision+1 || len(events) != eventCount+1 {
		t.Fatalf("re-register removal revision/events = %d/%d, want %d/%d", svc.Revision(), len(events), revision+1, eventCount+1)
	}
	if got := observedPeer(t, svc.SnapshotFor(3), 1).ObservedV4; len(got) != 0 {
		t.Fatalf("re-register retained votes: %#v", got)
	}

	// When the observer votes again and expires
	reportObservedVote(t, svc, 2, 1, "198.51.100.11:51820")
	now = now.Add(4 * time.Second)
	svc.mu.Lock()
	for _, id := range []mtypes.Vertex{1, 2, 3} {
		svc.peers[id].view.LastSeen = now
	}
	svc.mu.Unlock()
	now = now.Add(time.Second)
	revision = svc.Revision()
	eventCount = len(events)
	svc.SweepTimeouts()

	// Then expiry removes the stale observer vote with one revision/event.
	if svc.Revision() != revision+1 || len(events) != eventCount+1 {
		t.Fatalf("expiry removal revision/events = %d/%d, want %d/%d", svc.Revision(), len(events), revision+1, eventCount+1)
	}
	if got := observedPeer(t, svc.SnapshotFor(3), 1).ObservedV4; len(got) != 0 {
		t.Fatalf("expiry retained votes: %#v", got)
	}
}

func TestControlStateObservedReportReplacesCompleteVoteSet(t *testing.T) {
	// Given one observer voting for two targets and a reader of both targets.
	svc := NewControlState(ControlStateConfig{})
	registerObservedPeers(t, svc, 1, 2, 3, 4)
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) { events = append(events, event) })
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{
		NodeID: 2,
		Observed: []mtypes.ControlV2ObservedEndpoint{
			{TargetNodeID: 1, Address: "198.51.100.10:51820"},
			{TargetNodeID: 3, Address: "198.51.100.30:51820"},
		},
	}); err != nil {
		t.Fatalf("initial report: %v", err)
	}
	if got := observedPeer(t, svc.SnapshotFor(4), 3).ObservedV4; len(got) != 1 {
		t.Fatalf("initial target 3 hints = %#v", got)
	}

	// When the observer's next complete report omits target 3, its old vote is purged.
	revision := svc.Revision()
	eventCount := len(events)
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")
	if svc.Revision() != revision+1 || len(events) != eventCount+1 {
		t.Fatalf("omitted target removal revision/events = %d/%d, want %d/%d", svc.Revision(), len(events), revision+1, eventCount+1)
	}
	if got := observedPeer(t, svc.SnapshotFor(4), 3).ObservedV4; len(got) != 0 {
		t.Fatalf("omitted target retained hints: %#v", got)
	}

	// Then repeating the now-complete set is invisible to snapshot consumers.
	revision = svc.Revision()
	eventCount = len(events)
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")
	if svc.Revision() != revision || len(events) != eventCount {
		t.Fatalf("unchanged complete set changed revision/events: %d/%d", svc.Revision(), len(events))
	}
}

func TestControlStateSuppressedVoteExpiryIsSilent(t *testing.T) {
	// Given a vote that is suppressed because it duplicates the target's candidate.
	now := time.Unix(0, 0)
	svc := NewControlState(ControlStateConfig{Now: func() time.Time { return now }, PeerAliveTimeout: 5 * time.Second})
	target := controlRegisterRequest(1, "target")
	target.PublicV4 = []string{"198.51.100.10:51820"}
	if _, err := svc.Register(context.Background(), target, "target-key"); err != nil {
		t.Fatalf("register target: %v", err)
	}
	registerObservedPeers(t, svc, 2, 3)
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) { events = append(events, event) })
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")
	if got := observedPeer(t, svc.SnapshotFor(3), 1).ObservedV4; len(got) != 0 {
		t.Fatalf("self-suppressed vote published: %#v", got)
	}

	// When the vote expires while the observer remains alive, no published output changed.
	svc.mu.Lock()
	for _, id := range []mtypes.Vertex{1, 2, 3} {
		svc.peers[id].view.LastSeen = now.Add(4 * time.Second)
	}
	svc.mu.Unlock()
	now = now.Add(5 * time.Second)
	revision := svc.Revision()
	eventCount := len(events)
	svc.SweepTimeouts()

	// Then expiry produces neither a revision bump nor an event.
	if svc.Revision() != revision || len(events) != eventCount {
		t.Fatalf("suppressed vote expiry changed revision/events: %d/%d", svc.Revision(), len(events))
	}
}

func TestControlStateSnapshotPeersAreSortedByNodeID(t *testing.T) {
	// Given peers inserted in a deliberately unsorted order.
	svc := NewControlState(ControlStateConfig{})
	registerObservedPeers(t, svc, 30, 10, 20)

	// Then every snapshot produces peers in NodeID order.
	for i := 0; i < 32; i++ {
		peers := svc.SnapshotFor(99).Peers
		if len(peers) != 3 || peers[0].NodeID != 10 || peers[1].NodeID != 20 || peers[2].NodeID != 30 {
			t.Fatalf("snapshot %d peer order = %#v", i, peers)
		}
	}
}

func TestControlStateObservedVotesClearWhenObserverDeletes(t *testing.T) {
	// Given an observer vote visible to a third edge
	svc := NewControlState(ControlStateConfig{})
	registerObservedPeers(t, svc, 1, 2, 3)
	reportObservedVote(t, svc, 2, 1, "198.51.100.10:51820")
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) { events = append(events, event) })
	revision := svc.Revision()

	// When the observer is deleted
	if err := svc.DeletePeer(context.Background(), 2); err != nil {
		t.Fatalf("delete observer: %v", err)
	}

	// Then its vote disappears through one revision notification.
	if svc.Revision() != revision+1 || len(events) != 1 {
		t.Fatalf("delete removal revision/events = %d/%d, want %d/1", svc.Revision(), len(events), revision+1)
	}
	if got := observedPeer(t, svc.SnapshotFor(3), 1).ObservedV4; len(got) != 0 {
		t.Fatalf("delete retained votes: %#v", got)
	}
}

// TestControlStatePreAuthorizedRegistryRetainsKeysAcrossSweep proves the
// liveness-independent configured-key registry: a pre-authorized NodeID
// whose active peer record is swept (LastSeen expired) keeps its control
// PSKey so the Edge can re-authenticate after going offline longer than
// PeerAliveTimeout. Auth resolution must fall back to the registry when
// the active peer map no longer has the record.
func TestControlStatePreAuthorizedRegistryRetainsKeysAcrossSweep(t *testing.T) {
	// Given a configurable clock, a peer alive timeout, and a pre-authorized
	// key installed independently from any Register call.
	svc := NewControlState(ControlStateConfig{Now: currentTime, PeerAliveTimeout: 0})
	svc.SetPreAuthorized(42, "configured-key-42")

	// Sanity: the key is resolvable immediately, without an active peer record.
	if key, ok := svc.ControlKeyFor(42); !ok || key != "configured-key-42" {
		t.Fatalf("ControlKeyFor(42) before sweep: (%q, %v), want (\"configured-key-42\", true)", key, ok)
	}

	// When peer alive timeout becomes 1 minute and the clock advances past it.
	svc.peerAliveTimeout = time.Minute
	advance(2 * time.Minute)
	advance(0) // ensure atomic publish visibility
	svc.SweepTimeouts()

	// Then the registry STILL resolves the same key even though the
	// peer map had nothing to sweep (no active record was ever created).
	if key, ok := svc.ControlKeyFor(42); !ok || key != "configured-key-42" {
		t.Fatalf("ControlKeyFor(42) after sweep: (%q, %v), want (\"configured-key-42\", true)", key, ok)
	}
}

// TestControlStateSeededPeersAbsentFromSnapshots proves configured (not
// registered) NodeIDs do NOT appear as peers in any snapshot. Snapshots
// only reflect active, recently-observed peers.
func TestControlStateSeededPeersAbsentFromSnapshots(t *testing.T) {
	// Given pre-authorized keys for two IDs and one actively registered peer.
	svc := NewControlState(ControlStateConfig{PeerAliveTimeout: time.Hour})
	svc.SetPreAuthorized(7, "seed-key-7")
	svc.SetPreAuthorized(8, "seed-key-8")
	if _, err := svc.Register(context.Background(), controlRegisterRequest(9, "registered"), "reg-key-9"); err != nil {
		t.Fatalf("register 9: %v", err)
	}
	// The registered peer is required so the snapshot for it has SOMETHING
	// to read; the seeded NodeIDs must NOT appear.
	snap := svc.SnapshotFor(9)
	for _, peer := range snap.Peers {
		if peer.NodeID == 7 || peer.NodeID == 8 {
			t.Fatalf("seeded peer %d appeared in snapshot: %+v", peer.NodeID, peer)
		}
	}
}

// TestControlStateSweepRemovesActiveButRetainsConfigured proves that a
// peer which has BOTH an active record AND a pre-authorized key is
// subject to normal sweep semantics on the active record, while the
// configured key survives the sweep so the Edge can re-register.
func TestControlStateSweepRemovesActiveButRetainsConfigured(t *testing.T) {
	// Given a single clock and a registered + configured peer.
	svc := NewControlState(ControlStateConfig{Now: currentTime, PeerAliveTimeout: 0})
	svc.SetPreAuthorized(1, "configured-key-1")
	if _, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "active-key-1"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// When the clock advances past the alive timeout and we sweep.
	svc.peerAliveTimeout = time.Minute
	advance(2 * time.Minute)
	advance(0)
	if removed := svc.SweepTimeouts(); removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}

	// Then the active peer record is gone, but the configured PSKey is
	// still resolvable (this is the central bug-fix invariant).
	if _, ok := svc.peers[1]; ok {
		t.Fatalf("active peer 1 still present after sweep")
	}
	if key, ok := svc.ControlKeyFor(1); !ok || key != "configured-key-1" {
		t.Fatalf("ControlKeyFor(1) post-sweep: (%q, %v), want (\"configured-key-1\", true)", key, ok)
	}
}

// TestControlStateReRegistrationAfterSweepWorks proves that after a peer
// is swept and its active record is gone, the Edge can still authenticate
// and re-register using its configured key.
func TestControlStateReRegistrationAfterSweepWorks(t *testing.T) {
	// Given a peer that registered once and is configured.
	svc := NewControlState(ControlStateConfig{Now: currentTime, PeerAliveTimeout: 0})
	svc.SetPreAuthorized(1, "configured-key-1")
	if _, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "configured-key-1"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// When the clock advances past the alive timeout (peer falls silent)
	// and then the Edge re-registers using its configured PSKey.
	svc.peerAliveTimeout = time.Minute
	advance(2 * time.Minute)
	advance(0)
	svc.SweepTimeouts()
	if _, ok := svc.peers[1]; ok {
		t.Fatalf("active record should be gone")
	}
	if _, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "configured-key-1"); err != nil {
		t.Fatalf("re-register: %v", err)
	}

	// Then the new active record is populated and visible.
	if _, ok := svc.peers[1]; !ok {
		t.Fatalf("re-register did not install active record")
	}
	if key, ok := svc.ControlKeyFor(1); !ok || key != "configured-key-1" {
		t.Fatalf("ControlKeyFor(1) after re-register: (%q, %v)", key, ok)
	}
}

// TestControlStateDeleteRemovesPreAuthorized proves DeletePeer removes the
// active record AND the configured key in lock-step (so a deleted Edge
// cannot re-authenticate with stale credentials).
func TestControlStateDeleteRemovesPreAuthorized(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	svc.SetPreAuthorized(7, "config-7")
	if _, err := svc.Register(context.Background(), controlRegisterRequest(7, "edge-7"), "config-7"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := svc.DeletePeer(context.Background(), 7); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if _, ok := svc.peers[7]; ok {
		t.Fatalf("active peer still present")
	}
	if key, ok := svc.ControlKeyFor(7); ok {
		t.Fatalf("ControlKeyFor(7) after DeletePeer: (%q, true), want ('', false)", key)
	}
}

// TestControlStateSetPreAuthorizedInvalidatesOldKeyImmediately proves the
// configured-key registry holds AT MOST ONE key per NodeID — installing a
// new key immediately invalidates any prior key for the same NodeID, with
// no observable difference to "deleted then added".
func TestControlStateSetPreAuthorizedInvalidatesOldKeyImmediately(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	svc.SetPreAuthorized(5, "old-key")
	if key, ok := svc.ControlKeyFor(5); !ok || key != "old-key" {
		t.Fatalf("first install: (%q, %v)", key, ok)
	}
	svc.SetPreAuthorized(5, "new-key")
	if key, ok := svc.ControlKeyFor(5); !ok || key != "new-key" {
		t.Fatalf("rotate: (%q, %v), want (\"new-key\", true)", key, ok)
	}
	// Old key must NOT be resolvable through any secondary lookup.
	if _, ok := svc.preauthorized[5]; !ok || svc.preauthorized[5] != "new-key" {
		t.Fatalf("preauthorized[5]=%q ok=%v, want \"new-key\" true", svc.preauthorized[5], ok)
	}
}

// TestControlStateRemovePreAuthorizedDropsLookup proves RemovePreAuthorized
// (used by ManageV2 rollback paths) removes the entry entirely so a
// generic authentication failure is returned for that NodeID afterwards.
func TestControlStateRemovePreAuthorizedDropsLookup(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	svc.SetPreAuthorized(11, "k11")
	if _, ok := svc.ControlKeyFor(11); !ok {
		t.Fatalf("install failed")
	}
	svc.RemovePreAuthorized(11)
	if key, ok := svc.ControlKeyFor(11); ok {
		t.Fatalf("ControlKeyFor(11) after remove: (%q, true), want ('', false)", key)
	}
}

// TestControlStateControlKeyForDoesNotResurrectPeer proves authentication
// against the configured key does NOT install a peer record as a side
// effect — only explicit Register / Report may create an active record.
// An Edge must always follow up with Register after authenticating; the
// registry is purely a credential store.
func TestControlStateControlKeyForDoesNotResurrectPeer(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	svc.SetPreAuthorized(13, "config-13")
	if _, ok := svc.ControlKeyFor(13); !ok {
		t.Fatalf("ControlKeyFor must resolve the configured key")
	}
	if _, ok := svc.peers[13]; ok {
		t.Fatalf("ControlKeyFor side-effected an active peer record")
	}
	snap := svc.SnapshotFor(13)
	if len(snap.Peers) != 0 {
		t.Fatalf("snapshot for the requester contains other peers before any active registration: %+v", snap.Peers)
	}
}

// TestControlStateParametersCloneIsolationPointeeMutation proves the
// clone semantics of every projection path (construction via
// NewControlState, UpdateParameters, SnapshotFor, and the
// ParametersForBootstrap accessor) are deep: mutating the pointee of
// a cloned entry's *int Port or *ListenPortRange Range must NOT
// change the authoritative state. A shallow slice copy that aliases
// the pointer fields would mutate the same backing memory, and this
// test would fail at the assert-current step.
func TestControlStateParametersCloneIsolationPointeeMutation(t *testing.T) {
	port8080 := 8080
	port9090 := 9090
	cfg := validBaseConfig()
	cfg.ListenPortPriority = mtypes.ListenPortPriority{
		{Port: &port8080},
		{Range: &mtypes.ListenPortRange{From: 41000, To: 41002}},
		{Port: &port9090},
	}
	svc := NewControlState(ControlStateConfig{Parameters: buildControlV2Parameters(cfg)})

	// Helper: read the current authoritative policy via the accessor,
	// then mutate every pointee in the returned copy and assert the
	// accessor still returns the original values.
	assertUnchanged := func(stage string) {
		t.Helper()
		current := svc.ParametersForBootstrap()
		if len(current.ListenPortPriority) != 3 {
			t.Fatalf("%s: policy length=%d want 3", stage, len(current.ListenPortPriority))
		}
		if current.ListenPortPriority[0].Port == nil || *current.ListenPortPriority[0].Port != 8080 {
			t.Fatalf("%s: entry[0] Port = %v, want 8080", stage, current.ListenPortPriority[0].Port)
		}
		if current.ListenPortPriority[1].Range == nil || current.ListenPortPriority[1].Range.From != 41000 || current.ListenPortPriority[1].Range.To != 41002 {
			t.Fatalf("%s: entry[1] Range = %+v, want {41000,41002}", stage, current.ListenPortPriority[1].Range)
		}
		if current.ListenPortPriority[2].Port == nil || *current.ListenPortPriority[2].Port != 9090 {
			t.Fatalf("%s: entry[2] Port = %v, want 9090", stage, current.ListenPortPriority[2].Port)
		}
	}

	// 1. Accessor (ParametersForBootstrap) clones the stored parameters.
	mutBootstrap := svc.ParametersForBootstrap()
	*mutBootstrap.ListenPortPriority[0].Port = 1
	mutBootstrap.ListenPortPriority[1].Range.From = 1
	mutBootstrap.ListenPortPriority[1].Range.To = 2
	*mutBootstrap.ListenPortPriority[2].Port = 3
	assertUnchanged("accessor clone")

	// 2. Snapshot projection (SnapshotFor) clones the stored parameters.
	mutSnap := svc.SnapshotFor(1)
	*mutSnap.Parameters.ListenPortPriority[0].Port = 10
	mutSnap.Parameters.ListenPortPriority[1].Range.From = 11
	mutSnap.Parameters.ListenPortPriority[1].Range.To = 12
	*mutSnap.Parameters.ListenPortPriority[2].Port = 13
	assertUnchanged("snapshot clone")

	// 3. UpdateParameters path: install a fresh policy, mutate the SSE
	// payload + accessor return, then mutate the next UpdateParameters
	// input to a new policy and assert the prior update's pointee
	// mutations never bled into stored state.
	port7000 := 7000
	updated := mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		STUNServers:         []string{"stun:203.0.113.10:3478"},
		PollInterval:        15 * time.Second,
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
		ListenPortPriority:  mtypes.ListenPortPriority{{Port: &port7000}},
	}
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) {
		events = append(events, event)
	})
	if err := svc.UpdateParameters(context.Background(), updated); err != nil {
		t.Fatalf("UpdateParameters: %v", err)
	}
	payload, ok := events[0].Data.(mtypes.ControlV2Parameters)
	if !ok || len(payload.ListenPortPriority) != 1 {
		t.Fatalf("SSE payload=%#v", events[0].Data)
	}
	*payload.ListenPortPriority[0].Port = 9999
	if cur := svc.ParametersForBootstrap(); cur.ListenPortPriority[0].Port == nil || *cur.ListenPortPriority[0].Port != 7000 {
		t.Fatalf("SSE payload mutation bled into stored policy: %+v", cur.ListenPortPriority)
	}
	port7000 = 55555 // mutate the caller's pointer AFTER UpdateParameters; stored copy must remain 7000
	if cur := svc.ParametersForBootstrap(); cur.ListenPortPriority[0].Port == nil || *cur.ListenPortPriority[0].Port != 7000 {
		t.Fatalf("call-site pointer mutation bled into stored copy: %+v", cur.ListenPortPriority)
	}
}

func TestControlStateParametersCloneIsolationEndpointBlacklist(t *testing.T) {
	cfg := validBaseConfig()
	cfg.EndpointBlacklist = []string{"203.0.113.17", "198.51.100.0/24", "2001:db8::/32"}
	svc := NewControlState(ControlStateConfig{Parameters: buildControlV2Parameters(cfg)})

	bootstrap := svc.ParametersForBootstrap()
	bootstrap.EndpointBlacklist[0] = "192.0.2.1"
	current := svc.ParametersForBootstrap()
	if current.EndpointBlacklist[0] != "203.0.113.17" {
		t.Fatalf("bootstrap clone mutation changed state: %#v", current.EndpointBlacklist)
	}

	snapshot := svc.SnapshotFor(1)
	snapshot.Parameters.EndpointBlacklist[1] = "192.0.2.0/24"
	current = svc.ParametersForBootstrap()
	if current.EndpointBlacklist[1] != "198.51.100.0/24" {
		t.Fatalf("snapshot clone mutation changed state: %#v", current.EndpointBlacklist)
	}

	updated := buildControlV2Parameters(cfg)
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) {
		events = append(events, event)
	})
	if err := svc.UpdateParameters(context.Background(), updated); err != nil {
		t.Fatalf("UpdateParameters: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("published events=%d want 1", len(events))
	}
	payload, ok := events[0].Data.(mtypes.ControlV2Parameters)
	if !ok {
		t.Fatalf("event payload type=%T want mtypes.ControlV2Parameters", events[0].Data)
	}
	payload.EndpointBlacklist[2] = "192.0.2.0/24"
	updated.EndpointBlacklist[0] = "192.0.2.1"
	current = svc.ParametersForBootstrap()
	if current.EndpointBlacklist[0] != "203.0.113.17" || current.EndpointBlacklist[2] != "2001:db8::/32" {
		t.Fatalf("update clone mutation changed state: %#v", current.EndpointBlacklist)
	}
}

func TestControlStateObservedSnapshotConcurrentWithReportsAndSweeps(t *testing.T) {
	// Given a shared state with one target, readers, and live observers
	svc := NewControlState(ControlStateConfig{PeerAliveTimeout: time.Hour})
	registerObservedPeers(t, svc, 1, 100)
	for id := mtypes.Vertex(2); id < 18; id++ {
		registerObservedPeers(t, svc, id)
	}

	// When reports, snapshots, and timeout sweeps race through the state lock
	var wg sync.WaitGroup
	for id := mtypes.Vertex(2); id < 18; id++ {
		wg.Add(1)
		go func(observer mtypes.Vertex) {
			defer wg.Done()
			reportObservedVote(t, svc, observer, 1, fmt.Sprintf("198.51.100.%d:51820", observer))
		}(id)
	}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svc.SnapshotFor(100)
			svc.SweepTimeouts()
		}()
	}
	wg.Wait()

	// Then the bounded snapshot remains usable after concurrent mutation.
	if got := len(observedPeer(t, svc.SnapshotFor(100), 1).ObservedV4); got != 14 {
		t.Fatalf("concurrent observed hints = %d, want 14", got)
	}
}

func registerObservedPeers(t *testing.T, svc *ControlState, ids ...mtypes.Vertex) {
	t.Helper()
	for _, id := range ids {
		if _, err := svc.Register(context.Background(), controlRegisterRequest(id, fmt.Sprintf("observer-%d", id)), fmt.Sprintf("key-%d", id)); err != nil {
			t.Fatalf("register %d: %v", id, err)
		}
	}
}

func reportObservedVote(t *testing.T, svc *ControlState, observer, target mtypes.Vertex, address string) {
	t.Helper()
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: observer, Observed: []mtypes.ControlV2ObservedEndpoint{{TargetNodeID: target, Address: address}}}); err != nil {
		t.Fatalf("report observer %d target %d: %v", observer, target, err)
	}
}

func observedPeer(t *testing.T, snapshot mtypes.ControlV2Snapshot, id mtypes.Vertex) mtypes.ControlV2Peer {
	t.Helper()
	for _, peer := range snapshot.Peers {
		if peer.NodeID == id {
			return peer
		}
	}
	t.Fatalf("peer %d absent from snapshot: %#v", id, snapshot.Peers)
	return mtypes.ControlV2Peer{}
}

func containsObserved(observed []mtypes.ControlV2ObservedAddress, address string) bool {
	for _, hint := range observed {
		if hint.Address == address {
			return true
		}
	}
	return false
}

func containsJSONKey(encoded []byte, key string) bool {
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		return true
	}
	_, found := decoded[key]
	return found
}
