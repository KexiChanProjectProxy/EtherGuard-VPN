package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	graphpath "github.com/KusakabeSi/EtherGuard-VPN/path"
)

func TestClusterApplyPeerVisibleInSnapshot(t *testing.T) {
	// Given a target peer already known to this Super.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	state.ApplyReplicatedPeer(replicaTestPeer(now, 102, 1), 2)
	record := replicaTestPeer(now, 101, 2)
	record.Candidates = []mtypes.ControlV2Candidate{
		{Address: "10.0.0.101:51820", Source: mtypes.ControlV2CandidateLocal},
		{Address: "198.51.100.101:51820", Source: mtypes.ControlV2CandidateSTUN},
	}
	record.Observed = []mtypes.ControlV2ObservedEndpoint{{TargetNodeID: 102, Address: "203.0.113.102:51820"}}

	// When the remote record is applied.
	if !state.ApplyReplicatedPeer(record, 2) {
		t.Fatal("replicated peer was not applied")
	}

	// Then snapshots expose its candidates and its observed-endpoint vote.
	peer101 := replicaSnapshotPeer(t, state.SnapshotFor(102), 101)
	if !reflect.DeepEqual(peer101.LocalV4, []string{"10.0.0.101:51820"}) || !reflect.DeepEqual(peer101.PublicV4, []string{"198.51.100.101:51820"}) {
		t.Fatalf("replicated candidates = local %#v public %#v", peer101.LocalV4, peer101.PublicV4)
	}
	peer102 := replicaSnapshotPeer(t, state.SnapshotFor(103), 102)
	if len(peer102.ObservedV4) != 1 || peer102.ObservedV4[0].Address != "203.0.113.102:51820" || peer102.ObservedV4[0].ReporterCount != 1 {
		t.Fatalf("replicated observed hint = %#v", peer102.ObservedV4)
	}
}

func TestClusterApplyBatchOneRevisionOneEvent(t *testing.T) {
	// Given an empty state with a counting publish hook.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	var events []mtypes.ControlV2Event
	state := newReplicaTestState(now, func(event mtypes.ControlV2Event) { events = append(events, event) })
	live := make([]clusterPeerRecord, 50)
	for i := range live {
		live[i] = replicaTestPeer(now, mtypes.Vertex(100+i), uint64(i+1))
	}

	// When the full batch is merged.
	if applied := state.ApplyReplicatedBatch(live, nil, 2); applied != len(live) {
		t.Fatalf("applied count = %d, want %d", applied, len(live))
	}

	// Then the whole batch produces one revision and one aggregate event.
	if state.Revision() != 1 || len(events) != 1 {
		t.Fatalf("batch revision/events = %d/%d, want 1/1", state.Revision(), len(events))
	}
	if events[0].Type != mtypes.ControlV2EventRevision || events[0].Revision != 1 {
		t.Fatalf("batch event = %#v", events[0])
	}
	if payload, ok := events[0].Data.(mtypes.ControlV2PeerChangePayload); !ok || payload != (mtypes.ControlV2PeerChangePayload{}) {
		t.Fatalf("batch payload = %#v", events[0].Data)
	}
	mutations, resync := state.DrainOutbox()
	if resync || len(mutations) != len(live) {
		t.Fatalf("batch outbox = %d mutations, resync=%v", len(mutations), resync)
	}
	for _, mutation := range mutations {
		if mutation.FromLink != 2 {
			t.Fatalf("batch mutation FromLink = %d, want 2", mutation.FromLink)
		}
	}
}

func TestClusterApplyDeleteThenOlderUpsertIgnored(t *testing.T) {
	// Given a peer deleted at V2.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	v1 := replicaTestPeer(now, 101, 1)
	if !state.ApplyReplicatedPeer(v1, 2) {
		t.Fatal("initial peer was not applied")
	}
	v2 := clusterDelete{NodeID: 101, Version: replicaTestVersion(now, 2, 2)}
	if !state.ApplyReplicatedDelete(v2, 2) {
		t.Fatal("replicated delete was not applied")
	}

	// When the older upsert is replayed.
	if state.ApplyReplicatedPeer(v1, 2) {
		t.Fatal("older upsert resurrected a tombstoned peer")
	}

	// Then the tombstone remains and the record stays absent.
	if state.liveTombstones[101] != v2.Version || replicaHasPeer(state.SnapshotFor(103), 101) {
		t.Fatalf("delete state = tombstone %#v snapshot %#v", state.liveTombstones[101], state.SnapshotFor(103).Peers)
	}
}

func TestClusterReplayIdempotent(t *testing.T) {
	// Given a record with latency and an observed vote applied once.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	graph, err := graphpath.NewGraph(4, true, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("new graph: %v", err)
	}
	var events []mtypes.ControlV2Event
	state := NewControlState(ControlStateConfig{SelfID: 1, Graph: graph, PeerAliveTimeout: time.Minute, Now: func() time.Time { return now }, Publish: func(event mtypes.ControlV2Event) { events = append(events, event) }})
	state.ApplyReplicatedPeer(replicaTestPeer(now, 102, 1), 2)
	record := replicaTestPeer(now, 101, 2)
	record.LatencyMS = map[mtypes.Vertex]float64{102: 7.5}
	record.Observed = []mtypes.ControlV2ObservedEndpoint{{TargetNodeID: 102, Address: "203.0.113.102:51820"}}
	if !state.ApplyReplicatedPeer(record, 2) {
		t.Fatal("initial record was not applied")
	}
	revision := state.Revision()
	eventCount := len(events)
	hint := replicaSnapshotPeer(t, state.SnapshotFor(103), 102).ObservedV4
	state.DrainOutbox()
	graph.Vert = nil // Any second UpdateLatency call would panic on assignment.

	// When the exact same record is replayed.
	if state.ApplyReplicatedPeer(record, 2) {
		t.Fatal("duplicate record reported applied")
	}

	// Then no observable state, event, vote, or graph update is repeated.
	if state.Revision() != revision || len(events) != eventCount {
		t.Fatalf("duplicate changed revision/events: %d/%d", state.Revision(), len(events))
	}
	if got := replicaSnapshotPeer(t, state.SnapshotFor(103), 102).ObservedV4; !reflect.DeepEqual(got, hint) || len(got) != 1 || got[0].ReporterCount != 1 {
		t.Fatalf("duplicate changed observed votes: before %#v after %#v", hint, got)
	}
	if mutations, resync := state.DrainOutbox(); resync || len(mutations) != 0 {
		t.Fatalf("duplicate appended outbox mutations: %#v, resync=%v", mutations, resync)
	}
}

func TestClusterApplyOlderVersionRejected(t *testing.T) {
	// Given V2 is already visible.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	v2 := replicaTestPeer(now, 101, 2)
	v2.NodeName = "newer"
	state.ApplyReplicatedPeer(v2, 2)
	revision := state.Revision()
	v1 := replicaTestPeer(now, 101, 1)
	v1.NodeName = "older"

	// When V1 arrives after V2.
	if state.ApplyReplicatedPeer(v1, 2) {
		t.Fatal("older version reported applied")
	}

	// Then the V2 view and revision are unchanged.
	if got := replicaSnapshotPeer(t, state.SnapshotFor(103), 101).NodeName; got != "newer" || state.Revision() != revision {
		t.Fatalf("older apply left name/revision = %q/%d", got, state.Revision())
	}
}

func TestClusterApplyAliveOnlyForSameOrigin(t *testing.T) {
	// Given a peer owned by origin 2.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	state.ApplyReplicatedPeer(replicaTestPeer(now, 101, 1), 2)
	revision := state.Revision()
	lastSeen := replicaSnapshotPeer(t, state.SnapshotFor(103), 101).LastSeen

	// When an alive claim from a different origin, and one for a missing peer, arrive.
	wrongOrigin := clusterAlive{NodeID: 101, Version: replicaTestVersion(now, 2, 3), LastSeen: now.Add(time.Minute)}
	if state.ApplyReplicatedAlive(wrongOrigin, 3) || state.ApplyReplicatedAlive(clusterAlive{NodeID: 104, Version: replicaTestVersion(now, 2, 2), LastSeen: now}, 2) {
		t.Fatal("alive without an existing same-origin record was applied")
	}

	// Then neither claim mutates the record or revision.
	if got := replicaSnapshotPeer(t, state.SnapshotFor(103), 101).LastSeen; !got.Equal(lastSeen) || state.Revision() != revision {
		t.Fatalf("rejected alive changed last_seen/revision = %v/%d", got, state.Revision())
	}
}

func TestClusterApplyAliveUpdatesWithoutRevision(t *testing.T) {
	// Given a peer owned by origin 2.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	state.ApplyReplicatedPeer(replicaTestPeer(now, 101, 1), 2)
	revision := state.Revision()
	alive := clusterAlive{NodeID: 101, Version: replicaTestVersion(now, 2, 2), LastSeen: now.Add(time.Minute)}

	// When a newer same-origin heartbeat arrives.
	if !state.ApplyReplicatedAlive(alive, 2) {
		t.Fatal("same-origin alive was not applied")
	}

	// Then LastSeen advances without a revision or publish event.
	if got := replicaSnapshotPeer(t, state.SnapshotFor(103), 101).LastSeen; !got.Equal(alive.LastSeen) || state.Revision() != revision {
		t.Fatalf("alive last_seen/revision = %v/%d", got, state.Revision())
	}
	mutations, resync := state.DrainOutbox()
	if resync || len(mutations) != 2 || mutations[1].Kind != clusterMessagePeerAlive || mutations[1].FromLink != 2 {
		t.Fatalf("alive outbox = %#v, resync=%v", mutations, resync)
	}
}

func TestClusterApplyDeleteWithoutRecordKeepsTombstone(t *testing.T) {
	// Given an empty state.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	deleted := clusterDelete{NodeID: 101, Version: replicaTestVersion(now, 1, 2)}

	// When a new remote tombstone arrives without a live record.
	if !state.ApplyReplicatedDelete(deleted, 2) {
		t.Fatal("new tombstone was not applied")
	}

	// Then it is retained and forwarded without a snapshot revision.
	_, tombstones := state.ExportLive()
	if state.Revision() != 0 || !reflect.DeepEqual(tombstones, []clusterDelete{deleted}) {
		t.Fatalf("tombstone export/revision = %#v/%d", tombstones, state.Revision())
	}
	mutations, resync := state.DrainOutbox()
	if resync || len(mutations) != 1 || mutations[0].Kind != clusterMessagePeerDelete || mutations[0].FromLink != 2 {
		t.Fatalf("delete outbox = %#v, resync=%v", mutations, resync)
	}
}

func TestClusterApplyExportLiveDeepCopiesAllOrigins(t *testing.T) {
	// Given one local-origin record, one remote-origin record, and a tombstone.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := newReplicaTestState(now, nil)
	local := replicaTestPeer(now, 101, 1)
	local.Origin, local.Version.Origin = 1, 1
	remote := replicaTestPeer(now, 102, 2)
	remote.Candidates = []mtypes.ControlV2Candidate{{Address: "198.51.100.102:51820", Source: mtypes.ControlV2CandidateSTUN}}
	state.ApplyReplicatedPeer(local, 1)
	state.ApplyReplicatedPeer(remote, 2)
	state.ApplyReplicatedDelete(clusterDelete{NodeID: 103, Version: replicaTestVersion(now, 3, 2)}, 2)

	// When live state is exported and the returned data is mutated.
	live, tombstones := state.ExportLive()
	if len(live) != 2 || len(tombstones) != 1 {
		t.Fatalf("export sizes = %d live, %d tombstones", len(live), len(tombstones))
	}
	live[1].Candidates[0].Address = "192.0.2.1:1"
	live[1].LatencyMS[999] = 99
	tombstones[0].Version = ClusterVersion{}

	// Then a later export is complete, sorted, and unaliased.
	again, againTombstones := state.ExportLive()
	if again[0].NodeID != 101 || again[1].NodeID != 102 || again[1].Candidates[0].Address != "198.51.100.102:51820" || len(again[1].LatencyMS) != 0 {
		t.Fatalf("live export aliases or order differs: %#v", again)
	}
	if againTombstones[0].Version.IsZero() {
		t.Fatalf("tombstone export aliases state: %#v", againTombstones)
	}
}

func newReplicaTestState(now time.Time, publish func(mtypes.ControlV2Event)) *ControlState {
	return NewControlState(ControlStateConfig{SelfID: 1, PeerAliveTimeout: time.Minute, Now: func() time.Time { return now }, Publish: publish})
}

func replicaTestVersion(now time.Time, logical uint64, origin mtypes.Vertex) ClusterVersion {
	return ClusterVersion{HLC: hlcFromWallMS(uint64(now.UnixMilli())) + logical, Origin: origin}
}

func replicaTestPeer(now time.Time, nodeID mtypes.Vertex, logical uint64) clusterPeerRecord {
	return clusterPeerRecord{
		NodeID: nodeID, NodeName: "edge-" + nodeID.ToString(), PubKey: "pub-" + nodeID.ToString(),
		LatencyMS: map[mtypes.Vertex]float64{}, LastSeen: now, Version: replicaTestVersion(now, logical, 2), Origin: 2,
	}
}

func replicaSnapshotPeer(t *testing.T, snapshot mtypes.ControlV2Snapshot, nodeID mtypes.Vertex) mtypes.ControlV2Peer {
	t.Helper()
	for _, peer := range snapshot.Peers {
		if peer.NodeID == nodeID {
			return peer
		}
	}
	t.Fatalf("peer %d missing from snapshot %#v", nodeID, snapshot.Peers)
	return mtypes.ControlV2Peer{}
}

func replicaHasPeer(snapshot mtypes.ControlV2Snapshot, nodeID mtypes.Vertex) bool {
	for _, peer := range snapshot.Peers {
		if peer.NodeID == nodeID {
			return true
		}
	}
	return false
}
