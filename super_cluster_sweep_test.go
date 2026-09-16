package main

import (
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestClusterSweepRemoteOriginRetainedWhileLinkUp(t *testing.T) {
	// Given
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	state := NewControlState(ControlStateConfig{
		SelfID:           1,
		PeerAliveTimeout: 10 * time.Second,
		RemoteStaleGrace: time.Minute,
		Now:              func() time.Time { return now },
	})
	installRemoteSweepPeer(state, 101, 2, now)
	state.SetOriginLinkStatus(2, true, now)

	// When
	now = now.Add(10 * state.peerAliveTimeout)
	removed := state.SweepTimeouts()

	// Then
	if removed != 0 {
		t.Fatalf("SweepTimeouts removed %d remote peers while the origin link was up", removed)
	}
	if !snapshotHasPeer(state.SnapshotFor(1), 101) {
		t.Fatal("remote-origin peer disappeared while its origin link was up")
	}
}

func TestClusterSweepRemoteOriginEvictedAfterGrace(t *testing.T) {
	// Given
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	var events []mtypes.ControlV2Event
	state := NewControlState(ControlStateConfig{
		SelfID:           1,
		PeerAliveTimeout: 10 * time.Second,
		RemoteStaleGrace: time.Minute,
		Now:              func() time.Time { return now },
		Publish:          func(event mtypes.ControlV2Event) { events = append(events, event) },
	})
	installRemoteSweepPeer(state, 101, 2, now)
	state.SetOriginLinkStatus(2, false, now)

	// When
	now = now.Add(state.remoteStaleGrace + time.Second)
	removed := state.SweepTimeouts()

	// Then
	if removed != 1 {
		t.Fatalf("SweepTimeouts removed %d peers, want 1", removed)
	}
	if snapshotHasPeer(state.SnapshotFor(1), 101) {
		t.Fatal("remote-origin peer survived beyond the stale grace")
	}
	mutations, resync := state.DrainOutbox()
	if resync {
		t.Fatal("grace eviction requested a full resync")
	}
	for _, mutation := range mutations {
		if mutation.Kind == clusterMessagePeerDelete && mutation.NodeID == 101 {
			t.Fatalf("grace eviction emitted a peer_delete mutation: %#v", mutation)
		}
	}
	if len(events) != 1 || events[0].Type != mtypes.ControlV2EventPeerGone {
		t.Fatalf("grace eviction events = %#v, want exactly one peer_gone", events)
	}
}

func installRemoteSweepPeer(state *ControlState, nodeID, origin mtypes.Vertex, receivedAt time.Time) {
	state.mu.Lock()
	state.peers[nodeID] = &controlPeerRecord{
		view: mtypes.ControlV2Peer{
			NodeID:    nodeID,
			NodeName:  "remote-edge",
			LatencyMS: map[mtypes.Vertex]float64{},
			LastSeen:  receivedAt,
		},
		controlKey: "remote-key",
		origin:     origin,
		version:    ClusterVersion{HLC: 1, Origin: origin},
		receivedAt: receivedAt,
	}
	state.mu.Unlock()
}

func snapshotHasPeer(snapshot mtypes.ControlV2Snapshot, nodeID mtypes.Vertex) bool {
	for _, peer := range snapshot.Peers {
		if peer.NodeID == nodeID {
			return true
		}
	}
	return false
}
