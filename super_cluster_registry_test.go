package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestClusterRegistryLWW(t *testing.T) {
	// Given
	state := NewControlState(ControlStateConfig{SelfID: 1})
	nodeID := mtypes.Vertex(101)
	v1 := ClusterVersion{HLC: 1, Origin: 1}
	v2 := ClusterVersion{HLC: 2, Origin: 1}

	// When
	if !state.CommitRegistry(clusterRegistryEntry{NodeID: nodeID, ControlPSKey: "key-v2", Version: v2, Origin: 1}, 0) {
		t.Fatal("newer registry commit was rejected")
	}
	if state.CommitRegistry(clusterRegistryEntry{NodeID: nodeID, ControlPSKey: "key-v1", Version: v1, Origin: 1}, 0) {
		t.Fatal("older registry commit was accepted")
	}

	// Then
	if key, ok := state.ControlKeyFor(nodeID); !ok || key != "key-v2" {
		t.Fatalf("ControlKeyFor(%d) = (%q, %v), want key-v2", nodeID, key, ok)
	}
	if version, ok := state.RegistryVersion(nodeID); !ok || version != v2 {
		t.Fatalf("RegistryVersion(%d) = (%#v, %v), want (%#v, true)", nodeID, version, ok, v2)
	}
}

func TestClusterRegistryRotationUpdatesActiveKey(t *testing.T) {
	// Given
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{SelfID: 1, Now: clock.Now})
	const (
		nodeID mtypes.Vertex = 101
		keyV1                = "control-key-v1"
		keyV2                = "control-key-v2"
	)
	if _, err := state.Register(context.Background(), controlRegisterRequest(nodeID, "edge-101"), keyV1); err != nil {
		t.Fatalf("register: %v", err)
	}
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	version := ClusterVersion{HLC: state.hlc.Next(), Origin: 1}

	// When
	if !state.CommitRegistry(clusterRegistryEntry{
		NodeID:       nodeID,
		NodeName:     "edge-101",
		ControlPSKey: keyV2,
		Version:      version,
		Origin:       1,
	}, 0) {
		t.Fatal("key rotation was rejected")
	}

	// Then
	if key, ok := state.ControlKeyFor(nodeID); !ok || key != keyV2 {
		t.Fatalf("ControlKeyFor(%d) = (%q, %v), want key-v2", nodeID, key, ok)
	}
	state.mu.RLock()
	cachedKey := state.peers[nodeID].controlKey
	state.mu.RUnlock()
	if cachedKey != keyV2 {
		t.Fatalf("active cached key = %q, want %q", cachedKey, keyV2)
	}
	oldRequest := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, keyV1, clock)
	if _, _, err := auth.Verify(oldRequest); err == nil {
		t.Fatal("request signed with the rotated-out key was accepted")
	}
	newRequest := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, keyV2, clock)
	if _, _, err := auth.Verify(newRequest); err != nil {
		t.Fatalf("request signed with the rotated key failed: %v", err)
	}
}

func TestClusterNameConflictConverges(t *testing.T) {
	// Given
	newState := func(t *testing.T) *ControlState {
		t.Helper()
		state := NewControlState(ControlStateConfig{SelfID: 1})
		for _, nodeID := range []mtypes.Vertex{101, 102} {
			if _, err := state.Register(context.Background(), controlRegisterRequest(nodeID, "initial"), "key"); err != nil {
				t.Fatalf("register %d: %v", nodeID, err)
			}
		}
		return state
	}
	entries := map[mtypes.Vertex]clusterRegistryEntry{
		101: {NodeID: 101, NodeName: "edge-shared", ControlPSKey: "key-101", Version: ClusterVersion{HLC: 1, Origin: 1}, Origin: 1},
		102: {NodeID: 102, NodeName: "edge-shared", ControlPSKey: "key-102", Version: ClusterVersion{HLC: 2, Origin: 1}, Origin: 1},
	}
	stateA := newState(t)
	stateB := newState(t)

	// When
	for _, nodeID := range []mtypes.Vertex{101, 102} {
		if !stateA.CommitRegistry(entries[nodeID], 0) {
			t.Fatalf("state A commit %d was rejected", nodeID)
		}
	}
	for _, nodeID := range []mtypes.Vertex{102, 101} {
		if !stateB.CommitRegistry(entries[nodeID], 0) {
			t.Fatalf("state B commit %d was rejected", nodeID)
		}
	}

	// Then
	want := map[mtypes.Vertex]string{101: "edge-shared", 102: "edge-shared~102"}
	for label, state := range map[string]*ControlState{"A": stateA, "B": stateB} {
		got := snapshotNodeNames(state.SnapshotFor(1))
		for nodeID, wantName := range want {
			if got[nodeID] != wantName {
				t.Fatalf("state %s node %d name = %q, want %q; all=%#v", label, nodeID, got[nodeID], wantName, got)
			}
		}
	}
}

func TestClusterRegistryRevokeDeletesActiveAndTombstones(t *testing.T) {
	// Given
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	var events []mtypes.ControlV2Event
	state := NewControlState(ControlStateConfig{SelfID: 7, Now: func() time.Time { return now }})
	nodeID := mtypes.Vertex(101)
	v1 := ClusterVersion{HLC: 1, Origin: 7}
	v2 := ClusterVersion{HLC: 2, Origin: 7}
	entry := clusterRegistryEntry{NodeID: nodeID, NodeName: "edge-101", ControlPSKey: "key-v1", Version: v1, Origin: 7}
	if !state.CommitRegistry(entry, 0) {
		t.Fatal("initial registry commit was rejected")
	}
	if _, err := state.Register(context.Background(), controlRegisterRequest(nodeID, "edge-101"), "key-v1"); err != nil {
		t.Fatalf("register: %v", err)
	}
	state.DrainOutbox()
	state.SetPublishForTest(func(event mtypes.ControlV2Event) { events = append(events, event) })

	// When
	if !state.RevokeRegistry(nodeID, v2, 0) {
		t.Fatal("newer registry revoke was rejected")
	}
	if state.CommitRegistry(entry, 0) {
		t.Fatal("older registry commit was accepted after revoke")
	}

	// Then
	if _, ok := state.peers[nodeID]; ok {
		t.Fatal("active peer survived registry revoke")
	}
	if key, ok := state.ControlKeyFor(nodeID); ok {
		t.Fatalf("revoked key still resolves: %q", key)
	}
	if version, ok := state.RegistryVersion(nodeID); !ok || version != v2 {
		t.Fatalf("RegistryVersion(%d) = (%#v, %v), want tombstone %#v", nodeID, version, ok, v2)
	}
	if state.registryTombstones[nodeID] != v2 || state.liveTombstones[nodeID] != v2 {
		t.Fatalf("tombstones = registry %#v live %#v, want %#v", state.registryTombstones[nodeID], state.liveTombstones[nodeID], v2)
	}
	mutations, resync := state.DrainOutbox()
	if resync || len(mutations) != 1 || mutations[0].Kind != clusterMessageRegistryDelete || mutations[0].Version != v2 {
		t.Fatalf("revoke outbox = %#v, resync=%v", mutations, resync)
	}
	if len(events) != 1 || events[0].Type != mtypes.ControlV2EventPeerGone {
		t.Fatalf("revoke events = %#v, want one peer_gone", events)
	}
}

func snapshotNodeNames(snapshot mtypes.ControlV2Snapshot) map[mtypes.Vertex]string {
	names := make(map[mtypes.Vertex]string, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		names[peer.NodeID] = peer.NodeName
	}
	return names
}
