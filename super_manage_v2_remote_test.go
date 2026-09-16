package main

import (
	"bytes"
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestManageRemoteRegistryAppliesAndPersists(t *testing.T) {
	// Given
	base := validClusterBaseConfig()
	mgr, state, _, dir := newClusterManageV2UnderTest(t, t.TempDir(), base, nil)
	beforeLocal := marshalLocalOnlyConfigForTest(t, mgr.Snapshot())
	version := ClusterVersion{HLC: state.hlc.Current() + 1, Origin: 2}
	entry := clusterRegistryEntry{
		NodeID:         202,
		NodeName:       "remote-202",
		ControlPSKey:   "remote-key-202",
		AdditionalCost: 17,
		Version:        version,
		Origin:         2,
	}

	// When
	if err := mgr.ApplyRemoteRegistry(entry, 2); err != nil {
		t.Fatalf("ApplyRemoteRegistry: %v", err)
	}

	// Then
	superConfig := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if len(superConfig.Peers) != 1 || superConfig.Peers[0].NodeID != 202 {
		t.Fatalf("super.yaml peers = %#v, want remote node 202", superConfig.Peers)
	}
	if _, err := os.Stat(filepath.Join(dir, "edge_202.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("remote apply created an edge profile: %v", err)
	}
	afterLocal := marshalLocalOnlyConfigForTest(t, mgr.Snapshot())
	if !bytes.Equal(beforeLocal, afterLocal) {
		t.Fatalf("remote registry apply changed local-only config\nbefore:\n%s\nafter:\n%s", beforeLocal, afterLocal)
	}
	if key, ok := state.ControlKeyFor(202); !ok || key != "remote-key-202" {
		t.Fatalf("ControlKeyFor(202) = (%q, %v)", key, ok)
	}
}

func TestClusterStateRestartKeepsTombstone(t *testing.T) {
	// Given
	dir := t.TempDir()
	base := validClusterBaseConfig()
	mgr, state, _, _ := newClusterManageV2UnderTest(t, dir, base, nil)
	mgr.pskGen = fixedPSKSource("restart-key-101")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 101, NodeName: "edge-101"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := mgr.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 101}); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	state.DrainOutbox()
	reloadedBase := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	restarted, restartedState, _, _ := newClusterManageV2UnderTest(t, dir, reloadedBase, nil)
	tombstone, ok := restartedState.RegistryVersion(101)
	if !ok || tombstone.HLC == 0 {
		t.Fatalf("restarted RegistryVersion(101) = (%#v, %v), want persisted tombstone", tombstone, ok)
	}
	older := tombstone
	older.HLC--

	// When
	err := restarted.ApplyRemoteRegistry(clusterRegistryEntry{
		NodeID:         101,
		NodeName:       "stale-edge-101",
		ControlPSKey:   "stale-key",
		AdditionalCost: 10,
		Version:        older,
		Origin:         older.Origin,
	}, 2)

	// Then
	if err != nil {
		t.Fatalf("older remote registry apply returned error: %v", err)
	}
	if len(restarted.Snapshot().Peers) != 0 {
		t.Fatalf("older registry entry revived peer: %#v", restarted.Snapshot().Peers)
	}
	if key, ok := restartedState.ControlKeyFor(101); ok {
		t.Fatalf("older registry entry restored key %q", key)
	}
	if got, ok := restartedState.RegistryVersion(101); !ok || got != tombstone {
		t.Fatalf("RegistryVersion(101) = (%#v, %v), want %#v", got, ok, tombstone)
	}
}

func TestClusterRegistryWriteFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}

	// Given
	dir := t.TempDir()
	mgr, state, _, _ := newClusterManageV2UnderTest(t, dir, validClusterBaseConfig(), nil)
	mgr.pskGen = fixedPSKSource("write-failure-key")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	// When
	_, addErr := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 301, NodeName: "edge-301"})

	// Then
	if addErr == nil {
		t.Fatal("AddPeer under read-only ConfigDir succeeded")
	}
	if key, ok := state.ControlKeyFor(301); ok {
		t.Fatalf("failed AddPeer committed key %q", key)
	}
	mutations, resync := state.DrainOutbox()
	if len(mutations) != 0 || resync {
		t.Fatalf("failed AddPeer outbox = %#v, resync=%v", mutations, resync)
	}
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed AddPeer left files: %#v", entries)
	}

	remoteVersion := ClusterVersion{HLC: state.hlc.Current() + 1, Origin: 2}
	remoteErr := mgr.ApplyRemoteRegistry(clusterRegistryEntry{
		NodeID:       302,
		NodeName:     "remote-302",
		ControlPSKey: "remote-key-302",
		Version:      remoteVersion,
		Origin:       2,
	}, 2)
	if remoteErr == nil {
		t.Fatal("ApplyRemoteRegistry under read-only ConfigDir succeeded")
	}
	mutations, resync = state.DrainOutbox()
	if len(mutations) != 0 || !resync {
		t.Fatalf("failed remote apply outbox = %#v, resync=%v, want resync", mutations, resync)
	}
}
