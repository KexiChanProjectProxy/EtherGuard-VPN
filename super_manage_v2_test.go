/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

// yamlUnmarshalLocal is a thin wrapper around yaml.Unmarshal for tests;
// kept here because the matching mtypes.yamlUnmarshalImpl is unexported.
func yamlUnmarshalLocal(data []byte, out interface{}) error {
	return yaml.Unmarshal(data, out)
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// countingPublish is a Publish closure that records every event sent through
// it for later assertion. Designed for the "exactly one event per mutation"
// contract.
type countingPublish struct {
	mu  sync.Mutex
	all []mtypes.ControlV2Event
}

func (p *countingPublish) hook(ev mtypes.ControlV2Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.all = append(p.all, ev)
}

func (p *countingPublish) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.all)
}

func (p *countingPublish) last() mtypes.ControlV2Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.all) == 0 {
		return mtypes.ControlV2Event{}
	}
	return p.all[len(p.all)-1]
}

// validBaseConfig returns a fully-validated SuperConfigV2 to use as the
// starting point for management tests. Each test gets a copy.
func validBaseConfig() mtypes.SuperConfigV2 {
	return mtypes.SuperConfigV2{
		NodeName:  "super-test",
		APIUrl:    "http://127.0.0.1:3000",
		APIPrefix: mtypes.ControlV2APIPrefix,
		ManagementAuth: mtypes.SuperConfigV2ManagementAuth{
			User:         "admin",
			PasswordHash: "deadbeef" + string(mtypes.RandomStr(32, "salt")),
		},
		STUNServers:                []string{"stun:203.0.113.10:3478"},
		STUNRequestTimeoutSeconds:  3,
		STUNRefreshIntervalSeconds: 60,
		PollIntervalSeconds:        15,
		ReportIntervalSeconds:      15,
		HeartbeatIntervalSeconds:   10,
		EventReplay:                256,
		PeerAliveTimeoutSeconds:    70,
		UsePSKForInterEdge:         true,
		DampingFilterRadius:        4,
		Peers:                      []mtypes.SuperConfigV2Peer{},
	}
}

// validEdgeTemplate returns a minimal valid EdgeConfigV2 template. The
// management service clones + fills it for each AddPeer.
func validEdgeTemplate() mtypes.EdgeConfigV2 {
	return mtypes.EdgeConfigV2{
		Interface: mtypes.InterfaceConf{
			IType:         "tap",
			Name:          "tap",
			VPPIFaceID:    1,
			VPPBridgeID:   4242,
			MacAddrPrefix: "AA:BB:CC:DD",
			MTU:           1400,
			RecvAddr:      "127.0.0.1:4001",
			SendAddr:      "127.0.0.1:5001",
			L2HeaderMode:  "nochg",
		},
		NodeID:     1,
		NodeName:   "edge-template",
		DefaultTTL: 64,
		LogLevel: mtypes.LoggerInfo{
			LogLevel:    "error",
			LogControl:  true,
			LogInternal: true,
		},
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       "http://127.0.0.1:3000",
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: "_placeholder_",
		},
		Peers: []mtypes.PeerInfo{},
	}
}

// newManageV2UnderTest wires up a ManageV2 with a real ControlState, the
// supplied counter hook as the event publisher, and a t.TempDir as the
// config directory.
func newManageV2UnderTest(t *testing.T) (*ManageV2, *ControlState, *countingPublish, string) {
	t.Helper()
	pub := &countingPublish{}
	state := NewControlState(ControlStateConfig{Publish: pub.hook, Now: time.Now})
	dir := t.TempDir()
	base := validBaseConfig()
	mgr, err := NewManageV2(ManageV2Config{
		State:        state,
		ConfigDir:    dir,
		BaseConfig:   base,
		EdgeTemplate: validEdgeTemplate(),
	})
	if err != nil {
		t.Fatalf("NewManageV2: %v", err)
	}
	return mgr, state, pub, dir
}

// readSuperYAML decodes a SuperConfigV2 from path.
func readSuperYAML(t *testing.T, path string) mtypes.SuperConfigV2 {
	t.Helper()
	var out mtypes.SuperConfigV2
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yamlUnmarshalLocal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// readEdgeYAML decodes an EdgeConfigV2 from path.
func readEdgeYAML(t *testing.T, path string) mtypes.EdgeConfigV2 {
	t.Helper()
	var out mtypes.EdgeConfigV2
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := yamlUnmarshalLocal(data, &out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return out
}

// listDir returns the basenames in dir (non-recursive, sorted by name).
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// fixedPSKSource returns a closure that yields successive elements of psks
// on each call and panics on overflow. Lets tests avoid touching device's
// random source.
func fixedPSKSource(psks ...string) func() string {
	var counter atomic.Uint64
	return func() string {
		i := int(counter.Add(1)) - 1
		if i >= len(psks) {
			panic("fixedPSKSource exhausted")
		}
		return psks[i]
	}
}

// ---------------------------------------------------------------------------
// Acceptance tests — these are the contract surface for task 9.
// ---------------------------------------------------------------------------

// TestManageV2AddPeerWritesFreshProfiles — adding an Edge produces a
// viable Edge v2 profile with an isolated control PSKey (unique, not
// shared with other Edges).
func TestManageV2AddPeerWritesFreshProfiles(t *testing.T) {
	mgr, _, _, dir := newManageV2UnderTest(t)

	// Add two edges with deterministic, distinct PSKs.
	mgr.pskGen = fixedPSKSource("edge-one-key-fresh", "edge-two-key-fresh")

	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("AddPeer(1): %v", err)
	}
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 2, NodeName: "beta"}); err != nil {
		t.Fatalf("AddPeer(2): %v", err)
	}

	// super.yaml: both peers with their own PSKeys.
	superPath := filepath.Join(dir, "super.yaml")
	superConfig := readSuperYAML(t, superPath)
	if got := len(superConfig.Peers); got != 2 {
		t.Fatalf("super peers: got %d, want 2", got)
	}
	seen := map[mtypes.Vertex]string{}
	for _, p := range superConfig.Peers {
		seen[p.NodeID] = p.ControlPSKey
	}
	if seen[1] != "edge-one-key-fresh" {
		t.Fatalf("peer 1 key: got %q", seen[1])
	}
	if seen[2] != "edge-two-key-fresh" {
		t.Fatalf("peer 2 key: got %q", seen[2])
	}
	if seen[1] == seen[2] {
		t.Fatalf("two edges share the same control PSKey: %q", seen[1])
	}

	// edge_1.yaml: contains peer-1's PSKey in SuperNodeV2, and NOTHING
	// for peer-2.
	edge1 := readEdgeYAML(t, filepath.Join(dir, "edge_1.yaml"))
	if edge1.NodeID != 1 {
		t.Fatalf("edge1.NodeID: %v", edge1.NodeID)
	}
	if edge1.NodeName != "alpha" {
		t.Fatalf("edge1.NodeName: %q", edge1.NodeName)
	}
	if edge1.SuperNodeV2.ControlPSKey != "edge-one-key-fresh" {
		t.Fatalf("edge1 PSKey: got %q want %q", edge1.SuperNodeV2.ControlPSKey, "edge-one-key-fresh")
	}
	// edge_2.yaml: peer-2's key, NOT peer-1's.
	edge2 := readEdgeYAML(t, filepath.Join(dir, "edge_2.yaml"))
	if edge2.SuperNodeV2.ControlPSKey != "edge-two-key-fresh" {
		t.Fatalf("edge2 PSKey: got %q", edge2.SuperNodeV2.ControlPSKey)
	}
	if edge2.SuperNodeV2.ControlPSKey == edge1.SuperNodeV2.ControlPSKey {
		t.Fatalf("edge2 leaked edge1's PSKey: %q", edge2.SuperNodeV2.ControlPSKey)
	}

	// No legacy UDP fields should be present in any written file.
	data, _ := ioutil.ReadFile(superPath)
	for _, banned := range []string{"PrivKeyV4", "PrivKeyV6", "ListenPort", "FwMark", "API_Prefix", "ListenPort_EdgeAPI", "ListenPort_ManageAPI"} {
		if containsBytes(data, []byte(banned)) {
			t.Fatalf("super.yaml leaked legacy UDP field %q", banned)
		}
	}
}

// TestManageV2AddPeerDuplicateRejected — a duplicate NodeID is rejected
// without mutating state, files, or revision.
func TestManageV2AddPeerDuplicateRejected(t *testing.T) {
	mgr, state, pub, dir := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 7, NodeName: "alpha"}); err != nil {
		t.Fatalf("AddPeer(7): %v", err)
	}
	beforeRev := state.Revision()
	preEvents := pub.count()
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 7, NodeName: "alpha-dup"}); !errors.Is(err, ErrManageDuplicateNodeID) {
		t.Fatalf("AddPeer duplicate NodeID: want ErrManageDuplicateNodeID, got %v", err)
	}
	if state.Revision() != beforeRev {
		t.Fatalf("revision changed on rejected duplicate: %d -> %d", beforeRev, state.Revision())
	}
	if pub.count() != preEvents {
		t.Fatalf("events emitted on rejected duplicate: got %d, before %d", pub.count(), preEvents)
	}
	// super.yaml should still contain only one peer.
	sc := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if len(sc.Peers) != 1 {
		t.Fatalf("after rejected duplicate, peers=%d want 1", len(sc.Peers))
	}
}

// TestManageV2AddPeerNameDuplicateRejected — duplicate NodeName is rejected.
func TestManageV2AddPeerNameDuplicateRejected(t *testing.T) {
	mgr, _, _, _ := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "echo"}); err != nil {
		t.Fatalf("seed AddPeer: %v", err)
	}
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 2, NodeName: "echo"}); !errors.Is(err, ErrManageDuplicateNodeName) {
		t.Fatalf("AddPeer duplicate name: want ErrManageDuplicateNodeName, got %v", err)
	}
}

// TestManageV2AddPeerRejectsSpecialNodeID — reserved NodeIDs are rejected
// via typed v2 errors.
func TestManageV2AddPeerRejectsSpecialNodeID(t *testing.T) {
	for _, bad := range []mtypes.Vertex{mtypes.NodeID_Broadcast, mtypes.NodeID_Spread, mtypes.NodeID_SuperNode, mtypes.NodeID_Invalid} {
		mgr, _, _, _ := newManageV2UnderTest(t)
		_, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: bad, NodeName: "x"})
		if !mtypes.IsControlV2Error(err) {
			t.Fatalf("special NodeID %s: want ControlV2Error, got %v", bad.ToString(), err)
		}
		if mtypes.ErrorCode(err) != mtypes.ControlV2ErrInvalidNodeID {
			t.Fatalf("special NodeID %s: want code %q, got %q", bad.ToString(), mtypes.ControlV2ErrInvalidNodeID, mtypes.ErrorCode(err))
		}
	}
}

// TestManageV2AddPeerPublishesPeerChange — exactly one peer_change event
// fires for each successful AddPeer; revision bumps by exactly one.
func TestManageV2AddPeerPublishesPeerChange(t *testing.T) {
	mgr, state, pub, _ := newManageV2UnderTest(t)
	before := state.Revision()
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 4, NodeName: "delta"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	after := state.Revision()
	if after != before+1 {
		t.Fatalf("revision: got %d, want %d", after, before+1)
	}
	if pub.count() != 1 {
		t.Fatalf("events: got %d, want 1", pub.count())
	}
	last := pub.last()
	if last.Type != mtypes.ControlV2EventPeerChange {
		t.Fatalf("event type: got %q, want peer_change", last.Type)
	}
	if last.Revision != after {
		t.Fatalf("event revision: got %d, want %d", last.Revision, after)
	}
	payload, ok := last.Data.(mtypes.ControlV2PeerChangePayload)
	if !ok {
		t.Fatalf("event data type: got %T", last.Data)
	}
	if payload.NodeID != 4 || payload.NodeName != "delta" {
		t.Fatalf("event payload: %+v", payload)
	}
}

// TestManageV2UpdatePeerRotatesPSKey — operator-supplied ControlPSKey
// replaces the existing one; ControlKeyFor returns the new key.
func TestManageV2UpdatePeerRotatesPSKey(t *testing.T) {
	mgr, state, pub, _ := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 11, NodeName: "zulu"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	pub.mu.Lock()
	pub.all = pub.all[:0]
	pub.mu.Unlock()
	if err := mgr.UpdatePeer(context.Background(), ManageUpdatePeerRequest{NodeID: 11, ControlPSKey: "rotated-key-fresh"}); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if pub.count() != 1 {
		t.Fatalf("events: got %d, want 1 (peer_change)", pub.count())
	}
	if pub.last().Type != mtypes.ControlV2EventPeerChange {
		t.Fatalf("event type: %s", pub.last().Type)
	}
	got, ok := state.ControlKeyFor(11)
	if !ok || got != "rotated-key-fresh" {
		t.Fatalf("ControlKeyFor(11): (%q, %v)", got, ok)
	}
}

// TestManageV2UpdatePeerPSKeyMustDiffer — supplying the same key is a
// silent no-op for rotation purposes; it does NOT bump revision / publish
// an event for the unchanged control key.
func TestManageV2UpdatePeerPSKeyMustDiffer(t *testing.T) {
	mgr, state, pub, _ := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 12, NodeName: "yankee"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	pub.mu.Lock()
	pub.all = pub.all[:0]
	pub.mu.Unlock()
	prevRev := state.Revision()
	sameKey, _ := state.ControlKeyFor(12)
	if err := mgr.UpdatePeer(context.Background(), ManageUpdatePeerRequest{NodeID: 12, ControlPSKey: sameKey}); err != nil {
		t.Fatalf("UpdatePeer with same key: %v", err)
	}
	// Pure no-op: no new event expected.
	if pub.count() != 0 {
		t.Fatalf("events emitted on no-op UpdatePeer: got %d", pub.count())
	}
	if state.Revision() != prevRev {
		t.Fatalf("revision bumped on no-op: %d -> %d", prevRev, state.Revision())
	}
}

// TestManageV2UpdatePeerUnknownRejected — UpdatePeer for missing peer
// returns ErrManageUnknownPeer.
func TestManageV2UpdatePeerUnknownRejected(t *testing.T) {
	mgr, _, _, _ := newManageV2UnderTest(t)
	err := mgr.UpdatePeer(context.Background(), ManageUpdatePeerRequest{NodeID: 999})
	if !errors.Is(err, ErrManageUnknownPeer) {
		t.Fatalf("UpdatePeer(unknown): want ErrManageUnknownPeer, got %v", err)
	}
}

// TestManageV2DeletePeerRevokesAndPersists — delete removes from state,
// snapshot, file, and emits exactly one peer_gone.
func TestManageV2DeletePeerRevokesAndPersists(t *testing.T) {
	mgr, state, pub, dir := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 31, NodeName: "thirty-one"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	pub.mu.Lock()
	pub.all = pub.all[:0]
	pub.mu.Unlock()
	beforeRev := state.Revision()

	if err := mgr.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 31}); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}

	if got, ok := state.ControlKeyFor(31); ok {
		t.Fatalf("ControlKeyFor(31) after delete: (%q, true), want ('', false)", got)
	}
	if peers := state.SnapshotFor(99).Peers; len(peers) != 0 {
		t.Fatalf("deleted peer still appears in a fresh snapshot: %+v", peers)
	}
	if state.Revision() != beforeRev+1 {
		t.Fatalf("revision: got %d, want %d", state.Revision(), beforeRev+1)
	}
	if pub.count() != 1 || pub.last().Type != mtypes.ControlV2EventPeerGone {
		t.Fatalf("event: got count=%d last=%s", pub.count(), pub.last().Type)
	}

	superConfig := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	for _, p := range superConfig.Peers {
		if p.NodeID == 31 {
			t.Fatalf("super.yaml still contains the deleted peer: %+v", p)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "edge_31.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("edge file should be removed, got err=%v", err)
	}
}

// TestManageV2DeletePeerUnknownRejected — DeletePeer for missing peer is
// an error and does NOT touch state.
func TestManageV2DeletePeerUnknownRejected(t *testing.T) {
	mgr, state, pub, _ := newManageV2UnderTest(t)
	rev0 := state.Revision()
	err := mgr.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 999})
	if !errors.Is(err, ErrManageUnknownPeer) {
		t.Fatalf("DeletePeer(unknown): want ErrManageUnknownPeer, got %v", err)
	}
	if state.Revision() != rev0 {
		t.Fatalf("revision changed on rejected delete: %d -> %d", rev0, state.Revision())
	}
	if pub.count() != 0 {
		t.Fatalf("events on rejected delete: got %d", pub.count())
	}
}

// TestManageV2UpdateSTUNValidatesAndPersists — UpdateParameters with a
// valid STUN list persists; invalid STUN URI is rejected.
func TestManageV2UpdateSTUNValidatesAndPersists(t *testing.T) {
	mgr, _, pub, dir := newManageV2UnderTest(t)

	// Invalid STUN URI → typed error.
	pub.mu.Lock()
	pub.all = pub.all[:0]
	pub.mu.Unlock()
	bad := validParams()
	bad.STUNServers = []string{"http://not-stun.example/"}
	err := mgr.UpdateParameters(context.Background(), ManageUpdateParametersRequest{Parameters: bad})
	if !mtypes.IsControlV2Error(err) || mtypes.ErrorCode(err) != mtypes.ControlV2ErrInvalidSTUNServer {
		t.Fatalf("invalid STUN URI: want invalid_stun_server, got %v", err)
	}
	if pub.count() != 0 {
		t.Fatalf("events on rejected UpdateParameters: got %d", pub.count())
	}

	// Valid STUN → persisted and emitted.
	good := validParams()
	good.STUNServers = []string{"stun:198.51.100.20:3478", "stuns:[2001:db8::20]:5349"}
	if err := mgr.UpdateParameters(context.Background(), ManageUpdateParametersRequest{Parameters: good}); err != nil {
		t.Fatalf("UpdateParameters: %v", err)
	}
	if pub.count() != 1 {
		t.Fatalf("events: got %d, want 1 (params_change)", pub.count())
	}
	if pub.last().Type != mtypes.ControlV2EventParamsChange {
		t.Fatalf("event type: got %s, want params_change", pub.last().Type)
	}
	sc := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if len(sc.STUNServers) != 2 || sc.STUNServers[0] != "stun:198.51.100.20:3478" {
		t.Fatalf("STUNServers on disk: %v", sc.STUNServers)
	}
	if _, err := os.Stat(filepath.Join(dir, "super.yaml")); err != nil {
		t.Fatalf("super.yaml not on disk: %v", err)
	}
}

// TestManageV2AtomicWriteFailureLeavesPriorState — when the Super YAML
// cannot be written (simulated by making the config dir read-only mid-test
// is awkward; instead we inject a configDir that points at a read-only
// destination by passing an empty path through the helper after the
// initial dir has been removed). The state and on-disk files must remain
// at the last-known-good configuration.
func TestManageV2AtomicWriteFailureLeavesPriorState(t *testing.T) {
	mgr, _, _, dir := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 50, NodeName: "fifty"}); err != nil {
		t.Fatalf("seed AddPeer: %v", err)
	}
	before := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if len(before.Peers) != 1 {
		t.Fatalf("seed super peers: %d", len(before.Peers))
	}

	// Force a write failure by revoking write permission on the dir.
	// Skip on root-owned systems where chmod 0o555 is ineffective.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("chmod failed: %v (likely running as root)", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	_, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 51, NodeName: "fifty-one"})
	if err == nil {
		t.Fatal("AddPeer under read-only dir should fail")
	}

	// State must not contain the rejected peer (rolled back).
	if _, ok := mgr.state.ControlKeyFor(51); ok {
		t.Fatalf("rejected peer still in state")
	}
	// Filesystem stays at the prior good state.
	after := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if len(after.Peers) != 1 || after.Peers[0].NodeID != 50 {
		t.Fatalf("on-disk super.yaml after rejection: peers=%+v", after.Peers)
	}
}

// TestManageV2DeletePeerRemovesEdgeFile — after DeletePeer, the per-Edge
// file is removed (no orphan left behind).
func TestManageV2DeletePeerRemovesEdgeFile(t *testing.T) {
	mgr, _, _, dir := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 21, NodeName: "twenty-one"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "edge_21.yaml")); err != nil {
		t.Fatalf("edge_21.yaml missing after AddPeer: %v", err)
	}
	if err := mgr.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 21}); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "edge_21.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("edge_21.yaml should be gone, got err=%v", err)
	}
}

// TestManageV2SnapshotIsAuthorative — Snapshot() returns a copy of the
// current in-memory SuperConfigV2, not a reference.
func TestManageV2SnapshotIsAuthorative(t *testing.T) {
	mgr, _, _, _ := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 60, NodeName: "sixty"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	snap := mgr.Snapshot()
	if len(snap.Peers) != 1 || snap.Peers[0].NodeID != 60 {
		t.Fatalf("snapshot peers: %+v", snap.Peers)
	}
	// Mutating the returned slice must not affect future Snapshot() calls.
	snap.Peers[0].NodeID = 999
	snap2 := mgr.Snapshot()
	if snap2.Peers[0].NodeID != 60 {
		t.Fatalf("Snapshot leaked reference: %d", snap2.Peers[0].NodeID)
	}
}

// TestManageV2AllFilesAreV2Only — every YAML file written contains ONLY
// v2 fields (no PrivKeyV4/V6, ListenPort, FwMark, API_Prefix).
func TestManageV2AllFilesAreV2Only(t *testing.T) {
	mgr, _, _, dir := newManageV2UnderTest(t)
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 80, NodeName: "eighty"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	for _, name := range listDir(t, dir) {
		if filepath.Ext(name) != ".yaml" {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, banned := range []string{"PrivKeyV4", "PrivKeyV6", "ListenPort:", "FwMark:", "API_Prefix:", "ListenPort_EdgeAPI:", "ListenPort_ManageAPI:"} {
			if containsBytes(data, []byte(banned)) {
				t.Fatalf("%s leaked legacy UDP field marker %q", name, banned)
			}
		}
	}
}

// TestManageV2AddPeerIsolatedControlKey — distinct ControlKeyFor across
// AddPeer calls.
func TestManageV2AddPeerIsolatedControlKey(t *testing.T) {
	mgr, _, _, _ := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("key-a", "key-b", "key-c")
	for i, id := range []mtypes.Vertex{1, 2, 3} {
		name := []string{"a", "b", "c"}[i]
		res, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: id, NodeName: name})
		if err != nil {
			t.Fatalf("AddPeer(%d): %v", id, err)
		}
		got, ok := mgr.state.ControlKeyFor(id)
		if !ok || got != res.Profile.SuperNodeV2.ControlPSKey {
			t.Fatalf("ControlKeyFor(%d) mismatch with profile: got (%q,%v), profile=%q", id, got, ok, res.Profile.SuperNodeV2.ControlPSKey)
		}
		if res.Profile.SuperNodeV2.ControlPSKey == "" {
			t.Fatalf("profile PSKey is empty for edge %d", id)
		}
	}
	a, _ := mgr.state.ControlKeyFor(1)
	b, _ := mgr.state.ControlKeyFor(2)
	if a == b {
		t.Fatalf("shared control PSKey across edges: %q", a)
	}
}

// TestManageV2UpdateParametersRevisionBump — parameters update bumps
// revision by exactly one and emits exactly one params_change event.
func TestManageV2UpdateParametersRevisionBump(t *testing.T) {
	mgr, state, pub, _ := newManageV2UnderTest(t)
	before := state.Revision()
	good := validParams()
	if err := mgr.UpdateParameters(context.Background(), ManageUpdateParametersRequest{Parameters: good}); err != nil {
		t.Fatalf("UpdateParameters: %v", err)
	}
	if state.Revision() != before+1 {
		t.Fatalf("revision: got %d want %d", state.Revision(), before+1)
	}
	if pub.count() != 1 || pub.last().Type != mtypes.ControlV2EventParamsChange {
		t.Fatalf("event count/type: count=%d type=%s", pub.count(), pub.last().Type)
	}
}

// TestManageV2ControlStateDeletePeer — covered here to keep the
// state-level contract check next to the management-level one.
func TestManageV2ControlStateDeletePeer(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	if _, err := svc.Register(context.Background(), mtypes.ControlV2RegisterRequest{NodeID: 1, NodeName: "x", Version: mtypes.ControlV2ProtocolVersion}, "k"); err != nil {
		t.Fatalf("register: %v", err)
	}
	rev := svc.Revision()
	if err := svc.DeletePeer(context.Background(), 1); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if got, ok := svc.ControlKeyFor(1); ok {
		t.Fatalf("ControlKeyFor(1) after DeletePeer: (%q, true)", got)
	}
	if svc.Revision() != rev+1 {
		t.Fatalf("revision: got %d want %d", svc.Revision(), rev+1)
	}
	if err := svc.DeletePeer(context.Background(), 1); !errors.Is(err, ErrControlStateUnknownPeer) {
		t.Fatalf("second DeletePeer: want ErrControlStateUnknownPeer, got %v", err)
	}
	if err := svc.DeletePeer(context.Background(), mtypes.NodeID_SuperNode); !errors.Is(err, ErrControlStateSpecialNodeID) {
		t.Fatalf("DeletePeer special: want ErrControlStateSpecialNodeID, got %v", err)
	}
}

// TestManageV2ControlStateUpdateParameters — ControlState rejects
// invalid parameters and bumps revision on success.
func TestManageV2ControlStateUpdateParameters(t *testing.T) {
	pub := &countingPublish{}
	svc := NewControlState(ControlStateConfig{Publish: pub.hook})
	good := validParams()
	if err := svc.UpdateParameters(context.Background(), good); err != nil {
		t.Fatalf("UpdateParameters: %v", err)
	}
	if pub.count() != 1 || pub.last().Type != mtypes.ControlV2EventParamsChange {
		t.Fatalf("event after UpdateParameters: count=%d type=%s", pub.count(), pub.last().Type)
	}
	bad := validParams()
	bad.STUNServers = []string{"not-a-stun-uri"}
	if err := svc.UpdateParameters(context.Background(), bad); !errors.Is(err, ErrControlStateInvalidParameters) {
		t.Fatalf("invalid params: want ErrControlStateInvalidParameters, got %v", err)
	}
	if pub.count() != 1 {
		t.Fatalf("events on rejected UpdateParameters: %d", pub.count())
	}
}

// TestManageV2AddPeerInstallsPreAuthorizedKeyOnRegistry proves that
// AddPeer seeds the configured-key registry with the freshly generated
// PSKey so the Edge can authenticate before its first Register round-trip.
func TestManageV2AddPeerInstallsPreAuthorizedKeyOnRegistry(t *testing.T) {
	mgr, state, _, _ := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("registry-key-1")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	key, ok := state.ControlKeyFor(1)
	if !ok || key != "registry-key-1" {
		t.Fatalf("ControlKeyFor(1): (%q, %v), want (\"registry-key-1\", true)", key, ok)
	}
	if _, exists := state.preauthorized[1]; !exists {
		t.Fatalf("registry entry for peer 1 missing")
	}
}

// TestManageV2UpdatePeerRotationReplacesRegistryKey proves that
// ControlPSKey rotation immediately invalidates the previous configured
// key — the registry holds AT MOST ONE key per NodeID.
func TestManageV2UpdatePeerRotationReplacesRegistryKey(t *testing.T) {
	mgr, state, _, _ := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("initial-key")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := mgr.UpdatePeer(context.Background(), ManageUpdatePeerRequest{NodeID: 1, ControlPSKey: "rotated-key"}); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	key, ok := state.ControlKeyFor(1)
	if !ok || key != "rotated-key" {
		t.Fatalf("ControlKeyFor(1) post-rotation: (%q, %v), want (\"rotated-key\", true)", key, ok)
	}
	if state.preauthorized[1] != "rotated-key" {
		t.Fatalf("registry key: %q, want \"rotated-key\"", state.preauthorized[1])
	}
}

// TestManageV2DeletePeerRemovesRegistryKey proves DeletePeer removes
// both the active record and the registry entry in lock-step — a deleted
// Edge cannot re-authenticate with its prior credentials.
func TestManageV2DeletePeerRemovesRegistryKey(t *testing.T) {
	mgr, state, _, _ := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("doomed-key")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := mgr.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 1}); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	if _, exists := state.preauthorized[1]; exists {
		t.Fatalf("registry entry for deleted peer 1 still present: %q", state.preauthorized[1])
	}
	if key, ok := state.ControlKeyFor(1); ok {
		t.Fatalf("ControlKeyFor(1) after delete: (%q, true), want ('', false)", key)
	}
}

// TestManageV2YamlWriteFailureRollsBackRegistryKeyAdd proves that when a
// freshly-AddedPeer's YAML write fails, the registry entry inserted by
// AddPeer is removed in lock-step with the state rollback so the system
// never holds a configured key for a peer that does not exist on disk.
func TestManageV2YamlWriteFailureRollsBackRegistryKeyAdd(t *testing.T) {
	mgr, state, _, dir := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("doomed-add-key")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("seed AddPeer: %v", err)
	}
	// Force subsequent YAML writes to fail.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("chmod failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	mgr.pskGen = fixedPSKSource("doomed-rollback-key")
	_, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 2, NodeName: "beta"})
	if err == nil {
		t.Fatalf("AddPeer under read-only dir must fail")
	}
	// The registry must NOT carry an entry for the rolled-back peer.
	if _, exists := state.preauthorized[2]; exists {
		t.Fatalf("rolled-back AddPeer still in registry: %q", state.preauthorized[2])
	}
	if key, ok := state.ControlKeyFor(2); ok {
		t.Fatalf("ControlKeyFor(2) after rollback: (%q, true), want ('', false)", key)
	}
}

// TestManageV2YamlWriteFailureRollsBackRegistryKeyRotation proves the
// rotation rollback path: when YAML write fails after ControlPSKey
// rotation, the registry must be restored to the prior key so the
// operator can retry.
func TestManageV2YamlWriteFailureRollsBackRegistryKeyRotation(t *testing.T) {
	mgr, state, _, dir := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("original-key")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("seed AddPeer: %v", err)
	}
	originalKey, _ := state.ControlKeyFor(1)
	if originalKey != "original-key" {
		t.Fatalf("setup ControlKeyFor(1): %q", originalKey)
	}
	// Rotate, then force YAML write to fail on subsequent change.
	if err := mgr.UpdatePeer(context.Background(), ManageUpdatePeerRequest{NodeID: 1, ControlPSKey: "intermediate-key"}); err != nil {
		t.Fatalf("UpdatePeer: %v", err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("chmod failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := mgr.UpdatePeer(context.Background(), ManageUpdatePeerRequest{NodeID: 1, ControlPSKey: "final-key"}); err == nil {
		t.Fatalf("UpdatePeer under read-only dir must fail")
	}
	// The registry must be restored to the prior (intermediate) key.
	got, ok := state.ControlKeyFor(1)
	if !ok || got != "intermediate-key" {
		t.Fatalf("ControlKeyFor(1) after rotation rollback: (%q, %v), want (\"intermediate-key\", true)", got, ok)
	}
}

// TestManageV2YamlWriteFailureRollsBackRegistryKeyDelete proves the
// delete rollback path: when YAML write fails after DeletePeer, the
// registry entry is restored in lock-step with the active peer so the
// subsequent retry is consistent.
func TestManageV2YamlWriteFailureRollsBackRegistryKeyDelete(t *testing.T) {
	mgr, state, _, dir := newManageV2UnderTest(t)
	mgr.pskGen = fixedPSKSource("delete-rollback-key")
	if _, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 1, NodeName: "alpha"}); err != nil {
		t.Fatalf("seed AddPeer: %v", err)
	}
	// Force the delete-time YAML write to fail.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Skipf("chmod failed: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := mgr.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 1}); err == nil {
		t.Fatalf("DeletePeer under read-only dir must fail")
	}
	if _, exists := state.preauthorized[1]; !exists {
		t.Fatalf("rolled-back DeletePeer missing registry entry")
	}
	if key, ok := state.ControlKeyFor(1); !ok || key != "delete-rollback-key" {
		t.Fatalf("ControlKeyFor(1) after delete rollback: (%q, %v), want (\"delete-rollback-key\", true)", key, ok)
	}
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

// validParams returns a fully-validated ControlV2Parameters.
func validParams() mtypes.ControlV2Parameters {
	return mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		PollInterval:        15 * time.Second,
		STUNServers:         []string{"stun:203.0.113.10:3478"},
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
	}
}

// containsBytes reports whether needle is contained within haystack.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
