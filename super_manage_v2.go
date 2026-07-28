/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

var (
	// ErrManageDuplicateNodeID is returned when AddPeer is called with a
	// NodeID that already exists in the authorative SuperConfigV2 peer
	// list.
	ErrManageDuplicateNodeID = errors.New("manage v2: duplicate node id")
	// ErrManageDuplicateNodeName is returned when AddPeer is called with a
	// NodeName that already exists in the authorative SuperConfigV2 peer
	// list (the v2 Super keeps names unique for human diagnostics).
	ErrManageDuplicateNodeName = errors.New("manage v2: duplicate node name")
	// ErrManageUnknownPeer is returned by UpdatePeer / DeletePeer when the
	// requested NodeID has no entry in the authorative peer list.
	ErrManageUnknownPeer = errors.New("manage v2: unknown peer")
)

// manageV2Error constructs a *mtypes.ControlV2Error with the supplied
// code, field, and pre-formatted message. Kept private because the
// matching mtypes helper is unexported; we replicate the one-liner here so
// the management service can return uniform typed errors.
func manageV2Error(code, field, message string) *mtypes.ControlV2Error {
	return &mtypes.ControlV2Error{Code: code, Field: field, Message: message}
}

// ---------------------------------------------------------------------------
// Request / result shapes
// ---------------------------------------------------------------------------

// ManageAddPeerRequest is the typed body of AddPeer.
type ManageAddPeerRequest struct {
	NodeID   mtypes.Vertex
	NodeName string
}

// ManageUpdatePeerRequest is the typed body of UpdatePeer.
//
// Convention: a zero value in any optional field (NodeName == "",
// AdditionalCost < 0, ControlPSKey == "") means "do not change"; pass an
// explicit value to mutate. Pass a non-empty ControlPSKey to rotate the
// per-Edge control key — the old key is invalidated by the underlying
// Register call.
type ManageUpdatePeerRequest struct {
	NodeID         mtypes.Vertex
	NodeName       string
	AdditionalCost float64
	ControlPSKey   string
}

// ManageDeletePeerRequest is the typed body of DeletePeer.
type ManageDeletePeerRequest struct {
	NodeID mtypes.Vertex
}

// ManageUpdateParametersRequest is the typed body of UpdateParameters.
// STUN URIs (and every other field) are validated by
// mtypes.ControlV2Parameters.Validate.
type ManageUpdateParametersRequest struct {
	Parameters mtypes.ControlV2Parameters
}

// ManageAddPeerResult is returned by AddPeer and contains the freshly
// generated Edge profile so the operator can hand it directly to the Edge.
// ONLY this Edge's own ControlPSKey is exposed in the result.
type ManageAddPeerResult struct {
	SuperPeer mtypes.SuperConfigV2Peer
	Profile   mtypes.EdgeConfigV2
}

// ---------------------------------------------------------------------------
// Service configuration
// ---------------------------------------------------------------------------

// ManageV2Config wires the management service into the surrounding runtime.
// Only State and ConfigDir are strictly required; the rest are defaulted.
type ManageV2Config struct {
	// State is the singleton ControlState that owns the in-memory peer
	// map, the revision counter, and the publish hook.
	State *ControlState
	// ConfigDir is the directory where SuperConfigV2 YAML and per-Edge
	// EdgeConfigV2 YAML files are persisted. Must exist / be writable.
	ConfigDir string
	// BaseConfig is the initial / persistent SuperConfigV2. Must pass
	// mtypes.SuperConfigV2.Validate.
	BaseConfig mtypes.SuperConfigV2
	// EdgeTemplate is cloned into every generated per-Edge EdgeConfigV2
	// file; the SuperNodeV2 placeholder fields are filled in by
	// buildEdgeConfigV2.
	EdgeTemplate mtypes.EdgeConfigV2
	// PSKGen returns a fresh control PSKey; defaults to
	// device.RandomPSK().ToString.
	PSKGen func() string
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// ManageV2 is the typed, concurrency-safe management mutation service. One
// instance per Super runtime. The Zero value is NOT usable; always go
// through NewManageV2.
type ManageV2 struct {
	mu sync.Mutex // serialises multi-file YAML writes for rollback safety

	state        *ControlState
	configDir    string
	baseConfig   mtypes.SuperConfigV2
	edgeTemplate mtypes.EdgeConfigV2
	superFile    string // default "super.yaml"

	pskGen func() string
}

// NewManageV2 validates the configuration and constructs the service. It
// validates BaseConfig and a SuperNodeV2-injected copy of EdgeTemplate
// exactly once. It does NOT touch disk.
func NewManageV2(cfg ManageV2Config) (*ManageV2, error) {
	if cfg.State == nil {
		return nil, errors.New("manage v2: state is required")
	}
	if cfg.ConfigDir == "" {
		return nil, errors.New("manage v2: config dir is required")
	}
	if err := cfg.BaseConfig.Validate(); err != nil {
		return nil, fmt.Errorf("manage v2: base super config: %w", err)
	}
	// EdgeTemplate must validate with a placeholder SuperNodeV2 filled in.
	tpl := cfg.EdgeTemplate
	if tpl.SuperNodeV2.APIUrl == "" {
		tpl.SuperNodeV2.APIUrl = cfg.BaseConfig.APIUrl
	}
	if tpl.SuperNodeV2.APIPrefix == "" {
		tpl.SuperNodeV2.APIPrefix = cfg.BaseConfig.APIPrefix
	}
	if tpl.SuperNodeV2.NodeID.IsSpecial() {
		tpl.SuperNodeV2.NodeID = 1
	}
	if tpl.SuperNodeV2.ControlPSKey == "" {
		tpl.SuperNodeV2.ControlPSKey = "_template_"
	}
	if err := tpl.Validate(); err != nil {
		return nil, fmt.Errorf("manage v2: edge template: %w", err)
	}
	pskGen := cfg.PSKGen
	if pskGen == nil {
		pskGen = func() string { return device.RandomPSK().ToString() }
	}
	return &ManageV2{
		state:        cfg.State,
		configDir:    cfg.ConfigDir,
		baseConfig:   cfg.BaseConfig,
		edgeTemplate: tpl,
		superFile:    "super.yaml",
		pskGen:       pskGen,
	}, nil
}

// ---------------------------------------------------------------------------
// Public surface: AddPeer / UpdatePeer / DeletePeer / UpdateParameters
// ---------------------------------------------------------------------------

// AddPeer registers a new Edge under the Super's authorative state and
// writes the fresh per-Edge EdgeConfigV2 + updated SuperConfigV2 YAML
// atomically. EXACTLY one event (peer_change) is published on success.
//
// Returns ErrManageDuplicateNodeID / ErrManageDuplicateNodeName for
// collisions; mtypes.ControlV2Error-wrapped validation errors otherwise.
func (m *ManageV2) AddPeer(ctx context.Context, req ManageAddPeerRequest) (ManageAddPeerResult, error) {
	if err := ctx.Err(); err != nil {
		return ManageAddPeerResult{}, err
	}
	if req.NodeID.IsSpecial() {
		return ManageAddPeerResult{}, manageV2Error(mtypes.ControlV2ErrInvalidNodeID, "node_id", fmt.Sprintf("reserved / special node id: %s", req.NodeID.ToString()))
	}
	if req.NodeName == "" {
		return ManageAddPeerResult{}, manageV2Error(mtypes.ControlV2ErrMissingField, "node_name", "node_name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Duplicate checks against the in-memory authorative config.
	for _, p := range m.baseConfig.Peers {
		if p.NodeID == req.NodeID {
			return ManageAddPeerResult{}, ErrManageDuplicateNodeID
		}
		if p.NodeName == req.NodeName {
			return ManageAddPeerResult{}, ErrManageDuplicateNodeName
		}
	}

	// Generate fresh control PSKey (isolated to THIS edge).
	pskey := m.pskGen()

	// Build new authorative SuperConfigV2 + per-Edge profile.
	newBase := cloneSuperConfigV2(m.baseConfig)
	newPeer := mtypes.SuperConfigV2Peer{
		NodeID:         req.NodeID,
		NodeName:       req.NodeName,
		ControlPSKey:   pskey,
		AdditionalCost: 10, // sensible default; matches gencfg pattern
	}
	newBase.Peers = append(newBase.Peers, newPeer)
	sort.SliceStable(newBase.Peers, func(i, j int) bool {
		return newBase.Peers[i].NodeID < newBase.Peers[j].NodeID
	})
	edgeProfile := m.buildEdgeConfigV2(req.NodeID, req.NodeName, pskey)

	// Insert the peer into ControlState. Register bumps revision + emits
	// peer_change exactly once when the peer is new.
	if _, err := m.state.Register(ctx, mtypes.ControlV2RegisterRequest{
		NodeID:   req.NodeID,
		NodeName: req.NodeName,
		Version:  mtypes.ControlV2ProtocolVersion,
	}, pskey); err != nil {
		return ManageAddPeerResult{}, fmt.Errorf("manage v2: state register: %w", err)
	}

	// Install the credential into the pre-authorized registry BEFORE the
	// YAML write so a failed persist cleanly rolls back BOTH the active
	// peer record AND the registry entry. ManageV2 holds its own mutex,
	// the registry mutation is in-place, and no other goroutine races
	// AddPeer for the same NodeID (duplicate checks above reject this).
	m.state.SetPreAuthorized(req.NodeID, pskey)

	// Persist to disk atomically. On any failure, roll back the state.
	if err := m.atomicWriteConfigs(newBase, []*mtypes.EdgeConfigV2{&edgeProfile}); err != nil {
		// Best-effort rollback: undo the registry install and the active
		// peer record so the system never carries a configured key for a
		// peer whose YAML did not survive.
		m.state.RemovePreAuthorized(req.NodeID)
		_ = m.state.DeletePeer(ctx, req.NodeID)
		return ManageAddPeerResult{}, fmt.Errorf("manage v2: yaml write: %w", err)
	}

	m.baseConfig = newBase
	return ManageAddPeerResult{SuperPeer: newPeer, Profile: edgeProfile}, nil
}

// UpdatePeer mutates the peer metadata in the Super's authorative state
// (NodeName and/or AdditionalCost and/or ControlPSKey) and rewrites the
// YAML atomically. EXACTLY one event (peer_change) is published on
// success.
//
// Pass an explicit ControlPSKey to rotate the per-Edge control key — the
// old key is invalidated by the underlying Register call. Empty fields
// keep their existing value.
func (m *ManageV2) UpdatePeer(ctx context.Context, req ManageUpdatePeerRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.NodeID.IsSpecial() {
		return manageV2Error(mtypes.ControlV2ErrInvalidNodeID, "node_id", fmt.Sprintf("reserved / special node id: %s", req.NodeID.ToString()))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	for i, p := range m.baseConfig.Peers {
		if p.NodeID == req.NodeID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrManageUnknownPeer
	}
	cur := m.baseConfig.Peers[idx]
	newPSKey := cur.ControlPSKey
	if req.ControlPSKey != "" && req.ControlPSKey != cur.ControlPSKey {
		// Operator-initiated rotation. Register's controlKey diff detects
		// the change and emits peer_change exactly once.
		newPSKey = req.ControlPSKey
	}
	newNodeName := cur.NodeName
	if req.NodeName != "" {
		newNodeName = req.NodeName
	}
	newCost := cur.AdditionalCost
	if req.AdditionalCost >= 0 {
		newCost = req.AdditionalCost
	}
	newPeer := mtypes.SuperConfigV2Peer{
		NodeID:         cur.NodeID,
		NodeName:       newNodeName,
		ControlPSKey:   newPSKey,
		AdditionalCost: newCost,
	}
	newBase := cloneSuperConfigV2(m.baseConfig)
	newBase.Peers[idx] = newPeer

	// Capture the prior state for rollback in case of YAML-write failure.
	prevBase := cloneSuperConfigV2(m.baseConfig)

	// Single state mutation: Register detects any of {NodeName, ControlKey}
	// change and emits peer_change with one revision bump. For pure
	// AdditionalCost-only updates, no revision would bump; that's
	// acceptable here because the operator-visible state is the YAML on
	// disk, and the in-memory snapshot from SnapshotFor reflects the
	// current AdditionalCost via the peer record's SuperPeerInfo.
	// Specifically: AddPeer / Delete / UpdateParameters drive revision;
	// pure AdditionalCost-only UpdatePeer is a configuration metadata
	// change that does NOT alter the snapshot peer view and therefore
	// does NOT require a stream invalidation.
	if _, err := m.state.Register(ctx, mtypes.ControlV2RegisterRequest{
		NodeID:   req.NodeID,
		NodeName: newNodeName,
		Version:  mtypes.ControlV2ProtocolVersion,
	}, newPSKey); err != nil {
		return fmt.Errorf("manage v2: state reregister: %w", err)
	}

	// Update the pre-authorized registry. A new ControlPSKey (rotation)
	// MUST take effect immediately so the old key is invalidated even
	// before the YAML write lands; pure AdditionalCost/NodeName-only
	// updates reuse the existing key. The state mutation above already
	// carried the new key into the active peer record when applicable.
	m.state.SetPreAuthorized(req.NodeID, newPSKey)

	// Decide whether the per-Edge YAML must be rewritten. If neither the
	// control PSKey nor the NodeName changed, we only need to update the
	// Super YAML (in case AdditionalCost changed).
	writes := []*mtypes.EdgeConfigV2{}
	if newPSKey != cur.ControlPSKey || newNodeName != cur.NodeName {
		edge := m.buildEdgeConfigV2(req.NodeID, newNodeName, newPSKey)
		writes = append(writes, &edge)
	}
	if err := m.atomicWriteConfigs(newBase, writes); err != nil {
		// Roll back: restore the prior registry key AND re-register the
		// previous peer metadata, then re-write the prior Super YAML.
		m.state.SetPreAuthorized(req.NodeID, cur.ControlPSKey)
		if _, rerr := m.state.Register(ctx, mtypes.ControlV2RegisterRequest{
			NodeID:   req.NodeID,
			NodeName: cur.NodeName,
			Version:  mtypes.ControlV2ProtocolVersion,
		}, cur.ControlPSKey); rerr != nil {
			return fmt.Errorf("manage v2: rollback failed: %v (original: %w)", rerr, err)
		}
		if werr := m.atomicWriteConfigs(prevBase, nil); werr != nil {
			return fmt.Errorf("manage v2: rollback write failed: %v (original: %w)", werr, err)
		}
		return fmt.Errorf("manage v2: yaml write: %w", err)
	}

	m.baseConfig = newBase
	return nil
}

// DeletePeer removes a peer from the Super's authorative state, persists
// the updated SuperConfigV2, and removes the per-Edge EdgeConfigV2 file.
// EXACTLY one event (peer_gone) is published on success.
func (m *ManageV2) DeletePeer(ctx context.Context, req ManageDeletePeerRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.NodeID.IsSpecial() {
		return manageV2Error(mtypes.ControlV2ErrInvalidNodeID, "node_id", fmt.Sprintf("reserved / special node id: %s", req.NodeID.ToString()))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := -1
	for i, p := range m.baseConfig.Peers {
		if p.NodeID == req.NodeID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ErrManageUnknownPeer
	}
	cur := m.baseConfig.Peers[idx]
	newBase := cloneSuperConfigV2(m.baseConfig)
	newBase.Peers = append(newBase.Peers[:idx], newBase.Peers[idx+1:]...)

	// State mutation first (emits peer_gone once AND clears the
	// pre-authorized registry entry so the deleted Edge can no longer
	// re-authenticate with its old credentials).
	if err := m.state.DeletePeer(ctx, req.NodeID); err != nil {
		return fmt.Errorf("manage v2: state delete: %w", err)
	}

	// Persist updated Super YAML atomically.
	if err := m.atomicWriteConfigs(newBase, nil); err != nil {
		// Roll back: re-register the peer (revives the entry point) AND
		// restore the registry key so a successful retry is consistent.
		m.state.SetPreAuthorized(cur.NodeID, cur.ControlPSKey)
		if _, rerr := m.state.Register(ctx, mtypes.ControlV2RegisterRequest{
			NodeID:   cur.NodeID,
			NodeName: cur.NodeName,
			Version:  mtypes.ControlV2ProtocolVersion,
		}, cur.ControlPSKey); rerr != nil {
			return fmt.Errorf("manage v2: rollback failed: %v (original: %w)", rerr, err)
		}
		return fmt.Errorf("manage v2: yaml write: %w", err)
	}

	// Best-effort remove the per-Edge file (no rollback needed here
	// because the Edge config on disk is now stale but the state /
	// Super YAML are consistent).
	edgeFile := m.edgeFilePath(cur.NodeID)
	if _, err := os.Stat(edgeFile); err == nil {
		_ = os.Remove(edgeFile)
	}

	m.baseConfig = newBase
	return nil
}

// UpdateParameters replaces the published control parameter stream, persists
// it to the SuperConfigV2 YAML, and bumps the revision once. EXACTLY one
// event (params_change) is published on success.
func (m *ManageV2) UpdateParameters(ctx context.Context, req ManageUpdateParametersRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Validate up-front; the underlying ControlState also validates.
	if err := req.Parameters.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	prev := cloneSuperConfigV2(m.baseConfig)
	m.applyParameters(&m.baseConfig, req.Parameters)

	if err := m.atomicWriteConfigs(m.baseConfig, nil); err != nil {
		m.baseConfig = prev
		return fmt.Errorf("manage v2: yaml write: %w", err)
	}

	if err := m.state.UpdateParameters(ctx, req.Parameters); err != nil {
		m.baseConfig = prev
		_ = m.atomicWriteConfigs(prev, nil)
		return fmt.Errorf("manage v2: state update: %w", err)
	}
	return nil
}

// Snapshot returns a copy of the current authorative SuperConfigV2.
// Exposed for diagnostic / status endpoints; always deep-copied.
func (m *ManageV2) Snapshot() mtypes.SuperConfigV2 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return cloneSuperConfigV2(m.baseConfig)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildEdgeConfigV2 clones the edge template and fills in the per-Edge key,
// NodeID, NodeName, and the SuperNodeV2 reference (API URL, prefix, Super
// NodeID placeholder, freshly-generated control PSKey).
func (m *ManageV2) buildEdgeConfigV2(nodeID mtypes.Vertex, nodeName, controlPSKey string) mtypes.EdgeConfigV2 {
	p := m.edgeTemplate
	pri, _ := device.RandomKeyPair()
	p.PrivKey = pri.ToString()
	p.NodeID = nodeID
	p.NodeName = nodeName
	p.SuperNodeV2 = mtypes.SuperNodeV2Ref{
		APIUrl:       m.baseConfig.APIUrl,
		APIPrefix:    m.baseConfig.APIPrefix,
		NodeID:       1, // non-special placeholder; concrete Super is identified by APIUrl+PSKey pair
		ControlPSKey: controlPSKey,
	}
	return p
}

// applyParameters overwrites the timing/STUN fields on the SuperConfigV2.
func (m *ManageV2) applyParameters(cfg *mtypes.SuperConfigV2, p mtypes.ControlV2Parameters) {
	cfg.STUNServers = append([]string{}, p.STUNServers...)
	cfg.STUNRequestTimeoutSeconds = p.STUNRequestTimeout.Seconds()
	cfg.STUNRefreshIntervalSeconds = p.STUNRefreshInterval.Seconds()
	cfg.PollIntervalSeconds = p.PollInterval.Seconds()
	cfg.ReportIntervalSeconds = p.ReportInterval.Seconds()
	cfg.HeartbeatIntervalSeconds = p.HeartbeatInterval.Seconds()
	cfg.EventReplay = p.EventReplay
}

// atomicWriteConfigs serialises newBase to super.yaml atomically and, for
// every entry in newEdges, writes the per-Edge EdgeConfigV2 YAML
// atomically. On any failure the partial state on disk is rolled back to
// the prior in-memory state (m.baseConfig + previously-persisted edge
// files).
func (m *ManageV2) atomicWriteConfigs(newBase mtypes.SuperConfigV2, newEdges []*mtypes.EdgeConfigV2) error {
	prevBase := cloneSuperConfigV2(m.baseConfig)
	prevEdgeFiles := map[mtypes.Vertex][]byte{}
	for _, p := range prevBase.Peers {
		path := m.edgeFilePath(p.NodeID)
		if data, err := ioutil.ReadFile(path); err == nil {
			prevEdgeFiles[p.NodeID] = data
		}
	}
	prevSuperBytes, prevSuperHadFile := readFileIfExists(m.superFilePath())

	if err := atomicWriteYAML(m.superFilePath(), newBase); err != nil {
		return fmt.Errorf("write super.yaml: %w", err)
	}

	for _, edge := range newEdges {
		path := m.edgeFilePath(edge.NodeID)
		if err := atomicWriteYAML(path, *edge); err != nil {
			// Roll back: rewrite super.yaml from m.baseConfig (the
			// caller's snapshot) and the prior edge files.
			_ = restoreSuperFile(prevSuperBytes, prevSuperHadFile, m.superFilePath())
			for nodeID, data := range prevEdgeFiles {
				_ = atomicWriteBytes(m.edgeFilePath(nodeID), data)
			}
			return fmt.Errorf("write edge %d: %w", edge.NodeID, err)
		}
	}
	return nil
}

func (m *ManageV2) superFilePath() string {
	return filepath.Join(m.configDir, m.superFile)
}

func (m *ManageV2) edgeFilePath(nodeID mtypes.Vertex) string {
	return filepath.Join(m.configDir, fmt.Sprintf("edge_%d.yaml", int(nodeID)))
}

// ---------------------------------------------------------------------------
// YAML atomic-write helpers
// ---------------------------------------------------------------------------

// atomicWriteYAML serialises v to YAML and writes it atomically
// (temp file + fsync + rename) at path. The directory must exist.
func atomicWriteYAML(path string, v interface{}) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return atomicWriteBytes(path, data)
}

// atomicWriteBytes writes data to path atomically (temp file + rename).
func atomicWriteBytes(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := ioutil.TempFile(dir, ".tmp-*.yaml")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

func restoreSuperFile(prevBytes []byte, prevHadFile bool, path string) error {
	if !prevHadFile {
		return os.Remove(path)
	}
	return atomicWriteBytes(path, prevBytes)
}

func readFileIfExists(path string) ([]byte, bool) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// cloneSuperConfigV2 returns a deep copy of cfg so callers may mutate
// freely without affecting the service's authorative state.
func cloneSuperConfigV2(cfg mtypes.SuperConfigV2) mtypes.SuperConfigV2 {
	out := cfg
	if cfg.STUNServers != nil {
		out.STUNServers = append([]string{}, cfg.STUNServers...)
	}
	if cfg.Peers != nil {
		peers := make([]mtypes.SuperConfigV2Peer, len(cfg.Peers))
		copy(peers, cfg.Peers)
		out.Peers = peers
	}
	return out
}
