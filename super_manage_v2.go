/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
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
	// ClusterStateFile stores registry/parameter versions and registry
	// tombstones. Empty defaults to ConfigDir/cluster_state.yaml.
	ClusterStateFile string
	// WriteHook is a test seam invoked before every managed YAML write.
	WriteHook func(path string) error
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

// ManageV2 is the typed, concurrency-safe management mutation service. One
// instance per Super runtime. The Zero value is NOT usable; always go
// through NewManageV2.
type ManageV2 struct {
	mu sync.Mutex // serialises multi-file YAML writes for rollback safety

	state            *ControlState
	configDir        string
	baseConfig       mtypes.SuperConfigV2
	edgeTemplate     mtypes.EdgeConfigV2
	superFile        string // default "super.yaml"
	clusterStateFile string

	pskGen    func() string
	writeHook func(path string) error
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
	clusterStatePath := cfg.ClusterStateFile
	if clusterStatePath == "" {
		clusterStatePath = filepath.Join(cfg.ConfigDir, "cluster_state.yaml")
	}
	clusterState, err := loadClusterStateFile(clusterStatePath)
	if err != nil {
		return nil, fmt.Errorf("manage v2: load cluster state: %w", err)
	}
	clusterState = pruneClusterStateTombstones(clusterState, cfg.State.now())
	// EdgeTemplate must validate with a placeholder SuperNodeV2 filled in.
	tpl := cfg.EdgeTemplate
	superRef := tpl.SuperNodeV2
	if len(superRef.ResolveAPIUrls()) == 0 {
		superRef.APIUrl = cfg.BaseConfig.APIUrl
		tpl.SuperNodeV2 = superRef
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
	selfID := cfg.State.selfID
	if cfg.BaseConfig.Cluster != nil {
		selfID = cfg.BaseConfig.Cluster.SelfID
	}
	cfg.State.SetRegistryVersionsForSeed(cfg.BaseConfig.Peers, clusterState, selfID)
	return &ManageV2{
		state:            cfg.State,
		configDir:        cfg.ConfigDir,
		baseConfig:       cloneSuperConfigV2(cfg.BaseConfig),
		edgeTemplate:     tpl,
		superFile:        "super.yaml",
		clusterStateFile: clusterStatePath,
		pskGen:           pskGen,
		writeHook:        cfg.WriteHook,
	}, nil
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
	p.SuperNodeV2 = edgeSuperNodeV2Ref(m.baseConfig, controlPSKey)
	return p
}

func edgeSuperNodeV2Ref(cfg mtypes.SuperConfigV2, controlPSKey string) mtypes.SuperNodeV2Ref {
	ref := mtypes.SuperNodeV2Ref{
		APIPrefix:    cfg.APIPrefix,
		NodeID:       1, // non-special placeholder; concrete Super is identified by APIUrl+PSKey pair
		ControlPSKey: controlPSKey,
	}
	if cfg.Cluster == nil {
		ref.APIUrl = cfg.APIUrl
		return ref
	}
	urls := make([]string, 0, 1+len(cfg.Cluster.Peers))
	urls = append(urls, cfg.APIUrl)
	for _, peer := range cfg.Cluster.Peers {
		urls = append(urls, peer.APIUrl)
	}
	ref.APIUrls = urls
	return ref
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
	cfg.RelayCostMS = cloneFloat64Ptr(p.RelayCostMS)
	cfg.ListenPortPriority = cloneListenPortPriority(p.ListenPortPriority)
	cfg.EndpointBlacklist = append([]string{}, p.EndpointBlacklist...)
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
	if cfg.EndpointBlacklist != nil {
		out.EndpointBlacklist = append([]string{}, cfg.EndpointBlacklist...)
	}
	out.ListenPortPriority = cloneListenPortPriority(cfg.ListenPortPriority)
	out.RelayCostMS = cloneFloat64Ptr(cfg.RelayCostMS)
	if cfg.Cluster != nil {
		cluster := *cfg.Cluster
		if cfg.Cluster.Peers != nil {
			cluster.Peers = append([]mtypes.SuperConfigV2ClusterPeer{}, cfg.Cluster.Peers...)
		}
		out.Cluster = &cluster
	}
	return out
}
