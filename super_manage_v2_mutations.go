package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

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

	for _, peer := range m.baseConfig.Peers {
		if peer.NodeID == req.NodeID {
			return ManageAddPeerResult{}, ErrManageDuplicateNodeID
		}
		if peer.NodeName == req.NodeName {
			return ManageAddPeerResult{}, ErrManageDuplicateNodeName
		}
	}

	pskey := m.pskGen()
	newBase := cloneSuperConfigV2(m.baseConfig)
	newPeer := mtypes.SuperConfigV2Peer{
		NodeID:         req.NodeID,
		NodeName:       req.NodeName,
		ControlPSKey:   pskey,
		AdditionalCost: 10,
	}
	newBase.Peers = append(newBase.Peers, newPeer)
	sort.SliceStable(newBase.Peers, func(i, j int) bool {
		return newBase.Peers[i].NodeID < newBase.Peers[j].NodeID
	})
	edgeProfile := m.buildEdgeConfigV2(req.NodeID, req.NodeName, pskey)
	if err := m.atomicWriteConfigs(newBase, []*mtypes.EdgeConfigV2{&edgeProfile}); err != nil {
		return ManageAddPeerResult{}, fmt.Errorf("manage v2: yaml write: %w", err)
	}

	version := ClusterVersion{HLC: m.state.hlc.Next(), Origin: m.state.selfID}
	m.state.CommitRegistry(clusterRegistryEntry{
		NodeID:         newPeer.NodeID,
		NodeName:       newPeer.NodeName,
		ControlPSKey:   newPeer.ControlPSKey,
		AdditionalCost: newPeer.AdditionalCost,
		Version:        version,
		Origin:         version.Origin,
	}, 0)
	m.baseConfig = newBase
	if err := m.persistClusterState(); err != nil {
		return ManageAddPeerResult{SuperPeer: newPeer, Profile: edgeProfile}, err
	}
	return ManageAddPeerResult{SuperPeer: newPeer, Profile: edgeProfile}, nil
}

func (m *ManageV2) UpdatePeer(ctx context.Context, req ManageUpdatePeerRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.NodeID.IsSpecial() {
		return manageV2Error(mtypes.ControlV2ErrInvalidNodeID, "node_id", fmt.Sprintf("reserved / special node id: %s", req.NodeID.ToString()))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	index := -1
	for peerIndex, peer := range m.baseConfig.Peers {
		if peer.NodeID == req.NodeID {
			index = peerIndex
			break
		}
	}
	if index < 0 {
		return ErrManageUnknownPeer
	}
	current := m.baseConfig.Peers[index]
	newPSKey := current.ControlPSKey
	if req.ControlPSKey != "" && req.ControlPSKey != current.ControlPSKey {
		newPSKey = req.ControlPSKey
	}
	newNodeName := current.NodeName
	if req.NodeName != "" {
		newNodeName = req.NodeName
	}
	newCost := current.AdditionalCost
	if req.AdditionalCost >= 0 {
		newCost = req.AdditionalCost
	}
	newPeer := mtypes.SuperConfigV2Peer{
		NodeID:         current.NodeID,
		NodeName:       newNodeName,
		ControlPSKey:   newPSKey,
		AdditionalCost: newCost,
	}
	newBase := cloneSuperConfigV2(m.baseConfig)
	newBase.Peers[index] = newPeer
	writes := []*mtypes.EdgeConfigV2{}
	if newPSKey != current.ControlPSKey || newNodeName != current.NodeName {
		edge := m.buildEdgeConfigV2(req.NodeID, newNodeName, newPSKey)
		writes = append(writes, &edge)
	}
	if err := m.atomicWriteConfigs(newBase, writes); err != nil {
		return fmt.Errorf("manage v2: yaml write: %w", err)
	}

	version := ClusterVersion{HLC: m.state.hlc.Next(), Origin: m.state.selfID}
	m.state.CommitRegistry(clusterRegistryEntry{
		NodeID:         newPeer.NodeID,
		NodeName:       newPeer.NodeName,
		ControlPSKey:   newPeer.ControlPSKey,
		AdditionalCost: newPeer.AdditionalCost,
		Version:        version,
		Origin:         version.Origin,
	}, 0)
	m.baseConfig = newBase
	return m.persistClusterState()
}

func (m *ManageV2) DeletePeer(ctx context.Context, req ManageDeletePeerRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.NodeID.IsSpecial() {
		return manageV2Error(mtypes.ControlV2ErrInvalidNodeID, "node_id", fmt.Sprintf("reserved / special node id: %s", req.NodeID.ToString()))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	index := -1
	for peerIndex, peer := range m.baseConfig.Peers {
		if peer.NodeID == req.NodeID {
			index = peerIndex
			break
		}
	}
	if index < 0 {
		return ErrManageUnknownPeer
	}
	newBase := cloneSuperConfigV2(m.baseConfig)
	newBase.Peers = append(newBase.Peers[:index], newBase.Peers[index+1:]...)
	if err := m.atomicWriteConfigs(newBase, nil); err != nil {
		return fmt.Errorf("manage v2: yaml write: %w", err)
	}
	if err := os.Remove(m.edgeFilePath(req.NodeID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		restoreErr := m.atomicWriteConfigs(m.baseConfig, nil)
		if restoreErr != nil {
			return fmt.Errorf("manage v2: remove edge config: %w", errors.Join(err, restoreErr))
		}
		return fmt.Errorf("manage v2: remove edge config: %w", err)
	}

	version := ClusterVersion{HLC: m.state.hlc.Next(), Origin: m.state.selfID}
	m.state.RevokeRegistry(req.NodeID, version, 0)
	m.baseConfig = newBase
	return m.persistClusterState()
}

func (m *ManageV2) UpdateParameters(ctx context.Context, req ManageUpdateParametersRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := req.Parameters.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	newBase := cloneSuperConfigV2(m.baseConfig)
	m.applyParameters(&newBase, req.Parameters)
	if err := m.atomicWriteConfigs(newBase, nil); err != nil {
		return fmt.Errorf("manage v2: yaml write: %w", err)
	}

	version := ClusterVersion{HLC: m.state.hlc.Next(), Origin: m.state.selfID}
	m.state.CommitParameters(req.Parameters, version, 0)
	m.baseConfig = newBase
	return m.persistClusterState()
}
