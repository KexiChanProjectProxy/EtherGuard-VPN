package main

import (
	"fmt"
	"sort"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func (m *ManageV2) ApplyRemoteRegistry(entry clusterRegistryEntry, fromLink mtypes.Vertex) error {
	peer := mtypes.SuperConfigV2Peer{
		NodeID:         entry.NodeID,
		NodeName:       entry.NodeName,
		ControlPSKey:   entry.ControlPSKey,
		AdditionalCost: entry.AdditionalCost,
	}
	if err := peer.Validate(); err != nil {
		return fmt.Errorf("manage v2: remote registry entry: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.state.RegistryVersion(entry.NodeID); ok && !entry.Version.Newer(current) {
		return nil
	}

	newBase := cloneSuperConfigV2(m.baseConfig)
	found := false
	for index := range newBase.Peers {
		if newBase.Peers[index].NodeID == entry.NodeID {
			newBase.Peers[index] = peer
			found = true
			break
		}
	}
	if !found {
		newBase.Peers = append(newBase.Peers, peer)
	}
	sort.SliceStable(newBase.Peers, func(i, j int) bool {
		return newBase.Peers[i].NodeID < newBase.Peers[j].NodeID
	})
	if err := m.atomicWriteConfigs(newBase, nil); err != nil {
		m.state.MarkResyncNeeded()
		return fmt.Errorf("manage v2: persist remote registry: %w", err)
	}

	m.state.CommitRegistry(entry, fromLink)
	m.baseConfig = newBase
	if err := m.persistClusterState(); err != nil {
		m.state.MarkResyncNeeded()
		return err
	}
	return nil
}

func (m *ManageV2) ApplyRemoteRegistryDelete(nodeID mtypes.Vertex, version ClusterVersion, fromLink mtypes.Vertex) error {
	if nodeID.IsSpecial() {
		return manageV2Error(mtypes.ControlV2ErrInvalidNodeID, "node_id", fmt.Sprintf("reserved / special node id: %s", nodeID.ToString()))
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if current, ok := m.state.RegistryVersion(nodeID); ok && !version.Newer(current) {
		return nil
	}

	newBase := cloneSuperConfigV2(m.baseConfig)
	peers := newBase.Peers[:0]
	for _, peer := range newBase.Peers {
		if peer.NodeID != nodeID {
			peers = append(peers, peer)
		}
	}
	newBase.Peers = peers
	if err := m.atomicWriteConfigs(newBase, nil); err != nil {
		m.state.MarkResyncNeeded()
		return fmt.Errorf("manage v2: persist remote registry delete: %w", err)
	}

	m.state.RevokeRegistry(nodeID, version, fromLink)
	m.baseConfig = newBase
	if err := m.persistClusterState(); err != nil {
		m.state.MarkResyncNeeded()
		return err
	}
	return nil
}

func (m *ManageV2) ApplyRemoteParameters(params clusterParams, fromLink mtypes.Vertex) error {
	if err := params.Parameters.Validate(); err != nil {
		return fmt.Errorf("manage v2: remote parameters: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !params.Version.Newer(m.state.parametersVersion()) {
		return nil
	}

	newBase := cloneSuperConfigV2(m.baseConfig)
	m.applyParameters(&newBase, params.Parameters)
	if err := m.atomicWriteConfigs(newBase, nil); err != nil {
		m.state.MarkResyncNeeded()
		return fmt.Errorf("manage v2: persist remote parameters: %w", err)
	}

	m.state.CommitParameters(params.Parameters, params.Version, fromLink)
	m.baseConfig = newBase
	if err := m.persistClusterState(); err != nil {
		m.state.MarkResyncNeeded()
		return err
	}
	return nil
}

func (s *ControlState) parametersVersion() ClusterVersion {
	if s == nil {
		return ClusterVersion{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.paramsVersion
}
