package main

import (
	"fmt"
	"log"
	"sort"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func (s *ControlState) CommitRegistry(entry clusterRegistryEntry, fromLink mtypes.Vertex) bool {
	if s == nil || entry.NodeID.IsSpecial() {
		return false
	}
	if entry.Origin == 0 {
		entry.Origin = entry.Version.Origin
	}
	if entry.Version.HLC != 0 {
		s.hlc.Observe(entry.Version.HLC)
	}

	s.mu.Lock()
	if current, ok := s.registryVersionLocked(entry.NodeID); ok && !entry.Version.Newer(current) {
		s.mu.Unlock()
		return false
	}
	delete(s.registryTombstones, entry.NodeID)
	delete(s.registryTombstoneTimes, entry.NodeID)
	s.registry[entry.NodeID] = entry
	nameChanged := false
	if peer, ok := s.peers[entry.NodeID]; ok {
		peer.controlKey = entry.ControlPSKey
		if peer.view.NodeName != entry.NodeName {
			peer.view.NodeName = entry.NodeName
			nameChanged = true
			s.revision++
		}
	}
	s.appendMutationLocked(clusterMutation{
		Kind:     clusterMessageRegistryUpsert,
		NodeID:   entry.NodeID,
		Registry: &entry,
		Version:  entry.Version,
		Origin:   entry.Origin,
		FromLink: fromLink,
	})
	revision := s.revision
	effectiveName := ""
	if nameChanged {
		effectiveName = s.effectiveNodeNameLocked(entry.NodeID)
	}
	s.mu.Unlock()

	if nameChanged {
		s.emit(mtypes.ControlV2EventPeerChange, entry.NodeID, effectiveName, revision)
	}
	return true
}

func (s *ControlState) RevokeRegistry(nodeID mtypes.Vertex, version ClusterVersion, fromLink mtypes.Vertex) bool {
	if s == nil || nodeID.IsSpecial() {
		return false
	}
	if version.HLC != 0 {
		s.hlc.Observe(version.HLC)
	}

	now := s.now()
	s.mu.Lock()
	if current, ok := s.registryVersionLocked(nodeID); ok && !version.Newer(current) {
		s.mu.Unlock()
		return false
	}
	_, active := s.peers[nodeID]
	name := ""
	if active {
		name = s.effectiveNodeNameLocked(nodeID)
		delete(s.peers, nodeID)
		s.clearObservedVotesForObserverLocked(nodeID)
		delete(s.observedVotes, nodeID)
		s.revision++
	}
	delete(s.registry, nodeID)
	s.registryTombstones[nodeID] = version
	s.registryTombstoneTimes[nodeID] = now
	evictedTombstone, tombstoneEvicted := s.setLiveTombstoneLocked(nodeID, version, now)
	s.appendMutationLocked(clusterMutation{
		Kind:     clusterMessageRegistryDelete,
		NodeID:   nodeID,
		Version:  version,
		Origin:   version.Origin,
		FromLink: fromLink,
	})
	revision := s.revision
	s.mu.Unlock()

	if tombstoneEvicted {
		log.Printf("control state live tombstone evicted: node_id=%d", evictedTombstone)
	}
	if active {
		s.emit(mtypes.ControlV2EventPeerGone, nodeID, name, revision)
	}
	return true
}

func (s *ControlState) CommitParameters(parameters mtypes.ControlV2Parameters, version ClusterVersion, fromLink mtypes.Vertex) bool {
	applied, _ := s.commitParameters(parameters, version, fromLink)
	return applied
}

func (s *ControlState) commitParameters(parameters mtypes.ControlV2Parameters, version ClusterVersion, fromLink mtypes.Vertex) (bool, error) {
	if s == nil {
		return false, nil
	}
	if err := parameters.Validate(); err != nil {
		return false, err
	}
	if version.HLC != 0 {
		s.hlc.Observe(version.HLC)
	}

	s.mu.Lock()
	if !version.Newer(s.paramsVersion) {
		s.mu.Unlock()
		return false, nil
	}
	stored := cloneParameters(parameters)
	s.parameters = stored
	s.paramsVersion = version
	s.revision++
	s.appendMutationLocked(clusterMutation{
		Kind: clusterMessageParamsUpdate,
		Params: &clusterParams{
			Parameters: cloneParameters(stored),
			Version:    version,
		},
		Version:  version,
		Origin:   version.Origin,
		FromLink: fromLink,
	})
	revision := s.revision
	s.mu.Unlock()

	if s.publish != nil {
		s.publish(mtypes.ControlV2Event{
			Type:     mtypes.ControlV2EventParamsChange,
			Revision: revision,
			Data:     cloneParameters(stored),
		})
	}
	return true, nil
}

func (s *ControlState) ExportRegistry() ([]clusterRegistryEntry, []clusterRegistryTombstone, clusterParams) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	registry := make([]clusterRegistryEntry, 0, len(s.registry))
	for _, entry := range s.registry {
		registry = append(registry, entry)
	}
	sort.Slice(registry, func(i, j int) bool { return registry[i].NodeID < registry[j].NodeID })

	tombstones := make([]clusterRegistryTombstone, 0, len(s.registryTombstones))
	for nodeID, version := range s.registryTombstones {
		tombstones = append(tombstones, clusterRegistryTombstone{
			NodeID:    nodeID,
			Version:   version,
			Origin:    version.Origin,
			DeletedAt: s.registryTombstoneTimes[nodeID],
		})
	}
	sort.Slice(tombstones, func(i, j int) bool { return tombstones[i].NodeID < tombstones[j].NodeID })

	params := clusterParams{Parameters: cloneParameters(s.parameters), Version: s.paramsVersion}
	return registry, tombstones, params
}

func (s *ControlState) RegistryVersion(nodeID mtypes.Vertex) (ClusterVersion, bool) {
	if s == nil {
		return ClusterVersion{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registryVersionLocked(nodeID)
}

func (s *ControlState) registryVersionLocked(nodeID mtypes.Vertex) (ClusterVersion, bool) {
	entry, registryOK := s.registry[nodeID]
	version := entry.Version
	tombstone, tombstoneOK := s.registryTombstones[nodeID]
	if tombstoneOK && (!registryOK || !tombstone.Less(version)) {
		return tombstone, true
	}
	return version, registryOK
}

func (s *ControlState) effectiveNodeNameLocked(nodeID mtypes.Vertex) string {
	name := s.nodeNameLocked(nodeID)
	if name == "" {
		return ""
	}
	lowestID := nodeID
	for otherID := range s.registry {
		if otherID < lowestID && s.nodeNameLocked(otherID) == name {
			lowestID = otherID
		}
	}
	for otherID := range s.peers {
		if otherID < lowestID && s.nodeNameLocked(otherID) == name {
			lowestID = otherID
		}
	}
	if lowestID == nodeID {
		return name
	}
	return fmt.Sprintf("%s~%d", name, nodeID)
}

func (s *ControlState) nodeNameLocked(nodeID mtypes.Vertex) string {
	if entry, ok := s.registry[nodeID]; ok && entry.NodeName != "" {
		return entry.NodeName
	}
	if peer, ok := s.peers[nodeID]; ok {
		return peer.view.NodeName
	}
	return ""
}
