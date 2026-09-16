package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

const (
	registryTombstoneTTL      = 7 * 24 * time.Hour
	registryTombstoneCapacity = 4096
)

type clusterStateVersion struct {
	HLC    uint64        `yaml:"HLC"`
	Origin mtypes.Vertex `yaml:"Origin"`
}

func clusterStateVersionFrom(version ClusterVersion) clusterStateVersion {
	return clusterStateVersion{HLC: version.HLC, Origin: version.Origin}
}

func (version clusterStateVersion) clusterVersion() ClusterVersion {
	return ClusterVersion{HLC: version.HLC, Origin: version.Origin}
}

type clusterStateTombstone struct {
	NodeID    mtypes.Vertex `yaml:"NodeID"`
	HLC       uint64        `yaml:"HLC"`
	Origin    mtypes.Vertex `yaml:"Origin"`
	DeletedAt time.Time     `yaml:"DeletedAt"`
}

func (tombstone clusterStateTombstone) clusterVersion() ClusterVersion {
	return ClusterVersion{HLC: tombstone.HLC, Origin: tombstone.Origin}
}

type clusterStateFile struct {
	HLCHighWater       uint64                                `yaml:"HLCHighWater"`
	ParamsVersion      clusterStateVersion                   `yaml:"ParamsVersion"`
	Registry           map[mtypes.Vertex]clusterStateVersion `yaml:"Registry"`
	RegistryTombstones []clusterStateTombstone               `yaml:"RegistryTombstones"`
}

func loadClusterStateFile(path string) (clusterStateFile, error) {
	data, err := ioutil.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return clusterStateFile{Registry: make(map[mtypes.Vertex]clusterStateVersion)}, nil
	}
	if err != nil {
		return clusterStateFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	var state clusterStateFile
	if err := yaml.Unmarshal(data, &state); err != nil {
		return clusterStateFile{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if state.Registry == nil {
		state.Registry = make(map[mtypes.Vertex]clusterStateVersion)
	}
	return state, nil
}

func pruneClusterStateTombstones(state clusterStateFile, now time.Time) clusterStateFile {
	kept := make([]clusterStateTombstone, 0, len(state.RegistryTombstones))
	for _, tombstone := range state.RegistryTombstones {
		if tombstone.DeletedAt.Add(registryTombstoneTTL).After(now) {
			kept = append(kept, tombstone)
		}
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].DeletedAt.Equal(kept[j].DeletedAt) {
			return kept[i].NodeID < kept[j].NodeID
		}
		return kept[i].DeletedAt.Before(kept[j].DeletedAt)
	})
	if len(kept) > registryTombstoneCapacity {
		dropCount := len(kept) - registryTombstoneCapacity
		for _, tombstone := range kept[:dropCount] {
			log.Printf("manage v2 registry tombstone evicted: node_id=%d", tombstone.NodeID)
		}
		kept = append([]clusterStateTombstone(nil), kept[dropCount:]...)
	}
	state.RegistryTombstones = kept
	return state
}

// SetRegistryVersionsForSeed applies persisted versions without publishing
// events or appending startup mutations to the replication outbox.
func (s *ControlState) SetRegistryVersionsForSeed(peers []mtypes.SuperConfigV2Peer, persisted clusterStateFile, selfID mtypes.Vertex) {
	if s == nil {
		return
	}
	tombstones := make(map[mtypes.Vertex]clusterStateTombstone, len(persisted.RegistryTombstones))
	for _, tombstone := range persisted.RegistryTombstones {
		tombstones[tombstone.NodeID] = tombstone
	}

	s.mu.Lock()
	s.paramsVersion = persisted.ParamsVersion.clusterVersion()
	for _, peer := range peers {
		version, ok := persisted.Registry[peer.NodeID]
		if !ok {
			version = clusterStateVersion{Origin: selfID}
		}
		clusterVersion := version.clusterVersion()
		if tombstone, tombstoned := tombstones[peer.NodeID]; tombstoned && !clusterVersion.Newer(tombstone.clusterVersion()) {
			continue
		}
		s.registry[peer.NodeID] = clusterRegistryEntry{
			NodeID:         peer.NodeID,
			NodeName:       peer.NodeName,
			ControlPSKey:   peer.ControlPSKey,
			AdditionalCost: peer.AdditionalCost,
			Version:        clusterVersion,
			Origin:         clusterVersion.Origin,
		}
		delete(s.registryTombstones, peer.NodeID)
		delete(s.registryTombstoneTimes, peer.NodeID)
	}
	for _, tombstone := range persisted.RegistryTombstones {
		version := tombstone.clusterVersion()
		if current, ok := s.registryVersionLocked(tombstone.NodeID); ok && !version.Newer(current) {
			continue
		}
		delete(s.registry, tombstone.NodeID)
		s.registryTombstones[tombstone.NodeID] = version
		s.registryTombstoneTimes[tombstone.NodeID] = tombstone.DeletedAt
	}
	s.mu.Unlock()

	s.hlc.mu.Lock()
	if persisted.HLCHighWater > s.hlc.last {
		s.hlc.last = persisted.HLCHighWater
	}
	s.hlc.mu.Unlock()
}

func (m *ManageV2) persistClusterState() error {
	state, evicted := m.state.clusterStateForPersistence()
	for _, nodeID := range evicted {
		log.Printf("manage v2 registry tombstone evicted: node_id=%d", nodeID)
	}
	if err := m.writeYAML(m.clusterStateFile, state); err != nil {
		return fmt.Errorf("write cluster state: %w", err)
	}
	return nil
}

func (s *ControlState) clusterStateForPersistence() (clusterStateFile, []mtypes.Vertex) {
	now := s.now()
	s.mu.Lock()
	for nodeID, deletedAt := range s.registryTombstoneTimes {
		if !deletedAt.Add(registryTombstoneTTL).After(now) {
			delete(s.registryTombstoneTimes, nodeID)
			delete(s.registryTombstones, nodeID)
		}
	}

	type timedTombstone struct {
		nodeID    mtypes.Vertex
		deletedAt time.Time
	}
	ordered := make([]timedTombstone, 0, len(s.registryTombstones))
	for nodeID := range s.registryTombstones {
		ordered = append(ordered, timedTombstone{nodeID: nodeID, deletedAt: s.registryTombstoneTimes[nodeID]})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].deletedAt.Equal(ordered[j].deletedAt) {
			return ordered[i].nodeID < ordered[j].nodeID
		}
		return ordered[i].deletedAt.Before(ordered[j].deletedAt)
	})
	evicted := make([]mtypes.Vertex, 0)
	if len(ordered) > registryTombstoneCapacity {
		dropCount := len(ordered) - registryTombstoneCapacity
		evicted = make([]mtypes.Vertex, 0, dropCount)
		for _, item := range ordered[:dropCount] {
			delete(s.registryTombstoneTimes, item.nodeID)
			delete(s.registryTombstones, item.nodeID)
			evicted = append(evicted, item.nodeID)
		}
		ordered = ordered[dropCount:]
	}

	registry := make(map[mtypes.Vertex]clusterStateVersion, len(s.registry))
	for nodeID, entry := range s.registry {
		registry[nodeID] = clusterStateVersionFrom(entry.Version)
	}
	tombstones := make([]clusterStateTombstone, 0, len(ordered))
	for _, item := range ordered {
		version := s.registryTombstones[item.nodeID]
		tombstones = append(tombstones, clusterStateTombstone{
			NodeID:    item.nodeID,
			HLC:       version.HLC,
			Origin:    version.Origin,
			DeletedAt: item.deletedAt,
		})
	}
	paramsVersion := s.paramsVersion
	s.mu.Unlock()

	return clusterStateFile{
		HLCHighWater:       s.hlc.Current(),
		ParamsVersion:      clusterStateVersionFrom(paramsVersion),
		Registry:           registry,
		RegistryTombstones: tombstones,
	}, evicted
}

func (m *ManageV2) writeYAML(path string, value interface{}) error {
	if m.writeHook != nil {
		if err := m.writeHook(path); err != nil {
			return fmt.Errorf("write hook %s: %w", path, err)
		}
	}
	return atomicWriteYAML(path, value)
}
