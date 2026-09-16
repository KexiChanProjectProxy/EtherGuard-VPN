package main

import (
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const (
	clusterOutboxCapacity      = 4096
	liveTombstoneCapacity      = 4096
	minimumLiveTombstoneExpiry = 10 * time.Minute
)

type clusterMutation struct {
	Seq      uint64
	Kind     string
	NodeID   mtypes.Vertex
	Peer     *clusterPeerRecord
	Alive    *clusterAlive
	Registry *clusterRegistryEntry
	Params   *clusterParams
	Version  ClusterVersion
	Origin   mtypes.Vertex
	FromLink mtypes.Vertex
}

type clusterAlive struct {
	NodeID   mtypes.Vertex
	Version  ClusterVersion
	LastSeen time.Time
}

type clusterDelete struct {
	NodeID  mtypes.Vertex
	Version ClusterVersion
}

type originLinkStatus struct {
	up    bool
	since time.Time
}

func (s *ControlState) appendMutationLocked(mutation clusterMutation) {
	s.outboxSeq++
	mutation.Seq = s.outboxSeq
	if s.resyncNeeded {
		return
	}
	if len(s.outbox) == s.outboxCap {
		s.outbox = nil
		s.resyncNeeded = true
		s.notifyOutboxLocked()
		return
	}
	s.outbox = append(s.outbox, mutation)
	s.notifyOutboxLocked()
}

func (s *ControlState) notifyOutboxLocked() {
	select {
	case s.outboxNotify <- struct{}{}:
	default:
	}
}

func (s *ControlState) recordToClusterPeerLocked(record *controlPeerRecord) *clusterPeerRecord {
	return &clusterPeerRecord{
		NodeID:      record.view.NodeID,
		NodeName:    record.view.NodeName,
		PubKey:      record.view.PubKey,
		Candidates:  append([]mtypes.ControlV2Candidate(nil), record.candidates...),
		RelayCostMS: cloneFloat64Ptr(record.view.RelayCostMS),
		LatencyMS:   cloneLatency(record.view.LatencyMS),
		Observed:    append([]mtypes.ControlV2ObservedEndpoint(nil), record.observed...),
		LastSeen:    record.view.LastSeen,
		Version:     record.version,
		Origin:      record.origin,
	}
}

func (s *ControlState) setLiveTombstoneLocked(nodeID mtypes.Vertex, version ClusterVersion, deletedAt time.Time) (mtypes.Vertex, bool) {
	if current, ok := s.liveTombstones[nodeID]; ok && !version.Newer(current) {
		return 0, false
	}
	s.liveTombstones[nodeID] = version
	s.liveTombstoneTimes[nodeID] = deletedAt
	if len(s.liveTombstones) <= liveTombstoneCapacity {
		return 0, false
	}
	var oldestID mtypes.Vertex
	var oldestAt time.Time
	first := true
	for id, at := range s.liveTombstoneTimes {
		if first || at.Before(oldestAt) || (at.Equal(oldestAt) && id < oldestID) {
			oldestID = id
			oldestAt = at
			first = false
		}
	}
	delete(s.liveTombstones, oldestID)
	delete(s.liveTombstoneTimes, oldestID)
	return oldestID, true
}

func (s *ControlState) sweepLiveTombstonesLocked(now time.Time) {
	ttl := 2 * s.peerAliveTimeout
	if ttl < minimumLiveTombstoneExpiry {
		ttl = minimumLiveTombstoneExpiry
	}
	for nodeID, deletedAt := range s.liveTombstoneTimes {
		if deletedAt.Add(ttl).After(now) {
			continue
		}
		delete(s.liveTombstoneTimes, nodeID)
		delete(s.liveTombstones, nodeID)
	}
}

func (s *ControlState) DrainOutbox() (muts []clusterMutation, resync bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	muts = s.outbox
	s.outbox = nil
	resync = s.resyncNeeded
	s.resyncNeeded = false
	return muts, resync
}

func (s *ControlState) OutboxNotify() <-chan struct{} {
	return s.outboxNotify
}

func (s *ControlState) ClusterEnabled() bool {
	return s != nil && s.selfID != 0
}

func (s *ControlState) SetOriginLinkStatus(origin mtypes.Vertex, up bool, at time.Time) {
	s.mu.Lock()
	s.originLinks[origin] = originLinkStatus{up: up, since: at}
	s.mu.Unlock()
}

func (s *ControlState) MarkResyncNeeded() {
	s.mu.Lock()
	s.outbox = nil
	s.resyncNeeded = true
	s.notifyOutboxLocked()
	s.mu.Unlock()
}
