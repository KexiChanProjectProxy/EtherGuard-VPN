package main

import (
	"log"
	"maps"
	"sort"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type replicatedPeerChange struct {
	kind     mtypes.ControlV2EventType
	nodeID   mtypes.Vertex
	nodeName string
}

type replicatedLatencyUpdate struct {
	source  mtypes.Vertex
	dest    mtypes.Vertex
	latency float64
}

func (s *ControlState) ApplyReplicatedPeer(rec clusterPeerRecord, fromLink mtypes.Vertex) (applied bool) {
	return s.ApplyReplicatedBatch([]clusterPeerRecord{rec}, nil, fromLink) == 1
}

func (s *ControlState) ApplyReplicatedAlive(a clusterAlive, fromLink mtypes.Vertex) bool {
	s.hlc.Observe(a.Version.HLC)
	s.mu.Lock()
	peer, exists := s.peers[a.NodeID]
	if !exists || peer.origin != a.Version.Origin || !a.Version.Newer(peer.version) {
		s.mu.Unlock()
		return false
	}
	if tombstone, exists := s.liveTombstones[a.NodeID]; exists && !a.Version.Newer(tombstone) {
		s.mu.Unlock()
		return false
	}
	peer.version = a.Version
	peer.receivedAt = s.now()
	peer.view.LastSeen = a.LastSeen
	s.appendMutationLocked(clusterMutation{
		Kind:     clusterMessagePeerAlive,
		NodeID:   a.NodeID,
		Alive:    &clusterAlive{NodeID: a.NodeID, Version: a.Version, LastSeen: a.LastSeen},
		Version:  a.Version,
		Origin:   peer.origin,
		FromLink: fromLink,
	})
	s.mu.Unlock()
	return true
}

func (s *ControlState) ApplyReplicatedDelete(d clusterDelete, fromLink mtypes.Vertex) bool {
	return s.ApplyReplicatedBatch(nil, []clusterDelete{d}, fromLink) == 1
}

func (s *ControlState) ApplyReplicatedBatch(live []clusterPeerRecord, tombs []clusterDelete, fromLink mtypes.Vertex) (appliedCount int) {
	for i := range live {
		s.hlc.Observe(live[i].Version.HLC)
	}
	for i := range tombs {
		s.hlc.Observe(tombs[i].Version.HLC)
	}

	s.mu.Lock()
	changes := make(map[mtypes.Vertex]replicatedPeerChange)
	latencyUpdates := make([]replicatedLatencyUpdate, 0)
	evictedTombstones := make([]mtypes.Vertex, 0)
	for i := range live {
		applied, changed, updates := s.applyReplicatedPeerLocked(live[i], fromLink)
		if !applied {
			continue
		}
		appliedCount++
		latencyUpdates = append(latencyUpdates, updates...)
		if changed {
			changes[live[i].NodeID] = replicatedPeerChange{kind: mtypes.ControlV2EventPeerChange, nodeID: live[i].NodeID, nodeName: live[i].NodeName}
		}
	}
	for i := range tombs {
		applied, change, evicted, didEvict := s.applyReplicatedDeleteLocked(tombs[i], fromLink)
		if !applied {
			continue
		}
		appliedCount++
		if change != nil {
			changes[change.nodeID] = *change
		}
		if didEvict {
			evictedTombstones = append(evictedTombstones, evicted)
		}
	}

	var event *mtypes.ControlV2Event
	if len(changes) > 0 {
		s.revision++
		event = replicatedBatchEvent(changes, s.revision)
	}
	aliveSeconds := s.peerAliveTimeout.Seconds()
	publish := s.publish
	s.mu.Unlock()

	for _, nodeID := range evictedTombstones {
		log.Printf("control state live tombstone evicted: node_id=%d", nodeID)
	}
	if s.graph != nil {
		for _, update := range latencyUpdates {
			s.graph.UpdateLatency(update.source, update.dest, update.latency, aliveSeconds, 0, true, true)
		}
	}
	if event != nil && publish != nil {
		publish(*event)
	}
	return appliedCount
}

func (s *ControlState) ExportLive() ([]clusterPeerRecord, []clusterDelete) {
	s.mu.RLock()
	live := make([]clusterPeerRecord, 0, len(s.peers))
	for _, peer := range s.peers {
		live = append(live, *s.recordToClusterPeerLocked(peer))
	}
	tombstones := make([]clusterDelete, 0, len(s.liveTombstones))
	for nodeID, version := range s.liveTombstones {
		tombstones = append(tombstones, clusterDelete{NodeID: nodeID, Version: version})
	}
	s.mu.RUnlock()
	sort.Slice(live, func(i, j int) bool { return live[i].NodeID < live[j].NodeID })
	sort.Slice(tombstones, func(i, j int) bool { return tombstones[i].NodeID < tombstones[j].NodeID })
	return live, tombstones
}

func (s *ControlState) applyReplicatedPeerLocked(rec clusterPeerRecord, fromLink mtypes.Vertex) (bool, bool, []replicatedLatencyUpdate) {
	if tombstone, exists := s.liveTombstones[rec.NodeID]; exists && !rec.Version.Newer(tombstone) {
		return false, false, nil
	}
	previous, exists := s.peers[rec.NodeID]
	if exists && !rec.Version.Newer(previous.version) {
		return false, false, nil
	}

	previousTargets := s.observedTargetsForObserverLocked(rec.NodeID)
	hintTargets := append(previousTargets, rec.NodeID)
	hintTargets = append(hintTargets, observedTargets(rec.Observed)...)
	beforeHints := s.observedHintsForTargetsLocked(hintTargets)
	acceptedAt := s.now()
	candidates := append([]mtypes.ControlV2Candidate(nil), rec.Candidates...)
	view := mtypes.ControlV2Peer{
		NodeID: rec.NodeID, NodeName: rec.NodeName, PubKey: rec.PubKey,
		RelayCostMS: cloneFloat64Ptr(rec.RelayCostMS), LatencyMS: cloneLatency(rec.LatencyMS), LastSeen: rec.LastSeen,
	}
	mergeCandidatesIntoView(&view, candidates)
	controlKey := ""
	if entry, registered := s.registry[rec.NodeID]; registered {
		controlKey = entry.ControlPSKey
	}
	record := &controlPeerRecord{
		view: view, controlKey: controlKey, candidates: candidates, origin: rec.Origin,
		version: rec.Version, receivedAt: acceptedAt, observed: append([]mtypes.ControlV2ObservedEndpoint(nil), rec.Observed...),
	}
	latencyChanged := !exists || !maps.Equal(previous.view.LatencyMS, view.LatencyMS)
	viewChanged := !exists || !sameReplicatedPeerView(previous.view, view)
	s.peers[rec.NodeID] = record
	s.clearObservedVotesForObserverLocked(rec.NodeID)
	for _, observation := range rec.Observed {
		votes := s.observedVotes[observation.TargetNodeID]
		if votes == nil {
			votes = make(map[mtypes.Vertex]controlObservedVote)
			s.observedVotes[observation.TargetNodeID] = votes
		}
		votes[rec.NodeID] = controlObservedVote{address: observation.Address, receivedAt: acceptedAt}
	}
	changed := viewChanged || s.observedHintsChangedLocked(beforeHints)
	s.appendMutationLocked(clusterMutation{
		Kind: clusterMessagePeerUpsert, NodeID: rec.NodeID, Peer: s.recordToClusterPeerLocked(record),
		Version: rec.Version, Origin: rec.Origin, FromLink: fromLink,
	})
	if !latencyChanged {
		return true, changed, nil
	}
	updates := make([]replicatedLatencyUpdate, 0, len(view.LatencyMS))
	for dest, latency := range view.LatencyMS {
		updates = append(updates, replicatedLatencyUpdate{source: rec.NodeID, dest: dest, latency: latency})
	}
	return true, changed, updates
}

func (s *ControlState) applyReplicatedDeleteLocked(d clusterDelete, fromLink mtypes.Vertex) (bool, *replicatedPeerChange, mtypes.Vertex, bool) {
	if tombstone, exists := s.liveTombstones[d.NodeID]; exists && !d.Version.Newer(tombstone) {
		return false, nil, 0, false
	}
	now := s.now()
	evicted, didEvict := s.setLiveTombstoneLocked(d.NodeID, d.Version, now)
	var change *replicatedPeerChange
	if peer, exists := s.peers[d.NodeID]; exists && d.Version.Newer(peer.version) {
		change = &replicatedPeerChange{kind: mtypes.ControlV2EventPeerGone, nodeID: d.NodeID, nodeName: peer.view.NodeName}
		delete(s.peers, d.NodeID)
		s.clearObservedVotesForObserverLocked(d.NodeID)
		delete(s.observedVotes, d.NodeID)
	}
	s.appendMutationLocked(clusterMutation{
		Kind: clusterMessagePeerDelete, NodeID: d.NodeID, Version: d.Version,
		Origin: d.Version.Origin, FromLink: fromLink,
	})
	return true, change, evicted, didEvict
}

func replicatedBatchEvent(changes map[mtypes.Vertex]replicatedPeerChange, revision uint64) *mtypes.ControlV2Event {
	if len(changes) > 1 {
		return &mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision, Revision: revision, Data: mtypes.ControlV2PeerChangePayload{}}
	}
	for _, change := range changes {
		return &mtypes.ControlV2Event{
			Type: change.kind, Revision: revision,
			Data: mtypes.ControlV2PeerChangePayload{NodeID: change.nodeID, NodeName: change.nodeName},
		}
	}
	return nil
}

func sameReplicatedPeerView(a, b mtypes.ControlV2Peer) bool {
	return a.NodeID == b.NodeID && a.NodeName == b.NodeName && a.PubKey == b.PubKey &&
		sameFloat64Pointers(a.RelayCostMS, b.RelayCostMS) && maps.Equal(a.LatencyMS, b.LatencyMS) && a.LastSeen.Equal(b.LastSeen) &&
		sameStrings(a.LocalV4, b.LocalV4) && sameStrings(a.LocalV6, b.LocalV6) &&
		sameStrings(a.PublicV4, b.PublicV4) && sameStrings(a.PublicV6, b.PublicV6)
}

func sameFloat64Pointers(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
