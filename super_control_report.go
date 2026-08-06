package main

import (
	"context"
	"maps"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func (s *ControlState) Report(ctx context.Context, req mtypes.ControlV2ReportRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := req.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	peer, ok := s.peers[req.NodeID]
	if !ok {
		s.mu.Unlock()
		return ErrControlStateUnknownPeer
	}
	previousTargets := s.observedTargetsForObserverLocked(req.NodeID)
	reportedTargets := make(map[mtypes.Vertex]struct{}, len(req.Observed))
	hintTargets := append(previousTargets, observedTargets(req.Observed)...)
	beforeObserved := s.observedHintsForTargetsLocked(hintTargets)
	candidates, filterErr := s.filterCandidatesLocked(req.Candidates)
	if filterErr != nil {
		s.mu.Unlock()
		return filterErr
	}
	peer.candidates = candidates
	peer.view.LastSeen = s.now()
	viewChanged := mergeCandidatesIntoView(&peer.view, peer.candidates)
	if req.RelayCostMS != nil && (peer.view.RelayCostMS == nil || *peer.view.RelayCostMS != *req.RelayCostMS) {
		peer.view.RelayCostMS = cloneFloat64Ptr(req.RelayCostMS)
		viewChanged = true
	}
	latencies := make(map[mtypes.Vertex]float64, len(req.Pongs))
	for _, pong := range req.Pongs {
		if pong.SourceNode != req.NodeID {
			continue
		}
		latencies[pong.DestNode] = pong.LatencyMS
		if s.graph != nil {
			s.graph.UpdateLatency(pong.SourceNode, pong.DestNode, pong.LatencyMS, pong.AliveSeconds, 0, true, true)
		}
	}
	if !maps.Equal(peer.view.LatencyMS, latencies) {
		peer.view.LatencyMS = latencies
		viewChanged = true
	}
	for _, observation := range req.Observed {
		reportedTargets[observation.TargetNodeID] = struct{}{}
		votes := s.observedVotes[observation.TargetNodeID]
		if votes == nil {
			votes = make(map[mtypes.Vertex]controlObservedVote)
			s.observedVotes[observation.TargetNodeID] = votes
		}
		votes[req.NodeID] = controlObservedVote{address: observation.Address, receivedAt: s.now()}
	}
	for _, target := range previousTargets {
		if _, reported := reportedTargets[target]; reported {
			continue
		}
		votes := s.observedVotes[target]
		delete(votes, req.NodeID)
		if len(votes) == 0 {
			delete(s.observedVotes, target)
		}
	}
	viewChanged = viewChanged || s.observedHintsChangedLocked(beforeObserved)
	if viewChanged {
		s.revision++
	}
	rev := s.revision
	name := peer.view.NodeName
	s.mu.Unlock()
	if viewChanged {
		s.emit(mtypes.ControlV2EventPeerChange, req.NodeID, name, rev)
	}
	return nil
}
