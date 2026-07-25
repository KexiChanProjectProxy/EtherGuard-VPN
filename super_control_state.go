package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	graphpath "github.com/KusakabeSi/EtherGuard-VPN/path"
)

var ErrControlStateUnknownPeer = errors.New("control state: unknown peer")

type ControlStateConfig struct {
	Parameters         mtypes.ControlV2Parameters
	PeerAliveTimeout   time.Duration
	UsePSKForInterEdge bool
	Graph              *graphpath.IG
	Now                func() time.Time
	Publish            func(mtypes.ControlV2Event)
}

type controlPeerRecord struct {
	view       mtypes.ControlV2Peer
	controlKey string
	candidates []mtypes.ControlV2Candidate
}

type ControlState struct {
	mu                 sync.RWMutex
	peers              map[mtypes.Vertex]*controlPeerRecord
	parameters         mtypes.ControlV2Parameters
	graph              *graphpath.IG
	peerAliveTimeout   time.Duration
	usePSKForInterEdge bool
	now                func() time.Time
	publish            func(mtypes.ControlV2Event)
	revision           uint64
}

func NewControlState(config ControlStateConfig) *ControlState {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &ControlState{peers: make(map[mtypes.Vertex]*controlPeerRecord), parameters: cloneParameters(config.Parameters), graph: config.Graph, peerAliveTimeout: config.PeerAliveTimeout, usePSKForInterEdge: config.UsePSKForInterEdge, now: now, publish: config.Publish}
}

func (s *ControlState) Register(ctx context.Context, req mtypes.ControlV2RegisterRequest, controlPSKey string) (mtypes.ControlV2Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return mtypes.ControlV2Snapshot{}, err
	}
	if err := req.Validate(); err != nil {
		return mtypes.ControlV2Snapshot{}, err
	}
	if controlPSKey == "" {
		return mtypes.ControlV2Snapshot{}, errors.New("control state: empty control key")
	}
	s.mu.Lock()
	old, exists := s.peers[req.NodeID]
	candidateState := make([]mtypes.ControlV2Candidate, 0, len(req.LocalV4)+len(req.LocalV6)+len(req.PublicV4)+len(req.PublicV6))
	for _, address := range append(append(append(append([]string{}, req.LocalV4...), req.LocalV6...), req.PublicV4...), req.PublicV6...) {
		candidateState = append(candidateState, mtypes.ControlV2Candidate{Address: address, Source: mtypes.ControlV2CandidateLocal})
	}
	view := mtypes.ControlV2Peer{NodeID: req.NodeID, NodeName: req.NodeName, LocalV4: append([]string{}, req.LocalV4...), LocalV6: append([]string{}, req.LocalV6...), PublicV4: append([]string{}, req.PublicV4...), PublicV6: append([]string{}, req.PublicV6...), LatencyMS: map[mtypes.Vertex]float64{}, LastSeen: s.now()}
	changed := !exists || old.view.NodeName != view.NodeName || old.view.LastSeen.IsZero() || old.controlKey != controlPSKey
	if exists {
		view.PubKey, view.LatencyMS = old.view.PubKey, cloneLatency(old.view.LatencyMS)
		changed = changed || !sameStrings(old.view.LocalV4, view.LocalV4) || !sameStrings(old.view.LocalV6, view.LocalV6) || !sameStrings(old.view.PublicV4, view.PublicV4) || !sameStrings(old.view.PublicV6, view.PublicV6)
	}
	s.peers[req.NodeID] = &controlPeerRecord{view: view, controlKey: controlPSKey, candidates: candidateState}
	if changed {
		s.revision++
	}
	rev := s.revision
	snapshot := s.snapshotLocked(req.NodeID, rev)
	s.mu.Unlock()
	if changed {
		s.emit(mtypes.ControlV2EventPeerChange, req.NodeID, req.NodeName, rev)
	}
	return snapshot, nil
}

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
	changed := !sameCandidates(peer.candidates, req.Candidates)
	peer.candidates = cloneCandidates(req.Candidates)
	peer.view.LastSeen = s.now()
	for _, pong := range req.Pongs {
		if pong.SourceNode != req.NodeID {
			continue
		}
		if peer.view.LatencyMS[pong.DestNode] != pong.LatencyMS {
			peer.view.LatencyMS[pong.DestNode] = pong.LatencyMS
			changed = true
		}
		if s.graph != nil {
			s.graph.UpdateLatency(pong.SourceNode, pong.DestNode, pong.LatencyMS, pong.AliveSeconds, 0, true, true)
		}
	}
	if changed {
		s.revision++
	}
	rev := s.revision
	s.mu.Unlock()
	if changed {
		s.emit(mtypes.ControlV2EventPeerChange, req.NodeID, peer.view.NodeName, rev)
	}
	return nil
}

func (s *ControlState) SnapshotFor(nodeID mtypes.Vertex) mtypes.ControlV2Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked(nodeID, s.revision)
}

func (s *ControlState) ControlKeyFor(nodeID mtypes.Vertex) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peer, ok := s.peers[nodeID]
	if !ok {
		return "", false
	}
	return peer.controlKey, true
}

func (s *ControlState) Revision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *ControlState) SweepTimeouts() int {
	now := s.now()
	s.mu.Lock()
	removed := 0
	var events []mtypes.ControlV2PeerChangePayload
	for id, peer := range s.peers {
		if s.peerAliveTimeout > 0 && !peer.view.LastSeen.Add(s.peerAliveTimeout).After(now) {
			events = append(events, mtypes.ControlV2PeerChangePayload{NodeID: id, NodeName: peer.view.NodeName})
			delete(s.peers, id)
			removed++
		}
	}
	if removed > 0 {
		s.revision++
	}
	rev := s.revision
	s.mu.Unlock()
	for _, event := range events {
		s.emit(mtypes.ControlV2EventPeerGone, event.NodeID, event.NodeName, rev)
	}
	return removed
}

func (s *ControlState) snapshotLocked(requester mtypes.Vertex, revision uint64) mtypes.ControlV2Snapshot {
	peers := make([]mtypes.ControlV2Peer, 0, len(s.peers))
	for id, record := range s.peers {
		if id == requester {
			continue
		}
		peer := record.view
		peer.PSKey = ""
		peer.LocalV4 = append([]string{}, peer.LocalV4...)
		peer.LocalV6 = append([]string{}, peer.LocalV6...)
		peer.PublicV4 = append([]string{}, peer.PublicV4...)
		peer.PublicV6 = append([]string{}, peer.PublicV6...)
		peer.LatencyMS = cloneLatency(peer.LatencyMS)
		peers = append(peers, peer)
	}
	return mtypes.ControlV2Snapshot{Revision: revision, IssuedAt: s.now(), Parameters: cloneParameters(s.parameters), Peers: peers}
}

func (s *ControlState) emit(kind mtypes.ControlV2EventType, id mtypes.Vertex, name string, revision uint64) {
	if s.publish != nil {
		s.publish(mtypes.ControlV2Event{Type: kind, Revision: revision, Data: mtypes.ControlV2PeerChangePayload{NodeID: id, NodeName: name}})
	}
}
func cloneLatency(in map[mtypes.Vertex]float64) map[mtypes.Vertex]float64 {
	out := make(map[mtypes.Vertex]float64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func cloneCandidates(in []mtypes.ControlV2Candidate) []mtypes.ControlV2Candidate {
	return append([]mtypes.ControlV2Candidate{}, in...)
}
func cloneParameters(in mtypes.ControlV2Parameters) mtypes.ControlV2Parameters {
	in.STUNServers = append([]string{}, in.STUNServers...)
	return in
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func sameCandidates(a, b []mtypes.ControlV2Candidate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Test clock is shared by the TDD tests below; the production state
// service accepts any Now func, so we expose this only inside _test.go.
var testClockNanos atomic.Int64

func currentTime() time.Time {
	return time.Unix(0, testClockNanos.Load())
}

func advance(d time.Duration) {
	testClockNanos.Add(int64(d))
}

type timeValue = time.Time
