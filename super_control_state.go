package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	graphpath "github.com/KusakabeSi/EtherGuard-VPN/path"
)

var (
	// ErrControlStateUnknownPeer is returned by Report when the requested
	// NodeID has no peer entry in the Super's authorative state.
	ErrControlStateUnknownPeer = errors.New("control state: unknown peer")
	// ErrControlStateSpecialNodeID is returned by mutations that try to
	// register/delete/etc. a reserved (special) NodeID — 65532..65535 —
	// which by contract must never be assigned to a real Edge.
	ErrControlStateSpecialNodeID = errors.New("control state: reserved / special node id")
)

// ErrControlStateInvalidParameters is returned by UpdateParameters when the
// supplied ControlV2Parameters struct fails mtypes validation (zero or
// negative durations, empty STUN list, unsupported protocol version, etc.).
var ErrControlStateInvalidParameters = errors.New("control state: invalid parameters")

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
	candidateState := append([]mtypes.ControlV2Candidate{}, addressesToCandidates(req.LocalV4, mtypes.ControlV2CandidateLocal)...)
	candidateState = append(candidateState, addressesToCandidates(req.LocalV6, mtypes.ControlV2CandidateLocal)...)
	candidateState = append(candidateState, addressesToCandidates(req.PublicV4, mtypes.ControlV2CandidateSTUN)...)
	candidateState = append(candidateState, addressesToCandidates(req.PublicV6, mtypes.ControlV2CandidateSTUN)...)
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

// DeletePeer removes a peer entry previously inserted by Register / AddPeer
// from the Super's authorative state. It bumps the revision by exactly one
// when a peer is actually removed and emits a single peer_gone event after
// releasing the lock.
//
// Bumping semantics:
//   - If the NodeID does not exist, returns ErrControlStateUnknownPeer and
//     leaves the revision unchanged.
//   - If the NodeID is reserved / special (65532..65535), returns
//     ErrControlStateSpecialNodeID; reserved IDs must never reach this
//     method because validators reject them at the management boundary.
//
// Safe to call concurrently with Register / Report / SweepTimeouts.
func (s *ControlState) DeletePeer(ctx context.Context, nodeID mtypes.Vertex) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if nodeID.IsSpecial() {
		return ErrControlStateSpecialNodeID
	}
	s.mu.Lock()
	peer, ok := s.peers[nodeID]
	if !ok {
		s.mu.Unlock()
		return ErrControlStateUnknownPeer
	}
	delete(s.peers, nodeID)
	name := peer.view.NodeName
	s.revision++
	rev := s.revision
	s.mu.Unlock()
	s.emit(mtypes.ControlV2EventPeerGone, nodeID, name, rev)
	return nil
}

// UpdateParameters replaces the published control parameter stream (the
// same stream every Edge reads via /edge/v2/snapshot). It validates the
// supplied parameters exactly once via mtypes.ControlV2Parameters.Validate
// and bumps the revision by exactly one on a successful replacement.
//
// Returns ErrControlStateInvalidParameters when validation fails (the
// caller MUST translate mtypes.ControlV2Error into a typed response); the
// revision is unchanged in that case.
//
// The event type emitted on success is params_change so SSE consumers can
// distinguish control-plane configuration updates from peer churn.
func (s *ControlState) UpdateParameters(ctx context.Context, p mtypes.ControlV2Parameters) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := p.Validate(); err != nil {
		return ErrControlStateInvalidParameters
	}
	s.mu.Lock()
	s.parameters = cloneParameters(p)
	s.revision++
	rev := s.revision
	s.mu.Unlock()
	if s.publish != nil {
		s.publish(mtypes.ControlV2Event{
			Type:     mtypes.ControlV2EventParamsChange,
			Revision: rev,
			// Data carries the new parameter stream so SSE consumers
			// can observe the change without an extra snapshot fetch.
			// (Task 7's SSEParser caveat: data must be non-empty.)
			Data: cloneParameters(p),
		})
	}
	return nil
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
	peer.candidates = cloneCandidates(req.Candidates)
	peer.view.LastSeen = s.now()
	viewChanged := mergeCandidatesIntoView(&peer.view, peer.candidates)
	for _, pong := range req.Pongs {
		if pong.SourceNode != req.NodeID {
			continue
		}
		if peer.view.LatencyMS[pong.DestNode] != pong.LatencyMS {
			peer.view.LatencyMS[pong.DestNode] = pong.LatencyMS
			viewChanged = true
		}
		if s.graph != nil {
			s.graph.UpdateLatency(pong.SourceNode, pong.DestNode, pong.LatencyMS, pong.AliveSeconds, 0, true, true)
		}
	}
	if viewChanged {
		s.revision++
	}
	rev := s.revision
	s.mu.Unlock()
	if viewChanged {
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

// SetPublishForTest swaps the publish hook after construction. Production
// code wires the hook exactly once at startup; tests need a runtime seam so
// they can chain a countingPublish to a real hub without rebuilding the
// state from scratch. The method is named "ForTest" so accidental
// production use is obvious at the call site. Caller MUST serialise with
// concurrent Register / Report / SweepTimeouts calls (the test harness
// calls it before any traffic flows).
func (s *ControlState) SetPublishForTest(fn func(mtypes.ControlV2Event)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.publish = fn
	s.mu.Unlock()
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

// addressesToCandidates wraps raw address strings into typed candidate
// records with the given source so the register-time lists survive into
// the canonical controlPeerRecord.candidates list.
func addressesToCandidates(addresses []string, source mtypes.ControlV2CandidateSource) []mtypes.ControlV2Candidate {
	out := make([]mtypes.ControlV2Candidate, 0, len(addresses))
	for _, address := range addresses {
		out = append(out, mtypes.ControlV2Candidate{Address: address, Source: source})
	}
	return out
}

// mergeCandidatesIntoView rebuilds the LocalV4/LocalV6/PublicV4/PublicV6
// fields on view from the latest reported candidate list, partitioning by
// IP family and source. Returns true when any observable field changes,
// so the caller can decide whether the revision must bump.
func mergeCandidatesIntoView(view *mtypes.ControlV2Peer, candidates []mtypes.ControlV2Candidate) bool {
	var local4, local6, public4, public6 []string
	for _, candidate := range candidates {
		if candidate.Address == "" {
			continue
		}
		host, _, err := net.SplitHostPort(candidate.Address)
		if err != nil {
			host = candidate.Address
		}
		isV6 := func() bool {
			ip := net.ParseIP(host)
			return ip != nil && ip.To4() == nil
		}
		switch candidate.Source {
		case mtypes.ControlV2CandidateLocal:
			if isV6() {
				local6 = append(local6, candidate.Address)
			} else {
				local4 = append(local4, candidate.Address)
			}
		case mtypes.ControlV2CandidateSTUN:
			if isV6() {
				public6 = append(public6, candidate.Address)
			} else {
				public4 = append(public4, candidate.Address)
			}
		}
	}
	changed := !sameStrings(view.LocalV4, local4) || !sameStrings(view.LocalV6, local6) || !sameStrings(view.PublicV4, public4) || !sameStrings(view.PublicV6, public6)
	if changed {
		view.LocalV4 = local4
		view.LocalV6 = local6
		view.PublicV4 = public4
		view.PublicV6 = public6
	}
	return changed
}
