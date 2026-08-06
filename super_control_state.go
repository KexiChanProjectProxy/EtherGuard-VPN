package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
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

type controlObservedVote struct {
	address    string
	receivedAt time.Time
}

type ControlState struct {
	mu    sync.RWMutex
	peers map[mtypes.Vertex]*controlPeerRecord
	// preauthorized is the liveness-independent configured-key registry:
	// each NodeID holds AT MOST ONE control PSKey, installed directly from
	// SuperConfigV2.Peers at startup or via the ManageV2 service. The
	// registry exists so authentication can resolve credentials for an
	// Edge whose active peer record has been swept by SweepTimeouts (or
	// has never registered at all). SweepTimeouts MUST NOT mutate it.
	preauthorized      map[mtypes.Vertex]string
	observedVotes      map[mtypes.Vertex]map[mtypes.Vertex]controlObservedVote
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
	return &ControlState{
		peers:              make(map[mtypes.Vertex]*controlPeerRecord),
		preauthorized:      make(map[mtypes.Vertex]string),
		observedVotes:      make(map[mtypes.Vertex]map[mtypes.Vertex]controlObservedVote),
		parameters:         cloneParameters(config.Parameters),
		graph:              config.Graph,
		peerAliveTimeout:   config.PeerAliveTimeout,
		usePSKForInterEdge: config.UsePSKForInterEdge,
		now:                now,
		publish:            config.Publish,
	}
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
	observedTargets := s.observedTargetsForObserverLocked(req.NodeID)
	observedTargets = append(observedTargets, req.NodeID)
	beforeObserved := s.observedHintsForTargetsLocked(observedTargets)
	candidateState := append([]mtypes.ControlV2Candidate{}, addressesToCandidates(req.LocalV4, mtypes.ControlV2CandidateLocal)...)
	candidateState = append(candidateState, addressesToCandidates(req.LocalV6, mtypes.ControlV2CandidateLocal)...)
	candidateState = append(candidateState, addressesToCandidates(req.PublicV4, mtypes.ControlV2CandidateSTUN)...)
	candidateState = append(candidateState, addressesToCandidates(req.PublicV6, mtypes.ControlV2CandidateSTUN)...)
	candidateState, filterErr := s.filterCandidatesLocked(candidateState)
	if filterErr != nil {
		s.mu.Unlock()
		return mtypes.ControlV2Snapshot{}, filterErr
	}
	view := mtypes.ControlV2Peer{NodeID: req.NodeID, NodeName: req.NodeName, PubKey: req.PubKey, LatencyMS: map[mtypes.Vertex]float64{}, LastSeen: s.now()}
	mergeCandidatesIntoView(&view, candidateState)
	changed := !exists || old.view.NodeName != view.NodeName || old.view.PubKey != view.PubKey || old.view.LastSeen.IsZero() || old.controlKey != controlPSKey
	if exists {
		view.LatencyMS = cloneLatency(old.view.LatencyMS)
		changed = changed || !sameStrings(old.view.LocalV4, view.LocalV4) || !sameStrings(old.view.LocalV6, view.LocalV6) || !sameStrings(old.view.PublicV4, view.PublicV4) || !sameStrings(old.view.PublicV6, view.PublicV6)
		view.RelayCostMS = cloneFloat64Ptr(old.view.RelayCostMS)
	}
	s.peers[req.NodeID] = &controlPeerRecord{view: view, controlKey: controlPSKey, candidates: candidateState}
	s.clearObservedVotesForObserverLocked(req.NodeID)
	changed = changed || s.observedHintsChangedLocked(beforeObserved)
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
	delete(s.preauthorized, nodeID)
	s.clearObservedVotesForObserverLocked(nodeID)
	delete(s.observedVotes, nodeID)
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

func (s *ControlState) SnapshotFor(nodeID mtypes.Vertex) mtypes.ControlV2Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked(nodeID, s.revision)
}

func (s *ControlState) ControlKeyFor(nodeID mtypes.Vertex) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// The pre-authorized registry is the liveness-independent source of
	// truth for credentials — it survives SweepTimeouts and lets an Edge
	// re-authenticate after being offline longer than PeerAliveTimeout.
	// The active peer map may carry a fresher copy while the Edge is
	// online; prefer it when present so key rotation in the registry has
	// already propagated by the time auth runs.
	if peer, ok := s.peers[nodeID]; ok {
		return peer.controlKey, true
	}
	if key, ok := s.preauthorized[nodeID]; ok && key != "" {
		return key, true
	}
	return "", false
}

// SetPreAuthorized installs or replaces the configured control PSKey for
// the given NodeID. It holds the write lock; callers MUST NOT be holding
// any ControlState lock already. An empty pskey removes the entry (so
// deletion and rollback paths share the same seam). The operation never
// touches the active peer record — the Edge's own Register call is the
// only way to publish an active record.
func (s *ControlState) SetPreAuthorized(nodeID mtypes.Vertex, pskey string) {
	if s == nil || nodeID.IsSpecial() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if pskey == "" {
		delete(s.preauthorized, nodeID)
		return
	}
	s.preauthorized[nodeID] = pskey
}

// RemovePreAuthorized drops any configured key for the given NodeID. It
// is a no-op when the NodeID is absent, so ManageV2 delete/rollback
// paths can call it unconditionally.
func (s *ControlState) RemovePreAuthorized(nodeID mtypes.Vertex) {
	if s == nil || nodeID.IsSpecial() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.preauthorized, nodeID)
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
	type affectedPeer struct {
		name string
		kind mtypes.ControlV2EventType
	}
	affected := make(map[mtypes.Vertex]affectedPeer)
	beforeObserved := s.observedHintsForTargetsLocked(observedVoteTargets(s.observedVotes))
	for target, votes := range s.observedVotes {
		for observer, vote := range votes {
			if s.peerAliveTimeout > 0 && !vote.receivedAt.Add(s.peerAliveTimeout).After(now) {
				delete(votes, observer)
				if peer, ok := s.peers[target]; ok {
					affected[target] = affectedPeer{name: peer.view.NodeName, kind: mtypes.ControlV2EventPeerChange}
				}
			}
		}
		if len(votes) == 0 {
			delete(s.observedVotes, target)
		}
	}
	for id, peer := range s.peers {
		if s.peerAliveTimeout > 0 && !peer.view.LastSeen.Add(s.peerAliveTimeout).After(now) {
			affected[id] = affectedPeer{name: peer.view.NodeName, kind: mtypes.ControlV2EventPeerGone}
			delete(s.peers, id)
			s.clearObservedVotesForObserverLocked(id)
			delete(s.observedVotes, id)
			removed++
		}
	}
	changed := removed > 0 || s.observedHintsChangedLocked(beforeObserved)
	if changed {
		s.revision++
	}
	rev := s.revision
	var event *mtypes.ControlV2PeerChangePayload
	eventKind := mtypes.ControlV2EventPeerChange
	if changed {
		for id, affectedPeer := range affected {
			if event == nil || id < event.NodeID {
				event = &mtypes.ControlV2PeerChangePayload{NodeID: id, NodeName: affectedPeer.name}
				eventKind = affectedPeer.kind
			}
		}
	}
	s.mu.Unlock()
	if event != nil {
		s.emit(eventKind, event.NodeID, event.NodeName, rev)
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
		peer.RelayCostMS = cloneFloat64Ptr(peer.RelayCostMS)
		peer.ObservedV4, peer.ObservedV6 = s.observedHintsLocked(id)
		peer.LatencyMS = cloneLatency(peer.LatencyMS)
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].NodeID < peers[j].NodeID })
	return mtypes.ControlV2Snapshot{Revision: revision, IssuedAt: s.now(), Parameters: cloneParameters(s.parameters), Peers: peers}
}

func (s *ControlState) observedTargetsForObserverLocked(observer mtypes.Vertex) []mtypes.Vertex {
	targets := make([]mtypes.Vertex, 0)
	for target, votes := range s.observedVotes {
		if _, ok := votes[observer]; ok {
			targets = append(targets, target)
		}
	}
	return targets
}

func (s *ControlState) clearObservedVotesForObserverLocked(observer mtypes.Vertex) {
	for target, votes := range s.observedVotes {
		delete(votes, observer)
		if len(votes) == 0 {
			delete(s.observedVotes, target)
		}
	}
}

func observedTargets(observations []mtypes.ControlV2ObservedEndpoint) []mtypes.Vertex {
	targets := make([]mtypes.Vertex, 0, len(observations))
	for _, observation := range observations {
		targets = append(targets, observation.TargetNodeID)
	}
	return targets
}

func observedVoteTargets(votes map[mtypes.Vertex]map[mtypes.Vertex]controlObservedVote) []mtypes.Vertex {
	targets := make([]mtypes.Vertex, 0, len(votes))
	for target := range votes {
		targets = append(targets, target)
	}
	return targets
}

func (s *ControlState) observedHintsForTargetsLocked(targets []mtypes.Vertex) map[mtypes.Vertex][]mtypes.ControlV2ObservedAddress {
	hints := make(map[mtypes.Vertex][]mtypes.ControlV2ObservedAddress, len(targets))
	for _, target := range targets {
		v4, v6 := s.observedHintsLocked(target)
		hints[target] = append(v4, v6...)
	}
	return hints
}

func (s *ControlState) observedHintsChangedLocked(before map[mtypes.Vertex][]mtypes.ControlV2ObservedAddress) bool {
	for target, oldHints := range before {
		v4, v6 := s.observedHintsLocked(target)
		if !sameObservedHints(oldHints, append(v4, v6...)) {
			return true
		}
	}
	return false
}

func (s *ControlState) observedHintsLocked(target mtypes.Vertex) ([]mtypes.ControlV2ObservedAddress, []mtypes.ControlV2ObservedAddress) {
	record, ok := s.peers[target]
	if !ok {
		return nil, nil
	}
	selfCandidates := make(map[string]struct{}, len(record.candidates))
	for _, candidate := range record.candidates {
		selfCandidates[candidate.Address] = struct{}{}
	}
	counts := make(map[string]uint32)
	for _, vote := range s.observedVotes[target] {
		if _, self := selfCandidates[vote.address]; !self {
			counts[vote.address]++
		}
	}
	type observedHint struct {
		mtypes.ControlV2ObservedAddress
		ipv6 bool
	}
	hints := make([]observedHint, 0, len(counts))
	for address, count := range counts {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		hints = append(hints, observedHint{ControlV2ObservedAddress: mtypes.ControlV2ObservedAddress{Address: address, ReporterCount: count}, ipv6: ip != nil && ip.To4() == nil})
	}
	sort.Slice(hints, func(i, j int) bool {
		if hints[i].ReporterCount != hints[j].ReporterCount {
			return hints[i].ReporterCount > hints[j].ReporterCount
		}
		return hints[i].Address < hints[j].Address
	})
	var v4, v6 []mtypes.ControlV2ObservedAddress
	for _, hint := range hints {
		if len(v4)+len(v6) == 16 {
			break
		}
		if hint.ipv6 {
			if len(v6) < 14 {
				v6 = append(v6, hint.ControlV2ObservedAddress)
			}
			continue
		}
		if len(v4) < 14 {
			v4 = append(v4, hint.ControlV2ObservedAddress)
		}
	}
	return v4, v6
}

func sameObservedHints(a, b []mtypes.ControlV2ObservedAddress) bool {
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
// ParametersForBootstrap returns a deep copy of the currently-published
// control parameters. Bootstrap handlers (introduced in a later task)
// hand this value to an Edge so the Edge receives an isolated snapshot
// that cannot mutate the authoritative state when mutated locally.
// Reads are concurrent-safe with UpdateParameters / SnapshotFor.
func (s *ControlState) ParametersForBootstrap() mtypes.ControlV2Parameters {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneParameters(s.parameters)
}

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
func cloneFloat64Ptr(in *float64) *float64 {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneParameters(in mtypes.ControlV2Parameters) mtypes.ControlV2Parameters {
	in.RelayCostMS = cloneFloat64Ptr(in.RelayCostMS)
	in.STUNServers = append([]string{}, in.STUNServers...)
	in.ListenPortPriority = cloneListenPortPriority(in.ListenPortPriority)
	in.EndpointBlacklist = append([]string{}, in.EndpointBlacklist...)
	return in
}

func cloneListenPortPriority(in mtypes.ListenPortPriority) mtypes.ListenPortPriority {
	if in == nil {
		return nil
	}
	out := make(mtypes.ListenPortPriority, len(in))
	for i, entry := range in {
		out[i] = entry
		if entry.Port != nil {
			p := *entry.Port
			out[i].Port = &p
		}
		if entry.Range != nil {
			r := *entry.Range
			out[i].Range = &r
		}
	}
	return out
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

func (s *ControlState) filterCandidatesLocked(candidates []mtypes.ControlV2Candidate) ([]mtypes.ControlV2Candidate, error) {
	prefixes, err := s.parameters.ParseEndpointBlacklist()
	if err != nil {
		return nil, ErrControlStateInvalidParameters
	}
	filtered := make([]mtypes.ControlV2Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		host, _, err := net.SplitHostPort(candidate.Address)
		if err != nil {
			filtered = append(filtered, candidate)
			continue
		}
		address, err := netip.ParseAddr(host)
		if err != nil {
			filtered = append(filtered, candidate)
			continue
		}
		unmapped := address.Unmap()
		blacklisted := false
		for _, prefix := range prefixes {
			if prefix.Contains(address) || prefix.Contains(unmapped) {
				blacklisted = true
				break
			}
		}
		if !blacklisted {
			filtered = append(filtered, candidate)
		}
	}
	return filtered, nil
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
