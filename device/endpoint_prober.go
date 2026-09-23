package device

import (
	"fmt"
	"math"
	"math/rand"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// Lowest-latency endpoint selection.
//
// For every live, roaming-enabled peer with more than one usable path, the
// prober sends one encrypted probe ping per (local uplink, remote candidate)
// pair each round, measures the round-trip time with a local monotonic clock,
// and moves the peer to the fastest pair once it has been clearly better for
// several consecutive rounds. Each side only ranks its own outbound legs: the
// reply returns over the remote's current path, which is the same for every
// candidate, so the ranking stays valid. Probes also keep the NAT mappings of
// alternate uplinks warm.

const (
	endpointProbeMaxRemote  = 6
	endpointProbeMaxPairs   = 8
	endpointProbeEWMAAlpha  = 0.3
	endpointProbeMinSamples = 3
	endpointProbeMissLimit  = 2
)

// endpointSelectionSettings is the resolved endpoint selection policy.
type endpointSelectionSettings struct {
	enabled    bool
	interval   time.Duration
	minMargin  time.Duration
	marginFrac float64
	rounds     int
}

func (device *Device) endpointSelectionSettings() endpointSelectionSettings {
	route := device.EdgeConfig.DynamicRoute
	settings := endpointSelectionSettings{
		enabled:    !route.DisableEndpointSelection,
		interval:   mtypes.S2TD(route.EndpointProbeInterval),
		minMargin:  time.Duration(route.EndpointSwitchMarginMS * float64(time.Millisecond)),
		marginFrac: route.EndpointSwitchMarginPercent / 100,
		rounds:     route.EndpointSwitchRounds,
	}
	if settings.interval <= 0 {
		settings.interval = mtypes.S2TD(route.SendPingInterval)
	}
	if route.EndpointSwitchMarginMS == 0 {
		settings.minMargin = mtypes.DefaultEndpointSwitchMarginMS * time.Millisecond
	}
	if route.EndpointSwitchMarginPercent == 0 {
		settings.marginFrac = mtypes.DefaultEndpointSwitchMarginPercent / 100.0
	}
	if settings.rounds <= 0 {
		settings.rounds = mtypes.DefaultEndpointSwitchRounds
	}
	if settings.interval <= 0 {
		settings.enabled = false
	}
	return settings
}

type probePair struct {
	key     string
	remote  string
	local   *stunSource // nil: kernel default route
	rtt     float64     // seconds; +Inf until measured or after repeated misses
	samples int
	misses  int
}

type pendingProbe struct {
	key    string
	sentAt time.Time
}

type endpointProber struct {
	mu      sync.Mutex
	pairs   []*probePair
	pending map[uint32]pendingProbe
	// pinnedSent holds the endpoints of last round's pinned probes. A pin the
	// kernel dropped (src cleared after an IPv6 EINVAL) means that probe left
	// through the default route, so the pair's measurements are discarded.
	pinnedSent map[string]conn.Endpoint
	nextID     uint32
	bestKey    string
	bestStreak int
}

func probePairKey(local *stunSource, remote string) string {
	if local == nil {
		return "default|" + remote
	}
	return local.ip.String() + "#" + fmt.Sprint(local.ifindex) + "|" + remote
}

func (pair *probePair) String() string {
	if pair.local == nil {
		return "default->" + pair.remote
	}
	return pair.local.String() + "->" + pair.remote
}

// buildProbePairs combines remote candidates with local sources. The current
// remote comes first; pinned sources must match the remote's family. It
// returns nil when there is at most one pair, so single-homed peers with one
// candidate cost nothing.
func buildProbePairs(current string, candidates []trylistCandidate, sources []stunSource, pinning bool, allow func(netip.AddrPort) bool) []*probePair {
	remotes := make([]netip.AddrPort, 0, endpointProbeMaxRemote)
	seen := make(map[string]struct{})
	addRemote := func(address string) {
		if len(remotes) >= endpointProbeMaxRemote {
			return
		}
		addrPort, err := netip.ParseAddrPort(address)
		if err != nil {
			return
		}
		addrPort = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
		key := addrPort.String()
		if _, ok := seen[key]; ok || (allow != nil && !allow(addrPort)) {
			return
		}
		seen[key] = struct{}{}
		remotes = append(remotes, addrPort)
	}
	if current != "" {
		addRemote(current)
	}
	for _, candidate := range candidates {
		addRemote(candidate.address)
	}
	var pairs []*probePair
	for _, remote := range remotes {
		if len(pairs) < endpointProbeMaxPairs {
			pairs = append(pairs, &probePair{key: probePairKey(nil, remote.String()), remote: remote.String(), rtt: math.Inf(1)})
		}
		if !pinning {
			continue
		}
		for i := range sources {
			if len(pairs) >= endpointProbeMaxPairs {
				break
			}
			source := sources[i]
			if source.ip.Is4() != remote.Addr().Is4() {
				continue
			}
			pairs = append(pairs, &probePair{key: probePairKey(&source, remote.String()), remote: remote.String(), local: &source, rtt: math.Inf(1)})
		}
	}
	if len(pairs) <= 1 {
		return nil
	}
	return pairs
}

// currentPairKey maps the peer's live endpoint to a pair key: the pinned
// source it uses when that source is still a known uplink, else the default
// route.
func currentPairKey(endpoint conn.Endpoint, sources []stunSource) string {
	if endpoint == nil {
		return ""
	}
	addrPort, err := netip.ParseAddrPort(endpoint.DstToString())
	if err != nil {
		return ""
	}
	remote := netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()).String()
	if src, ok := netip.AddrFromSlice(endpoint.SrcIP()); ok && !src.IsUnspecified() {
		src = src.Unmap()
		for i := range sources {
			if sources[i].ip == src {
				return probePairKey(&sources[i], remote)
			}
		}
	}
	return probePairKey(nil, remote)
}

// rebuild replaces the pair set and keeps measurements of pairs that remain.
func (p *endpointProber) rebuild(pairs []*probePair) {
	p.mu.Lock()
	defer p.mu.Unlock()
	old := make(map[string]*probePair, len(p.pairs))
	for _, pair := range p.pairs {
		old[pair.key] = pair
	}
	for _, pair := range pairs {
		if previous, ok := old[pair.key]; ok {
			pair.rtt, pair.samples, pair.misses = previous.rtt, previous.samples, previous.misses
		}
	}
	p.pairs = pairs
	if p.pending == nil {
		p.pending = make(map[uint32]pendingProbe)
	}
	if len(pairs) == 0 {
		p.resetLocked()
	}
}

func (p *endpointProber) reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pairs = nil
	p.resetLocked()
}

func (p *endpointProber) resetLocked() {
	p.pending = make(map[uint32]pendingProbe)
	p.pinnedSent = nil
	p.bestKey = ""
	p.bestStreak = 0
}

// expire counts probes older than maxAge as misses.
func (p *endpointProber) expire(now time.Time, maxAge time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, probe := range p.pending {
		if now.Sub(probe.sentAt) < maxAge {
			continue
		}
		delete(p.pending, id)
		for _, pair := range p.pairs {
			if pair.key != probe.key {
				continue
			}
			pair.misses++
			if pair.misses >= endpointProbeMissLimit {
				pair.rtt = math.Inf(1)
				pair.samples = 0
			}
		}
	}
}

// register records a probe for pair and returns its non-zero RequestID.
func (p *endpointProber) register(key string, now time.Time) uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pending == nil {
		p.pending = make(map[uint32]pendingProbe)
	}
	if p.nextID == 0 {
		p.nextID = rand.Uint32() | 1
	}
	for {
		id := p.nextID
		p.nextID++
		if id == 0 {
			continue
		}
		if _, busy := p.pending[id]; busy {
			continue
		}
		p.pending[id] = pendingProbe{key: key, sentAt: now}
		return id
	}
}

// onPong folds a probe reply into its pair's smoothed RTT.
func (p *endpointProber) onPong(id uint32, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	probe, ok := p.pending[id]
	if !ok {
		return
	}
	delete(p.pending, id)
	rtt := now.Sub(probe.sentAt).Seconds()
	if rtt < 0 {
		return
	}
	for _, pair := range p.pairs {
		if pair.key != probe.key {
			continue
		}
		if pair.samples == 0 || math.IsInf(pair.rtt, 1) {
			pair.rtt = rtt
		} else {
			pair.rtt = endpointProbeEWMAAlpha*rtt + (1-endpointProbeEWMAAlpha)*pair.rtt
		}
		pair.samples++
		pair.misses = 0
	}
}

type pairStats struct {
	key     string
	rtt     float64
	samples int
}

// selectEndpointPair returns the fastest measured pair and whether it beats
// the current pair by more than max(minMargin, marginFrac*current). An
// unmeasured or failing current pair can always be replaced.
func selectEndpointPair(pairs []pairStats, currentKey string, minMargin time.Duration, marginFrac float64, minSamples int) (string, bool) {
	best := -1
	current := math.Inf(1)
	for i, pair := range pairs {
		if pair.key == currentKey && pair.samples >= minSamples {
			current = pair.rtt
		}
		if pair.samples < minSamples || math.IsInf(pair.rtt, 1) || math.IsNaN(pair.rtt) {
			continue
		}
		if best < 0 || pair.rtt < pairs[best].rtt || (pair.rtt == pairs[best].rtt && pair.key < pairs[best].key) {
			best = i
		}
	}
	if best < 0 || pairs[best].key == currentKey {
		return "", false
	}
	if math.IsInf(current, 1) {
		return pairs[best].key, true
	}
	margin := math.Max(minMargin.Seconds(), marginFrac*current)
	return pairs[best].key, current-pairs[best].rtt > margin
}

// decide advances the hysteresis streak and returns the pair to switch to.
func (p *endpointProber) decide(currentKey string, settings endpointSelectionSettings) *probePair {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := make([]pairStats, 0, len(p.pairs))
	for _, pair := range p.pairs {
		stats = append(stats, pairStats{key: pair.key, rtt: pair.rtt, samples: pair.samples})
	}
	key, better := selectEndpointPair(stats, currentKey, settings.minMargin, settings.marginFrac, endpointProbeMinSamples)
	if !better {
		p.bestKey, p.bestStreak = "", 0
		return nil
	}
	if key == p.bestKey {
		p.bestStreak++
	} else {
		p.bestKey, p.bestStreak = key, 1
	}
	if p.bestStreak < settings.rounds {
		return nil
	}
	p.bestKey, p.bestStreak = "", 0
	for _, pair := range p.pairs {
		if pair.key == key {
			copied := *pair
			return &copied
		}
	}
	return nil
}

// checkDroppedPins discards measurements of pairs whose last pinned probe lost
// its pin, and forgets last round's endpoints.
func (p *endpointProber) checkDroppedPins() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for key, endpoint := range p.pinnedSent {
		src := endpoint.SrcIP()
		if src == nil || !src.IsUnspecified() {
			continue
		}
		for _, pair := range p.pairs {
			if pair.key == key {
				pair.rtt, pair.samples = math.Inf(1), 0
			}
		}
		for id, probe := range p.pending {
			if probe.key == key {
				delete(p.pending, id)
			}
		}
	}
	p.pinnedSent = nil
}

func (p *endpointProber) rememberPinned(key string, endpoint conn.Endpoint) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.pinnedSent == nil {
		p.pinnedSent = make(map[string]conn.Endpoint)
	}
	p.pinnedSent[key] = endpoint
}

func (p *endpointProber) snapshot() []*probePair {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*probePair, 0, len(p.pairs))
	for _, pair := range p.pairs {
		copied := *pair
		out = append(out, &copied)
	}
	return out
}

// makePairEndpoint builds a fresh endpoint for pair; pinned pairs need a bind
// that implements conn.EndpointSourcePinner.
func makePairEndpoint(bind conn.Bind, pair *probePair) (conn.Endpoint, error) {
	if pair.local == nil {
		return bind.ParseEndpoint(pair.remote)
	}
	pinner, ok := bind.(conn.EndpointSourcePinner)
	if !ok {
		return nil, fmt.Errorf("bind cannot pin sources")
	}
	return pinner.ParseEndpointFrom(pair.remote, pair.local.ip, pair.local.ifindex)
}

// endpointProbeEligible reports whether the prober may manage peer's endpoint.
func (device *Device) endpointProbeEligible(peer *Peer) bool {
	if peer == nil || peer.ID.IsSpecial() || !peer.isRunning.Get() {
		return false
	}
	peer.RLock()
	excluded := peer.StaticConn || peer.disableRoaming
	peer.RUnlock()
	return !excluded
}

// probeEndpointsRound runs one probing round over every peer.
func (device *Device) probeEndpointsRound(settings endpointSelectionSettings, now time.Time) {
	device.net.RLock()
	bind := device.net.bind
	device.net.RUnlock()
	if bind == nil {
		return
	}
	_, pinning := bind.(conn.EndpointSourcePinner)
	var sources []stunSource
	if pinning {
		sources = device.stunSources()
	}
	for _, peer := range device.retryPeersSnapshot() {
		device.probePeerEndpoints(peer, bind, sources, pinning, settings, now)
	}
}

func (device *Device) probePeerEndpoints(peer *Peer, bind conn.Bind, sources []stunSource, pinning bool, settings endpointSelectionSettings, now time.Time) {
	if !device.endpointProbeEligible(peer) {
		peer.prober.reset()
		return
	}
	if !peer.IsPeerAlive() {
		// Dead peers belong to the retry loop; forget stale measurements.
		peer.endpointPinned.Store(false)
		peer.prober.reset()
		return
	}
	// The retry loop's handshake hold is not honoured here: the peer is
	// already alive, and the sample and streak rounds damp switching.
	peer.RLock()
	currentEndpoint := peer.endpoint
	peer.RUnlock()
	current := ""
	if currentEndpoint != nil {
		current = currentEndpoint.DstToString()
	}
	// Reflexive addresses are proven to carry the peer's traffic, so they
	// rank ahead of published candidates under the remote cap.
	trylist, _ := peer.endpoint_trylist.candidates()
	candidates := append(peer.reflexive.candidates(now, mtypes.S2TD(device.EdgeConfig.DynamicRoute.PeerAliveTimeout)), trylist...)
	allow := func(addrPort netip.AddrPort) bool {
		if addrPort.Addr().Is4() && !device.enabledAf.IPv4 {
			return false
		}
		if !addrPort.Addr().Is4() && !device.enabledAf.IPv6 {
			return false
		}
		device.endpointBlacklistMu.RLock()
		defer device.endpointBlacklistMu.RUnlock()
		return !device.endpointAddressBlacklisted(addrPort.Addr())
	}
	peer.prober.rebuild(buildProbePairs(current, candidates, sources, pinning, allow))
	pairs := peer.prober.snapshot()
	if len(pairs) == 0 {
		return
	}
	peer.prober.checkDroppedPins()
	peer.prober.expire(now, settings.interval)

	currentKey := currentPairKey(currentEndpoint, sources)
	if target := peer.prober.decide(currentKey, settings); target != nil {
		if endpoint, err := makePairEndpoint(bind, target); err == nil {
			if peer.applyProbedEndpoint(endpoint, currentKey, target) {
				peer.prober.reset()
				return
			}
		}
	}

	for _, pair := range pairs {
		endpoint, err := makePairEndpoint(bind, pair)
		if err != nil {
			continue
		}
		id := peer.prober.register(pair.key, time.Now())
		packet, usage, ttl, err := device.GeneratePingPacketWithRequestID(device.ID, 0, id)
		if err != nil {
			continue
		}
		device.SendPacketVia(peer, endpoint, usage, ttl, packet, MessageTransportOffsetContent)
		if pair.local != nil {
			peer.prober.rememberPinned(pair.key, endpoint)
		}
	}
}

// applyProbedEndpoint moves peer to a probed pair. It deliberately bypasses
// SetEndpointFromPacket's roaming guard: this is a local decision.
func (peer *Peer) applyProbedEndpoint(endpoint conn.Endpoint, fromKey string, target *probePair) bool {
	device := peer.device
	device.endpointBlacklistMu.RLock()
	blacklisted := device.endpointBlacklisted(endpoint.DstIP())
	device.endpointBlacklistMu.RUnlock()
	if blacklisted {
		return false
	}
	peer.Lock()
	if peer.disableRoaming || peer.StaticConn {
		peer.Unlock()
		return false
	}
	device.SaveToConfig(peer, endpoint)
	peer.endpoint = endpoint
	peer.ConnURL = target.remote
	peer.Unlock()
	peer.endpointPinned.Store(true)
	peer.lastEndpointChange.Store(time.Now().UnixNano())
	if device.LogLevel.LogControl {
		fmt.Printf("Control: Peer %v switched to lower-latency path %v (%.1f ms), was %v\n", peer.ID.ToString(), target.String(), target.rtt*1000, fromKey)
	}
	if device.log != nil {
		device.log.Verbosef("Endpoint selection: peer=%v path=%v rtt_ms=%.3f previous=%v", peer.ID, target.String(), target.rtt*1000, fromKey)
	}
	return true
}

// RoutineProbeEndpoints drives endpoint selection for P2P and Super modes.
func (device *Device) RoutineProbeEndpoints() {
	if !(device.EdgeConfig.DynamicRoute.P2P.UseP2P || device.EdgeConfig.SuperNodeV2Enabled) {
		return
	}
	for {
		settings := device.endpointSelectionSettings()
		if !settings.enabled {
			return
		}
		select {
		case <-device.closed:
			return
		case <-time.After(settings.interval):
		}
		device.probeEndpointsRound(settings, time.Now())
	}
}

const (
	maxReflexiveEndpoints  = 4
	reflexiveCandidateCost = 30000
)

// reflexiveEndpoints is a small, recency-bounded set of peer-reflexive
// addresses (ICE prflx): sources of authenticated packets from the peer.
type reflexiveEndpoints struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (r *reflexiveEndpoints) note(address string, now time.Time) {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return
	}
	address = netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port()).String()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = make(map[string]time.Time)
	}
	if _, ok := r.seen[address]; !ok && len(r.seen) >= maxReflexiveEndpoints {
		oldest := ""
		for candidate, seenAt := range r.seen {
			if oldest == "" || seenAt.Before(r.seen[oldest]) {
				oldest = candidate
			}
		}
		delete(r.seen, oldest)
	}
	r.seen[address] = now
}

// candidates returns addresses seen within maxAge, most recent first, and
// forgets older ones.
func (r *reflexiveEndpoints) candidates(now time.Time, maxAge time.Duration) []trylistCandidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	type entry struct {
		address string
		seenAt  time.Time
	}
	var fresh []entry
	for address, seenAt := range r.seen {
		if now.Sub(seenAt) > maxAge {
			delete(r.seen, address)
			continue
		}
		fresh = append(fresh, entry{address, seenAt})
	}
	sort.Slice(fresh, func(i, j int) bool {
		if !fresh[i].seenAt.Equal(fresh[j].seenAt) {
			return fresh[i].seenAt.After(fresh[j].seenAt)
		}
		return fresh[i].address < fresh[j].address
	})
	out := make([]trylistCandidate, 0, len(fresh))
	for _, e := range fresh {
		out = append(out, trylistCandidate{address: e.address, cost: reflexiveCandidateCost})
	}
	return out
}
