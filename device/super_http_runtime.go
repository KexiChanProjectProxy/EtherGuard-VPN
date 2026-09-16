package device

import (
	"context"
	"errors"
	"math"
	"net"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type superHTTPReady struct {
	port   int
	fwmark uint32
	v4     net.IP
	v6     net.IP
}

type superSelector struct {
	urls                      []string
	idx                       int
	epoch                     uint64
	consecutiveReportFailures int
	lastSuccess               time.Time
	minFailoverWindow         time.Duration
	now                       func() time.Time
}

func (selector *superSelector) recordSuccess() {
	selector.consecutiveReportFailures = 0
	selector.lastSuccess = selector.now()
}

func (selector *superSelector) recordReportFailure(err error) {
	if errors.Is(err, ErrControlUnknownPeer) {
		return
	}
	selector.consecutiveReportFailures++
}

func (selector *superSelector) shouldRotate(reportInterval time.Duration) bool {
	if len(selector.urls) <= 1 {
		return false
	}
	if selector.consecutiveReportFailures >= 3 {
		return true
	}
	minimum := selector.minFailoverWindow
	if minimum <= 0 {
		minimum = 15 * time.Second
	}
	window := 3 * reportInterval
	if window < minimum {
		window = minimum
	}
	return selector.now().Sub(selector.lastSuccess) >= window
}

func (selector *superSelector) rotate() string {
	if len(selector.urls) == 0 {
		return ""
	}
	selector.idx = (selector.idx + 1) % len(selector.urls)
	return selector.urls[selector.idx]
}

type SuperHTTPRuntimeOption func(*superHTTPRuntimeOptions)

type superHTTPRuntimeOptions struct {
	startIndex int
}

func WithStartIndex(index int) SuperHTTPRuntimeOption {
	return func(options *superHTTPRuntimeOptions) {
		options.startIndex = index
	}
}

// SuperHTTPRuntime owns the Edge HTTP control-plane lifecycle.
type SuperHTTPRuntime struct {
	relayCostMS atomic.Uint64

	device *Device
	config mtypes.EdgeConfigV2
	client *ControlHTTPClient
	now    func() time.Time

	ready chan superHTTPReady
	done  chan struct{}
	once  sync.Once
	apply sync.Mutex

	mu               sync.RWMutex
	candidates       []mtypes.ControlV2Candidate
	parameters       mtypes.ControlV2Parameters
	generation       uint64
	recoveryRequests map[mtypes.Vertex]time.Time
	selector         superSelector
	lastReregister   map[uint64]time.Time
	reregistering    bool
	reregisterEpoch  uint64
	reregisterWG     sync.WaitGroup
	parameterUpdates chan struct{}
	networkChanges   chan struct{}
	readyInfo        superHTTPReady
}

func NewSuperHTTPRuntime(device *Device, config mtypes.EdgeConfigV2, options ...SuperHTTPRuntimeOption) *SuperHTTPRuntime {
	settings := superHTTPRuntimeOptions{}
	for _, option := range options {
		option(&settings)
	}
	urls := config.SuperNodeV2.ResolveAPIUrls()
	startIndex := settings.startIndex
	if startIndex < 0 || startIndex >= len(urls) {
		startIndex = 0
	}
	baseURL := ""
	if len(urls) > 0 {
		baseURL = urls[startIndex]
	}
	now := time.Now
	runtime := &SuperHTTPRuntime{
		device:           device,
		config:           config,
		client:           NewControlHTTPClient(baseURL, config.SuperNodeV2.APIPrefix, config.NodeID, config.SuperNodeV2.ControlPSKey),
		now:              now,
		ready:            make(chan superHTTPReady, 1),
		done:             make(chan struct{}),
		recoveryRequests: make(map[mtypes.Vertex]time.Time),
		selector: superSelector{
			urls:        urls,
			idx:         startIndex,
			lastSuccess: now(),
			now:         now,
		},
		lastReregister:   make(map[uint64]time.Time),
		parameterUpdates: make(chan struct{}, 1),
		networkChanges:   make(chan struct{}, 1),
	}
	runtime.client.OnSuccess = runtime.recordControlSuccess
	runtime.relayCostMS.Store(math.Float64bits(resolveRelayCostMS(config.RelayCostMS, nil)))
	return runtime
}

func (runtime *SuperHTTPRuntime) SetClockForTest(now func() time.Time) {
	if runtime == nil || now == nil {
		return
	}
	runtime.mu.Lock()
	runtime.now = now
	runtime.selector.now = now
	runtime.selector.lastSuccess = now()
	runtime.mu.Unlock()
}

// SetFailoverThresholdsForTest overrides the production 15-second minimum
// failover window for deterministic integration tests. A non-positive value
// restores the production floor.
func (runtime *SuperHTTPRuntime) SetFailoverThresholdsForTest(minWindow time.Duration) {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	runtime.selector.minFailoverWindow = minWindow
	runtime.mu.Unlock()
}

func (runtime *SuperHTTPRuntime) recordControlSuccess() {
	runtime.mu.Lock()
	runtime.selector.recordSuccess()
	runtime.mu.Unlock()
}

func resolveRelayCostMS(override, serverDefault *float64) float64 {
	if override != nil {
		return *override
	}
	if serverDefault != nil {
		return *serverDefault
	}
	return 0
}

func (runtime *SuperHTTPRuntime) effectiveRelayCostMS() float64 {
	return math.Float64frombits(runtime.relayCostMS.Load())
}

func (device *Device) effectiveRelayCostMS() float64 {
	if device.superHTTP == nil {
		return 0
	}
	return device.superHTTP.effectiveRelayCostMS()
}

func (runtime *SuperHTTPRuntime) Start(ctx context.Context) {
	runtime.once.Do(func() { go runtime.run(ctx) })
}

func (runtime *SuperHTTPRuntime) MarkReady(port int, fwmark uint32, v4, v6 net.IP) {
	select {
	case runtime.ready <- superHTTPReady{port: port, fwmark: fwmark, v4: v4, v6: v6}:
	default:
	}
}

func (runtime *SuperHTTPRuntime) Done() <-chan struct{} { return runtime.done }

func (runtime *SuperHTTPRuntime) run(ctx context.Context) {
	defer close(runtime.done)
	var ready superHTTPReady
	select {
	case ready = <-runtime.ready:
	case <-ctx.Done():
		return
	}
	runtime.readyInfo = ready

	local := localControlCandidates(runtime.device, ready)
	runtime.setCandidates(local)
	registerEpoch := runtime.client.Epoch()
	register := runtime.registerRequest(ready, local)
	snapshot, err := runtime.client.Register(ctx, &register)
	if err == nil {
		runtime.recordControlSuccess()
		if runtime.applySnapshot(snapshot, registerEpoch) {
			runtime.refreshSTUN(ctx, snapshot.Parameters)
		}
	} else if runtime.device != nil {
		runtime.device.log.Errorf("HTTP control register failed; continuing with sync retry: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		err := runtime.client.Sync(ctx, func(snapshot *mtypes.ControlV2Snapshot) {
			epoch := runtime.client.Epoch()
			if runtime.client.Current() != snapshot {
				return
			}
			runtime.applySnapshot(snapshot, epoch)
		})
		if err != nil && !errors.Is(err, context.Canceled) && runtime.device != nil {
			runtime.device.log.Errorf("HTTP control sync stopped: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		runtime.reportLoop(ctx, ready)
	}()
	go func() {
		defer wg.Done()
		runtime.stunLoop(ctx)
	}()
	wg.Wait()
	runtime.reregisterWG.Wait()
}

func localControlCandidates(device *Device, ready superHTTPReady) []mtypes.ControlV2Candidate {
	var localEndpoints []string
	if device != nil {
		localEndpoints = device.localEndpointURLs(ready.port)
	}
	return localControlCandidatesFromAddresses(device, ready, localEndpoints)
}

func localControlCandidatesFromAddresses(device *Device, ready superHTTPReady, localEndpoints []string) []mtypes.ControlV2Candidate {
	candidates := make([]mtypes.ControlV2Candidate, 0, len(localEndpoints)+2)
	if ready.v4 != nil && !ready.v4.IsUnspecified() && !sharedAddressSpaceIP(ready.v4) {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: net.JoinHostPort(ready.v4.String(), strconv.Itoa(ready.port)), Source: mtypes.ControlV2CandidateLocal})
	}
	if ready.v6 != nil && !ready.v6.IsUnspecified() && !sharedAddressSpaceIP(ready.v6) {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: net.JoinHostPort(ready.v6.String(), strconv.Itoa(ready.port)), Source: mtypes.ControlV2CandidateLocal})
	}
	for _, endpoint := range localEndpoints {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: endpoint, Source: mtypes.ControlV2CandidateLocal})
	}
	candidates = mergeControlCandidates(candidates, nil)
	if device == nil {
		return candidates
	}
	return device.filterControlCandidates(candidates)
}

func (runtime *SuperHTTPRuntime) registerRequest(ready superHTTPReady, candidates []mtypes.ControlV2Candidate) mtypes.ControlV2RegisterRequest {
	request := mtypes.ControlV2RegisterRequest{
		NodeID: runtime.config.NodeID, NodeName: runtime.config.NodeName,
		Version: mtypes.ControlV2ProtocolVersion, ListenPort: ready.port, FwMark: ready.fwmark,
		DesiredTTL: runtime.config.DefaultTTL, RequestedAt: runtime.now(), Implementation: "etherguard",
	}
	if runtime.device != nil {
		runtime.device.staticIdentity.RLock()
		request.PubKey = runtime.device.staticIdentity.publicKey.ToString()
		runtime.device.staticIdentity.RUnlock()
		candidates = runtime.device.filterControlCandidates(candidates)
	}
	for _, candidate := range candidates {
		host, _, err := net.SplitHostPort(candidate.Address)
		if err != nil {
			continue
		}
		if net.ParseIP(host).To4() != nil {
			request.LocalV4 = append(request.LocalV4, candidate.Address)
		} else {
			request.LocalV6 = append(request.LocalV6, candidate.Address)
		}
	}
	return request
}

func (runtime *SuperHTTPRuntime) applySnapshot(snapshot *mtypes.ControlV2Snapshot, epochs ...uint64) bool {
	if snapshot == nil {
		return false
	}
	epoch := runtime.client.Epoch()
	if len(epochs) > 0 {
		epoch = epochs[0]
	}
	if runtime.client.Epoch() != epoch {
		return false
	}
	runtime.apply.Lock()
	defer runtime.apply.Unlock()
	if runtime.client.Epoch() != epoch {
		return false
	}
	if runtime.device != nil {
		runtime.device.applyEndpointBlacklist(snapshot.Parameters)
	}
	runtime.mu.Lock()
	runtime.parameters = snapshot.Parameters
	runtime.relayCostMS.Store(math.Float64bits(resolveRelayCostMS(runtime.config.RelayCostMS, snapshot.Parameters.RelayCostMS)))
	runtime.generation = snapshot.Revision
	if runtime.device != nil {
		runtime.candidates = runtime.device.filterControlCandidates(runtime.candidates)
	}
	runtime.mu.Unlock()
	wanted := make(map[mtypes.Vertex]struct{}, len(snapshot.Peers))
	for _, peer := range snapshot.Peers {
		if peer.NodeID != runtime.config.NodeID {
			wanted[peer.NodeID] = struct{}{}
		}
	}
	runtime.pruneRecoveryRequests(wanted)
	select {
	case runtime.parameterUpdates <- struct{}{}:
	default:
	}
	if runtime.device != nil {
		runtime.device.applySuperHTTPSnapshot(snapshot, uint32(runtime.config.DirectConnectivity.PersistentKeepaliveSeconds))
	}
	return true
}

func (runtime *SuperHTTPRuntime) requestNetworkRefresh() {
	if runtime == nil {
		return
	}
	select {
	case runtime.networkChanges <- struct{}{}:
	default:
	}
}

func (runtime *SuperHTTPRuntime) currentLocalCandidates() []mtypes.ControlV2Candidate {
	ready := runtime.readyInfo
	if runtime.device != nil {
		ready.v4 = nil
		ready.v6 = nil
	}
	return localControlCandidates(runtime.device, ready)
}

func stunCandidates(candidates []mtypes.ControlV2Candidate) []mtypes.ControlV2Candidate {
	filtered := make([]mtypes.ControlV2Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Source == mtypes.ControlV2CandidateSTUN {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func (runtime *SuperHTTPRuntime) republishLocals() {
	locals := runtime.currentLocalCandidates()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	runtime.candidates = mergeControlCandidates(locals, stunCandidates(runtime.candidates))
	if runtime.device != nil {
		runtime.candidates = runtime.device.filterControlCandidates(runtime.candidates)
	}
}

func (runtime *SuperHTTPRuntime) refreshSTUN(ctx context.Context, parameters mtypes.ControlV2Parameters) {
	var public []mtypes.ControlV2Candidate
	if runtime.device != nil && runtime.device.superSTUN != nil && len(parameters.STUNServers) > 0 {
		public = runtime.device.superSTUN.Discover(ctx, parameters.STUNServers, parameters.STUNRequestTimeout)
	}
	locals := runtime.currentLocalCandidates()
	runtime.mu.Lock()
	runtime.candidates = mergeControlCandidates(locals, public)
	if runtime.device != nil {
		runtime.candidates = runtime.device.filterControlCandidates(runtime.candidates)
	}
	runtime.mu.Unlock()
}

func mergeControlCandidates(previous, refreshed []mtypes.ControlV2Candidate) []mtypes.ControlV2Candidate {
	merged := make([]mtypes.ControlV2Candidate, 0, len(previous)+len(refreshed))
	seen := make(map[string]struct{}, len(previous)+len(refreshed))
	for _, candidate := range previous {
		if candidate.Source == mtypes.ControlV2CandidateSTUN {
			continue
		}
		if _, exists := seen[candidate.Address]; exists {
			continue
		}
		seen[candidate.Address] = struct{}{}
		merged = append(merged, candidate)
	}
	for _, candidate := range refreshed {
		if candidate.Source != mtypes.ControlV2CandidateSTUN {
			continue
		}
		if _, exists := seen[candidate.Address]; exists {
			continue
		}
		seen[candidate.Address] = struct{}{}
		merged = append(merged, candidate)
	}
	return merged
}

func (runtime *SuperHTTPRuntime) stunLoop(ctx context.Context) {
	for {
		runtime.mu.RLock()
		parameters := runtime.parameters
		runtime.mu.RUnlock()
		interval := parameters.STUNRefreshInterval
		if interval <= 0 {
			interval = time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-runtime.parameterUpdates:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			runtime.refreshSTUN(ctx, parameters)
		}
	}
}

func (runtime *SuperHTTPRuntime) setCandidates(candidates []mtypes.ControlV2Candidate) {
	if runtime.device != nil {
		candidates = runtime.device.filterControlCandidates(candidates)
	}
	runtime.mu.Lock()
	runtime.candidates = append([]mtypes.ControlV2Candidate(nil), candidates...)
	runtime.mu.Unlock()
}

func (runtime *SuperHTTPRuntime) reportLoop(ctx context.Context, ready superHTTPReady) {
	for {
		runtime.mu.RLock()
		interval := runtime.parameters.ReportInterval
		runtime.mu.RUnlock()
		if interval <= 0 {
			interval = time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-runtime.networkChanges:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			runtime.mu.RLock()
			parameters := runtime.parameters
			runtime.mu.RUnlock()
			runtime.refreshSTUN(ctx, parameters)
		case <-timer.C:
			runtime.republishLocals()
		}
		runtime.mu.RLock()
		candidates := append([]mtypes.ControlV2Candidate(nil), runtime.candidates...)
		runtime.mu.RUnlock()
		relayCostMS := runtime.effectiveRelayCostMS()
		report := mtypes.ControlV2ReportRequest{NodeID: runtime.config.NodeID, RelayCostMS: &relayCostMS, Candidates: candidates, ReportedAt: runtime.now()}
		if runtime.device != nil {
			report.Candidates = runtime.device.filterControlCandidates(report.Candidates)
			report.Pongs = runtime.device.superHTTPPongs()
			report.Observed = runtime.observedEndpoints()
			runtime.recoverExhaustedPeers()
		}
		reportCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := runtime.client.Report(reportCtx, &report)
		cancel()
		if err != nil && ctx.Err() == nil {
			runtime.client.InvalidateHTTP()
			runtime.mu.Lock()
			runtime.selector.recordReportFailure(err)
			runtime.mu.Unlock()
			if errors.Is(err, ErrControlUnknownPeer) {
				runtime.requestReregistration(ctx, ready, runtime.client.Epoch())
			}
			if runtime.device != nil {
				runtime.device.log.Errorf("HTTP control report failed: %v", err)
			}
		} else if err == nil {
			runtime.recordControlSuccess()
		}
		if ctx.Err() != nil {
			continue
		}
		runtime.mu.Lock()
		if !runtime.selector.shouldRotate(interval) {
			runtime.mu.Unlock()
			continue
		}
		url := runtime.selector.rotate()
		runtime.mu.Unlock()
		runtime.apply.Lock()
		epoch := runtime.client.SwitchBase(url)
		runtime.mu.Lock()
		runtime.selector.epoch = epoch
		runtime.mu.Unlock()
		runtime.apply.Unlock()
		if runtime.device != nil {
			runtime.device.log.Errorf("HTTP control failover to %s (epoch %d)", url, epoch)
		}
		runtime.requestReregistration(ctx, ready, epoch)
	}
}

func (runtime *SuperHTTPRuntime) requestReregistration(ctx context.Context, ready superHTTPReady, epoch uint64) {
	runtime.mu.Lock()
	now := runtime.now()
	lastReregister, attempted := runtime.lastReregister[epoch]
	if (runtime.reregistering && runtime.reregisterEpoch == epoch) || (attempted && now.Sub(lastReregister) < 30*time.Second) {
		runtime.mu.Unlock()
		return
	}
	runtime.lastReregister[epoch] = now
	runtime.reregistering = true
	runtime.reregisterEpoch = epoch
	runtime.reregisterWG.Add(1)
	runtime.mu.Unlock()

	go func() {
		success := false
		defer func() {
			runtime.mu.Lock()
			if runtime.reregistering && runtime.reregisterEpoch == epoch && runtime.client.Epoch() == epoch {
				runtime.reregistering = false
				if success {
					runtime.lastReregister[epoch] = runtime.now()
				}
			}
			runtime.mu.Unlock()
			runtime.reregisterWG.Done()
		}()

		runtime.mu.RLock()
		candidates := append([]mtypes.ControlV2Candidate(nil), runtime.candidates...)
		runtime.mu.RUnlock()
		if runtime.device != nil {
			candidates = runtime.device.filterControlCandidates(candidates)
		}
		register := runtime.registerRequest(ready, candidates)
		snapshot, err := runtime.client.Register(ctx, &register)
		if err != nil {
			if !errors.Is(err, context.Canceled) && runtime.device != nil {
				runtime.device.log.Errorf("HTTP control re-register failed: %v", err)
			}
			return
		}
		if runtime.client.Epoch() != epoch {
			return
		}
		runtime.recordControlSuccess()
		if !runtime.applySnapshot(snapshot, epoch) {
			return
		}
		runtime.refreshSTUN(ctx, snapshot.Parameters)
		success = true
	}()
}

func (runtime *SuperHTTPRuntime) observedEndpoints() []mtypes.ControlV2ObservedEndpoint {
	if runtime.device == nil {
		return nil
	}
	peers := runtime.device.allPeersByIDSnapshot()
	ids := make([]mtypes.Vertex, 0, len(peers))
	for id := range peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool { return ids[left] < ids[right] })
	observed := make([]mtypes.ControlV2ObservedEndpoint, 0, min(len(ids), 256))
	for _, id := range ids {
		peer := peers[id]
		static, _, _ := peer.endpointRetryConfig()
		if id == runtime.config.NodeID || static || !peer.IsPeerAlive() || peer.GetEndpointSrcStr() == "" {
			continue
		}
		address := peer.GetEndpointDstStr()
		if address == "" {
			continue
		}
		if runtime.device.endpointURLBlacklistedReadLocked(address) {
			continue
		}
		observed = append(observed, mtypes.ControlV2ObservedEndpoint{TargetNodeID: id, Address: address})
		if len(observed) == 256 {
			break
		}
	}
	return observed
}

func (runtime *SuperHTTPRuntime) recoverExhaustedPeers() {
	if runtime.device == nil {
		return
	}
	for _, peer := range runtime.device.allPeersByIDSnapshot() {
		static, _, _ := peer.endpointRetryConfig()
		if static {
			continue
		}
		if peer.IsPeerAlive() {
			runtime.mu.Lock()
			delete(runtime.recoveryRequests, peer.ID)
			runtime.mu.Unlock()
			continue
		}
		if peer.endpoint_trylist.ConsumeSuperCycleComplete() && runtime.shouldRequestSnapshotRefresh(peer.ID, time.Now()) {
			runtime.client.RequestSnapshotRefresh()
		}
	}
}

func (runtime *SuperHTTPRuntime) pruneRecoveryRequests(existing map[mtypes.Vertex]struct{}) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for id := range runtime.recoveryRequests {
		if _, ok := existing[id]; !ok {
			delete(runtime.recoveryRequests, id)
		}
	}
}

func (runtime *SuperHTTPRuntime) shouldRequestSnapshotRefresh(id mtypes.Vertex, now time.Time) bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if previous, exists := runtime.recoveryRequests[id]; exists && now.Sub(previous) < 30*time.Second {
		return false
	}
	runtime.recoveryRequests[id] = now
	return true
}

func (device *Device) applySuperHTTPSnapshot(snapshot *mtypes.ControlV2Snapshot, persistentKeepalive uint32) {
	wanted := make(map[mtypes.Vertex]mtypes.ControlV2Peer, len(snapshot.Peers))
	relayCosts := make(map[mtypes.Vertex]float64, len(snapshot.Peers)+1)
	relayCosts[device.ID] = device.effectiveRelayCostMS()
	for _, info := range snapshot.Peers {
		if info.NodeID == device.ID {
			continue
		}
		relayCosts[info.NodeID] = resolveRelayCostMS(info.RelayCostMS, snapshot.Parameters.RelayCostMS)
	}
	for _, info := range snapshot.Peers {
		if info.NodeID == device.ID {
			continue
		}
		wanted[info.NodeID] = info
		publicKey, err := Str2PubKey(info.PubKey)
		if err != nil {
			device.log.Errorf("HTTP control peer %v has invalid public key: %v", info.NodeID, err)
			continue
		}
		peer := device.LookupPeer(publicKey)
		if peer == nil {
			peer, err = device.NewPeer(publicKey, info.NodeID, false, persistentKeepalive)
			if err != nil {
				device.log.Errorf("HTTP control peer %v create failed: %v", info.NodeID, err)
				continue
			}
		}
		static, _, _ := peer.endpointRetryConfig()
		if static {
			continue
		}
		if info.PSKey != "" {
			if psk, keyErr := Str2PSKey(info.PSKey); keyErr == nil {
				peer.SetPSK(psk)
			}
		}
		urls := snapshotURLs(info)
		peer.endpoint_trylist.UpdateSuper(urls, true, device.EdgeConfig.AfPrefer)
		for destination, latencyMS := range info.LatencyMS {
			device.graph.UpdateLatency(info.NodeID, destination, latencyMS/1000, device.EdgeConfig.DynamicRoute.PeerAliveTimeout, relayCosts[destination], false, false)
		}
	}
	for id, peer := range device.allPeersByIDSnapshot() {
		static, _, _ := peer.endpointRetryConfig()
		if _, ok := wanted[id]; !ok && !static {
			device.RemovePeer(peer.handshake.remoteStatic)
		}
	}
	device.graph.RecalculateNhTable(false)
	for id := range wanted {
		next := device.graph.Next(device.ID, id)
		if next == mtypes.NodeID_Invalid {
			device.log.Verbosef("super route missing next hop self=%v wanted=%v", device.ID, id)
			continue
		}
		device.log.Verbosef("super route next hop self=%v wanted=%v next=%v", device.ID, id, next)
	}
	device.signalEndpointRetry()
}

func snapshotURLs(info mtypes.ControlV2Peer) mtypes.API_connurl {
	urls := mtypes.API_connurl{
		LocalV4:    candidateCosts(info.LocalV4),
		LocalV6:    candidateCosts(info.LocalV6),
		ExternalV4: candidateCosts(info.PublicV4),
		ExternalV6: candidateCosts(info.PublicV6),
	}
	urls.Candidates = make([]mtypes.APIConnURLCandidate, 0, len(info.ObservedV4)+len(info.ObservedV6))
	for _, observed := range info.ObservedV4 {
		urls.Candidates = append(urls.Candidates, mtypes.APIConnURLCandidate{URL: observed.Address, Source: mtypes.APIConnURLSourceObserved, ReporterCount: observed.ReporterCount})
	}
	for _, observed := range info.ObservedV6 {
		urls.Candidates = append(urls.Candidates, mtypes.APIConnURLCandidate{URL: observed.Address, Source: mtypes.APIConnURLSourceObserved, ReporterCount: observed.ReporterCount})
	}
	return urls
}

func candidateCosts(addresses []string) map[string]float64 {
	costs := make(map[string]float64, len(addresses))
	for _, address := range addresses {
		costs[address] = 0
	}
	return costs
}

func (device *Device) allPeersByIDSnapshot() map[mtypes.Vertex]*Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()
	peers := make(map[mtypes.Vertex]*Peer, len(device.peers.IDMap))
	for id, peer := range device.peers.IDMap {
		peers[id] = peer
	}
	return peers
}

func (device *Device) superHTTPPongs() []mtypes.ControlV2Pong {
	peers := device.allPeersByIDSnapshot()
	pongs := make([]mtypes.ControlV2Pong, 0, len(peers))
	for id, peer := range peers {
		if !peer.IsPeerAlive() {
			continue
		}
		alive := device.EdgeConfig.DynamicRoute.PeerAliveTimeout - time.Since(*peer.LastPacketReceivedAdd1Sec.Load().(*time.Time)).Seconds()
		if alive < 0 {
			alive = 0
		}
		latency := peer.OutboundLatency.GetVal()
		if latency < 0 || latency >= mtypes.Infinity || math.IsNaN(latency) || math.IsInf(latency, 0) {
			continue
		}
		latencyMS := latency * 1000
		pongs = append(pongs, mtypes.ControlV2Pong{SourceNode: device.ID, DestNode: id, TimediffMS: latencyMS, LatencyMS: latencyMS, AliveSeconds: alive})
	}
	return pongs
}

// EnableSuperHTTP configures and starts the HTTP control runtime. It waits for SuperHTTPReady before network I/O.
func (device *Device) EnableSuperHTTP(config mtypes.EdgeConfigV2, startIdx int) {
	ctx, cancel := context.WithCancel(context.Background())
	device.controlCancel = cancel
	device.superHTTP = NewSuperHTTPRuntime(device, config, WithStartIndex(startIdx))
	device.superHTTP.Start(ctx)
}

// SuperHTTPReady releases the runtime after the bind listen port and interface addresses are available.
func (device *Device) SuperHTTPReady() {
	if device.superHTTP == nil {
		return
	}
	device.net.RLock()
	port, fwmark := int(device.net.port), device.net.fwmark
	device.net.RUnlock()
	device.peers.RLock()
	v4, v6 := append(net.IP(nil), device.peers.LocalV4...), append(net.IP(nil), device.peers.LocalV6...)
	device.peers.RUnlock()
	device.superHTTP.MarkReady(port, fwmark, v4, v6)
}
