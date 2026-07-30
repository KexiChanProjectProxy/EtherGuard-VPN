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

// SuperHTTPRuntime owns the Edge HTTP control-plane lifecycle.
type SuperHTTPRuntime struct {
	relayCostMS atomic.Uint64

	device *Device
	config mtypes.EdgeConfigV2
	client *ControlHTTPClient

	ready chan superHTTPReady
	done  chan struct{}
	once  sync.Once
	apply sync.Mutex

	mu               sync.RWMutex
	candidates       []mtypes.ControlV2Candidate
	parameters       mtypes.ControlV2Parameters
	generation       uint64
	recoveryRequests map[mtypes.Vertex]time.Time
	lastReregister   time.Time
	reregistering    bool
	reregisterWG     sync.WaitGroup
	parameterUpdates chan struct{}
}

func NewSuperHTTPRuntime(device *Device, config mtypes.EdgeConfigV2) *SuperHTTPRuntime {
	runtime := &SuperHTTPRuntime{
		device:           device,
		config:           config,
		client:           NewControlHTTPClient(config.SuperNodeV2.APIUrl, config.SuperNodeV2.APIPrefix, config.NodeID, config.SuperNodeV2.ControlPSKey),
		ready:            make(chan superHTTPReady, 1),
		done:             make(chan struct{}),
		recoveryRequests: make(map[mtypes.Vertex]time.Time),
		parameterUpdates: make(chan struct{}, 1),
	}
	runtime.relayCostMS.Store(math.Float64bits(resolveRelayCostMS(config.RelayCostMS, nil)))
	return runtime
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

	local := localControlCandidates(runtime.device, ready)
	runtime.setCandidates(local)
	register := runtime.registerRequest(ready, local)
	snapshot, err := runtime.client.Register(ctx, &register)
	if err == nil {
		runtime.applySnapshot(snapshot)
		runtime.refreshSTUN(ctx, snapshot.Parameters)
	} else if runtime.device != nil {
		runtime.device.log.Errorf("HTTP control register failed; continuing with sync retry: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		err := runtime.client.Sync(ctx, runtime.applySnapshot)
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
	if ready.v4 != nil && !ready.v4.IsUnspecified() {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: net.JoinHostPort(ready.v4.String(), strconv.Itoa(ready.port)), Source: mtypes.ControlV2CandidateLocal})
	}
	if ready.v6 != nil && !ready.v6.IsUnspecified() {
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
		DesiredTTL: runtime.config.DefaultTTL, RequestedAt: time.Now(), Implementation: "etherguard",
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

func (runtime *SuperHTTPRuntime) applySnapshot(snapshot *mtypes.ControlV2Snapshot) {
	if snapshot == nil {
		return
	}
	runtime.apply.Lock()
	defer runtime.apply.Unlock()
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
}

func (runtime *SuperHTTPRuntime) refreshSTUN(ctx context.Context, parameters mtypes.ControlV2Parameters) {
	var public []mtypes.ControlV2Candidate
	if runtime.device != nil && runtime.device.superSTUN != nil && len(parameters.STUNServers) > 0 {
		public = runtime.device.superSTUN.Discover(ctx, parameters.STUNServers, parameters.STUNRequestTimeout)
	}
	runtime.mu.Lock()
	runtime.candidates = mergeControlCandidates(runtime.candidates, public)
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
		candidates := append([]mtypes.ControlV2Candidate(nil), runtime.candidates...)
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
		case <-timer.C:
		}
		relayCostMS := runtime.effectiveRelayCostMS()
		report := mtypes.ControlV2ReportRequest{NodeID: runtime.config.NodeID, RelayCostMS: &relayCostMS, Candidates: candidates, ReportedAt: time.Now()}
		if runtime.device != nil {
			report.Candidates = runtime.device.filterControlCandidates(report.Candidates)
			report.Pongs = runtime.device.superHTTPPongs()
			report.Observed = runtime.observedEndpoints()
			runtime.recoverExhaustedPeers()
		}
		if err := runtime.client.Report(ctx, &report); err != nil && ctx.Err() == nil {
			if errors.Is(err, ErrControlUnknownPeer) {
				runtime.requestReregistration(ctx, ready)
			}
			if runtime.device != nil {
				runtime.device.log.Errorf("HTTP control report failed: %v", err)
			}
		}
	}
}

func (runtime *SuperHTTPRuntime) requestReregistration(ctx context.Context, ready superHTTPReady) {
	now := time.Now()
	runtime.mu.Lock()
	if runtime.reregistering || (!runtime.lastReregister.IsZero() && now.Sub(runtime.lastReregister) < 30*time.Second) {
		runtime.mu.Unlock()
		return
	}
	runtime.lastReregister = now
	runtime.reregistering = true
	runtime.reregisterWG.Add(1)
	runtime.mu.Unlock()

	go func() {
		success := false
		defer func() {
			runtime.mu.Lock()
			runtime.reregistering = false
			if success {
				runtime.lastReregister = time.Now()
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
		runtime.applySnapshot(snapshot)
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
func (device *Device) EnableSuperHTTP(config mtypes.EdgeConfigV2) {
	ctx, cancel := context.WithCancel(context.Background())
	device.controlCancel = cancel
	device.superHTTP = NewSuperHTTPRuntime(device, config)
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
