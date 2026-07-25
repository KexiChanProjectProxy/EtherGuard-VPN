package device

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
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
	device *Device
	config mtypes.EdgeConfigV2
	client *ControlHTTPClient

	ready chan superHTTPReady
	done  chan struct{}
	once  sync.Once
	apply sync.Mutex

	mu         sync.RWMutex
	candidates []mtypes.ControlV2Candidate
	parameters mtypes.ControlV2Parameters
}

func NewSuperHTTPRuntime(device *Device, config mtypes.EdgeConfigV2) *SuperHTTPRuntime {
	return &SuperHTTPRuntime{
		device: device,
		config: config,
		client: NewControlHTTPClient(config.SuperNodeV2.APIUrl, config.SuperNodeV2.APIPrefix, config.NodeID, config.SuperNodeV2.ControlPSKey),
		ready:  make(chan superHTTPReady, 1),
		done:   make(chan struct{}),
	}
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

	local := localControlCandidates(ready)
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
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := runtime.client.Sync(ctx, runtime.applySnapshot)
		if err != nil && !errors.Is(err, context.Canceled) && runtime.device != nil {
			runtime.device.log.Errorf("HTTP control sync stopped: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		runtime.reportLoop(ctx)
	}()
	wg.Wait()
}

func localControlCandidates(ready superHTTPReady) []mtypes.ControlV2Candidate {
	candidates := make([]mtypes.ControlV2Candidate, 0, 2)
	if ready.v4 != nil && !ready.v4.IsUnspecified() {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: net.JoinHostPort(ready.v4.String(), strconv.Itoa(ready.port)), Source: mtypes.ControlV2CandidateLocal})
	}
	if ready.v6 != nil && !ready.v6.IsUnspecified() {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: net.JoinHostPort(ready.v6.String(), strconv.Itoa(ready.port)), Source: mtypes.ControlV2CandidateLocal})
	}
	return candidates
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
	runtime.mu.Lock()
	runtime.parameters = snapshot.Parameters
	runtime.mu.Unlock()
	if runtime.device != nil {
		runtime.device.applySuperHTTPSnapshot(snapshot)
	}
}

func (runtime *SuperHTTPRuntime) refreshSTUN(ctx context.Context, parameters mtypes.ControlV2Parameters) {
	if runtime.device == nil || runtime.device.superSTUN == nil || len(parameters.STUNServers) == 0 {
		return
	}
	public := runtime.device.superSTUN.Discover(ctx, parameters.STUNServers, parameters.STUNRequestTimeout)
	if len(public) == 0 {
		return
	}
	runtime.mu.Lock()
	local := append([]mtypes.ControlV2Candidate(nil), runtime.candidates...)
	for _, candidate := range local {
		if candidate.Source == mtypes.ControlV2CandidateSTUN {
			local = local[:0]
			break
		}
	}
	runtime.candidates = append(local, public...)
	runtime.mu.Unlock()
}

func (runtime *SuperHTTPRuntime) setCandidates(candidates []mtypes.ControlV2Candidate) {
	runtime.mu.Lock()
	runtime.candidates = append([]mtypes.ControlV2Candidate(nil), candidates...)
	runtime.mu.Unlock()
}

func (runtime *SuperHTTPRuntime) reportLoop(ctx context.Context) {
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
		report := mtypes.ControlV2ReportRequest{NodeID: runtime.config.NodeID, Candidates: candidates, ReportedAt: time.Now()}
		if runtime.device != nil {
			report.Pongs = runtime.device.superHTTPPongs()
		}
		if err := runtime.client.Report(ctx, &report); err != nil && ctx.Err() == nil && runtime.device != nil {
			runtime.device.log.Errorf("HTTP control report failed: %v", err)
		}
	}
}

func (device *Device) applySuperHTTPSnapshot(snapshot *mtypes.ControlV2Snapshot) {
	wanted := make(map[mtypes.Vertex]mtypes.ControlV2Peer, len(snapshot.Peers))
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
			peer, err = device.NewPeer(publicKey, info.NodeID, false, 0)
			if err != nil {
				device.log.Errorf("HTTP control peer %v create failed: %v", info.NodeID, err)
				continue
			}
		}
		if info.PSKey != "" {
			if psk, keyErr := Str2PSKey(info.PSKey); keyErr == nil {
				peer.SetPSK(psk)
			}
		}
		urls := mtypes.API_connurl{LocalV4: candidateCosts(info.LocalV4), LocalV6: candidateCosts(info.LocalV6), ExternalV4: candidateCosts(info.PublicV4), ExternalV6: candidateCosts(info.PublicV6)}
		peer.endpoint_trylist.UpdateSuper(urls, true, device.EdgeConfig.AfPrefer)
		for destination, latencyMS := range info.LatencyMS {
			device.graph.UpdateLatency(info.NodeID, destination, latencyMS/1000, device.EdgeConfig.DynamicRoute.PeerAliveTimeout, 0, false, false)
		}
	}
	for id, peer := range device.allPeersByIDSnapshot() {
		if _, ok := wanted[id]; !ok {
			device.RemovePeer(peer.handshake.remoteStatic)
		}
	}
	device.graph.RecalculateNhTable(false)
	device.signalEndpointRetry()
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
		latencyMS := peer.SingleWayLatency.GetVal() * 1000
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
