package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
	"github.com/pion/stun/v3"
)

const e2eSTUNAddress = "127.0.0.1:3478"

type e2eClock struct {
	mu  sync.Mutex
	now time.Time
}

func newE2EClock() *e2eClock {
	return &e2eClock{now: time.Now()}
}

func (c *e2eClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *e2eClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	c.mu.Unlock()
}

type e2eTap struct {
	events chan tap.Event
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newE2ETap() *e2eTap {
	t := &e2eTap{
		events: make(chan tap.Event, 1),
		writes: make(chan []byte, 8),
		closed: make(chan struct{}),
	}
	t.events <- tap.EventUp
	return t
}

func (t *e2eTap) Read([]byte, int) (int, error) {
	<-t.closed
	return 0, io.EOF
}

func (t *e2eTap) Write(packet []byte, offset int) (int, error) {
	copyPacket := append([]byte(nil), packet[offset:]...)
	select {
	case t.writes <- copyPacket:
	case <-t.closed:
		return 0, io.EOF
	}
	return len(copyPacket), nil
}

func (*e2eTap) Flush() error             { return nil }
func (*e2eTap) MTU() (int, error)        { return 1400, nil }
func (*e2eTap) Name() (string, error)    { return "e2e", nil }
func (t *e2eTap) Events() chan tap.Event { return t.events }

func (t *e2eTap) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

type e2eDatagram struct {
	packet   []byte
	endpoint conn.Endpoint
}

type e2eEndpoint struct {
	destination string
	source      string
}

func (e e2eEndpoint) ClearSrc()           {}
func (e e2eEndpoint) SrcToString() string { return e.source }
func (e e2eEndpoint) DstToString() string { return e.destination }
func (e e2eEndpoint) DstToBytes() []byte  { return []byte(e.destination) }
func (e e2eEndpoint) DstIP() net.IP {
	host, _, err := net.SplitHostPort(e.destination)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
func (e e2eEndpoint) SrcIP() net.IP { return nil }

// e2eFabric routes each fake public address to one Edge bind. It lets the
// test use a different observed source address from an Edge's STUN candidate.
type e2eFabric struct {
	mu    sync.RWMutex
	binds map[string]*e2eBind
}

func newE2EFabric() *e2eFabric {
	return &e2eFabric{binds: make(map[string]*e2eBind)}
}

func (f *e2eFabric) add(address string, bind *e2eBind) {
	f.mu.Lock()
	f.binds[address] = bind
	f.mu.Unlock()
}

func (f *e2eFabric) remove(address string, bind *e2eBind) {
	f.mu.Lock()
	if f.binds[address] == bind {
		delete(f.binds, address)
	}
	f.mu.Unlock()
}

func (f *e2eFabric) deliver(packet []byte, destination, source string) error {
	f.mu.RLock()
	bind := f.binds[destination]
	if bind == nil {
		_, destinationPort, err := net.SplitHostPort(destination)
		if err == nil {
			for address, candidate := range f.binds {
				_, candidatePort, splitErr := net.SplitHostPort(address)
				if splitErr == nil && candidatePort == destinationPort {
					bind = candidate
					break
				}
			}
		}
	}
	f.mu.RUnlock()
	if bind == nil {
		return nil
	}
	bind.observe(packet)
	select {
	case <-bind.closed:
		return net.ErrClosed
	case bind.inbox <- e2eDatagram{packet: append([]byte(nil), packet...), endpoint: e2eEndpoint{destination: source, source: source}}:
		return nil
	}
}

func (b *e2eBind) observe(packet []byte) {
	if len(packet) > 0 && packet[0] == uint8(path.MessageResponseType) {
		select {
		case b.responses <- struct{}{}:
		default:
		}
	}
	if len(packet) > 0 && path.Usage(packet[0]) >= path.MessageTransportType {
		select {
		case b.transports <- path.Usage(packet[0]):
		default:
		}
	}
}

// e2eBind provides an in-process STUN responder and a routable fake Internet
// topology through the same active bind.
type e2eBind struct {
	fabric         *e2eFabric
	mappedIP       net.IP
	observedIP     net.IP
	inbox          chan e2eDatagram
	closed         chan struct{}
	close          sync.Once
	port           uint16
	advertisedPort uint16
	dropInitiation atomic.Bool
	dropOutbound   atomic.Bool
	responses      chan struct{}
	transports     chan path.Usage
}

func newE2EBind(fabric *e2eFabric, mappedIP, observedIP net.IP, advertisedPort uint16, allowInitiation bool) *e2eBind {
	bind := &e2eBind{
		fabric:         fabric,
		mappedIP:       append(net.IP(nil), mappedIP...),
		observedIP:     append(net.IP(nil), observedIP...),
		inbox:          make(chan e2eDatagram, 8192),
		closed:         make(chan struct{}),
		advertisedPort: advertisedPort,
		responses:      make(chan struct{}, 1),
		transports:     make(chan path.Usage, 8),
	}
	bind.dropInitiation.Store(!allowInitiation)
	return bind
}

func (b *e2eBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closed = make(chan struct{})
	b.close = sync.Once{}
	if b.advertisedPort != 0 {
		port = b.advertisedPort
	}
	b.port = port
	b.fabric.add(b.address(b.mappedIP), b)
	b.fabric.add(b.address(b.observedIP), b)
	b.fabric.add(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(b.port))), b)
	return []conn.ReceiveFunc{b.receive}, port, nil
}

func (b *e2eBind) receive(buffer []byte) (int, conn.Endpoint, error) {
	select {
	case <-b.closed:
		return 0, nil, net.ErrClosed
	case datagram := <-b.inbox:
		return copy(buffer, datagram.packet), datagram.endpoint, nil
	}
}

func (b *e2eBind) Send(packet []byte, endpoint conn.Endpoint) error {
	if endpoint.DstToString() != e2eSTUNAddress {
		if b.dropOutbound.Load() {
			return nil
		}
		if b.dropInitiation.Load() && len(packet) >= 1 && packet[0] == uint8(path.MessageInitiationType) {
			return nil
		}
		return b.fabric.deliver(packet, endpoint.DstToString(), b.address(b.observedIP))
	}
	if len(packet) < 20 {
		return errors.New("short STUN request")
	}
	var transactionID [stun.TransactionIDSize]byte
	copy(transactionID[:], packet[8:20])
	response, err := stun.Build(
		stun.BindingSuccess,
		stun.NewTransactionIDSetter(transactionID),
		&stun.XORMappedAddress{IP: b.mappedIP, Port: int(b.port)},
		stun.Fingerprint,
	)
	if err != nil {
		return err
	}
	select {
	case <-b.closed:
		return net.ErrClosed
	case b.inbox <- e2eDatagram{packet: append([]byte(nil), response.Raw...), endpoint: endpoint}:
		return nil
	}
}

func (b *e2eBind) discardPending() {
	for {
		select {
		case <-b.inbox:
		default:
			return
		}
	}
}

func (b *e2eBind) Close() error {
	var closeErr error
	b.close.Do(func() {
		close(b.closed)
		b.fabric.remove(b.address(b.mappedIP), b)
		b.fabric.remove(b.address(b.observedIP), b)
		b.fabric.remove(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(b.port))), b)
	})
	return closeErr
}

func (b *e2eBind) address(ip net.IP) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(b.port)))
}

func (*e2eBind) SetMark(uint32) error { return nil }

func (*e2eBind) EnabledAf() conn.EnabledAf { return conn.EnabledAf{IPv4: true} }

func (*e2eBind) ParseEndpoint(address string) (conn.Endpoint, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, err
	}
	return e2eEndpoint{destination: address}, nil
}

type e2eTopology struct {
	runtime            *superRuntime
	fabric             *e2eFabric
	edgeListener       net.Listener
	manageListener     net.Listener
	baseURL            string
	proxy              *httptest.Server
	releaseCEvents     chan struct{}
	forcedCNotModified *atomic.Int64
	forcedCSnapshots   *atomic.Int64
	clock              *e2eClock

	edgeA    *device.Device
	edgeB    *device.Device
	edgeC    *device.Device
	bindA    *e2eBind
	bindB    *e2eBind
	bindC    *e2eBind
	runtimeA *device.SuperHTTPRuntime
	runtimeB *device.SuperHTTPRuntime
	runtimeC *device.SuperHTTPRuntime
	cancelA  context.CancelFunc
	cancelB  context.CancelFunc
	cancelC  context.CancelFunc
	tapB     *e2eTap
	pubA     device.NoisePublicKey
	pubB     device.NoisePublicKey
	pubC     device.NoisePublicKey
	keyA     string
	keyB     string
	keyC     string

	closeOnce sync.Once
	closeErr  error
}

type e2eSuper struct {
	id        mtypes.Vertex
	runtime   *superRuntime
	edgeURL   string
	manageURL string
	clock     *e2eClock
	dir       string
	hash      string
	proxy     *httptest.Server
	edgeLn    net.Listener
	manageLn  net.Listener
}

type e2eClusterOptions struct {
	heartbeat   time.Duration
	deadAfter   time.Duration
	grace       time.Duration
	compression string
	linkPairs   [][2]int
	apiPrefix   string
}

type e2eMultiSuper struct {
	supers          []e2eSuper
	proxies         []*httptest.Server
	edgeListeners   []net.Listener
	manageListeners []net.Listener
	edges           []*device.Device
	edgeRuntimes    []*device.SuperHTTPRuntime
	edgeCancels     []context.CancelFunc
	apiPrefix       string
	closeOnce       sync.Once
	closeErr        error
}

func newE2EMultiSuperTopology(t *testing.T, n int, opts e2eClusterOptions) *e2eMultiSuper {
	t.Helper()
	if n < 2 {
		t.Fatalf("multi-super topology size = %d, want at least 2", n)
	}
	if opts.heartbeat <= 0 {
		opts.heartbeat = 100 * time.Millisecond
	}
	if opts.deadAfter <= 0 {
		opts.deadAfter = 500 * time.Millisecond
	}
	if opts.grace <= 0 {
		opts.grace = 2 * time.Second
	}
	if opts.compression == "" {
		opts.compression = "zstd"
	}
	if opts.apiPrefix == "" {
		opts.apiPrefix = mtypes.ControlV2APIPrefix
	}

	topology := &e2eMultiSuper{
		supers:          make([]e2eSuper, n),
		proxies:         make([]*httptest.Server, n),
		edgeListeners:   make([]net.Listener, n),
		manageListeners: make([]net.Listener, n),
		apiPrefix:       opts.apiPrefix,
	}
	t.Cleanup(func() {
		if err := topology.shutdown(); err != nil {
			t.Errorf("shutdown multi-super topology: %v", err)
		}
	})

	for index := range n {
		edgeListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen super %d edge API: %v", index, err)
		}
		topology.edgeListeners[index] = edgeListener
		manageListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen super %d management API: %v", index, err)
		}
		topology.manageListeners[index] = manageListener

		upstreamURL, err := url.Parse("http://" + edgeListener.Addr().String())
		if err != nil {
			t.Fatalf("parse super %d edge URL: %v", index, err)
		}
		proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			httputil.NewSingleHostReverseProxy(upstreamURL).ServeHTTP(writer, request)
		}))
		topology.proxies[index] = proxy
		topology.supers[index] = e2eSuper{
			id:        mtypes.Vertex(index + 1),
			edgeURL:   proxy.URL,
			manageURL: "http://" + manageListener.Addr().String(),
			clock:     newE2EClock(),
			dir:       t.TempDir(),
			hash:      "e2e-management-hash-" + strconv.Itoa(index+1),
			proxy:     proxy,
			edgeLn:    edgeListener,
			manageLn:  manageListener,
		}
	}

	links := make([][]bool, n)
	for index := range links {
		links[index] = make([]bool, n)
	}
	if opts.linkPairs == nil {
		for left := range n {
			for right := left + 1; right < n; right++ {
				links[left][right] = true
				links[right][left] = true
			}
		}
	} else {
		for _, pair := range opts.linkPairs {
			if pair[0] < 0 || pair[0] >= n || pair[1] < 0 || pair[1] >= n || pair[0] == pair[1] {
				t.Fatalf("invalid multi-super link pair %v for size %d", pair, n)
			}
			links[pair[0]][pair[1]] = true
			links[pair[1]][pair[0]] = true
		}
	}

	const sharedSecret = "e2e-multi-super-shared-secret-0123456789"
	for index := range n {
		clusterPeers := make([]mtypes.SuperConfigV2ClusterPeer, 0, n-1)
		for peerIndex := range n {
			if links[index][peerIndex] {
				clusterPeers = append(clusterPeers, mtypes.SuperConfigV2ClusterPeer{
					SuperID: topology.supers[peerIndex].id,
					APIUrl:  topology.supers[peerIndex].edgeURL,
				})
			}
		}
		cluster := &mtypes.SuperConfigV2Cluster{
			SelfID:                  topology.supers[index].id,
			Secret:                  sharedSecret,
			Peers:                   clusterPeers,
			HeartbeatSeconds:        opts.heartbeat.Seconds(),
			DeadAfterSeconds:        opts.deadAfter.Seconds(),
			ReconnectMinSeconds:     0.05,
			ReconnectMaxSeconds:     0.2,
			RemoteStaleGraceSeconds: opts.grace.Seconds(),
			Compression:             opts.compression,
		}
		base := validBaseConfig()
		base.NodeName = "e2e-super-" + strconv.Itoa(index+1)
		base.APIUrl = topology.supers[index].edgeURL
		base.APIPrefix = opts.apiPrefix
		base.ManagementAuth.PasswordHash = topology.supers[index].hash
		base.STUNServers = nil
		base.Peers = nil
		base.PeerAliveTimeoutSeconds = min(1, opts.grace.Seconds())
		runtime, err := RunWithListeners(&superConfig{
			BaseConfig:      base,
			EdgeTemplate:    validEdgeTemplate(),
			ClusterOverride: cluster,
			ConfigDir:       topology.supers[index].dir,
			EdgeListen:      topology.edgeListeners[index],
			ManageListen:    topology.manageListeners[index],
			ShutdownTimeout: 5 * time.Second,
			TickInterval:    10 * time.Millisecond,
			Now:             topology.supers[index].clock.Now,
		})
		if err != nil {
			t.Fatalf("start super %d: %v", index, err)
		}
		topology.supers[index].runtime = runtime
	}
	return topology
}

func newE2ESuperFrom(t *testing.T, dir string, id mtypes.Vertex, clock *e2eClock) *e2eSuper {
	t.Helper()
	base, err := loadSuperConfigV2(filepath.Join(dir, "super.yaml"))
	if err != nil {
		t.Fatalf("load restarted super %d config: %v", id, err)
	}
	if base.Cluster == nil || base.Cluster.SelfID != id {
		t.Fatalf("restarted super cluster identity = %+v, want %d", base.Cluster, id)
	}
	edgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen restarted super %d edge API: %v", id, err)
	}
	manageListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = edgeListener.Close()
		t.Fatalf("listen restarted super %d management API: %v", id, err)
	}
	upstreamURL, err := url.Parse("http://" + edgeListener.Addr().String())
	if err != nil {
		_ = edgeListener.Close()
		_ = manageListener.Close()
		t.Fatalf("parse restarted super %d edge URL: %v", id, err)
	}
	proxy := httptest.NewServer(httputil.NewSingleHostReverseProxy(upstreamURL))
	base.APIUrl = proxy.URL
	runtime, err := RunWithListeners(&superConfig{
		BaseConfig:      base,
		EdgeTemplate:    validEdgeTemplate(),
		ClusterOverride: base.Cluster,
		ConfigDir:       dir,
		EdgeListen:      edgeListener,
		ManageListen:    manageListener,
		ShutdownTimeout: 5 * time.Second,
		TickInterval:    10 * time.Millisecond,
		Now:             clock.Now,
	})
	if err != nil {
		proxy.Close()
		_ = edgeListener.Close()
		_ = manageListener.Close()
		t.Fatalf("restart super %d: %v", id, err)
	}
	return &e2eSuper{
		id: id, runtime: runtime, edgeURL: proxy.URL,
		manageURL: "http://" + manageListener.Addr().String(), clock: clock,
		dir: dir, hash: base.ManagementAuth.PasswordHash,
		proxy: proxy, edgeLn: edgeListener, manageLn: manageListener,
	}
}

func (topology *e2eMultiSuper) shutdown() error {
	topology.closeOnce.Do(func() {
		for _, cancel := range topology.edgeCancels {
			if cancel != nil {
				cancel()
			}
		}
		for _, runtime := range topology.edgeRuntimes {
			if runtime == nil {
				continue
			}
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-runtime.Done():
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
				topology.closeErr = errors.Join(topology.closeErr, errors.New("edge runtime shutdown timed out"))
			}
		}
		for _, edge := range topology.edges {
			if edge != nil {
				edge.Close()
			}
		}
		for index := range topology.supers {
			if topology.supers[index].runtime == nil {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := topology.supers[index].runtime.Shutdown(ctx)
			cancel()
			if err != nil {
				topology.closeErr = errors.Join(topology.closeErr, err)
			}
		}
		for _, proxy := range topology.proxies {
			if proxy != nil {
				proxy.Close()
			}
		}
		for _, listener := range append(topology.edgeListeners, topology.manageListeners...) {
			if listener == nil {
				continue
			}
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				topology.closeErr = errors.Join(topology.closeErr, err)
			}
		}
	})
	return topology.closeErr
}

func newE2ETopology(t *testing.T) *e2eTopology {
	return newE2ETopologyWithOptions(t, e2eTopologyOptions{pollIntervalSeconds: 0.01})
}

func newE2ETopologyWithPoll(t *testing.T, pollIntervalSeconds float64) *e2eTopology {
	return newE2ETopologyWithOptions(t, e2eTopologyOptions{pollIntervalSeconds: pollIntervalSeconds})
}

type e2eTopologyOptions struct {
	pollIntervalSeconds float64
	reportInterval      time.Duration
	edgeCRetry          e2eRetryConfig
	disableSTUN         bool
	allowBInitiation    bool
	twoEdges            bool
	blockCEvents        bool
	// listenPortPolicy, when non-nil, sets the Super's published
	// ListenPortPriority. Used by the bootstrap-listening-port
	// integration test; leave nil for the default empty policy.
	listenPortPolicy mtypes.ListenPortPriority
}

type e2eRetryConfig struct {
	peerAliveTimeout     float64
	connNextTry          float64
	timeoutCheckInterval float64
}

type e2eEdgeOptions struct {
	startIndex int
	logger     *device.Logger
	apiPrefix  string
}

type e2eEdgeOption func(*e2eEdgeOptions)

func withE2EEdgeStartIndex(index int) e2eEdgeOption {
	return func(options *e2eEdgeOptions) {
		options.startIndex = index
	}
}

func withE2EEdgeLogger(logger *device.Logger) e2eEdgeOption {
	return func(options *e2eEdgeOptions) {
		options.logger = logger
	}
}

func withE2EEdgeAPIPrefix(apiPrefix string) e2eEdgeOption {
	return func(options *e2eEdgeOptions) {
		options.apiPrefix = apiPrefix
	}
}

func newE2ETopologyWithOptions(t *testing.T, options e2eTopologyOptions) *e2eTopology {
	t.Helper()
	edgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen control: %v", err)
	}
	manageListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = edgeListener.Close()
		t.Fatalf("listen management: %v", err)
	}
	clock := newE2EClock()
	baseURL := "http://" + edgeListener.Addr().String()
	upstreamURL, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse control URL: %v", err)
	}
	forcedCNotModified := &atomic.Int64{}
	forcedCSnapshots := &atomic.Int64{}
	releaseCEvents := make(chan struct{})
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if options.blockCEvents && strings.HasSuffix(request.URL.Path, "/events") && request.Header.Get("X-EG-NodeID") == "103" {
			writer.Header().Set("Content-Type", "text/event-stream")
			writer.WriteHeader(http.StatusOK)
			writer.(http.Flusher).Flush()
			select {
			case <-request.Context().Done():
			case <-releaseCEvents:
			}
			return
		}
		isCSnapshot := strings.HasSuffix(request.URL.Path, "/snapshot") && request.Header.Get("X-EG-NodeID") == "103"
		if isCSnapshot {
			forcedCSnapshots.Add(1)
		}
		reverseProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
		reverseProxy.ModifyResponse = func(response *http.Response) error {
			if isCSnapshot && response.StatusCode == http.StatusNotModified {
				forcedCNotModified.Add(1)
			}
			return nil
		}
		reverseProxy.ServeHTTP(writer, request)
	}))
	baseURL = proxy.URL
	base := validBaseConfig()
	base.APIUrl = baseURL
	if !options.disableSTUN {
		base.STUNServers = []string{"stun:" + e2eSTUNAddress}
	}
	base.STUNRequestTimeoutSeconds = 0.05
	base.STUNRefreshIntervalSeconds = 60
	base.PollIntervalSeconds = options.pollIntervalSeconds
	base.ReportIntervalSeconds = options.reportInterval.Seconds()
	if base.ReportIntervalSeconds == 0 {
		base.ReportIntervalSeconds = 0.01
	}
	base.HeartbeatIntervalSeconds = 1
	base.PeerAliveTimeoutSeconds = 3600
	base.UsePSKForInterEdge = false
	if options.listenPortPolicy != nil {
		base.ListenPortPriority = options.listenPortPolicy
	}

	keyA := "edge-a-control-key"
	keyB := "edge-b-control-key"
	keyC := "edge-c-control-key"
	base.Peers = []mtypes.SuperConfigV2Peer{
		{NodeID: 102, NodeName: "edge-b", ControlPSKey: keyB},
		{NodeID: 103, NodeName: "edge-c", ControlPSKey: keyC},
	}
	if !options.twoEdges {
		base.Peers = append([]mtypes.SuperConfigV2Peer{{NodeID: 101, NodeName: "edge-a", ControlPSKey: keyA}}, base.Peers...)
	}
	runtime, err := RunWithListeners(&superConfig{
		BaseConfig:      base,
		EdgeTemplate:    validEdgeTemplate(),
		ConfigDir:       t.TempDir(),
		EdgeListen:      edgeListener,
		ManageListen:    manageListener,
		ShutdownTimeout: 3 * time.Second,
		TickInterval:    10 * time.Millisecond,
		Now:             clock.Now,
	})
	if err != nil {
		_ = edgeListener.Close()
		_ = manageListener.Close()
		t.Fatalf("start HTTP-only Super: %v", err)
	}

	fabric := newE2EFabric()
	tapA := newE2ETap()
	tapB := newE2ETap()
	tapC := newE2ETap()
	privateA, publicA := device.RandomKeyPair()
	privateB, publicB := device.RandomKeyPair()
	privateC, publicC := device.RandomKeyPair()
	bindA := newE2EBind(fabric, net.ParseIP("198.51.100.101"), net.ParseIP("198.51.100.101"), 101, true)
	bindB := newE2EBind(fabric, net.ParseIP("198.51.100.102"), net.ParseIP("203.0.113.102"), 102, options.allowBInitiation)
	bindC := newE2EBind(fabric, net.ParseIP("198.51.100.103"), net.ParseIP("198.51.100.103"), 103, true)
	var edgeA *device.Device
	var runtimeA *device.SuperHTTPRuntime
	var cancelA context.CancelFunc
	if !options.twoEdges {
		edgeA, runtimeA, cancelA = newE2EEdge(t, 101, "edge-a", keyA, baseURL, bindA, tapA, privateA, e2eRetryConfig{}, nil, nil)
	}
	edgeB, runtimeB, cancelB := newE2EEdge(t, 102, "edge-b", keyB, baseURL, bindB, tapB, privateB, e2eRetryConfig{}, nil, nil)
	edgeC, runtimeC, cancelC := newE2EEdge(t, 103, "edge-c", keyC, baseURL, bindC, tapC, privateC, options.edgeCRetry, nil, nil)

	return &e2eTopology{
		runtime:            runtime,
		fabric:             fabric,
		edgeListener:       edgeListener,
		manageListener:     manageListener,
		baseURL:            baseURL,
		proxy:              proxy,
		releaseCEvents:     releaseCEvents,
		forcedCNotModified: forcedCNotModified,
		forcedCSnapshots:   forcedCSnapshots,
		clock:              clock,
		edgeA:              edgeA,
		edgeB:              edgeB,
		edgeC:              edgeC,
		bindA:              bindA,
		bindB:              bindB,
		bindC:              bindC,
		runtimeA:           runtimeA,
		runtimeB:           runtimeB,
		runtimeC:           runtimeC,
		cancelA:            cancelA,
		cancelB:            cancelB,
		cancelC:            cancelC,
		tapB:               tapB,
		pubA:               publicA,
		pubB:               publicB,
		pubC:               publicC,
		keyA:               keyA,
		keyB:               keyB,
		keyC:               keyC,
	}
}

func newE2EEdge(t *testing.T, id mtypes.Vertex, name, controlKey, baseURL string, bind *e2eBind, tapDevice tap.Device, privateKey device.NoisePrivateKey, retry e2eRetryConfig, beforeRuntime func(), baseURLs []string, optionValues ...e2eEdgeOption) (*device.Device, *device.SuperHTTPRuntime, context.CancelFunc) {
	t.Helper()
	options := e2eEdgeOptions{apiPrefix: mtypes.ControlV2APIPrefix}
	for _, option := range optionValues {
		option(&options)
	}
	graph, err := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("new edge graph: %v", err)
	}
	legacy := &mtypes.EdgeConfig{
		NodeID:     id,
		NodeName:   name,
		DefaultTTL: 64,
		Interface:  mtypes.InterfaceConf{MTU: 1400},
		DynamicRoute: mtypes.DynamicRouteInfo{
			PeerAliveTimeout:     retry.peerAliveTimeout,
			ConnNextTry:          retry.connNextTry,
			TimeoutCheckInterval: retry.timeoutCheckInterval,
			DupCheckTimeout:      5,
		},
		SuperNodeV2Enabled: true,
	}
	logger := options.logger
	if logger == nil {
		logger = device.NewLogger(device.LogLevelSilent, "e2e")
	}
	edge := device.NewDevice(tapDevice, id, bind, logger, graph, "", legacy, "e2e")
	if err := edge.SetPrivateKey(privateKey); err != nil {
		edge.Close()
		t.Fatalf("set edge private key: %v", err)
	}
	if err := edge.Up(); err != nil {
		edge.Close()
		t.Fatalf("bring edge up: %v", err)
	}
	edge.Chan_Device_Initialized <- struct{}{}
	if beforeRuntime != nil {
		beforeRuntime()
	}
	config := mtypes.EdgeConfigV2{
		NodeID:     id,
		NodeName:   name,
		DefaultTTL: 64,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       baseURL,
			APIUrls:      append([]string(nil), baseURLs...),
			APIPrefix:    options.apiPrefix,
			NodeID:       1,
			ControlPSKey: controlKey,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := device.NewSuperHTTPRuntime(edge, config, device.WithStartIndex(options.startIndex))
	runtime.Start(ctx)
	runtime.MarkReady(int(bind.port), 0, net.ParseIP("127.0.0.1"), nil)
	return edge, runtime, cancel
}

func WaitLinked(t *testing.T, topology *e2eMultiSuper, a, b int, timeout time.Duration) {
	t.Helper()
	awaitE2E(t, timeout, func() bool {
		return e2eLinkConnected(topology, a, b)
	})
}

func e2eLinkConnected(topology *e2eMultiSuper, a, b int) bool {
	manager := topology.supers[a].runtime.Cluster()
	if manager == nil {
		return false
	}
	wantID := topology.supers[b].id
	for _, link := range manager.Status().Links {
		if link.SuperID == wantID {
			return link.State == "connected"
		}
	}
	return false
}

func WaitApplied(t *testing.T, topology *e2eMultiSuper, s int, nodeID mtypes.Vertex, pred func(mtypes.ControlV2Peer) bool, timeout time.Duration) {
	t.Helper()
	awaitE2E(t, timeout, func() bool {
		snapshot := topology.supers[s].runtime.State().SnapshotFor(60000)
		for _, peer := range snapshot.Peers {
			if peer.NodeID == nodeID && pred(peer) {
				return true
			}
		}
		return false
	})
}

func CutLink(topology *e2eMultiSuper, a, b int) {
	left := topology.supers[a]
	right := topology.supers[b]
	left.runtime.Cluster().SetDialGateForTest(right.id, true)
	right.runtime.Cluster().SetDialGateForTest(left.id, true)
	left.runtime.Cluster().CloseSessionForTest(right.id)
	right.runtime.Cluster().CloseSessionForTest(left.id)
}

func HealLink(topology *e2eMultiSuper, a, b int) {
	left := topology.supers[a]
	right := topology.supers[b]
	left.runtime.Cluster().SetDialGateForTest(right.id, false)
	right.runtime.Cluster().SetDialGateForTest(left.id, false)
}

func ShutdownSuper(t *testing.T, topology *e2eMultiSuper, s int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := topology.supers[s].runtime.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown super %d: %v", s, err)
	}
}

func LinkStats(topology *e2eMultiSuper, a, b int) clusterLinkStats {
	wantID := topology.supers[b].id
	for _, link := range topology.supers[a].runtime.Cluster().Status().Links {
		if link.SuperID == wantID {
			return clusterLinkStats{
				TX:             link.TX,
				RX:             link.RX,
				ConnectedSince: link.ConnectedSince,
				LastRXAt:       link.LastRXAt,
				Dialer:         link.Dialer,
				Compression:    link.Compression,
			}
		}
	}
	return clusterLinkStats{}
}

func (topology *e2eTopology) shutdown(ctx context.Context) error {
	topology.closeOnce.Do(func() {
		if topology.cancelA != nil {
			topology.cancelA()
		}
		topology.cancelB()
		topology.cancelC()
		for _, runtime := range []*device.SuperHTTPRuntime{topology.runtimeA, topology.runtimeB, topology.runtimeC} {
			if runtime == nil {
				continue
			}
			select {
			case <-runtime.Done():
			case <-ctx.Done():
				topology.closeErr = ctx.Err()
				return
			}
		}
		if topology.edgeA != nil {
			topology.edgeA.Close()
		}
		topology.edgeB.Close()
		topology.edgeC.Close()
		if err := topology.runtime.Shutdown(ctx); err != nil {
			topology.closeErr = err
		}
		topology.proxy.Close()
		if err := topology.edgeListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && topology.closeErr == nil {
			topology.closeErr = err
		}
		if err := topology.manageListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && topology.closeErr == nil {
			topology.closeErr = err
		}
	})
	return topology.closeErr
}

func TestE2EMultiSuperTopologySmoke(t *testing.T) {
	t.Run("two supers link through reverse proxies", func(t *testing.T) {
		topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})

		WaitLinked(t, topology, 0, 1, 3*time.Second)
		WaitLinked(t, topology, 1, 0, 3*time.Second)

		CutLink(topology, 0, 1)
		awaitE2E(t, time.Second, func() bool {
			return !e2eLinkConnected(topology, 0, 1) && !e2eLinkConnected(topology, 1, 0)
		})
		gateWindow := time.NewTimer(300 * time.Millisecond)
		gatePoll := time.NewTicker(5 * time.Millisecond)
		for gateWindow != nil {
			select {
			case <-gateWindow.C:
				gateWindow = nil
			case <-gatePoll.C:
				if e2eLinkConnected(topology, 0, 1) || e2eLinkConnected(topology, 1, 0) {
					gatePoll.Stop()
					t.Fatal("cut cluster link reconnected while both dial gates were closed")
				}
			}
		}
		gatePoll.Stop()
		HealLink(topology, 0, 1)
		WaitLinked(t, topology, 0, 1, 3*time.Second)
		WaitLinked(t, topology, 1, 0, 3*time.Second)
	})

	t.Run("three supers form a full mesh", func(t *testing.T) {
		topology := newE2EMultiSuperTopology(t, 3, e2eClusterOptions{linkPairs: nil})
		for index := range topology.supers {
			for peerIndex := range topology.supers {
				if index != peerIndex {
					WaitLinked(t, topology, index, peerIndex, 3*time.Second)
				}
			}
		}
		awaitE2E(t, 3*time.Second, func() bool {
			for index := range topology.supers {
				links := topology.supers[index].runtime.Cluster().Status().Links
				connected := 0
				for _, link := range links {
					if link.State == "connected" {
						connected++
					}
				}
				if len(links) != 2 || connected != 2 {
					return false
				}
			}
			return true
		})
	})
}
