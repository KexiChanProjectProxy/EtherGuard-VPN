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
}

type e2eRetryConfig struct {
	peerAliveTimeout     float64
	connNextTry          float64
	timeoutCheckInterval float64
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
		edgeA, runtimeA, cancelA = newE2EEdge(t, 101, "edge-a", keyA, baseURL, bindA, tapA, privateA, e2eRetryConfig{}, nil)
	}
	edgeB, runtimeB, cancelB := newE2EEdge(t, 102, "edge-b", keyB, baseURL, bindB, tapB, privateB, e2eRetryConfig{}, nil)
	edgeC, runtimeC, cancelC := newE2EEdge(t, 103, "edge-c", keyC, baseURL, bindC, tapC, privateC, options.edgeCRetry, nil)

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

func newE2EEdge(t *testing.T, id mtypes.Vertex, name, controlKey, baseURL string, bind *e2eBind, tapDevice tap.Device, privateKey device.NoisePrivateKey, retry e2eRetryConfig, beforeRuntime func()) (*device.Device, *device.SuperHTTPRuntime, context.CancelFunc) {
	t.Helper()
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
	edge := device.NewDevice(tapDevice, id, bind, device.NewLogger(device.LogLevelSilent, "e2e"), graph, "", legacy, "e2e")
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
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: controlKey,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := device.NewSuperHTTPRuntime(edge, config)
	runtime.Start(ctx)
	runtime.MarkReady(int(bind.port), 0, net.ParseIP("127.0.0.1"), nil)
	return edge, runtime, cancel
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
