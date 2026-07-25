package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/conn/bindtest"
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

// e2eBind preserves bindtest's direct Edge-to-Edge channel topology while
// providing an in-process STUN responder through the same active bind.
type e2eBind struct {
	conn.Bind

	mappedIP        net.IP
	inbox           chan e2eDatagram
	closed          chan struct{}
	close           sync.Once
	workers         sync.WaitGroup
	port            uint16
	advertisedPort  uint16
	allowInitiation bool
	responses       chan struct{}
	transports      chan path.Usage
}

func newE2EBind(bind conn.Bind, mappedIP net.IP, advertisedPort uint16, allowInitiation bool) *e2eBind {
	return &e2eBind{
		Bind:            bind,
		mappedIP:        append(net.IP(nil), mappedIP...),
		inbox:           make(chan e2eDatagram, 8192),
		closed:          make(chan struct{}),
		advertisedPort:  advertisedPort,
		allowInitiation: allowInitiation,
		responses:       make(chan struct{}, 1),
		transports:      make(chan path.Usage, 8),
	}
}

func (b *e2eBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closed = make(chan struct{})
	b.close = sync.Once{}
	receivers, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	if b.advertisedPort != 0 {
		actualPort = b.advertisedPort
	}
	b.port = actualPort
	for index, receiver := range receivers {
		b.workers.Add(1)
		go b.forward(receiver, index == 0)
	}
	wrapped := make([]conn.ReceiveFunc, len(receivers))
	for index := range wrapped {
		wrapped[index] = b.receive
	}
	return wrapped, actualPort, nil
}

func (b *e2eBind) forward(receive conn.ReceiveFunc, ipv4 bool) {
	defer b.workers.Done()
	buffer := make([]byte, device.MaxMessageSize)
	for {
		size, endpoint, err := receive(buffer)
		if err != nil {
			return
		}
		if ipv4 {
			endpoint, err = b.ipv4Sender(endpoint)
			if err != nil {
				return
			}
		}
		if len(buffer[:size]) > 0 && buffer[0] == uint8(path.MessageResponseType) {
			select {
			case b.responses <- struct{}{}:
			default:
			}
		}
		if len(buffer[:size]) > 0 && path.Usage(buffer[0]) >= path.MessageTransportType {
			select {
			case b.transports <- path.Usage(buffer[0]):
			default:
			}
		}
		datagram := e2eDatagram{packet: append([]byte(nil), buffer[:size]...), endpoint: endpoint}
		select {
		case <-b.closed:
			return
		case b.inbox <- datagram:
		}
	}
}

func (b *e2eBind) ipv4Sender(endpoint conn.Endpoint) (conn.Endpoint, error) {
	_, rawPort, err := net.SplitHostPort(endpoint.DstToString())
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return nil, err
	}
	return b.Bind.ParseEndpoint(net.JoinHostPort("127.0.0.1", strconv.Itoa(port-2)))
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
		if !b.allowInitiation && len(packet) >= 1 && packet[0] == uint8(path.MessageInitiationType) {
			return nil
		}
		return b.Bind.Send(packet, endpoint)
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

func (b *e2eBind) Close() error {
	var closeErr error
	b.close.Do(func() {
		close(b.closed)
		closeErr = b.Bind.Close()
		b.workers.Wait()
	})
	return closeErr
}

type e2eTopology struct {
	runtime        *superRuntime
	edgeListener   net.Listener
	manageListener net.Listener
	baseURL        string
	clock          *e2eClock

	edgeA    *device.Device
	edgeB    *device.Device
	bindA    *e2eBind
	bindB    *e2eBind
	runtimeA *device.SuperHTTPRuntime
	runtimeB *device.SuperHTTPRuntime
	cancelA  context.CancelFunc
	cancelB  context.CancelFunc
	tapB     *e2eTap
	pubA     device.NoisePublicKey
	pubB     device.NoisePublicKey
	keyA     string
	keyB     string

	closeOnce sync.Once
	closeErr  error
}

func newE2ETopology(t *testing.T) *e2eTopology {
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
	base := validBaseConfig()
	base.APIUrl = baseURL
	base.STUNServers = []string{"stun:" + e2eSTUNAddress}
	base.STUNRequestTimeoutSeconds = 0.05
	base.STUNRefreshIntervalSeconds = 60
	base.PollIntervalSeconds = 0.01
	base.ReportIntervalSeconds = 0.01
	base.HeartbeatIntervalSeconds = 1
	base.UsePSKForInterEdge = false

	keyA := "edge-a-control-key"
	keyB := "edge-b-control-key"
	base.Peers = []mtypes.SuperConfigV2Peer{
		{NodeID: 101, NodeName: "edge-a", ControlPSKey: keyA},
		{NodeID: 102, NodeName: "edge-b", ControlPSKey: keyB},
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

	binds := bindtest.NewChannelBinds()
	tapA := newE2ETap()
	tapB := newE2ETap()
	privateA, publicA := device.RandomKeyPair()
	privateB, publicB := device.RandomKeyPair()
	bindA := newE2EBind(binds[0], net.ParseIP("198.51.100.101"), 2, true)
	bindB := newE2EBind(binds[1], net.ParseIP("198.51.100.102"), 1, false)
	edgeA, runtimeA, cancelA := newE2EEdge(t, 101, "edge-a", keyA, baseURL, bindA, tapA, privateA)
	edgeB, runtimeB, cancelB := newE2EEdge(t, 102, "edge-b", keyB, baseURL, bindB, tapB, privateB)

	return &e2eTopology{
		runtime:        runtime,
		edgeListener:   edgeListener,
		manageListener: manageListener,
		baseURL:        baseURL,
		clock:          clock,
		edgeA:          edgeA,
		edgeB:          edgeB,
		bindA:          bindA,
		bindB:          bindB,
		runtimeA:       runtimeA,
		runtimeB:       runtimeB,
		cancelA:        cancelA,
		cancelB:        cancelB,
		tapB:           tapB,
		pubA:           publicA,
		pubB:           publicB,
		keyA:           keyA,
		keyB:           keyB,
	}
}

func newE2EEdge(t *testing.T, id mtypes.Vertex, name, controlKey, baseURL string, bind *e2eBind, tapDevice tap.Device, privateKey device.NoisePrivateKey) (*device.Device, *device.SuperHTTPRuntime, context.CancelFunc) {
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
			PeerAliveTimeout: 0,
			DupCheckTimeout:  5,
			SuperNode:        mtypes.SuperInfo{UseSuperNode: true},
		},
	}
	edge := device.NewDevice(tapDevice, id, bind, device.NewLogger(device.LogLevelSilent, "e2e"), graph, false, "", legacy, nil, nil, "e2e")
	if err := edge.SetPrivateKey(privateKey); err != nil {
		edge.Close()
		t.Fatalf("set edge private key: %v", err)
	}
	if err := edge.Up(); err != nil {
		edge.Close()
		t.Fatalf("bring edge up: %v", err)
	}
	edge.Chan_Device_Initialized <- struct{}{}
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
		topology.cancelA()
		topology.cancelB()
		for _, runtime := range []*device.SuperHTTPRuntime{topology.runtimeA, topology.runtimeB} {
			select {
			case <-runtime.Done():
			case <-ctx.Done():
				topology.closeErr = ctx.Err()
				return
			}
		}
		topology.edgeA.Close()
		topology.edgeB.Close()
		if err := topology.runtime.Shutdown(ctx); err != nil {
			topology.closeErr = err
		}
		if err := topology.edgeListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && topology.closeErr == nil {
			topology.closeErr = err
		}
		if err := topology.manageListener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && topology.closeErr == nil {
			topology.closeErr = err
		}
	})
	return topology.closeErr
}
