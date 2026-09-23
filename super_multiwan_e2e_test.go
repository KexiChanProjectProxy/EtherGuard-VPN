package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/pion/stun/v3"
)

// e2ePinnedEndpoint is an e2e endpoint whose datagrams leave through one
// pinned local uplink.
type e2ePinnedEndpoint struct {
	e2eEndpoint
	pinned net.IP
}

func (e e2ePinnedEndpoint) SrcIP() net.IP { return e.pinned }

// e2eMultiWANBind emulates an edge with several uplinks, each behind its own
// NAT: a datagram pinned to an uplink appears on the fabric from that uplink's
// public address, and STUN reports that address. Unpinned datagrams use the
// default route (the embedded bind's mapped address).
type e2eMultiWANBind struct {
	*e2eBind
	publicBySource map[string]net.IP
	// peerPortBySource, when set for an uplink, is the NAT port its traffic to
	// peers uses; STUN still sees the bind port (endpoint-dependent mapping).
	peerPortBySource map[string]uint16
}

var _ conn.EndpointSourcePinner = (*e2eMultiWANBind)(nil)

func newE2EMultiWANBind(fabric *e2eFabric, port uint16, defaultPublic net.IP, publicBySource map[string]net.IP) *e2eMultiWANBind {
	return &e2eMultiWANBind{
		e2eBind:        newE2EBind(fabric, defaultPublic, defaultPublic, port, true),
		publicBySource: publicBySource,
	}
}

func (b *e2eMultiWANBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.e2eBind.Open(port)
	for source := range b.publicBySource {
		b.fabric.add(b.peerAddress(source), b.e2eBind)
	}
	return fns, actual, err
}

func (b *e2eMultiWANBind) Close() error {
	for source := range b.publicBySource {
		b.fabric.remove(b.peerAddress(source), b.e2eBind)
	}
	return b.e2eBind.Close()
}

// peerAddress is the public ip:port peers see for traffic from source.
func (b *e2eMultiWANBind) peerAddress(source string) string {
	public := b.publicBySource[source]
	if port, ok := b.peerPortBySource[source]; ok {
		return net.JoinHostPort(public.String(), strconv.Itoa(int(port)))
	}
	return b.address(public)
}

func (b *e2eMultiWANBind) ParseEndpointFrom(dst string, src netip.Addr, ifindex int) (conn.Endpoint, error) {
	if !src.IsValid() || ifindex <= 0 {
		return nil, conn.ErrInvalidSource
	}
	if _, _, err := net.SplitHostPort(dst); err != nil {
		return nil, err
	}
	return e2ePinnedEndpoint{e2eEndpoint: e2eEndpoint{destination: dst}, pinned: src.AsSlice()}, nil
}

func (b *e2eMultiWANBind) public(endpoint conn.Endpoint) (net.IP, string) {
	if pinned, ok := endpoint.(e2ePinnedEndpoint); ok {
		if public, found := b.publicBySource[pinned.pinned.String()]; found {
			return public, b.peerAddress(pinned.pinned.String())
		}
	}
	return b.mappedIP, b.address(b.mappedIP)
}

func (b *e2eMultiWANBind) Send(packet []byte, endpoint conn.Endpoint) error {
	public, peerAddress := b.public(endpoint)
	if endpoint.DstToString() != e2eSTUNAddress {
		if b.dropOutbound.Load() {
			return nil
		}
		if b.dropInitiation.Load() && len(packet) >= 1 && packet[0] == uint8(path.MessageInitiationType) {
			return nil
		}
		return b.fabric.deliver(packet, endpoint.DstToString(), peerAddress)
	}
	if len(packet) < 20 {
		return errors.New("short STUN request")
	}
	var transactionID [stun.TransactionIDSize]byte
	copy(transactionID[:], packet[8:20])
	response, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(transactionID), &stun.XORMappedAddress{IP: public, Port: int(b.port)}, stun.Fingerprint)
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

type e2eMultiWANEdgeConfig struct {
	id      mtypes.Vertex
	name    string
	key     string
	bind    conn.Bind
	port    uint16
	uplinks []device.UplinkForTest
	p2p     bool
	// disableSelection turns lowest-latency endpoint selection off.
	disableSelection bool
}

// newE2EMultiWANEdge starts a real edge device with fast direct-connectivity
// timings so the retry loop, pings and endpoint probing run in test time.
func newE2EMultiWANEdge(t *testing.T, cfg e2eMultiWANEdgeConfig, baseURL string, privateKey device.NoisePrivateKey) (*device.Device, *device.SuperHTTPRuntime) {
	t.Helper()
	graph, err := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	legacy := &mtypes.EdgeConfig{
		NodeID:     cfg.id,
		NodeName:   cfg.name,
		DefaultTTL: 64,
		Interface:  mtypes.InterfaceConf{MTU: 1400},
		DynamicRoute: mtypes.DynamicRouteInfo{
			PeerAliveTimeout:         30,
			ConnNextTry:              0.05,
			TimeoutCheckInterval:     0.05,
			SendPingInterval:         0.2,
			EndpointProbeInterval:    0.2,
			DupCheckTimeout:          5,
			P2P:                      mtypes.P2PInfo{UseP2P: cfg.p2p, SendPeerInterval: 5},
			DisableEndpointSelection: cfg.disableSelection,
		},
		SuperNodeV2Enabled: !cfg.p2p,
	}
	edge := device.NewDevice(newE2ETap(), cfg.id, cfg.bind, device.NewLogger(device.LogLevelSilent, "multiwan-e2e"), graph, "", legacy, "e2e")
	edge.SetUplinksForTest(cfg.uplinks)
	if err := edge.SetPrivateKey(privateKey); err != nil {
		edge.Close()
		t.Fatalf("set private key: %v", err)
	}
	if err := edge.Up(); err != nil {
		edge.Close()
		t.Fatalf("edge up: %v", err)
	}
	edge.Chan_Device_Initialized <- struct{}{}
	t.Cleanup(edge.Close)
	if cfg.p2p {
		return edge, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runtime := device.NewSuperHTTPRuntime(edge, mtypes.EdgeConfigV2{
		NodeID:     cfg.id,
		NodeName:   cfg.name,
		DefaultTTL: 64,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       baseURL,
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: cfg.key,
		},
	})
	runtime.Start(ctx)
	runtime.MarkReady(int(cfg.port), 0, net.ParseIP("127.0.0.1"), nil)
	return edge, runtime
}

type e2eMultiWANTopology struct {
	fabric *e2eFabric
	super  *superRuntime
	edgeA  *device.Device
	edgeB  *device.Device
	bindB  *e2eMultiWANBind
	keyA   string
	keyB   string
	base   string
	pubA   device.NoisePublicKey
	pubB   device.NoisePublicKey
}

// newE2EMultiWANTopology runs a Super, a single-homed edge A (101) and a
// multi-WAN edge B (102) whose uplinks sit behind NATs 203.0.113.11 and .12.
// Before A's first probe, delayFor installs per-destination fabric latency.
type e2eMultiWANOptions struct {
	configureA       func(*e2eMultiWANEdgeConfig)
	peerPortBySource map[string]uint16
	strictFabric     func(destination string) bool
}

func newE2EMultiWANTopology(t *testing.T, delayFor func(destination string) time.Duration, options ...e2eMultiWANOptions) *e2eMultiWANTopology {
	var opts e2eMultiWANOptions
	if len(options) > 0 {
		opts = options[0]
	}
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
	baseURL := "http://" + edgeListener.Addr().String()
	base := validBaseConfig()
	base.APIUrl = baseURL
	base.STUNServers = []string{"stun:" + e2eSTUNAddress}
	base.STUNRequestTimeoutSeconds = 0.2
	base.STUNRefreshIntervalSeconds = 60
	base.PollIntervalSeconds = 0.01
	base.ReportIntervalSeconds = 0.01
	base.HeartbeatIntervalSeconds = 1
	base.PeerAliveTimeoutSeconds = 3600
	base.UsePSKForInterEdge = false
	topology := &e2eMultiWANTopology{fabric: newE2EFabric(), keyA: "edge-a-control-key", keyB: "edge-b-control-key", base: baseURL}
	topology.fabric.delay = delayFor
	topology.fabric.strict = opts.strictFabric
	base.Peers = []mtypes.SuperConfigV2Peer{
		{NodeID: 101, NodeName: "edge-a", ControlPSKey: topology.keyA},
		{NodeID: 102, NodeName: "edge-b", ControlPSKey: topology.keyB},
	}
	topology.super, err = RunWithListeners(&superConfig{
		BaseConfig:      base,
		EdgeTemplate:    validEdgeTemplate(),
		ConfigDir:       t.TempDir(),
		EdgeListen:      edgeListener,
		ManageListen:    manageListener,
		ShutdownTimeout: 3 * time.Second,
		TickInterval:    10 * time.Millisecond,
	})
	if err != nil {
		_ = edgeListener.Close()
		_ = manageListener.Close()
		t.Fatalf("start Super: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = topology.super.Shutdown(ctx)
	})

	privateA, pubA := device.RandomKeyPair()
	privateB, pubB := device.RandomKeyPair()
	topology.pubA, topology.pubB = pubA, pubB
	bindA := newE2EBind(topology.fabric, net.ParseIP("198.51.100.101"), net.ParseIP("198.51.100.101"), 101, true)
	topology.bindB = newE2EMultiWANBind(topology.fabric, 102, net.ParseIP("203.0.113.11"), map[string]net.IP{
		"192.0.2.2":    net.ParseIP("203.0.113.11"),
		"198.51.100.2": net.ParseIP("203.0.113.12"),
	})
	topology.bindB.peerPortBySource = opts.peerPortBySource
	configA := e2eMultiWANEdgeConfig{id: 101, name: "edge-a", key: topology.keyA, bind: bindA, port: 101, uplinks: []device.UplinkForTest{}}
	if opts.configureA != nil {
		opts.configureA(&configA)
	}
	topology.edgeA, _ = newE2EMultiWANEdge(t, configA, baseURL, privateA)
	topology.edgeB, _ = newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{id: 102, name: "edge-b", key: topology.keyB, bind: topology.bindB, port: 102, uplinks: []device.UplinkForTest{
		{Addr: netip.MustParseAddr("192.0.2.2"), Ifindex: 3, Name: "wan1"},
		{Addr: netip.MustParseAddr("198.51.100.2"), Ifindex: 4, Name: "wan2"},
	}}, baseURL, privateB)
	return topology
}

func (topology *e2eMultiWANTopology) snapshotFor(ctx context.Context, nodeID mtypes.Vertex, key string) (*mtypes.ControlV2Snapshot, error) {
	client := device.NewControlHTTPClient(topology.base, mtypes.ControlV2APIPrefix, nodeID, key)
	snapshot, _, err := client.Snapshot(ctx)
	return snapshot, err
}

func TestHTTPOnlySuperMultiWANEdgeReportsOneSTUNCandidatePerUplink(t *testing.T) {
	// Given a multi-WAN edge B whose uplinks sit behind different NATs
	topology := newE2EMultiWANTopology(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// When B registers and refreshes STUN through every uplink
	var public []string
	awaitE2E(t, 8*time.Second, func() bool {
		snapshot, err := topology.snapshotFor(ctx, 101, topology.keyA)
		if err != nil {
			return false
		}
		peer, found := e2ePeer(snapshot, 102)
		public = peer.PublicV4
		return found && len(peer.PublicV4) == 2
	})

	// Then the Super publishes both uplinks' public endpoints to A
	want := map[string]bool{"203.0.113.11:102": true, "203.0.113.12:102": true}
	for _, address := range public {
		if !want[address] {
			t.Fatalf("PublicV4 = %v, want both uplinks %v", public, want)
		}
		delete(want, address)
	}
	if len(want) != 0 {
		t.Fatalf("PublicV4 = %v, missing %v", public, want)
	}
}

// shapedLatency makes every path to port 102 slow except the chosen fast
// address; nothing is slow until a fast address is chosen.
func shapedLatency(fast *atomic.Value) func(string) time.Duration {
	fast.Store("")
	return func(destination string) time.Duration {
		fastAddress := fast.Load().(string)
		_, port, _ := net.SplitHostPort(destination)
		if fastAddress == "" || port != "102" || destination == fastAddress {
			return 0
		}
		return 30 * time.Millisecond
	}
}

// awaitLiveOnUplink waits until A has a live session to B over one of B's
// public uplinks and returns the other uplink's address.
func awaitLiveOnUplink(t *testing.T, edgeA *device.Device, pubB device.NoisePublicKey) (initial, other string) {
	t.Helper()
	awaitE2E(t, 10*time.Second, func() bool {
		peer := edgeA.LookupPeer(pubB)
		current := edgeA.GetConnurl(102)
		return peer != nil && peer.IsPeerAlive() && (current == "203.0.113.11:102" || current == "203.0.113.12:102")
	})
	initial = edgeA.GetConnurl(102)
	other = "203.0.113.12:102"
	if initial == other {
		other = "203.0.113.11:102"
	}
	return initial, other
}

func TestHTTPOnlySuperEdgeConvergesToLowestLatencyEndpoint(t *testing.T) {
	// Given a multi-WAN edge B reachable through two public uplinks
	var fast atomic.Value
	topology := newE2EMultiWANTopology(t, shapedLatency(&fast))
	// Only A initiates, avoiding WireGuard's simultaneous-initiation retry.
	topology.bindB.dropInitiation.Store(true)
	_, target := awaitLiveOnUplink(t, topology.edgeA, topology.pubB)

	// When every path to B except the uplink A is not using becomes slow
	fast.Store(target)

	// Then A's prober moves B to the fast uplink while B stays alive, so the
	// retry loop (which only handles dead peers) cannot be what moved it
	awaitE2E(t, 15*time.Second, func() bool { return topology.edgeA.GetConnurl(102) == target })
	time.Sleep(time.Second)
	if got := topology.edgeA.GetConnurl(102); got != target {
		t.Fatalf("A left the fastest endpoint: %s", got)
	}
	if !topology.edgeA.LookupPeer(topology.pubB).IsPeerAlive() {
		t.Fatal("B is no longer alive after the switch")
	}
}

func TestHTTPOnlySuperEdgeKeepsEndpointWhenSelectionDisabled(t *testing.T) {
	// Given the same topology with endpoint selection disabled on A
	var fast atomic.Value
	topology := newE2EMultiWANTopology(t, shapedLatency(&fast), e2eMultiWANOptions{configureA: func(cfg *e2eMultiWANEdgeConfig) { cfg.disableSelection = true }})
	topology.bindB.dropInitiation.Store(true)
	initial, target := awaitLiveOnUplink(t, topology.edgeA, topology.pubB)

	// When the other uplink becomes much faster
	fast.Store(target)
	time.Sleep(3 * time.Second)

	// Then A stays on its original endpoint
	if got := topology.edgeA.GetConnurl(102); got != initial {
		t.Fatalf("A switched to %s with selection disabled, want %s", got, initial)
	}
}

func TestP2PEdgeConvergesToLowestLatencyEndpoint(t *testing.T) {
	// Given two P2P edges without a Super; B has two public uplinks and A
	// knows both as retry candidates
	var fast atomic.Value
	fabric := newE2EFabric()
	fabric.delay = shapedLatency(&fast)
	privateA, pubA := device.RandomKeyPair()
	privateB, pubB := device.RandomKeyPair()
	bindA := newE2EBind(fabric, net.ParseIP("198.51.100.101"), net.ParseIP("198.51.100.101"), 101, true)
	bindB := newE2EMultiWANBind(fabric, 102, net.ParseIP("203.0.113.11"), map[string]net.IP{
		"192.0.2.2":    net.ParseIP("203.0.113.11"),
		"198.51.100.2": net.ParseIP("203.0.113.12"),
	})
	bindB.dropInitiation.Store(true)
	edgeA, _ := newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{id: 101, name: "edge-a", bind: bindA, port: 101, uplinks: []device.UplinkForTest{}, p2p: true}, "", privateA)
	edgeB, _ := newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{id: 102, name: "edge-b", bind: bindB, port: 102, p2p: true, uplinks: []device.UplinkForTest{
		{Addr: netip.MustParseAddr("192.0.2.2"), Ifindex: 3, Name: "wan1"},
		{Addr: netip.MustParseAddr("198.51.100.2"), Ifindex: 4, Name: "wan2"},
	}}, "", privateB)
	peerB, err := edgeA.NewPeer(pubB, 102, false, 0)
	if err != nil {
		t.Fatalf("A new peer: %v", err)
	}
	peerA, err := edgeB.NewPeer(pubA, 101, false, 0)
	if err != nil {
		t.Fatalf("B new peer: %v", err)
	}
	if err := peerA.SetEndpointFromConnURL("198.51.100.101:101", conn.EnabledAf4, 0, false); err != nil {
		t.Fatalf("B endpoint: %v", err)
	}
	peerB.AddEndpointRetry("203.0.113.11:102", false)
	peerB.AddEndpointRetry("203.0.113.12:102", false)
	if err := peerB.SetEndpointFromConnURL("203.0.113.11:102", conn.EnabledAf4, 0, false); err != nil {
		t.Fatalf("A endpoint: %v", err)
	}
	if err := peerB.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("A handshake: %v", err)
	}
	_, target := awaitLiveOnUplink(t, edgeA, pubB)

	// When every path to B except the other uplink becomes slow
	fast.Store(target)

	// Then A converges to it and B stays alive
	awaitE2E(t, 15*time.Second, func() bool { return edgeA.GetConnurl(102) == target })
	time.Sleep(time.Second)
	if got := edgeA.GetConnurl(102); got != target {
		t.Fatalf("A left the fastest endpoint: %s", got)
	}
	if !peerB.IsPeerAlive() {
		t.Fatal("B is no longer alive after the switch")
	}
}

func TestHTTPOnlySuperEdgeReachesUplinkBehindEndpointDependentNAT(t *testing.T) {
	// Given B's second uplink sits behind a NAT whose peer-facing port (50000)
	// differs from the port STUN sees, so its published STUN candidate
	// 203.0.113.12:102 is unreachable
	var fast atomic.Value
	delay := shapedLatency(&fast)
	topology := newE2EMultiWANTopology(t, func(destination string) time.Duration {
		_, port, _ := net.SplitHostPort(destination)
		if fast.Load().(string) != "" && port == "50000" && destination != fast.Load().(string) {
			return 30 * time.Millisecond
		}
		return delay(destination)
	}, e2eMultiWANOptions{
		peerPortBySource: map[string]uint16{"198.51.100.2": 50000},
		strictFabric:     func(destination string) bool { return strings.HasPrefix(destination, "203.0.113.12:") },
	})
	topology.bindB.dropInitiation.Store(true)
	awaitE2E(t, 10*time.Second, func() bool {
		peer := topology.edgeA.LookupPeer(topology.pubB)
		return peer != nil && peer.IsPeerAlive()
	})
	t.Logf("A reaches B at %s before shaping", topology.edgeA.GetConnurl(102))

	// When only the wan2 NAT mapping is fast
	fast.Store("203.0.113.12:50000")

	// Then A learns that mapping from B's probes and moves to it
	awaitE2E(t, 15*time.Second, func() bool { return topology.edgeA.GetConnurl(102) == "203.0.113.12:50000" })
	if !topology.edgeA.LookupPeer(topology.pubB).IsPeerAlive() {
		t.Fatal("B is no longer alive after the switch")
	}
}
