package device

import (
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

type endpointBlacklistTestEndpoint struct {
	src net.IP
	dst net.IP
}

func (endpointBlacklistTestEndpoint) ClearSrc() {}

func (endpoint endpointBlacklistTestEndpoint) SrcToString() string {
	return net.JoinHostPort(endpoint.src.String(), "51820")
}

func (endpoint endpointBlacklistTestEndpoint) DstToString() string {
	return net.JoinHostPort(endpoint.dst.String(), "51820")
}

func (endpoint endpointBlacklistTestEndpoint) DstToBytes() []byte {
	return []byte(endpoint.DstToString())
}

func (endpoint endpointBlacklistTestEndpoint) DstIP() net.IP { return endpoint.dst }

func (endpoint endpointBlacklistTestEndpoint) SrcIP() net.IP { return endpoint.src }

type endpointBlacklistTestBind struct {
	sends int
}

func (*endpointBlacklistTestBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, 0, nil
}

func (*endpointBlacklistTestBind) Close() error { return nil }

func (*endpointBlacklistTestBind) SetMark(uint32) error { return nil }

func (bind *endpointBlacklistTestBind) Send([]byte, conn.Endpoint) error {
	bind.sends++
	return nil
}

func (*endpointBlacklistTestBind) ParseEndpoint(address string) (conn.Endpoint, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	return endpointBlacklistTestEndpoint{dst: net.ParseIP(host)}, nil
}

func (*endpointBlacklistTestBind) EnabledAf() conn.EnabledAf { return conn.EnabledAf46 }

func newEndpointBlacklistTestDevice(t *testing.T) *Device {
	t.Helper()
	graph, err := path.NewGraph(1, false, mtypes.GraphRecalculateSetting{StaticMode: true}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("new graph: %v", err)
	}
	device := &Device{
		ID:                1,
		EdgeConfig:        &mtypes.EdgeConfig{},
		event_tryendpoint: make(chan struct{}, 1),
		graph:             graph,
		log:               &Logger{Verbosef: DiscardLogf, Errorf: DiscardLogf},
	}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	return device
}

func TestRoutineReceiveIncomingDropsBlacklistedSourceAndQueuesAllowedSource(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	device.PopulatePools()
	device.queue.decryption = newInboundQueue()
	device.queue.handshake = newHandshakeQueue()
	device.net.stopping.Add(1)
	device.applyEndpointBlacklist(mtypes.ControlV2Parameters{EndpointBlacklist: []string{"198.51.100.0/24"}})
	packet := make([]byte, MessageInitiationSize)
	packet[0] = byte(path.MessageInitiationType)
	packets := []struct {
		endpoint conn.Endpoint
		packet   []byte
	}{
		{endpoint: endpointBlacklistTestEndpoint{src: net.ParseIP("198.51.100.4"), dst: net.ParseIP("192.0.2.1")}, packet: packet},
		{endpoint: endpointBlacklistTestEndpoint{src: net.ParseIP("203.0.113.4"), dst: net.ParseIP("192.0.2.1")}, packet: packet},
	}
	next := 0
	recv := conn.ReceiveFunc(func(buffer []byte) (int, conn.Endpoint, error) {
		if next == len(packets) {
			return 0, nil, net.ErrClosed
		}
		current := packets[next]
		next++
		return copy(buffer, current.packet), current.endpoint, nil
	})
	done := make(chan struct{})

	// When
	go func() {
		device.RoutineReceiveIncoming(recv)
		close(done)
	}()
	<-done

	// Then
	select {
	case element := <-device.queue.handshake.c:
		if got := element.endpoint.SrcIP().String(); got != "203.0.113.4" {
			t.Fatalf("queued packet source = %s, want 203.0.113.4", got)
		}
		device.PutMessageBuffer(element.buffer)
	default:
		t.Fatal("allowed packet was not queued")
	}
	select {
	case element, open := <-device.queue.handshake.c:
		if open {
			device.PutMessageBuffer(element.buffer)
			t.Fatal("blacklisted packet was queued")
		}
	default:
	}
}

func TestEndpointTrylistUpdateSuperFiltersBlacklistedCandidates(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	device.applyEndpointBlacklist(mtypes.ControlV2Parameters{EndpointBlacklist: []string{"192.0.2.0/24"}})
	peer := &Peer{device: device}
	trylist := NewEndpoint_trylist(peer, time.Hour, conn.EnabledAf46)
	peer.endpoint_trylist = trylist

	// When
	trylist.UpdateSuper(superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.10:51820", Source: mtypes.APIConnURLSourceSTUN},
		mtypes.APIConnURLCandidate{URL: "192.0.2.11:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 3},
		mtypes.APIConnURLCandidate{URL: "198.51.100.10:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 3},
	), true, 0)

	// Then
	_, first := trylist.GetNextTry()
	if first != "198.51.100.10:51820" {
		t.Fatalf("first candidate = %q, want non-blacklisted candidate", first)
	}
	_, second := trylist.GetNextTry()
	if second != "198.51.100.10:51820" {
		t.Fatalf("blacklisted candidate entered retry list: %q", second)
	}
}

func TestLocalControlCandidatesExcludeBlacklistedAddresses(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	device.applyEndpointBlacklist(mtypes.ControlV2Parameters{EndpointBlacklist: []string{"192.0.2.0/24"}})
	ready := superHTTPReady{port: 51820, v4: net.ParseIP("192.0.2.8"), v6: net.ParseIP("2001:db8::8")}

	// When
	candidates := localControlCandidates(device, ready)

	// Then
	if len(candidates) != 1 || candidates[0].Address != "[2001:db8::8]:51820" {
		t.Fatalf("local candidates = %+v, want only non-blacklisted IPv6 candidate", candidates)
	}
}

func TestLocalControlCandidatesAdvertiseEligibleInterfaceEndpoints(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	device.applyEndpointBlacklist(mtypes.ControlV2Parameters{EndpointBlacklist: []string{"100.64.0.0/22"}})
	ready := superHTTPReady{port: 51820, v4: net.ParseIP("10.10.0.2")}
	interfaces := []interfaceAddresses{
		{name: "eth0", flags: net.FlagUp, addrs: []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.10.0.2"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("192.168.50.8"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("100.64.0.2"), Mask: net.CIDRMask(22, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::8"), Mask: net.CIDRMask(64, 128)},
		}},
		{name: "eg0", flags: net.FlagUp, addrs: []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.55.0.1"), Mask: net.CIDRMask(24, 32)},
		}},
	}
	endpoints := endpointURLsForInterfaces(interfaces, "eg0", ready.port, conn.EnabledAf4)

	// When
	candidates := localControlCandidatesFromAddresses(device, ready, endpoints)

	// Then
	want := []mtypes.ControlV2Candidate{
		{Address: "10.10.0.2:51820", Source: mtypes.ControlV2CandidateLocal},
		{Address: "192.168.50.8:51820", Source: mtypes.ControlV2CandidateLocal},
	}
	if !reflect.DeepEqual(candidates, want) {
		t.Fatalf("local candidates = %#v, want %#v", candidates, want)
	}
}

func TestRuntimeBlacklistSwapClearsCurrentEndpoint(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	peer := &Peer{device: device, endpoint: endpointBlacklistTestEndpoint{dst: net.ParseIP("203.0.113.8")}}
	peer.endpoint_trylist = NewEndpoint_trylist(peer, time.Hour, conn.EnabledAf46)
	device.peers.keyMap[NoisePublicKey{}] = peer
	runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{NodeID: device.ID})
	snapshot := runtimeTestSnapshot(t, 1)
	snapshot.Peers = []mtypes.ControlV2Peer{{NodeID: device.ID}}
	snapshot.Parameters.EndpointBlacklist = []string{"203.0.113.0/24"}

	// When
	runtime.applySnapshot(snapshot)

	// Then
	peer.RLock()
	endpoint := peer.endpoint
	peer.RUnlock()
	if endpoint != nil {
		t.Fatalf("blacklisted endpoint remained active: %s", endpoint.DstToString())
	}
}

func TestRuntimeMalformedBlacklistRetainsPreviousPolicy(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{NodeID: device.ID})
	valid := runtimeTestSnapshot(t, 1)
	valid.Peers = []mtypes.ControlV2Peer{{NodeID: device.ID}}
	valid.Parameters.EndpointBlacklist = []string{"203.0.113.0/24"}
	runtime.applySnapshot(valid)
	malformed := runtimeTestSnapshot(t, 2)
	malformed.Peers = []mtypes.ControlV2Peer{{NodeID: device.ID}}
	malformed.Parameters.EndpointBlacklist = []string{"not-an-ip"}

	// When
	runtime.applySnapshot(malformed)

	// Then
	if !device.endpointBlacklisted(net.ParseIP("203.0.113.8")) {
		t.Fatal("malformed update replaced the previous endpoint blacklist")
	}
}

func TestObservedEndpointsExcludeBlacklistedDestination(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	device.EdgeConfig.DynamicRoute.PeerAliveTimeout = 60
	device.applyEndpointBlacklist(mtypes.ControlV2Parameters{EndpointBlacklist: []string{"203.0.113.0/24"}})
	now := time.Now()
	peer := &Peer{
		ID:     2,
		device: device,
		endpoint: endpointBlacklistTestEndpoint{
			src: net.ParseIP("192.0.2.8"),
			dst: net.ParseIP("203.0.113.8"),
		},
	}
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	device.peers.IDMap[peer.ID] = peer
	runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{NodeID: device.ID})

	// When
	observed := runtime.observedEndpoints()

	// Then
	if len(observed) != 0 {
		t.Fatalf("blacklisted observed endpoints = %+v, want none", observed)
	}
}

func TestSendBufferRejectsBlacklistedEndpoint(t *testing.T) {
	// Given
	device := newEndpointBlacklistTestDevice(t)
	bind := &endpointBlacklistTestBind{}
	device.net.bind = bind
	device.applyEndpointBlacklist(mtypes.ControlV2Parameters{EndpointBlacklist: []string{"203.0.113.0/24"}})
	peer := &Peer{device: device, endpoint: endpointBlacklistTestEndpoint{dst: net.ParseIP("203.0.113.9")}}

	// When
	err := peer.SendBuffer([]byte("blocked"))

	// Then
	if !errors.Is(err, errEndpointBlacklisted) {
		t.Fatalf("send error = %v, want endpoint blacklist error", err)
	}
	if bind.sends != 0 {
		t.Fatalf("blacklisted endpoint was written %d times", bind.sends)
	}
}
