package device

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/pion/stun/v3"
)

type stunTestEndpoint struct{ address string }

func (e stunTestEndpoint) ClearSrc()           {}
func (e stunTestEndpoint) SrcToString() string { return "" }
func (e stunTestEndpoint) DstToString() string { return e.address }
func (e stunTestEndpoint) DstToBytes() []byte  { return []byte(e.address) }
func (e stunTestEndpoint) DstIP() net.IP {
	host, _, _ := net.SplitHostPort(e.address)
	return net.ParseIP(host)
}
func (e stunTestEndpoint) SrcIP() net.IP { return nil }

type sameBindSTUNFake struct {
	port          uint16
	responses     map[string]net.IP
	responsePorts map[string]uint16
	delay         map[string]time.Duration
	incoming      chan []byte
	sent          chan string
	closed        chan struct{}
	closeOnce     sync.Once
}

func newSameBindSTUNFake(port uint16) *sameBindSTUNFake {
	return &sameBindSTUNFake{
		port:          port,
		responses:     make(map[string]net.IP),
		responsePorts: make(map[string]uint16),
		delay:         make(map[string]time.Duration),
		incoming:      make(chan []byte, 8),
		sent:          make(chan string, 8),
		closed:        make(chan struct{}),
	}
}

func (b *sameBindSTUNFake) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, b.port, nil
}
func (b *sameBindSTUNFake) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}
func (b *sameBindSTUNFake) SetMark(uint32) error { return nil }
func (b *sameBindSTUNFake) EnabledAf() conn.EnabledAf {
	return conn.EnabledAf46
}
func (b *sameBindSTUNFake) ParseEndpoint(address string) (conn.Endpoint, error) {
	return stunTestEndpoint{address: address}, nil
}
func (b *sameBindSTUNFake) Send(packet []byte, endpoint conn.Endpoint) error {
	select {
	case b.sent <- endpoint.DstToString():
	default:
	}
	var tx [stun.TransactionIDSize]byte
	copy(tx[:], packet[8:20])
	mappedIP, ok := b.responses[endpoint.DstToString()]
	if !ok {
		if endpoint.DstToString() == "[::1]:3478" {
			mappedIP, ok = b.responses["[::1]:3478"]
		}
	}
	if !ok {
		return nil
	}
	mappedPort := b.port
	if override, hasOverride := b.responsePorts[endpoint.DstToString()]; hasOverride {
		mappedPort = override
	}
	response, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(tx), &stun.XORMappedAddress{IP: mappedIP, Port: int(mappedPort)}, stun.Fingerprint)
	if err != nil {
		return err
	}
	delay := b.delay[endpoint.DstToString()]
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			b.incoming <- append([]byte(nil), response.Raw...)
		case <-b.closed:
		}
	}()
	return nil
}

func TestSuperSTUNResolvesHostnameBeforeSendingLiteralEndpoint(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40100)
	bind.responses["203.0.113.80:3478"] = net.ParseIP("198.51.100.80")
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	resolverCalled := false
	manager.resolver = func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolverCalled = true
		if host != "stun.example.test" {
			t.Fatalf("resolver host = %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.80")}}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun://stun.example.test:3478"}, 100*time.Millisecond)

	// Then
	if !resolverCalled {
		t.Fatal("hostname resolver was not called")
	}
	if len(candidates) != 1 || candidates[0].Address != "198.51.100.80:40100" {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestSuperSTUNBypassesResolverForLiteralURI(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40101)
	bind.responses["203.0.113.81:3478"] = net.ParseIP("198.51.100.81")
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	manager.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		t.Fatal("literal URI unexpectedly invoked resolver")
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.81:3478"}, 100*time.Millisecond)

	// Then
	if len(candidates) != 1 || candidates[0].Address != "198.51.100.81:40101" {
		t.Fatalf("candidates = %#v", candidates)
	}
}

func TestSuperSTUNDiscoveryReturnsPromptlyWhenCallerCancelsResolver(t *testing.T) {
	// Given
	manager := NewSuperSTUNManager(&Device{})
	resolverStarted := make(chan struct{})
	resolverStopped := make(chan struct{})
	manager.resolver = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		close(resolverStarted)
		<-ctx.Done()
		close(resolverStopped)
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan []mtypes.ControlV2Candidate, 1)
	go func() { result <- manager.Discover(ctx, []string{"stun:stun.example.test:3478"}, time.Second) }()
	<-resolverStarted

	// When
	cancel()

	// Then
	select {
	case candidates := <-result:
		if len(candidates) != 0 {
			t.Fatalf("candidates = %#v", candidates)
		}
	case <-time.After(time.Second):
		t.Fatal("discovery did not return after caller cancellation")
	}
	select {
	case <-resolverStopped:
	case <-time.After(time.Second):
		t.Fatal("resolver did not observe caller cancellation")
	}
}

func TestSuperSTUNResolverErrorPublishesNoCandidatesOrPendingRequests(t *testing.T) {
	// Given
	manager := NewSuperSTUNManager(&Device{})
	manager.resolver = func(context.Context, string) ([]net.IPAddr, error) {
		return nil, errors.New("resolver unavailable")
	}

	// When
	candidates := manager.Discover(context.Background(), []string{"stun:stun.example.test:3478"}, time.Second)

	// Then
	if len(candidates) != 0 {
		t.Fatalf("candidates = %#v", candidates)
	}
	manager.mu.Lock()
	pending := len(manager.pending)
	manager.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending transactions = %d, want 0", pending)
	}
}

func TestSuperSTUNCloseCancelsInFlightRequestAndDrainsPending(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40102)
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	result := make(chan []mtypes.ControlV2Candidate, 1)
	go func() {
		result <- manager.Discover(context.Background(), []string{"stun:203.0.113.82:3478"}, time.Second)
	}()
	<-bind.sent

	// When
	manager.Close()

	// Then
	select {
	case candidates := <-result:
		if len(candidates) != 0 {
			t.Fatalf("candidates = %#v", candidates)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight STUN request did not return after manager close")
	}
	manager.mu.Lock()
	pending := len(manager.pending)
	manager.mu.Unlock()
	if pending != 0 {
		t.Fatalf("pending transactions = %d, want 0", pending)
	}
}
func (b *sameBindSTUNFake) receive(packet []byte) (int, conn.Endpoint, error) {
	select {
	case response := <-b.incoming:
		return copy(packet, response), stunTestEndpoint{address: "127.0.0.1:3478"}, nil
	case <-b.closed:
		return 0, nil, net.ErrClosed
	}
}

func TestSuperSTUNDiscoversMappedCandidatesThroughActiveBind(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(43210)
	bind.responses["127.0.0.1:3478"] = net.ParseIP("198.51.100.44")
	bind.responses["[::1]:3478"] = net.ParseIP("2001:db8::44")
	device := &Device{}
	device.net.bind = bind
	device.net.port = bind.port
	manager := NewSuperSTUNManager(device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:127.0.0.1:3478", "stun:[::1]:3478"}, 100*time.Millisecond)

	// Then
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	for _, candidate := range candidates {
		_, port, err := net.SplitHostPort(candidate.Address)
		if err != nil {
			t.Fatalf("invalid candidate address %q: %v", candidate.Address, err)
		}
		if port != "43210" {
			t.Fatalf("mapped source port = %s, want active bind port 43210", port)
		}
		if candidate.Source != mtypes.ControlV2CandidateSTUN {
			t.Fatalf("candidate source = %q, want stun", candidate.Source)
		}
	}
}

func TestSuperSTUNFailsOverAfterFirstServerTimeout(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40001)
	bind.responses["127.0.0.2:3478"] = net.ParseIP("203.0.113.7")
	device := &Device{}
	device.net.bind = bind
	device.net.port = bind.port
	manager := NewSuperSTUNManager(device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:127.0.0.1:3478", "stun:127.0.0.2:3478"}, 20*time.Millisecond)

	// Then
	if len(candidates) != 1 || candidates[0].Address != "203.0.113.7:40001" {
		t.Fatalf("candidates = %#v, want successful second-server mapping", candidates)
	}
}

func TestSuperSTUNAllServersFailPublishesNoMappedCandidates(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40002)
	device := &Device{}
	device.net.bind = bind
	device.net.port = bind.port
	manager := NewSuperSTUNManager(device)
	ctx := context.Background()

	// When
	candidates := manager.Discover(ctx, []string{"stun:127.0.0.1:3478"}, time.Millisecond)

	// Then
	if len(candidates) != 0 {
		t.Fatalf("candidates = %#v, want no fabricated mapping", candidates)
	}
}

func TestSuperSTUNRefreshRetainsLocalCandidatesAndDeduplicatesMappings(t *testing.T) {
	// Given
	previous := []mtypes.ControlV2Candidate{
		{Address: "10.0.0.2:51820", Source: mtypes.ControlV2CandidateLocal},
		{Address: "198.51.100.2:51820", Source: mtypes.ControlV2CandidateSTUN},
	}
	refreshed := []mtypes.ControlV2Candidate{
		{Address: "198.51.100.3:51820", Source: mtypes.ControlV2CandidateSTUN},
		{Address: "198.51.100.3:51820", Source: mtypes.ControlV2CandidateSTUN},
	}

	// When
	candidates := mergeControlCandidates(previous, refreshed)

	// Then
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	if candidates[0].Address != "10.0.0.2:51820" || candidates[0].Source != mtypes.ControlV2CandidateLocal {
		t.Fatalf("local candidate lost: %#v", candidates)
	}
	if candidates[1].Address != "198.51.100.3:51820" || candidates[1].Source != mtypes.ControlV2CandidateSTUN {
		t.Fatalf("refreshed STUN candidate = %#v", candidates)
	}
}

func TestSuperSTUNDiscoversBothFamiliesFromSingleHostname(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40103)
	bind.responses["203.0.113.90:3478"] = net.ParseIP("198.51.100.90")
	bind.responses["[2001:db8::90]:3478"] = net.ParseIP("2001:db8::1234")
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	manager.resolver = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "dual.example.test" {
			t.Fatalf("resolver host = %q", host)
		}
		return []net.IPAddr{
			{IP: net.ParseIP("203.0.113.90")},
			{IP: net.ParseIP("2001:db8::90")},
		}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun://dual.example.test:3478"}, 100*time.Millisecond)

	// Then
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	seen := make(map[string]bool)
	for _, candidate := range candidates {
		seen[candidate.Address] = true
	}
	if !seen["198.51.100.90:40103"] {
		t.Fatalf("IPv4 candidate missing: %#v", candidates)
	}
	if !seen["[2001:db8::1234]:40103"] {
		t.Fatalf("IPv6 candidate missing: %#v", candidates)
	}
}

func TestSuperSTUNDeduplicatesMappedIPsAcrossServers(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40104)
	bind.responses["203.0.113.91:3478"] = net.ParseIP("198.51.100.91")
	bind.responses["203.0.113.92:3478"] = net.ParseIP("198.51.100.91") // same mapped IP
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.91:3478", "stun:203.0.113.92:3478"}, 100*time.Millisecond)

	// Then
	if len(candidates) != 1 || candidates[0].Address != "198.51.100.91:40104" {
		t.Fatalf("candidates = %#v, want one deduplicated IP", candidates)
	}
}

func TestSuperSTUNDetectsMappedPortMismatch(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40105)
	bind.responses["203.0.113.93:3478"] = net.ParseIP("198.51.100.92")
	bind.responses["203.0.113.94:3478"] = net.ParseIP("2001:db8::92")
	bind.responsePorts["203.0.113.94:3478"] = 40106
	var logged []string
	device := &Device{
		log: &Logger{
			Errorf:   func(format string, args ...interface{}) { logged = append(logged, fmt.Sprintf(format, args...)) },
			Verbosef: DiscardLogf,
		},
	}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.93:3478", "stun:203.0.113.94:3478"}, 100*time.Millisecond)

	// Then
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	found := false
	for _, msg := range logged {
		if strings.Contains(msg, "mapped port mismatch") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected port mismatch log, got %v", logged)
	}
}

func receiveSTUNTestPackets(ctx context.Context, manager *SuperSTUNManager, receive conn.ReceiveFunc) {
	buffer := make([]byte, 2048)
	for {
		size, _, err := receive(buffer)
		if err != nil {
			return
		}
		manager.HandlePacket(buffer[:size])
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
