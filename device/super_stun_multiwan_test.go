package device

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/pion/stun/v3"
)

// pinnedSTUNEndpoint records the pinned source so the fake bind can emulate
// per-uplink NAT mappings. A cleared pin reports an unspecified SrcIP like
// LinuxSocketEndpoint after ClearSrc.
type pinnedSTUNEndpoint struct {
	dst     string
	src     netip.Addr
	ifindex int
	cleared bool
}

func (e *pinnedSTUNEndpoint) ClearSrc()           { e.cleared = true }
func (e *pinnedSTUNEndpoint) SrcToString() string { return e.src.String() }
func (e *pinnedSTUNEndpoint) DstToString() string { return e.dst }
func (e *pinnedSTUNEndpoint) DstToBytes() []byte  { return []byte(e.dst) }
func (e *pinnedSTUNEndpoint) DstIP() net.IP {
	host, _, _ := net.SplitHostPort(e.dst)
	return net.ParseIP(host)
}
func (e *pinnedSTUNEndpoint) SrcIP() net.IP {
	if !e.src.IsValid() {
		return nil
	}
	if e.cleared {
		if e.src.Is4() {
			return net.IPv4zero
		}
		return net.IPv6unspecified
	}
	return e.src.AsSlice()
}

type stunSendRecord struct {
	dst    string
	source string // "" for unpinned
	txID   [stun.TransactionIDSize]byte
}

// pinningSTUNFake is a conn.Bind that can pin sources. mapped[source][server]
// is the public IP a NAT on that uplink would report; source "" is the
// kernel's default route.
type pinningSTUNFake struct {
	mu        sync.Mutex
	port      uint16
	mapped    map[string]map[string]net.IP
	ports     map[string]uint16
	delay     map[string]time.Duration
	rejectPin map[string]bool
	records   []stunSendRecord
	incoming  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newPinningSTUNFake(port uint16) *pinningSTUNFake {
	return &pinningSTUNFake{
		port:      port,
		mapped:    make(map[string]map[string]net.IP),
		ports:     make(map[string]uint16),
		delay:     make(map[string]time.Duration),
		rejectPin: make(map[string]bool),
		incoming:  make(chan []byte, 64),
		closed:    make(chan struct{}),
	}
}

func (b *pinningSTUNFake) mapSource(source, server, ip string) {
	if b.mapped[source] == nil {
		b.mapped[source] = make(map[string]net.IP)
	}
	b.mapped[source][server] = net.ParseIP(ip)
}

func (b *pinningSTUNFake) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, b.port, nil
}
func (b *pinningSTUNFake) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}
func (b *pinningSTUNFake) SetMark(uint32) error      { return nil }
func (b *pinningSTUNFake) EnabledAf() conn.EnabledAf { return conn.EnabledAf46 }
func (b *pinningSTUNFake) ParseEndpoint(address string) (conn.Endpoint, error) {
	return &pinnedSTUNEndpoint{dst: address}, nil
}
func (b *pinningSTUNFake) receive(packet []byte) (int, conn.Endpoint, error) {
	select {
	case response := <-b.incoming:
		return copy(packet, response), &pinnedSTUNEndpoint{dst: "127.0.0.1:3478"}, nil
	case <-b.closed:
		return 0, nil, net.ErrClosed
	}
}

func (b *pinningSTUNFake) Send(packet []byte, endpoint conn.Endpoint) error {
	end := endpoint.(*pinnedSTUNEndpoint)
	source := ""
	if end.src.IsValid() {
		source = end.src.String()
		if b.rejectPin[source] {
			// Emulate send6's EINVAL fallback: pin cleared, sent via default route.
			end.cleared = true
			source = ""
		}
	}
	var tx [stun.TransactionIDSize]byte
	copy(tx[:], packet[8:20])
	b.mu.Lock()
	b.records = append(b.records, stunSendRecord{dst: end.dst, source: source, txID: tx})
	mappedIP := b.mapped[source][end.dst]
	mappedPort, hasPort := b.ports[source]
	delay := b.delay[source]
	b.mu.Unlock()
	if mappedIP == nil {
		return nil
	}
	if !hasPort {
		mappedPort = b.port
	}
	response, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(tx), &stun.XORMappedAddress{IP: mappedIP, Port: int(mappedPort)}, stun.Fingerprint)
	if err != nil {
		return err
	}
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

func (b *pinningSTUNFake) sendRecords() []stunSendRecord {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]stunSendRecord(nil), b.records...)
}

// nonPinningSTUNFake hides ParseEndpointFrom so Discover must fall back.
type nonPinningSTUNFake struct{ *pinningSTUNFake }

func (b *pinningSTUNFake) ParseEndpointFrom(dst string, src netip.Addr, ifindex int) (conn.Endpoint, error) {
	if !src.IsValid() || ifindex <= 0 {
		return nil, conn.ErrInvalidSource
	}
	return &pinnedSTUNEndpoint{dst: dst, src: src, ifindex: ifindex}, nil
}

var (
	wan1Source = stunSource{ip: netip.MustParseAddr("192.0.2.2"), ifindex: 3, ifname: "wan1"}
	wan2Source = stunSource{ip: netip.MustParseAddr("198.51.100.2"), ifindex: 4, ifname: "wan2"}
	wan1V6     = stunSource{ip: netip.MustParseAddr("2001:db8:1::2"), ifindex: 3, ifname: "wan1"}
)

func newMultiWANManager(t *testing.T, bind conn.Bind, sources ...stunSource) (*SuperSTUNManager, *Device, context.Context) {
	t.Helper()
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	manager.sources = func() []stunSource { return append([]stunSource(nil), sources...) }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	t.Cleanup(manager.Close)
	var receive conn.ReceiveFunc
	switch b := bind.(type) {
	case *pinningSTUNFake:
		receive = b.receive
	case nonPinningSTUNFake:
		receive = b.receive
	}
	go receiveSTUNTestPackets(ctx, manager, receive)
	return manager, device, ctx
}

func candidateAddresses(candidates []mtypes.ControlV2Candidate) string {
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.Address)
	}
	return strings.Join(out, ",")
}

func TestSuperSTUNDiscoversOneMappingPerPinnedSource(t *testing.T) {
	// Given two uplinks behind different NATs; the default route uses wan1
	bind := newPinningSTUNFake(40200)
	bind.mapSource("", "203.0.113.100:3478", "203.0.113.11")
	bind.mapSource(wan1Source.ip.String(), "203.0.113.100:3478", "203.0.113.11")
	bind.mapSource(wan2Source.ip.String(), "203.0.113.100:3478", "203.0.113.12")
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source, wan2Source)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478"}, 200*time.Millisecond)

	// Then both public endpoints are learned, deduplicated, in deterministic order
	if got := candidateAddresses(candidates); got != "203.0.113.11:40200,203.0.113.12:40200" {
		t.Fatalf("candidates = %s", got)
	}
	for _, candidate := range candidates {
		if candidate.Source != mtypes.ControlV2CandidateSTUN {
			t.Fatalf("candidate source = %q", candidate.Source)
		}
	}
}

func TestSuperSTUNAlwaysRunsUnpinnedPassAlongsidePinnedSources(t *testing.T) {
	// Given a tun uplink with no enumerable source that owns the default route
	bind := newPinningSTUNFake(40201)
	bind.mapSource("", "203.0.113.100:3478", "203.0.113.50")
	bind.mapSource(wan1Source.ip.String(), "203.0.113.100:3478", "203.0.113.11")
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478"}, 200*time.Millisecond)

	// Then
	if got := candidateAddresses(candidates); got != "203.0.113.50:40201,203.0.113.11:40201" {
		t.Fatalf("candidates = %s", got)
	}
	var unpinned, pinned int
	for _, record := range bind.sendRecords() {
		if record.source == "" {
			unpinned++
		} else {
			pinned++
		}
	}
	if unpinned != 1 || pinned != 1 {
		t.Fatalf("unpinned=%d pinned=%d, want 1 each", unpinned, pinned)
	}
}

func TestSuperSTUNPortMismatchIsScopedPerSource(t *testing.T) {
	// Given two uplinks whose NATs map different ports
	bind := newPinningSTUNFake(40202)
	bind.mapSource(wan1Source.ip.String(), "203.0.113.100:3478", "203.0.113.11")
	bind.mapSource(wan1Source.ip.String(), "203.0.113.101:3478", "203.0.113.11")
	bind.mapSource(wan2Source.ip.String(), "203.0.113.100:3478", "203.0.113.12")
	bind.mapSource(wan2Source.ip.String(), "203.0.113.101:3478", "203.0.113.12")
	bind.ports[wan2Source.ip.String()] = 50000
	var mu sync.Mutex
	var logged []string
	device := &Device{log: &Logger{
		Errorf: func(format string, args ...interface{}) {
			mu.Lock()
			logged = append(logged, fmt.Sprintf(format, args...))
			mu.Unlock()
		},
		Verbosef: DiscardLogf,
	}}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	manager.sources = func() []stunSource { return []stunSource{wan1Source, wan2Source} }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478", "stun:203.0.113.101:3478"}, 200*time.Millisecond)

	// Then
	if got := candidateAddresses(candidates); got != "203.0.113.11:40202,203.0.113.12:50000" {
		t.Fatalf("candidates = %s", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, msg := range logged {
		if strings.Contains(msg, "mapped port mismatch") {
			t.Fatalf("unexpected cross-source mismatch log: %s", msg)
		}
	}
}

func TestSuperSTUNDeduplicatesIdenticalMappingAcrossSources(t *testing.T) {
	// Given two uplinks behind the same NAT
	bind := newPinningSTUNFake(40203)
	for _, source := range []string{"", wan1Source.ip.String(), wan2Source.ip.String()} {
		bind.mapSource(source, "203.0.113.100:3478", "203.0.113.11")
	}
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source, wan2Source)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478"}, 200*time.Millisecond)

	// Then
	if got := candidateAddresses(candidates); got != "203.0.113.11:40203" {
		t.Fatalf("candidates = %s", got)
	}
}

func TestSuperSTUNUnreachableSourceDoesNotDelayOthers(t *testing.T) {
	// Given wan2 silently drops (IPv4 on-link fallback) and wan1 answers
	bind := newPinningSTUNFake(40204)
	bind.mapSource(wan1Source.ip.String(), "203.0.113.100:3478", "203.0.113.11")
	bind.mapSource(wan1Source.ip.String(), "203.0.113.101:3478", "203.0.113.11")
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source, wan2Source)
	timeout := 150 * time.Millisecond

	// When
	started := time.Now()
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478", "stun:203.0.113.101:3478"}, timeout)
	elapsed := time.Since(started)

	// Then sources run concurrently: wall time is one source's worst case
	if got := candidateAddresses(candidates); got != "203.0.113.11:40204" {
		t.Fatalf("candidates = %s", got)
	}
	if elapsed >= 4*timeout {
		t.Fatalf("Discover took %v, want < %v (sources must not be serialized)", elapsed, 4*timeout)
	}
}

func TestSuperSTUNFallsBackToLegacyWhenBindCannotPin(t *testing.T) {
	// Given a bind without EndpointSourcePinner
	inner := newPinningSTUNFake(40205)
	inner.mapSource("", "203.0.113.100:3478", "203.0.113.11")
	bind := nonPinningSTUNFake{inner}
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source, wan2Source)

	// When
	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478"}, 200*time.Millisecond)

	// Then only the unpinned probe is sent
	if got := candidateAddresses(candidates); got != "203.0.113.11:40205" {
		t.Fatalf("candidates = %s", got)
	}
	for _, record := range inner.sendRecords() {
		if record.source != "" {
			t.Fatalf("pinned probe sent through a non-pinning bind: %+v", record)
		}
	}
}

func (nonPinningSTUNFake) ParseEndpointFrom() {} // shadows the embedded method with an incompatible signature

func TestSuperSTUNSkipsProbeWhenKernelRejectsPin(t *testing.T) {
	// Given the kernel refuses wan1's IPv6 pin and resends via the default route
	bind := newPinningSTUNFake(40206)
	bind.mapSource("", "[2001:db8::100]:3478", "2001:db8:99::1")
	bind.rejectPin[wan1V6.ip.String()] = true
	manager, _, ctx := newMultiWANManager(t, bind, wan1V6)

	// When
	candidates := manager.Discover(ctx, []string{"stun:[2001:db8::100]:3478"}, 150*time.Millisecond)

	// Then the default-route reply is reported once and never attributed to wan1
	if got := candidateAddresses(candidates); got != "[2001:db8:99::1]:40206" {
		t.Fatalf("candidates = %s", got)
	}
}

func TestSuperSTUNSourceFamilyMustMatchServerFamily(t *testing.T) {
	// Given one v4 and one v6 source and one server per family
	bind := newPinningSTUNFake(40207)
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source, wan1V6)

	// When
	manager.Discover(ctx, []string{"stun:203.0.113.100:3478", "stun:[2001:db8::100]:3478"}, 50*time.Millisecond)

	// Then no pinned probe crosses families
	for _, record := range bind.sendRecords() {
		if record.source == "" {
			continue
		}
		serverIs4 := strings.HasPrefix(record.dst, "203.")
		sourceIs4 := !strings.Contains(record.source, ":")
		if serverIs4 != sourceIs4 {
			t.Fatalf("cross-family probe: %+v", record)
		}
	}
}

func TestSuperSTUNCloseDuringMultiSourceDiscoveryReturnsWithoutLeak(t *testing.T) {
	// Given every source waits for replies that never come
	bind := newPinningSTUNFake(40208)
	device := &Device{}
	device.net.bind = bind
	manager := NewSuperSTUNManager(device)
	manager.sources = func() []stunSource { return []stunSource{wan1Source, wan2Source} }
	before := runtime.NumGoroutine()
	done := make(chan []mtypes.ControlV2Candidate, 1)
	go func() {
		done <- manager.Discover(context.Background(), []string{"stun:203.0.113.100:3478"}, 5*time.Second)
	}()
	deadline := time.Now().Add(time.Second)
	for len(bind.sendRecords()) < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}

	// When
	manager.Close()

	// Then
	select {
	case candidates := <-done:
		if len(candidates) != 0 {
			t.Fatalf("candidates = %v", candidates)
		}
	case <-time.After(time.Second):
		t.Fatal("Discover did not return after Close")
	}
	deadline = time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutines before=%d after=%d", before, after)
	}
}

func TestSuperSTUNCandidateOrderIsDeterministicAcrossRuns(t *testing.T) {
	// Given sources answering with inverted delays
	bind := newPinningSTUNFake(40209)
	bind.mapSource("", "203.0.113.100:3478", "203.0.113.10")
	bind.mapSource(wan1Source.ip.String(), "203.0.113.100:3478", "203.0.113.11")
	bind.mapSource(wan2Source.ip.String(), "203.0.113.100:3478", "203.0.113.12")
	bind.delay[""] = 30 * time.Millisecond
	bind.delay[wan1Source.ip.String()] = 15 * time.Millisecond
	manager, _, ctx := newMultiWANManager(t, bind, wan2Source, wan1Source)

	// When / Then
	want := "203.0.113.10:40209,203.0.113.12:40209,203.0.113.11:40209"
	for i := 0; i < 3; i++ {
		if got := candidateAddresses(manager.Discover(ctx, []string{"stun:203.0.113.100:3478"}, 200*time.Millisecond)); got != want {
			t.Fatalf("run %d candidates = %s, want %s", i, got, want)
		}
	}
}

func TestSuperSTUNRequestsUseDistinctRandomTransactionIDs(t *testing.T) {
	// Given concurrent probes from several slots to several servers
	bind := newPinningSTUNFake(40210)
	manager, _, ctx := newMultiWANManager(t, bind, wan1Source, wan2Source)

	// When
	manager.Discover(ctx, []string{"stun:203.0.113.100:3478", "stun:203.0.113.101:3478"}, 20*time.Millisecond)

	// Then every request carries its own non-zero transaction ID
	records := bind.sendRecords()
	if len(records) != 6 {
		t.Fatalf("sent %d requests, want 6", len(records))
	}
	seen := make(map[[stun.TransactionIDSize]byte]struct{})
	for _, record := range records {
		if record.txID == ([stun.TransactionIDSize]byte{}) {
			t.Fatal("STUN request sent with an all-zero transaction ID")
		}
		if _, dup := seen[record.txID]; dup {
			t.Fatalf("duplicate transaction ID %x", record.txID)
		}
		seen[record.txID] = struct{}{}
	}
}

func TestSTUNLoopKeepsRefreshingWhileSnapshotsArrive(t *testing.T) {
	// Given a runtime whose parameters ask for a STUN refresh every 60ms
	bind := newPinningSTUNFake(40300)
	device := &Device{EdgeConfig: &mtypes.EdgeConfig{}, enabledAf: conn.EnabledAf46}
	device.net.bind = bind
	device.superSTUN = NewSuperSTUNManager(device)
	device.superSTUN.sources = func() []stunSource { return nil }
	t.Cleanup(device.superSTUN.Close)
	runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{})
	runtime.parameters = mtypes.ControlV2Parameters{
		STUNServers:         []string{"stun:203.0.113.100:3478"},
		STUNRequestTimeout:  5 * time.Millisecond,
		STUNRefreshInterval: 60 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runtime.stunLoop(ctx)

	// When snapshot revisions arrive far more often than the refresh interval
	deadline := time.Now().Add(400 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case runtime.parameterUpdates <- struct{}{}:
		default:
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Then periodic refreshes still happen
	if sent := len(bind.sendRecords()); sent < 3 {
		t.Fatalf("STUN requests during 400ms of snapshot churn = %d, want >= 3", sent)
	}
}
