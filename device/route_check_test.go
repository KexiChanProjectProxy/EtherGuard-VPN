package device

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRouteChecker answers from a table; legs not listed are routable.
type fakeRouteChecker struct {
	mu     sync.Mutex
	routes map[routeKey]error
	calls  int
}

func newFakeRouteChecker() *fakeRouteChecker {
	return &fakeRouteChecker{routes: make(map[routeKey]error)}
}

// deny marks the leg from local (nil: default route) to dst as having no route.
func (f *fakeRouteChecker) deny(local *stunSource, dst string) {
	f.set(local, dst, &noRouteError{reason: "test"})
}

func (f *fakeRouteChecker) set(local *stunSource, dst string, err error) {
	key := routeKey{dst: netip.MustParseAddr(dst)}
	if local != nil {
		key.src, key.ifindex = local.ip, local.ifindex
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[key] = err
}

func (f *fakeRouteChecker) routable(dst, src netip.Addr, ifindex int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.routes[routeKey{dst: dst, src: src, ifindex: ifindex}]
}

// recordingLogger captures log lines for assertions.
type recordingLogger struct {
	mu      sync.Mutex
	verbose []string
	errors  []string
}

func (r *recordingLogger) logger() *Logger {
	return &Logger{
		Verbosef: func(format string, args ...interface{}) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.verbose = append(r.verbose, fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...interface{}) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.errors = append(r.errors, fmt.Sprintf(format, args...))
		},
	}
}

func (r *recordingLogger) count(lines func(*recordingLogger) []string, substr string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, line := range lines(r) {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func verboseLines(r *recordingLogger) []string { return r.verbose }
func errorLines(r *recordingLogger) []string   { return r.errors }

func TestRouteMemoWithoutCheckerAllowsEverything(t *testing.T) {
	memo := newRouteMemo(nil, nil)
	if memo != nil {
		t.Fatal("memo without a checker should be nil")
	}
	if !memo.routable(&wan1Source, netip.MustParseAddr("203.0.113.20")) || !memo.routable(nil, netip.MustParseAddr("2001:db8::20")) {
		t.Fatal("nil memo must treat every leg as routable")
	}
}

func TestRouteMemoCachesPerLeg(t *testing.T) {
	check := newFakeRouteChecker()
	check.deny(&wan2Source, "203.0.113.20")
	memo := newRouteMemo(check, nil)
	remote := netip.MustParseAddr("203.0.113.20")

	for i := 0; i < 3; i++ {
		if !memo.routable(&wan1Source, remote) {
			t.Fatal("wan1 leg should be routable")
		}
		if memo.routable(&wan2Source, remote) {
			t.Fatal("wan2 leg should have no route")
		}
	}
	if check.calls != 2 {
		t.Fatalf("lookups = %d, want 2 (one per leg)", check.calls)
	}
}

func TestRouteMemoKeepsLegWhenLookupFailsAndLogsOnce(t *testing.T) {
	check := newFakeRouteChecker()
	check.set(nil, "2001:db8::20", errors.New("netlink receive: timeout"))
	logs := &recordingLogger{}
	memo := newRouteMemo(check, logs.logger())

	for i := 0; i < 2; i++ {
		if !memo.routable(nil, netip.MustParseAddr("2001:db8::20")) {
			t.Fatal("a failed lookup must keep the leg")
		}
	}
	if got := logs.count(verboseLines, "Route check failed, keeping leg: src=default"); got != 1 {
		t.Fatalf("failure log lines = %d, want 1; logs=%v", got, logs.verbose)
	}
}

func TestRouteMemoMapsIPv4MappedAddresses(t *testing.T) {
	check := newFakeRouteChecker()
	check.deny(nil, "203.0.113.20")
	memo := newRouteMemo(check, nil)
	if memo.routable(nil, netip.MustParseAddr("::ffff:203.0.113.20")) {
		t.Fatal("mapped address should hit the IPv4 entry")
	}
}

func TestBuildProbePairsSkipsUnroutablePinnedPair(t *testing.T) {
	check := newFakeRouteChecker()
	check.deny(&wan2Source, "203.0.113.21")
	memo := newRouteMemo(check, nil)

	pairs := buildProbePairs("203.0.113.21:3001", nil, []stunSource{wan1Source, wan2Source}, true, nil, memo.routable)

	if got := pairKeys(pairs); got != "default|203.0.113.21:3001,192.0.2.2#3|203.0.113.21:3001" {
		t.Fatalf("pairs = %s", got)
	}
}

func TestBuildProbePairsSkipsUnroutableDefaultIPv6Pair(t *testing.T) {
	// Given a host without an IPv6 default route but with a pinned IPv6 uplink
	check := newFakeRouteChecker()
	check.deny(nil, "2001:db8::20")
	memo := newRouteMemo(check, nil)
	candidates := []trylistCandidate{{address: "[2001:db8::20]:3001"}}

	pairs := buildProbePairs("203.0.113.21:3001", candidates, []stunSource{wan1Source, wan1V6}, true, nil, memo.routable)

	want := "default|203.0.113.21:3001,192.0.2.2#3|203.0.113.21:3001,2001:db8:1::2#3|[2001:db8::20]:3001"
	if got := pairKeys(pairs); got != want {
		t.Fatalf("pairs = %s, want %s", got, want)
	}
}

func TestBuildProbePairsDropsRemoteWithoutAnyRoutableLeg(t *testing.T) {
	check := newFakeRouteChecker()
	check.deny(nil, "2001:db8::20")
	memo := newRouteMemo(check, nil)
	candidates := []trylistCandidate{{address: "[2001:db8::20]:3001"}, {address: "203.0.113.22:3001"}}

	pairs := buildProbePairs("203.0.113.21:3001", candidates, nil, false, nil, memo.routable)

	if got := pairKeys(pairs); got != "default|203.0.113.21:3001,default|203.0.113.22:3001" {
		t.Fatalf("pairs = %s", got)
	}
}

func TestProbeRoundSkipsLegsWithoutRoute(t *testing.T) {
	// Given two remotes, two uplinks, and no route from wan2 (a tunnel
	// interface) to either remote
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	logs := &recordingLogger{}
	device.log = logs.logger()
	check := newFakeRouteChecker()
	check.deny(&wan2Source, "203.0.113.20")
	check.deny(&wan2Source, "203.0.113.21")
	device.routeCheck = check
	device.SetUplinksForTest([]UplinkForTest{
		{Addr: wan1Source.ip, Ifindex: wan1Source.ifindex, Name: wan1Source.ifname},
		{Addr: wan2Source.ip, Ifindex: wan2Source.ifindex, Name: wan2Source.ifname},
	})
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")

	// When
	device.probeEndpointsRound(testSelection, time.Now())

	// Then only default and wan1 legs are probed, and the skip is logged
	probes := drainProbes(device)
	if len(probes) != 4 {
		t.Fatalf("probes = %d, want 4", len(probes))
	}
	for _, probe := range probes {
		if src := probe.endpoint.SrcIP(); src != nil && src.Equal(wan2Source.ip.AsSlice()) {
			t.Fatalf("probe pinned to wan2: %s", probe.endpoint.DstToString())
		}
	}
	if got := logs.count(verboseLines, "Route check skipped leg: src=wan2/198.51.100.2#4 ifindex=4"); got != 2 {
		t.Fatalf("skip log lines = %d, want 2; logs=%v", got, logs.verbose)
	}
}

func TestProbeRoundKeepsLegsWhenRouteLookupFails(t *testing.T) {
	bind := newPinningSTUNFake(3001)
	device, peer := newProberTestDevice(t, bind)
	check := newFakeRouteChecker()
	check.set(&wan2Source, "203.0.113.20", errors.New("netlink receive: timeout"))
	device.routeCheck = check
	device.SetUplinksForTest([]UplinkForTest{
		{Addr: wan1Source.ip, Ifindex: wan1Source.ifindex, Name: wan1Source.ifname},
		{Addr: wan2Source.ip, Ifindex: wan2Source.ifindex, Name: wan2Source.ifname},
	})
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001", "203.0.113.21:3001")

	device.probeEndpointsRound(testSelection, time.Now())

	if probes := drainProbes(device); len(probes) != 6 {
		t.Fatalf("probes = %d, want 6", len(probes))
	}
}

func TestRouteCheckerForFakeBindIsNil(t *testing.T) {
	device := &Device{}
	if check := device.routeCheckerFor(newPinningSTUNFake(3001)); check != nil {
		t.Fatalf("fake bind got checker %T", check)
	}
	fake := newFakeRouteChecker()
	device.routeCheck = fake
	if check := device.routeCheckerFor(newPinningSTUNFake(3001)); check != fake {
		t.Fatal("test override was not used")
	}
}
