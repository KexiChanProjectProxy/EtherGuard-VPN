package device

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

// legFakeBind adds remote legs to pinningSTUNFake the way conn.LegBind does:
// leg ifindexes pin to conn.RemoteLegEndpoint, and sends on a leg reach the
// fake as if pinned to the leg's address, so per-uplink NAT emulation applies.
type legFakeBind struct {
	*pinningSTUNFake
	legs    []conn.RemoteLeg
	handler func(conn.LegEvent)
	legSent []*conn.RemoteLegEndpoint
}

func newLegFakeBind(port uint16, legs ...conn.RemoteLeg) *legFakeBind {
	return &legFakeBind{pinningSTUNFake: newPinningSTUNFake(port), legs: legs}
}

func (b *legFakeBind) RemoteLegs() []conn.RemoteLeg                   { return b.legs }
func (b *legFakeBind) SetLegEventHandler(handler func(conn.LegEvent)) { b.handler = handler }
func (b *legFakeBind) Unwrap() conn.Bind                              { return b.pinningSTUNFake }

func (b *legFakeBind) ParseEndpointFrom(dst string, src netip.Addr, ifindex int) (conn.Endpoint, error) {
	if !conn.IsLegIfindex(ifindex) {
		return b.pinningSTUNFake.ParseEndpointFrom(dst, src, ifindex)
	}
	for _, leg := range b.legs {
		if leg.Ifindex == ifindex {
			return &conn.RemoteLegEndpoint{AgentID: leg.AgentID, LegID: leg.LegID, Src: leg.Addr.Addr(), Dst: netip.MustParseAddrPort(dst)}, nil
		}
	}
	return nil, conn.ErrLegUnavailable
}

func (b *legFakeBind) Send(packet []byte, endpoint conn.Endpoint) error {
	if leg, ok := endpoint.(*conn.RemoteLegEndpoint); ok {
		b.mu.Lock()
		b.legSent = append(b.legSent, leg)
		b.mu.Unlock()
		return b.pinningSTUNFake.Send(packet, &pinnedSTUNEndpoint{dst: leg.DstToString(), src: leg.Src, ifindex: leg.SrcIfindex()})
	}
	return b.pinningSTUNFake.Send(packet, endpoint)
}

func testRemoteLeg(agentID uint16, legID uint8, addr string) conn.RemoteLeg {
	return conn.RemoteLeg{
		AgentID: agentID, LegID: legID, Name: "eth0",
		Addr:    netip.MustParseAddrPort(addr),
		Ifindex: conn.LegIfindex(agentID, legID),
	}
}

var (
	legB = testRemoteLeg(2, 0, "203.0.113.70:16386")
	legC = testRemoteLeg(3, 0, "203.0.113.80:16999")
)

func legSource(leg conn.RemoteLeg) stunSource {
	return stunSource{ip: leg.Addr.Addr(), ifindex: leg.Ifindex, ifname: leg.Key(), remote: true}
}

func TestStunSourcesAppendRemoteLegsAfterLocalUplinks(t *testing.T) {
	bind := newLegFakeBind(3001, legB, testRemoteLeg(2, 1, "[2001:db8:70::1]:16386"))
	device, _ := newProberTestDevice(t, bind)
	device.attachRemoteLegs(bind)
	device.SetUplinksForTest([]UplinkForTest{{Addr: wan1Source.ip, Ifindex: 3, Name: "wan1"}})

	got := device.stunSources()
	if len(got) != 3 || got[0].remote || !got[1].remote || !got[2].remote {
		t.Fatalf("sources = %+v", got)
	}
	if got[1].ifindex != legB.Ifindex || got[1].ip != legB.Addr.Addr() {
		t.Fatalf("remote source = %+v", got[1])
	}

	// A family the edge disabled leaves its legs out.
	device.enabledAf = conn.EnabledAf4
	if got := device.stunSources(); len(got) != 2 {
		t.Fatalf("IPv4-only sources = %+v", got)
	}
}

func TestStunSourcesWithoutLocalPinningListOnlyRemoteLegs(t *testing.T) {
	bind := newLegFakeBind(3001, legB)
	device, _ := newProberTestDevice(t, bind)
	device.attachRemoteLegs(nonPinningLegBind{bind})
	if device.localPinning {
		t.Fatal("inner bind without pinning reported as pinning")
	}
	got := device.stunSources()
	if len(got) != 1 || !got[0].remote {
		t.Fatalf("sources = %+v", got)
	}
}

// nonPinningLegBind is a leg bind over a socket bind that cannot pin.
type nonPinningLegBind struct{ *legFakeBind }

func (b nonPinningLegBind) Unwrap() conn.Bind { return nonPinningSTUNFake{b.pinningSTUNFake} }

type failingRouteChecker struct{ t *testing.T }

func (c failingRouteChecker) routable(dst, src netip.Addr, ifindex int) error {
	if conn.IsLegIfindex(ifindex) {
		c.t.Fatalf("route check asked about remote leg %s#%d", src, ifindex)
	}
	return nil
}

func TestRouteMemoKeepsRemoteLegsWithoutAskingTheKernel(t *testing.T) {
	memo := newRouteMemo(failingRouteChecker{t}, nil)
	source := legSource(legB)
	if !memo.routable(&source, netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("remote leg dropped")
	}
	if !memo.routable(&wan1Source, netip.MustParseAddr("192.0.2.9")) {
		t.Fatal("local leg dropped")
	}
}

func TestBuildProbePairsGivesRemoteLegsTheirOwnBudget(t *testing.T) {
	sources := []stunSource{wan1Source, wan2Source, legSource(legB), legSource(legC)}
	candidates := []trylistCandidate{{address: "203.0.113.21:3001"}, {address: "203.0.113.22:3001"}}
	pairs := buildProbePairs("203.0.113.20:3001", candidates, sources, true, nil, nil)
	// Three remotes x (default + 4 uplinks) = 15, capped at 8 + 2 per leg.
	if len(pairs) != 12 {
		t.Fatalf("pairs = %d: %s", len(pairs), pairKeys(pairs))
	}
	keys := pairKeys(pairs)
	if !strings.Contains(keys, probePairKey(&sources[2], "203.0.113.21:3001")) {
		t.Fatalf("second remote has no remote leg pair: %s", keys)
	}
	// Without remote legs the local budget is unchanged.
	if got := buildProbePairs("203.0.113.20:3001", candidates, sources[:2], true, nil, nil); len(got) != endpointProbeMaxPairs {
		t.Fatalf("local-only pairs = %d", len(got))
	}
}

func TestCurrentPairKeyTellsRemoteLegFromLocalUplinkWithSameAddress(t *testing.T) {
	// Two sites behind different NATs can use the same private address.
	twin := testRemoteLeg(2, 0, wan1Source.ip.String()+":16386")
	sources := []stunSource{wan1Source, legSource(twin)}
	remote := "203.0.113.20:3001"

	viaLeg := &conn.RemoteLegEndpoint{AgentID: 2, LegID: 0, Src: wan1Source.ip, Dst: netip.MustParseAddrPort(remote)}
	if got, want := currentPairKey(viaLeg, sources), probePairKey(&sources[1], remote); got != want {
		t.Fatalf("leg endpoint key = %s, want %s", got, want)
	}
	local := &pinnedSTUNEndpoint{dst: remote, src: wan1Source.ip, ifindex: wan1Source.ifindex}
	if got, want := currentPairKey(local, sources), probePairKey(&sources[0], remote); got != want {
		t.Fatalf("local endpoint key = %s, want %s", got, want)
	}
	// A leg that is gone matches no pair, so any measured pair may replace it.
	gone := &conn.RemoteLegEndpoint{AgentID: 9, LegID: 4, Src: wan1Source.ip, Dst: netip.MustParseAddrPort(remote)}
	key := currentPairKey(gone, sources)
	for _, pair := range buildProbePairs(remote, nil, sources, true, nil, nil) {
		if pair.key == key {
			t.Fatalf("gone leg matched pair %s", key)
		}
	}
}

func TestProbeRoundsSwitchPeerToFasterRemoteLeg(t *testing.T) {
	bind := newLegFakeBind(3001, legB)
	device, peer := newProberTestDevice(t, bind)
	device.attachRemoteLegs(bind)
	device.SetUplinksForTest(nil)
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	setTrylist(peer, "203.0.113.20:3001")
	rtt := func(endpoint conn.Endpoint) time.Duration {
		if _, ok := endpoint.(conn.LegEndpoint); ok {
			return 10 * time.Millisecond
		}
		return 80 * time.Millisecond
	}
	for round := 0; round < 10; round++ {
		device.probeEndpointsRound(testSelection, time.Now())
		answerProbes(peer, drainProbes(device), rtt)
		peer.RLock()
		_, onLeg := peer.endpoint.(conn.LegEndpoint)
		peer.RUnlock()
		if onLeg {
			if !peer.endpointPinned.Load() {
				t.Fatal("leg endpoint is not pinned")
			}
			return
		}
	}
	t.Fatal("peer never moved to the faster remote leg")
}

func newLegEventTestDevice(t *testing.T, bind *legFakeBind) (*Device, *Peer, *Peer) {
	t.Helper()
	device, peer := newProberTestDevice(t, bind)
	device.closed = make(chan int)
	t.Cleanup(func() { close(device.closed) })
	device.event_tryendpoint = make(chan struct{}, 1)
	device.peers.keyMap = map[NoisePublicKey]*Peer{{1}: peer}
	other := &Peer{ID: 3, device: device}
	device.peers.keyMap[NoisePublicKey{2}] = other
	device.attachRemoteLegs(bind)
	return device, peer, other
}

func peerEndpoint(peer *Peer) conn.Endpoint {
	peer.RLock()
	defer peer.RUnlock()
	return peer.endpoint
}

func awaitDevice(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRemoteLegDownMovesPeersOffTheLeg(t *testing.T) {
	bind := newLegFakeBind(3001, legB, legC)
	device, peer, other := newLegEventTestDevice(t, bind)

	onB, _ := bind.ParseEndpointFrom("203.0.113.20:3001", legB.Addr.Addr(), legB.Ifindex)
	onC, _ := bind.ParseEndpointFrom("203.0.113.30:3001", legC.Addr.Addr(), legC.Ifindex)
	peer.endpoint = onB
	peer.endpointPinned.Store(true)
	other.endpoint = onC

	bind.handler(conn.LegEvent{Leg: legB, Up: false})

	awaitDevice(t, "peer moved off the lost leg", func() bool {
		_, still := peerEndpoint(peer).(conn.LegEndpoint)
		return !still
	})
	if peerEndpoint(peer).DstToString() != "203.0.113.20:3001" || peer.endpointPinned.Load() {
		t.Fatalf("peer endpoint %v pinned=%v", peerEndpoint(peer).DstToString(), peer.endpointPinned.Load())
	}
	if peerEndpoint(other) != onC {
		t.Fatal("peer on another leg was moved")
	}
	awaitDevice(t, "endpoint retry signal", func() bool {
		select {
		case <-device.event_tryendpoint:
			return true
		default:
			return false
		}
	})
	awaitDevice(t, "STUN refresh request", func() bool { return len(device.p2pSTUNRefresh) == 1 })
}

func TestRemoteLegEventHandlerNeverBlocksOnDeviceLocks(t *testing.T) {
	// The bind calls the handler from goroutines its Close waits for, so the
	// handler must return even while the peer table is locked.
	bind := newLegFakeBind(3001, legB)
	device, peer, _ := newLegEventTestDevice(t, bind)
	peer.endpoint, _ = bind.ParseEndpointFrom("203.0.113.20:3001", legB.Addr.Addr(), legB.Ifindex)

	device.peers.Lock()
	returned := make(chan struct{})
	go func() {
		bind.handler(conn.LegEvent{Leg: legB, Up: false})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		device.peers.Unlock()
		t.Fatal("leg event handler blocked on the peer table")
	}
	device.peers.Unlock()
	awaitDevice(t, "peer moved off the lost leg", func() bool {
		_, still := peerEndpoint(peer).(conn.LegEndpoint)
		return !still
	})
}

func TestRemoteLegDownForOldAddressKeepsPeersOnNewAddress(t *testing.T) {
	// The leg moved from .70 to .71; its down event for .70 may be handled
	// after a peer already switched to .71.
	moved := testRemoteLeg(2, 0, "203.0.113.71:16386")
	bind := newLegFakeBind(3001, moved)
	_, peer, other := newLegEventTestDevice(t, bind)
	onNew, _ := bind.ParseEndpointFrom("203.0.113.20:3001", moved.Addr.Addr(), moved.Ifindex)
	peer.endpoint = onNew
	onOld := &conn.RemoteLegEndpoint{AgentID: 2, LegID: 0, Src: legB.Addr.Addr(), Dst: netip.MustParseAddrPort("203.0.113.30:3001")}
	other.endpoint = onOld

	bind.handler(conn.LegEvent{Leg: legB, Up: false})

	awaitDevice(t, "peer on the old address moved", func() bool {
		_, still := peerEndpoint(other).(conn.LegEndpoint)
		return !still
	})
	if peerEndpoint(peer) != onNew {
		t.Fatal("peer on the leg's new address was moved")
	}
}

func TestRemoteLegEndpointURLsAdvertiseLegPorts(t *testing.T) {
	bind := newLegFakeBind(3001, legB, legC, testRemoteLeg(4, 0, "100.64.1.1:16386"), testRemoteLeg(4, 1, "[2001:db8:70::1]:16386"))
	device, _ := newProberTestDevice(t, bind)
	device.attachRemoteLegs(bind)
	device.enabledAf = conn.EnabledAf4
	got := strings.Join(device.remoteLegEndpointURLs(), ",")
	if got != "203.0.113.70:16386,203.0.113.80:16999" {
		t.Fatalf("leg URLs = %s", got)
	}
}

func TestSuperSTUNDiscoversMappingThroughRemoteLeg(t *testing.T) {
	bind := newLegFakeBind(40300, legB)
	bind.mapSource("", "203.0.113.100:3478", "203.0.113.11")
	bind.mapSource(legB.Addr.Addr().String(), "203.0.113.100:3478", "203.0.113.99")
	bind.ports[legB.Addr.Addr().String()] = 16386
	manager, _, ctx := newMultiWANManager(t, bind.pinningSTUNFake, legSource(legB))
	manager.device.net.bind = bind

	candidates := manager.Discover(ctx, []string{"stun:203.0.113.100:3478"}, 200*time.Millisecond)

	if got := candidateAddresses(candidates); got != "203.0.113.11:40300,203.0.113.99:16386" {
		t.Fatalf("candidates = %s", got)
	}
	if len(bind.legSent) != 1 {
		t.Fatalf("%d STUN requests went through the leg", len(bind.legSent))
	}
}
