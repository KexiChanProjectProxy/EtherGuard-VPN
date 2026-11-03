package main

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type pureP2PNode struct {
	id      mtypes.Vertex
	ip      string
	mac     net.HardwareAddr
	private device.NoisePrivateKey
	public  device.NoisePublicKey
	tap     *e2eTap
	edge    *device.Device
}

func (n *pureP2PNode) url() string {
	return net.JoinHostPort(n.ip, n.id.ToString()) // each bind listens on its node id
}

func ethernetFrame(dst, src net.HardwareAddr, payload string) []byte {
	frame := make([]byte, 0, 60)
	frame = append(frame, dst...)
	frame = append(frame, src...)
	frame = append(frame, 0x88, 0xb5) // local experimental ethertype
	frame = append(frame, payload...)
	for len(frame) < 60 {
		frame = append(frame, 0)
	}
	return frame
}

// awaitFrame waits for a frame carrying payload on node's tap.
func awaitFrame(t *testing.T, node *pureP2PNode, payload string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case frame := <-node.tap.writes:
			if bytes.Contains(frame, []byte(payload)) {
				return
			}
		case <-deadline:
			t.Fatalf("node %v never received %q", node.id, payload)
		}
	}
}

// assertNoFrame fails if a frame carrying payload reaches node's tap.
func assertNoFrame(t *testing.T, node *pureP2PNode, payload string, wait time.Duration) {
	t.Helper()
	deadline := time.After(wait)
	for {
		select {
		case frame := <-node.tap.writes:
			if bytes.Contains(frame, []byte(payload)) {
				t.Fatalf("node %v received %q, PureP2P must not relay", node.id, payload)
			}
		case <-deadline:
			return
		}
	}
}

func connectPureP2P(t *testing.T, from, to *pureP2PNode) *device.Peer {
	t.Helper()
	peer, err := from.edge.NewPeer(to.public, to.id, false, 0)
	if err != nil {
		t.Fatalf("node %v new peer %v: %v", from.id, to.id, err)
	}
	peer.AddEndpointRetry(to.url(), false)
	if err := peer.SetEndpointFromConnURL(to.url(), conn.EnabledAf4, 0, false); err != nil {
		t.Fatalf("node %v endpoint for %v: %v", from.id, to.id, err)
	}
	return peer
}

// TestPureP2PChainHasNoRelay runs A - B - C where A and C cannot reach each
// other: peer info about C still reaches A through B, but no data frame ever
// crosses B.
func TestPureP2PChainHasNoRelay(t *testing.T) {
	fabric := newE2EFabric()
	fabric.strict = func(string) bool { return true }
	nodes := map[string]*pureP2PNode{
		"A": {id: 101, ip: "198.51.100.101", mac: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}},
		"B": {id: 102, ip: "198.51.100.102", mac: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x02}},
		"C": {id: 103, ip: "198.51.100.103", mac: net.HardwareAddr{0x02, 0, 0, 0, 0, 0x03}},
	}
	blacklist := map[string][]string{"A": {"198.51.100.103/32"}, "C": {"198.51.100.101/32"}}
	for name, node := range nodes {
		node.private, node.public = device.RandomKeyPair()
		node.tap = newE2ETap()
		bind := newE2EBind(fabric, net.ParseIP(node.ip), net.ParseIP(node.ip), uint16(node.id), true)
		node.edge, _ = newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{
			id:               node.id,
			name:             "pure-" + name,
			bind:             bind,
			port:             uint16(node.id),
			uplinks:          []device.UplinkForTest{},
			p2p:              true,
			pureP2P:          true,
			sendPeerInterval: 0.3,
			blacklist:        blacklist[name],
			tap:              node.tap,
		}, "", node.private)
	}
	a, b, c := nodes["A"], nodes["B"], nodes["C"]
	connectPureP2P(t, b, a)
	connectPureP2P(t, b, c)
	peerBAtA := connectPureP2P(t, a, b)
	peerBAtC := connectPureP2P(t, c, b)
	if err := peerBAtA.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("A handshake: %v", err)
	}
	if err := peerBAtC.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("C handshake: %v", err)
	}

	// Given A-B and B-C are live and A learned about C through B
	awaitE2E(t, 10*time.Second, func() bool {
		return peerBAtA.IsPeerAlive() && peerBAtC.IsPeerAlive() &&
			b.edge.LookupPeer(a.public).IsPeerAlive() && b.edge.LookupPeer(c.public).IsPeerAlive()
	})
	awaitE2E(t, 10*time.Second, func() bool { return a.edge.LookupPeer(c.public) != nil })
	time.Sleep(time.Second)
	// A keeps trying C's advertised addresses, but none of them works.
	if a.edge.LookupPeer(c.public).IsPeerAlive() {
		t.Fatalf("A reached C directly at %q despite the blacklist", a.edge.GetConnurl(c.id))
	}

	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// When B broadcasts, both direct neighbours receive it (and learn B's MAC)
	b.tap.inject(ethernetFrame(broadcast, b.mac, "from-b-broadcast"))
	awaitFrame(t, a, "from-b-broadcast", 5*time.Second)
	awaitFrame(t, c, "from-b-broadcast", 5*time.Second)

	// When A unicasts to B, only B receives it
	a.tap.inject(ethernetFrame(b.mac, a.mac, "a-to-b-unicast"))
	awaitFrame(t, b, "a-to-b-unicast", 5*time.Second)

	// When A broadcasts, B receives it and does not re-forward it to C
	a.tap.inject(ethernetFrame(broadcast, a.mac, "from-a-broadcast"))
	awaitFrame(t, b, "from-a-broadcast", 5*time.Second)
	assertNoFrame(t, c, "from-a-broadcast", 500*time.Millisecond)

	// When A sends to C's MAC (unknown at A, so flooded to direct peers),
	// B gets the flood and C still gets nothing
	a.tap.inject(ethernetFrame(c.mac, a.mac, "a-to-c-unicast"))
	awaitFrame(t, b, "a-to-c-unicast", 5*time.Second)
	assertNoFrame(t, c, "a-to-c-unicast", 500*time.Millisecond)
}

// e2eFirewall is the stateful filter of an endpoint-independent NAT: a guarded
// address accepts a source only after sending to that source itself.
type e2eFirewall struct {
	mu      sync.Mutex
	guarded map[string]bool
	opened  map[[2]string]bool
	dropped int
}

func (f *e2eFirewall) admit(source, destination string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opened[[2]string{source, destination}] = true
	if !f.guarded[destination] || f.opened[[2]string{destination, source}] {
		return true
	}
	f.dropped++
	return false
}

func (f *e2eFirewall) droppedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dropped
}

// hostEndpointBlacklist covers this machine's real addresses. Edges advertise
// them, but the fabric cannot reach them, and a first advert for one would
// hold the handshake grace on a dead address.
func hostEndpointBlacklist(t *testing.T) []string {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatalf("interface addresses: %v", err)
	}
	var blacklist []string
	for _, address := range addresses {
		ipNet, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		bits := 128
		if ipNet.IP.To4() != nil {
			bits = 32
		}
		blacklist = append(blacklist, fmt.Sprintf("%s/%d", ipNet.IP, bits))
	}
	return blacklist
}

// TestPureP2PFirewalledEdgesPunchThroughAdvertisedAddresses runs A - B - C with
// A and C behind stateful firewalls. Neither can reach the other until both
// have sent, so they must act on the address B advertises. PureP2P never
// relays, so a frame arriving at C proves the direct path.
func TestPureP2PFirewalledEdgesPunchThroughAdvertisedAddresses(t *testing.T) {
	fabric := newE2EFabric()
	fabric.strict = func(string) bool { return true }
	nodes := map[string]*pureP2PNode{
		"A": {id: 111, ip: "198.51.100.111", mac: net.HardwareAddr{0x02, 0, 0, 0, 1, 0x01}},
		"B": {id: 112, ip: "198.51.100.112", mac: net.HardwareAddr{0x02, 0, 0, 0, 1, 0x02}},
		"C": {id: 113, ip: "198.51.100.113", mac: net.HardwareAddr{0x02, 0, 0, 0, 1, 0x03}},
	}
	firewall := &e2eFirewall{
		guarded: map[string]bool{"198.51.100.111:111": true, "198.51.100.113:113": true},
		opened:  make(map[[2]string]bool),
	}
	fabric.admit = firewall.admit
	blacklist := hostEndpointBlacklist(t)
	for name, node := range nodes {
		node.private, node.public = device.RandomKeyPair()
		node.tap = newE2ETap()
		bind := newE2EBind(fabric, net.ParseIP(node.ip), net.ParseIP(node.ip), uint16(node.id), true)
		node.edge, _ = newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{
			id:               node.id,
			name:             "punch-" + name,
			bind:             bind,
			port:             uint16(node.id),
			uplinks:          []device.UplinkForTest{},
			p2p:              true,
			pureP2P:          true,
			sendPeerInterval: 0.3,
			blacklist:        blacklist,
			tap:              node.tap,
		}, "", node.private)
	}
	a, b, c := nodes["A"], nodes["B"], nodes["C"]

	// Given A and C each hold a session with the public B and nothing else
	connectPureP2P(t, b, a)
	connectPureP2P(t, b, c)
	peerBAtA := connectPureP2P(t, a, b)
	peerBAtC := connectPureP2P(t, c, b)
	if err := peerBAtA.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("A handshake: %v", err)
	}
	if err := peerBAtC.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("C handshake: %v", err)
	}

	// When the flood through B teaches each of them the other's address, a
	// direct session comes up inside the first handshake grace
	awaitE2E(t, 15*time.Second, func() bool {
		peerCAtA, peerAAtC := a.edge.LookupPeer(c.public), c.edge.LookupPeer(a.public)
		return peerCAtA != nil && peerAAtC != nil && peerCAtA.IsPeerAlive() && peerAAtC.IsPeerAlive()
	})
	if firewall.droppedCount() == 0 {
		t.Fatal("the firewall dropped nothing, so the test did not exercise a punch")
	}

	// Then data crosses the direct path
	broadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	a.tap.inject(ethernetFrame(broadcast, a.mac, "punched-a-to-c"))
	awaitFrame(t, c, "punched-a-to-c", 5*time.Second)
}
