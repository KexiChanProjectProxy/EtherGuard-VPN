package main

import (
	"bytes"
	"net"
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
