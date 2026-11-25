package main

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const e2eLegKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

// e2eLegSite is a controller edge (101) whose own uplink 192.0.2.101 cannot
// reach edge C (103), and a leg agent whose uplink 203.0.113.50 can. The
// controller and the agent talk over real loopback UDP.
type e2eLegSite struct {
	fabric     *e2eFabric
	controller *device.Device
	legBind    *conn.LegBind
	agent      *legAgent
	peerC      *device.Peer // C as the controller sees it
	edgeC      *device.Device
	pubA       device.NoisePublicKey
}

func startE2ELegAgent(t *testing.T, fabric *e2eFabric, controller netip.AddrPort) *legAgent {
	t.Helper()
	key, err := conn.ParseLegKey(e2eLegKey)
	if err != nil {
		t.Fatal(err)
	}
	wan := newE2EBind(fabric, net.ParseIP("203.0.113.50"), net.ParseIP("203.0.113.50"), 150, true)
	agent := newLegAgent(mtypes.LegAgentSettings{
		AgentID:          7,
		Listen:           netip.MustParseAddrPort("127.0.0.1:0"),
		Controller:       controller,
		Key:              key,
		HeartbeatTimeout: 3 * time.Second,
	}, legAgentOptions{
		wan: wan,
		uplinks: func() ([]device.Uplink, error) {
			return []device.Uplink{{Addr: netip.MustParseAddr("203.0.113.50"), Ifindex: 7, Name: "wan-b"}}, nil
		},
	})
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start: %v", err)
	}
	return agent
}

func newE2ELegSite(t *testing.T) *e2eLegSite {
	t.Helper()
	site := &e2eLegSite{fabric: newE2EFabric()}
	// The controller's own uplink and C cannot reach each other.
	site.fabric.admit = func(source, destination string) bool {
		a, c := "192.0.2.101:", "198.51.100.103:"
		return !(strings.HasPrefix(source, a) && strings.HasPrefix(destination, c)) &&
			!(strings.HasPrefix(source, c) && strings.HasPrefix(destination, a))
	}
	key, _ := conn.ParseLegKey(e2eLegKey)
	inner := newE2EBind(site.fabric, net.ParseIP("192.0.2.101"), net.ParseIP("192.0.2.101"), 101, true)
	site.legBind = conn.NewLegBind(inner, conn.LegConfig{
		Listen:           netip.MustParseAddrPort("127.0.0.1:0"),
		Key:              key,
		HeartbeatTimeout: 3 * time.Second,
	})
	privateA, pubA := device.RandomKeyPair()
	privateC, pubC := device.RandomKeyPair()
	site.pubA = pubA
	site.controller, _ = newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{id: 101, name: "controller", bind: site.legBind, port: 101, p2p: true, uplinks: []device.UplinkForTest{}}, "", privateA)
	bindC := newE2EBind(site.fabric, net.ParseIP("198.51.100.103"), net.ParseIP("198.51.100.103"), 103, true)
	site.edgeC, _ = newE2EMultiWANEdge(t, e2eMultiWANEdgeConfig{id: 103, name: "edge-c", bind: bindC, port: 103, p2p: true, uplinks: []device.UplinkForTest{}}, "", privateC)

	site.agent = startE2ELegAgent(t, site.fabric, site.legBind.LocalAddr())
	t.Cleanup(func() {
		if site.agent != nil {
			site.agent.Close()
		}
	})
	awaitE2E(t, 5*time.Second, func() bool { return len(site.legBind.RemoteLegs()) == 1 })

	var err error
	site.peerC, err = site.controller.NewPeer(pubC, 103, false, 0)
	if err != nil {
		t.Fatalf("controller new peer: %v", err)
	}
	if _, err := site.edgeC.NewPeer(pubA, 101, false, 0); err != nil {
		t.Fatalf("C new peer: %v", err)
	}
	if err := site.peerC.SetEndpointFromConnURL("198.51.100.103:103", conn.EnabledAf4, 0, false); err != nil {
		t.Fatalf("controller endpoint for C: %v", err)
	}
	return site
}

func onRemoteLeg(peer *device.Peer) bool {
	return strings.HasPrefix(peer.GetEndpointSrcStr(), "203.0.113.50")
}

func TestP2PControllerReachesPeerOnlyThroughRemoteLeg(t *testing.T) {
	// Given the controller's own uplink is firewalled from C
	site := newE2ELegSite(t)

	// When the controller starts a handshake
	if err := site.peerC.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Then the session comes up over the agent's uplink, in both directions
	awaitE2E(t, 10*time.Second, func() bool {
		return site.peerC.IsPeerAlive() && onRemoteLeg(site.peerC)
	})
	peerA := site.edgeC.LookupPeer(site.pubA)
	awaitE2E(t, 10*time.Second, func() bool { return peerA.IsPeerAlive() })
	if got := site.edgeC.GetConnurl(101); got != "203.0.113.50:150" {
		t.Fatalf("C reaches the controller at %s, want the leg 203.0.113.50:150", got)
	}
	if got := site.controller.GetConnurl(103); got != "198.51.100.103:103" {
		t.Fatalf("controller endpoint for C = %s", got)
	}
}

func TestP2PControllerMovesPeerOffLostRemoteLeg(t *testing.T) {
	// Given a live session over the remote leg
	site := newE2ELegSite(t)
	site.peerC.SendHandshakeInitiation(false)
	awaitE2E(t, 10*time.Second, func() bool {
		return site.peerC.IsPeerAlive() && onRemoteLeg(site.peerC)
	})

	// When the agent stops
	site.agent.Close()
	site.agent = nil

	// Then the leg expires and the peer leaves it for the controller's own
	// uplink, keeping the remote address
	awaitE2E(t, 10*time.Second, func() bool { return len(site.legBind.RemoteLegs()) == 0 })
	awaitE2E(t, 5*time.Second, func() bool { return !onRemoteLeg(site.peerC) })
	if got := site.controller.GetConnurl(103); got != "198.51.100.103:103" {
		t.Fatalf("controller endpoint for C = %s", got)
	}
}

func TestP2PControllerAdvertisesRemoteLegAddresses(t *testing.T) {
	site := newE2ELegSite(t)
	awaitE2E(t, 5*time.Second, func() bool {
		for _, url := range site.controller.P2PLocalEndpointURLsForTest() {
			if url == "203.0.113.50:150" {
				return true
			}
		}
		return false
	})
}
