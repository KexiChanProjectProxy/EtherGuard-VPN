package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestValidateDynamicRouteAcceptsLegsOnlyInP2PMode(t *testing.T) {
	legs := &mtypes.LegsConfig{Listen: "0.0.0.0:16400", Key: e2eLegKey}
	p2p := &mtypes.EdgeConfig{Legs: legs, DynamicRoute: mtypes.DynamicRouteInfo{P2P: mtypes.P2PInfo{UseP2P: true}}}
	if err := validateDynamicRoute(p2p); err != nil {
		t.Fatalf("P2P with Legs: %v", err)
	}
	static := &mtypes.EdgeConfig{Legs: legs}
	if err := validateDynamicRoute(static); err == nil {
		t.Fatal("static mode with Legs accepted")
	}
	super := &mtypes.EdgeConfig{Legs: legs, SuperNodeV2Enabled: true, DynamicRoute: mtypes.DynamicRouteInfo{P2P: mtypes.P2PInfo{UseP2P: true}}}
	if err := validateDynamicRoute(super); err == nil {
		t.Fatal("SuperNodeV2 with Legs accepted")
	}
	broken := &mtypes.EdgeConfig{Legs: &mtypes.LegsConfig{Listen: "0.0.0.0:16400"}, DynamicRoute: p2p.DynamicRoute}
	if err := validateDynamicRoute(broken); err == nil {
		t.Fatal("Legs without key accepted")
	}
}

func TestLegAgentKeepsLegIDsAcrossScans(t *testing.T) {
	scan := []device.Uplink{
		{Addr: netip.MustParseAddr("203.0.113.1"), Ifindex: 2, Name: "eth0"},
		{Addr: netip.MustParseAddr("198.51.100.1"), Ifindex: 3, Name: "wwan0"},
	}
	agent := newLegAgent(mtypes.LegAgentSettings{AgentID: 1}, legAgentOptions{
		wan:     newE2EBind(newE2EFabric(), net.ParseIP("203.0.113.1"), net.ParseIP("203.0.113.1"), 1, true),
		uplinks: func() ([]device.Uplink, error) { return scan, nil },
	})
	agent.pinner = pinnerStub{}
	agent.rescan()
	ids := map[string]uint8{}
	for _, leg := range agent.legs {
		ids[leg.uplink.Name] = leg.id
	}
	// eth0 goes away and comes back after wwan0: IDs follow the uplinks.
	scan = []device.Uplink{scan[1]}
	agent.rescan()
	if len(agent.legs) != 1 || agent.legs[0].id != ids["wwan0"] {
		t.Fatalf("legs after removal: %+v", agent.legs)
	}
	scan = append(scan, device.Uplink{Addr: netip.MustParseAddr("203.0.113.9"), Ifindex: 2, Name: "eth0"})
	agent.rescan()
	for _, leg := range agent.legs {
		if leg.uplink.Name == "wwan0" && leg.id != ids["wwan0"] {
			t.Fatalf("wwan0 changed ID: %+v", agent.legs)
		}
	}
	if len(agent.legs) != 2 || agent.legs[0].id == agent.legs[1].id {
		t.Fatalf("legs: %+v", agent.legs)
	}
}

func TestLegAgentMapsArrivalAddressToLeg(t *testing.T) {
	agent := &legAgent{legs: []agentLeg{
		{id: 0, uplink: device.Uplink{Addr: netip.MustParseAddr("203.0.113.1")}},
		{id: 4, uplink: device.Uplink{Addr: netip.MustParseAddr("198.51.100.1")}},
		{id: 5, uplink: device.Uplink{Addr: netip.MustParseAddr("2001:db8::1")}},
	}}
	if id, ok := agent.legFor(net.ParseIP("198.51.100.1"), netip.MustParseAddr("192.0.2.1")); !ok || id != 4 {
		t.Fatalf("by address: %d %v", id, ok)
	}
	if _, ok := agent.legFor(net.ParseIP("192.0.2.200"), netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("unknown local address mapped to a leg")
	}
	// Without source information only an unambiguous family maps.
	if id, ok := agent.legFor(nil, netip.MustParseAddr("2001:db8::9")); !ok || id != 5 {
		t.Fatalf("IPv6 fallback: %d %v", id, ok)
	}
	if _, ok := agent.legFor(nil, netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("ambiguous IPv4 fallback mapped")
	}
}

// pinnerStub lets rescan keep several uplinks per family.
type pinnerStub struct{}

func (pinnerStub) ParseEndpointFrom(string, netip.Addr, int) (conn.Endpoint, error) {
	return nil, conn.ErrInvalidSource
}
