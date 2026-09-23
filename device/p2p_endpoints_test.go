package device

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

func TestEndpointURLsForInterfacesAdvertisesBothUnderlayFamilies(t *testing.T) {
	interfaces := []interfaceAddresses{
		{name: "eth0", flags: net.FlagUp, addrs: []net.Addr{
			&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("2001:db8::10"), Mask: net.CIDRMask(64, 128)},
		}},
		{name: "eg0", flags: net.FlagUp, addrs: []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.0.0.1"), Mask: net.CIDRMask(24, 32)},
		}},
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []net.Addr{
			&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		}},
	}
	got := endpointURLsForInterfaces(interfaces, "eg0", 3001, conn.EnabledAf46)
	want := []string{"192.0.2.10:3001", "[2001:db8::10]:3001"}
	if len(got) != len(want) {
		t.Fatalf("advertised endpoints = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("advertised endpoints = %v, want %v", got, want)
		}
	}
}

func TestEndpointURLsForInterfacesSkipsSharedAddressSpace(t *testing.T) {
	interfaces := []interfaceAddresses{
		{name: "ppp0", flags: net.FlagUp, addrs: []net.Addr{
			&net.IPNet{IP: net.ParseIP("100.64.75.132"), Mask: net.CIDRMask(32, 32)},
			&net.IPNet{IP: net.ParseIP("10.38.5.1"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("240e:34c:506:18d4::1"), Mask: net.CIDRMask(64, 128)},
		}},
	}
	got := endpointURLsForInterfaces(interfaces, "ngsdn", 16386, conn.EnabledAf46)
	want := map[string]struct{}{"10.38.5.1:16386": {}, "[240e:34c:506:18d4::1]:16386": {}}
	if len(got) != len(want) {
		t.Fatalf("advertised endpoints = %v, want %v", got, want)
	}
	for _, endpoint := range got {
		if _, ok := want[endpoint]; !ok {
			t.Fatalf("advertised endpoints = %v, want %v", got, want)
		}
	}
}

func TestSharedAddressSpaceIPBounds(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"100.64.0.0", true},
		{"100.64.75.132", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"10.38.5.1", false},
		{"240e:34c:506:18d4::1", false},
	}
	for _, tc := range cases {
		if got := sharedAddressSpaceIP(net.ParseIP(tc.ip)); got != tc.want {
			t.Fatalf("sharedAddressSpaceIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestActiveListenPortUsesPortSelectedByBind(t *testing.T) {
	device := &Device{}
	device.net.port = 43210
	if got := device.activeListenPort(); got != 43210 {
		t.Fatalf("active listen port = %d, want 43210", got)
	}
}

func v4net(ip string) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(24, 32)}
}

func v6net(ip string) *net.IPNet {
	return &net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(64, 128)}
}

func sourceStrings(sources []stunSource) []string {
	out := make([]string, 0, len(sources))
	for _, source := range sources {
		out = append(out, source.String())
	}
	return out
}

func TestSTUNSourcesForInterfacesOnePerInterfaceAndFamily(t *testing.T) {
	// Given two uplinks, one carrying several v6 (temporary) addresses
	running := net.FlagUp | net.FlagRunning
	interfaces := []interfaceAddresses{
		{name: "wan2", index: 4, flags: running, addrs: []net.Addr{v4net("198.51.100.2")}},
		{name: "wan1", index: 3, flags: running, addrs: []net.Addr{
			v4net("192.0.2.2"), v4net("192.0.2.3"),
			v6net("2001:db8:1::10"), v6net("2001:db8:1::abcd"),
		}},
	}

	// When
	got := sourceStrings(stunSourcesForInterfaces(interfaces, "eg0", conn.EnabledAf46, netip.Addr{}, netip.Addr{}, 8))

	// Then
	want := []string{"wan1/192.0.2.2#3", "wan1/2001:db8:1::10#3", "wan2/198.51.100.2#4"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("sources = %v, want %v", got, want)
	}
}

func TestSTUNSourcesForInterfacesSkipsTapLoopbackDownAndNotRunning(t *testing.T) {
	running := net.FlagUp | net.FlagRunning
	interfaces := []interfaceAddresses{
		{name: "eg0", index: 2, flags: running, addrs: []net.Addr{v4net("10.0.0.1")}},
		{name: "lo", index: 1, flags: running | net.FlagLoopback, addrs: []net.Addr{v4net("127.0.0.1")}},
		{name: "down", index: 5, flags: 0, addrs: []net.Addr{v4net("192.0.2.5")}},
		{name: "nocarrier", index: 6, flags: net.FlagUp, addrs: []net.Addr{v4net("192.0.2.6")}},
		{name: "cgnat", index: 7, flags: running, addrs: []net.Addr{v4net("100.64.1.1")}},
		{name: "wan", index: 8, flags: running, addrs: []net.Addr{v4net("192.0.2.8")}},
	}
	got := sourceStrings(stunSourcesForInterfaces(interfaces, "eg0", conn.EnabledAf46, netip.Addr{}, netip.Addr{}, 8))
	if len(got) != 1 || got[0] != "wan/192.0.2.8#8" {
		t.Fatalf("sources = %v, want only wan", got)
	}
}

func TestSTUNSourcesForInterfacesHonorsListenAddressAndFamily(t *testing.T) {
	running := net.FlagUp | net.FlagRunning
	interfaces := []interfaceAddresses{
		{name: "wan1", index: 3, flags: running, addrs: []net.Addr{v4net("192.0.2.2"), v6net("2001:db8:1::10")}},
		{name: "wan2", index: 4, flags: running, addrs: []net.Addr{v4net("198.51.100.2"), v6net("2001:db8:2::10")}},
	}
	got := sourceStrings(stunSourcesForInterfaces(interfaces, "eg0", conn.EnabledAf46, netip.MustParseAddr("198.51.100.2"), netip.Addr{}, 8))
	want := "wan1/2001:db8:1::10#3,wan2/198.51.100.2#4,wan2/2001:db8:2::10#4"
	if strings.Join(got, ",") != want {
		t.Fatalf("listen-restricted sources = %v, want %s", got, want)
	}
	got = sourceStrings(stunSourcesForInterfaces(interfaces, "eg0", conn.EnabledAf4, netip.Addr{}, netip.Addr{}, 8))
	if strings.Join(got, ",") != "wan1/192.0.2.2#3,wan2/198.51.100.2#4" {
		t.Fatalf("IPv4-only sources = %v", got)
	}
}

func TestSTUNSourcesForInterfacesCapsAndOrdersByIfindex(t *testing.T) {
	running := net.FlagUp | net.FlagRunning
	var interfaces []interfaceAddresses
	for i := 20; i > 10; i-- {
		interfaces = append(interfaces, interfaceAddresses{name: "wan", index: i, flags: running, addrs: []net.Addr{v4net(net.IPv4(192, 0, 2, byte(i)).String())}})
	}
	got := stunSourcesForInterfaces(interfaces, "eg0", conn.EnabledAf46, netip.Addr{}, netip.Addr{}, 3)
	if len(got) != 3 || got[0].ifindex != 11 || got[1].ifindex != 12 || got[2].ifindex != 13 {
		t.Fatalf("sources = %v, want ifindex 11,12,13", sourceStrings(got))
	}
}
