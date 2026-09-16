package device

import (
	"net"
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
