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

func TestActiveListenPortUsesPortSelectedByBind(t *testing.T) {
	device := &Device{}
	device.net.port = 43210
	if got := device.activeListenPort(); got != 43210 {
		t.Fatalf("active listen port = %d, want 43210", got)
	}
}
