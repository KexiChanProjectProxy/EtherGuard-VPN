//go:build linux

package conn

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func loopbackIndex(t *testing.T) int {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Index
		}
	}
	t.Skip("no loopback interface")
	return 0
}

func TestLinuxSocketBindParseEndpointFromPinsIPv4SourceAndIfindex(t *testing.T) {
	// Given
	bind := NewLinuxSocketBind().(*LinuxSocketBind)

	// When
	endpoint, err := bind.ParseEndpointFrom("203.0.113.9:3478", netip.MustParseAddr("192.0.2.10"), 7)

	// Then
	if err != nil {
		t.Fatalf("ParseEndpointFrom: %v", err)
	}
	end := endpoint.(*LinuxSocketEndpoint)
	if got := end.SrcIP().String(); got != "192.0.2.10" {
		t.Fatalf("src = %s, want 192.0.2.10", got)
	}
	if end.Src4().Ifindex != 7 {
		t.Fatalf("ifindex = %d, want 7", end.Src4().Ifindex)
	}
	if got := end.DstToString(); got != "203.0.113.9:3478" {
		t.Fatalf("dst = %s", got)
	}
}

func TestLinuxSocketBindParseEndpointFromPinsIPv6SourceViaZoneID(t *testing.T) {
	// Given
	bind := NewLinuxSocketBind().(*LinuxSocketBind)

	// When
	endpoint, err := bind.ParseEndpointFrom("[2001:db8::9]:3478", netip.MustParseAddr("2001:db8:1::10"), 5)

	// Then
	if err != nil {
		t.Fatalf("ParseEndpointFrom: %v", err)
	}
	end := endpoint.(*LinuxSocketEndpoint)
	if got := end.SrcIP().String(); got != "2001:db8:1::10" {
		t.Fatalf("src = %s", got)
	}
	if end.dst6().ZoneId != 5 {
		t.Fatalf("zone/ifindex = %d, want 5", end.dst6().ZoneId)
	}
}

func TestLinuxSocketBindParseEndpointFromRejectsFamilyMismatch(t *testing.T) {
	bind := NewLinuxSocketBind().(*LinuxSocketBind)
	if _, err := bind.ParseEndpointFrom("203.0.113.9:3478", netip.MustParseAddr("2001:db8::1"), 2); !errors.Is(err, ErrSourceFamilyMismatch) {
		t.Fatalf("v4 dst + v6 src err = %v", err)
	}
	if _, err := bind.ParseEndpointFrom("[2001:db8::9]:3478", netip.MustParseAddr("192.0.2.1"), 2); !errors.Is(err, ErrSourceFamilyMismatch) {
		t.Fatalf("v6 dst + v4 src err = %v", err)
	}
}

func TestLinuxSocketBindParseEndpointFromRejectsInvalidSource(t *testing.T) {
	bind := NewLinuxSocketBind().(*LinuxSocketBind)
	for _, tc := range []struct {
		src     netip.Addr
		ifindex int
	}{
		{netip.Addr{}, 1},
		{netip.MustParseAddr("0.0.0.0"), 1},
		{netip.MustParseAddr("192.0.2.1"), 0},
	} {
		if _, err := bind.ParseEndpointFrom("203.0.113.9:3478", tc.src, tc.ifindex); !errors.Is(err, ErrInvalidSource) {
			t.Fatalf("src=%v ifindex=%d err = %v, want ErrInvalidSource", tc.src, tc.ifindex, err)
		}
	}
}

func TestLinuxSocketBindSendPinnedToLoopbackKeepsSource(t *testing.T) {
	// Given a receiver on loopback and an open bind
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer receiver.Close()
	bind := NewLinuxSocketBindAf(true, false, [4]byte{}, [16]byte{}, 0)
	if _, _, err := bind.Open(0); err != nil {
		t.Fatalf("open: %v", err)
	}
	defer bind.Close()
	endpoint, err := bind.(EndpointSourcePinner).ParseEndpointFrom(receiver.LocalAddr().String(), netip.MustParseAddr("127.0.0.1"), loopbackIndex(t))
	if err != nil {
		t.Fatalf("ParseEndpointFrom: %v", err)
	}

	// When
	if err := bind.Send([]byte("probe"), endpoint); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Then the datagram arrives and the pin survives
	buf := make([]byte, 16)
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := receiver.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "probe" {
		t.Fatalf("read = %q, %v", buf[:n], err)
	}
	if !from.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("source = %v, want 127.0.0.1", from.IP)
	}
	if endpoint.SrcIP().IsUnspecified() {
		t.Fatal("pin was dropped on a valid loopback send")
	}
}

func TestLinuxSocketBindSendIPv6PinRejectedClearsSource(t *testing.T) {
	// Given an IPv6 bind and a pinned source that is not assigned locally
	receiver, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer receiver.Close()
	bind := NewLinuxSocketBindAf(false, true, [4]byte{}, [16]byte{}, 0)
	if _, _, err := bind.Open(0); err != nil {
		t.Skipf("open v6: %v", err)
	}
	defer bind.Close()
	endpoint, err := bind.(EndpointSourcePinner).ParseEndpointFrom(receiver.LocalAddr().String(), netip.MustParseAddr("2001:db8:ffff::1"), loopbackIndex(t))
	if err != nil {
		t.Fatalf("ParseEndpointFrom: %v", err)
	}

	// When
	_ = bind.Send([]byte("probe"), endpoint)

	// Then callers can detect that the kernel refused the pin
	if !endpoint.SrcIP().IsUnspecified() {
		t.Fatalf("src = %v, want unspecified after rejected pin", endpoint.SrcIP())
	}
}
