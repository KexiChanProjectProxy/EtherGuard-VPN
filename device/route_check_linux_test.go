package device

import (
	"bufio"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func netlinkMessage(seq uint32, kind uint16, body []byte) []byte {
	header := unix.NlMsghdr{Len: uint32(unix.SizeofNlMsghdr + len(body)), Type: kind, Seq: seq}
	out := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&header)), unix.SizeofNlMsghdr)...)
	out = append(out, body...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func routeMessage(seq uint32, family, rtmType uint8, table uint32, withTableAttr bool) []byte {
	rt := unix.RtMsg{Family: family, Type: rtmType, Table: uint8(table)}
	body := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(&rt)), unix.SizeofRtMsg)...)
	attr := func(kind uint16, value uint32) {
		var buf [8]byte
		binary.NativeEndian.PutUint16(buf[0:2], 8)
		binary.NativeEndian.PutUint16(buf[2:4], kind)
		binary.NativeEndian.PutUint32(buf[4:8], value)
		body = append(body, buf[:]...)
	}
	if withTableAttr {
		attr(unix.RTA_TABLE, table)
	}
	attr(unix.RTA_OIF, 7)
	return netlinkMessage(seq, unix.RTM_NEWROUTE, body)
}

func errorMessage(seq uint32, code int32) []byte {
	body := make([]byte, unix.SizeofNlMsgerr)
	binary.NativeEndian.PutUint32(body[0:4], uint32(code))
	return netlinkMessage(seq, unix.NLMSG_ERROR, body)
}

func TestClassifyRouteReplies(t *testing.T) {
	cases := []struct {
		name    string
		msg     []byte
		noRoute string // "" means routable
	}{
		{"ipv4 main table", routeMessage(1, unix.AF_INET, unix.RTN_UNICAST, 254, true), ""},
		{"ipv4 policy table", routeMessage(1, unix.AF_INET, unix.RTN_UNICAST, 1000, true), ""},
		{"ipv4 on-link fallback", routeMessage(1, unix.AF_INET, unix.RTN_UNICAST, 0, true), "on-link fallback"},
		{"ipv4 local", routeMessage(1, unix.AF_INET, unix.RTN_LOCAL, 255, true), ""},
		{"ipv4 blackhole", routeMessage(1, unix.AF_INET, unix.RTN_BLACKHOLE, 254, true), "route type"},
		{"ipv4 table only in header", routeMessage(1, unix.AF_INET, unix.RTN_UNICAST, 254, false), ""},
		{"ipv6 route", routeMessage(1, unix.AF_INET6, unix.RTN_UNICAST, 0, true), ""},
		{"network unreachable", errorMessage(1, -int32(unix.ENETUNREACH)), "network is unreachable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reply, found, err := parseRouteReply(tc.msg, 1)
			if err != nil || !found {
				t.Fatalf("parse: found=%v err=%v", found, err)
			}
			err = classifyRouteReply(reply)
			var noRoute *noRouteError
			if tc.noRoute == "" {
				if err != nil {
					t.Fatalf("want routable, got %v", err)
				}
				return
			}
			if !errors.As(err, &noRoute) || !strings.Contains(noRoute.reason, tc.noRoute) {
				t.Fatalf("want no route %q, got %v", tc.noRoute, err)
			}
		})
	}
}

func TestParseRouteReplyAckIsAnError(t *testing.T) {
	if _, found, err := parseRouteReply(errorMessage(3, 0), 3); !found || err == nil {
		t.Fatalf("ack: found=%v err=%v, want an error", found, err)
	}
}

func TestParseRouteReplySkipsOtherSequences(t *testing.T) {
	buf := append(routeMessage(8, unix.AF_INET, unix.RTN_UNICAST, 0, true), routeMessage(9, unix.AF_INET, unix.RTN_UNICAST, 254, true)...)
	reply, found, err := parseRouteReply(buf, 9)
	if err != nil || !found || reply.table != 254 || reply.oif != 7 {
		t.Fatalf("reply=%+v found=%v err=%v", reply, found, err)
	}
	if _, found, _ := parseRouteReply(buf[:len(buf)/2], 9); found {
		t.Fatal("found seq 9 in a buffer that only holds seq 8")
	}
}

func TestBuildRouteRequestLayout(t *testing.T) {
	request, err := buildRouteRequest(5, netip.MustParseAddr("203.0.113.20"), netip.MustParseAddr("192.0.2.2"), 3, 0x51)
	if err != nil {
		t.Fatal(err)
	}
	header := (*unix.NlMsghdr)(unsafe.Pointer(&request[0]))
	if int(header.Len) != len(request) || header.Type != unix.RTM_GETROUTE || header.Seq != 5 || header.Flags != unix.NLM_F_REQUEST {
		t.Fatalf("header = %+v, len %d", *header, len(request))
	}
	rt := (*unix.RtMsg)(unsafe.Pointer(&request[unix.SizeofNlMsghdr]))
	if rt.Family != unix.AF_INET || rt.Dst_len != 32 || rt.Src_len != 32 || rt.Flags != unix.RTM_F_LOOKUP_TABLE {
		t.Fatalf("rtmsg = %+v", *rt)
	}
	var kinds []uint16
	for attrs := request[unix.SizeofNlMsghdr+unix.SizeofRtMsg:]; len(attrs) >= 4; {
		length := binary.NativeEndian.Uint16(attrs[0:2])
		kinds = append(kinds, binary.NativeEndian.Uint16(attrs[2:4]))
		if length != 8 {
			t.Fatalf("attribute length = %d, want 8", length)
		}
		attrs = attrs[length:]
	}
	want := []uint16{unix.RTA_DST, unix.RTA_SRC, unix.RTA_OIF, unix.RTA_MARK}
	if len(kinds) != len(want) {
		t.Fatalf("attributes = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("attributes = %v, want %v", kinds, want)
		}
	}

	request, err = buildRouteRequest(6, netip.MustParseAddr("2001:db8::20"), netip.Addr{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	rt = (*unix.RtMsg)(unsafe.Pointer(&request[unix.SizeofNlMsghdr]))
	if rt.Family != unix.AF_INET6 || rt.Dst_len != 128 || rt.Src_len != 0 || len(request) != unix.SizeofNlMsghdr+unix.SizeofRtMsg+20 {
		t.Fatalf("v6 request rtmsg=%+v len=%d", *rt, len(request))
	}
	if _, err := buildRouteRequest(7, netip.MustParseAddr("2001:db8::20"), netip.MustParseAddr("192.0.2.2"), 3, 0); err == nil {
		t.Fatal("mixed families must be rejected")
	}
}

// --- against the running kernel; RTM_GETROUTE needs no privileges ---

func kernelRouteChecker() *netlinkRouteChecker {
	return &netlinkRouteChecker{timeout: 2 * time.Second}
}

func TestNetlinkRouteCheckerLoopbackIsRoutable(t *testing.T) {
	check := kernelRouteChecker()
	if err := check.routable(netip.MustParseAddr("127.0.0.1"), netip.Addr{}, 1); err != nil {
		t.Fatalf("127.0.0.1 via lo: %v", err)
	}
	if err := check.routable(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), 1); err != nil {
		t.Fatalf("127.0.0.1 from 127.0.0.1 via lo: %v", err)
	}
}

func TestNetlinkRouteCheckerDetectsOnLinkFallback(t *testing.T) {
	// TEST-NET-3 is never routed through lo, so forcing lo only "works"
	// through the kernel's assume-on-link fallback.
	check := kernelRouteChecker()
	err := check.routable(netip.MustParseAddr("203.0.113.1"), netip.Addr{}, 1)
	var noRoute *noRouteError
	if !errors.As(err, &noRoute) {
		t.Fatalf("203.0.113.1 via lo: got %v, want the on-link fallback", err)
	}
	if !strings.Contains(noRoute.reason, "on-link") {
		t.Fatalf("reason = %q", noRoute.reason)
	}
}

func hostHasIPv6DefaultRoute(t *testing.T) (has bool, known bool) {
	file, err := os.Open("/proc/net/ipv6_route")
	if err != nil {
		return false, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 10 && fields[0] == strings.Repeat("0", 32) && fields[1] == "00" && fields[9] != "lo" {
			// ignore the kernel's unreachable default entries on lo
			return true, true
		}
	}
	return false, true
}

func TestNetlinkRouteCheckerIPv6(t *testing.T) {
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		t.Skip("IPv6 disabled")
	}
	check := kernelRouteChecker()
	if err := check.routable(netip.MustParseAddr("::1"), netip.Addr{}, 1); err != nil {
		t.Fatalf("::1 via lo: %v", err)
	}
	has, known := hostHasIPv6DefaultRoute(t)
	if !known {
		t.Skip("cannot read the IPv6 routing table")
	}
	err := check.routable(netip.MustParseAddr("2001:db8::1"), netip.Addr{}, 0)
	var noRoute *noRouteError
	if has {
		if err != nil {
			t.Fatalf("host has an IPv6 default route, lookup said %v", err)
		}
		return
	}
	if !errors.As(err, &noRoute) {
		t.Fatalf("no IPv6 default route, want no route, got %v", err)
	}
}
