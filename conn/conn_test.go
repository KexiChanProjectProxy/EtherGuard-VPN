package conn_test

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"golang.org/x/sys/unix"
)

type lookupIPTestConn struct {
	remote net.Addr
}

func (c *lookupIPTestConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (c *lookupIPTestConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *lookupIPTestConn) Close() error                     { return nil }
func (c *lookupIPTestConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *lookupIPTestConn) RemoteAddr() net.Addr             { return c.remote }
func (c *lookupIPTestConn) SetDeadline(time.Time) error      { return nil }
func (c *lookupIPTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *lookupIPTestConn) SetWriteDeadline(time.Time) error { return nil }

func mustLookupIPTestAddr(t *testing.T, network, address string) net.Addr {
	t.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q, %q): %v", network, address, err)
	}
	return addr
}

func newIPv6NoRouteError(addr string) error {
	return &net.OpError{
		Op:   "sendto",
		Net:  "udp6",
		Addr: &net.UDPAddr{IP: net.ParseIP(addr)},
		Err:  syscall.ENETUNREACH,
	}
}

func TestLookupIPClassifiesTransientIPv6Errors(t *testing.T) {
	v4URL := "127.0.0.2:10000"
	v6URL := "[2001:db8::2]:10001"
	restore := conn.SetLookupIPDialForTest(func(network, address string) (net.Conn, error) {
		switch address {
		case v6URL:
			switch network {
			case "udp6", "udp":
				return nil, newIPv6NoRouteError("2001:db8::2")
			default:
				return nil, &net.AddrError{Err: "no suitable address found", Addr: address}
			}
		case v4URL:
			switch network {
			case "udp4", "udp":
				return &lookupIPTestConn{remote: mustLookupIPTestAddr(t, network, address)}, nil
			default:
				return nil, &net.AddrError{Err: "no suitable address found", Addr: address}
			}
		case "bad-endpoint":
			return nil, &net.AddrError{Err: "missing port in address", Addr: address}
		default:
			return nil, &net.AddrError{Err: "unexpected address", Addr: address}
		}
	})
	defer restore()

	_, _, err := conn.LookupIP(v6URL, conn.EnabledAf46, 6)
	if err == nil {
		t.Fatal("LookupIP() error = nil, want transient IPv6 route error")
	}
	if !conn.IsTransientEndpointError(err) {
		t.Fatalf("LookupIP() error = %v, want transient classification", err)
	}
	if !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("LookupIP() error = %v, want ENETUNREACH", err)
	}

	network, endpoint, err := conn.LookupIP(v4URL, conn.EnabledAf46, 6)
	if err != nil {
		t.Fatalf("LookupIP(v4) error = %v", err)
	}
	if network != "udp4" {
		t.Fatalf("LookupIP(v4) network = %q, want udp4", network)
	}
	if endpoint != v4URL {
		t.Fatalf("LookupIP(v4) endpoint = %q, want %q", endpoint, v4URL)
	}

	_, _, err = conn.LookupIP("bad-endpoint", conn.EnabledAf46, 0)
	if err == nil {
		t.Fatal("LookupIP(bad-endpoint) error = nil, want fatal parse error")
	}
	if conn.IsTransientEndpointError(err) {
		t.Fatalf("LookupIP(bad-endpoint) error = %v, want fatal classification", err)
	}
}
