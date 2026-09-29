package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

const netlinkRouteLookupTimeout = 500 * time.Millisecond

// netlinkRouteChecker answers routeChecker queries with RTM_GETROUTE, the same
// lookup "ip route get" performs.
//
// IPv4 with an explicit output interface never fails a lookup: when no route
// matches, the kernel assumes the destination is on link and sends there
// anyway (for a WireGuard tunnel that ends in ENOKEY). With
// RTM_F_LOOKUP_TABLE the reply's RTA_TABLE carries the table the route came
// from, and 0 (RT_TABLE_UNSPEC) marks that fallback. IPv6 has no fallback and
// fails with ENETUNREACH instead.
type netlinkRouteChecker struct {
	fwmark  func() uint32
	timeout time.Duration
	seq     atomic.Uint32
}

// platformRouteChecker asks the kernel only for binds that send through real
// kernel sockets; fake binds in tests keep every leg.
func (device *Device) platformRouteChecker(bind conn.Bind) routeChecker {
	switch bind.(type) {
	case *conn.LinuxSocketBind, *conn.StdNetBind:
		return &netlinkRouteChecker{fwmark: device.currentFwmark, timeout: netlinkRouteLookupTimeout}
	}
	return nil
}

func (c *netlinkRouteChecker) routable(dst, src netip.Addr, ifindex int) error {
	var fwmark uint32
	if c.fwmark != nil {
		fwmark = c.fwmark()
	}
	seq := c.seq.Add(1)
	request, err := buildRouteRequest(seq, dst, src, ifindex, fwmark)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}
	timeout := unix.NsecToTimeval(c.timeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		return fmt.Errorf("netlink timeout: %w", err)
	}
	if err := unix.Sendto(fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 1<<14)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("netlink receive: %w", err)
		}
		reply, found, err := parseRouteReply(buf[:n], seq)
		if err != nil {
			return err
		}
		if found {
			return classifyRouteReply(reply)
		}
	}
}

// buildRouteRequest serialises an RTM_GETROUTE request for dst, optionally
// from src, out of ifindex, with fwmark.
func buildRouteRequest(seq uint32, dst, src netip.Addr, ifindex int, fwmark uint32) ([]byte, error) {
	if !dst.IsValid() {
		return nil, errors.New("route lookup: invalid destination")
	}
	dst = dst.Unmap()
	family, bits := uint8(unix.AF_INET), uint8(32)
	if dst.Is6() {
		family, bits = unix.AF_INET6, 128
	}
	withSrc := src.IsValid() && !src.IsUnspecified()
	if withSrc {
		src = src.Unmap()
		if src.Is4() != dst.Is4() {
			return nil, errors.New("route lookup: source and destination families differ")
		}
	}
	buf := make([]byte, unix.SizeofNlMsghdr+unix.SizeofRtMsg, 64)
	rt := unix.RtMsg{Family: family, Dst_len: bits, Flags: unix.RTM_F_LOOKUP_TABLE}
	if withSrc {
		rt.Src_len = bits
	}
	copy(buf[unix.SizeofNlMsghdr:], unsafe.Slice((*byte)(unsafe.Pointer(&rt)), unix.SizeofRtMsg))
	appendAttr := func(kind uint16, value []byte) {
		var header [unix.SizeofRtAttr]byte
		binary.NativeEndian.PutUint16(header[0:2], uint16(unix.SizeofRtAttr+len(value)))
		binary.NativeEndian.PutUint16(header[2:4], kind)
		buf = append(buf, header[:]...)
		buf = append(buf, value...)
	}
	appendAttr(unix.RTA_DST, dst.AsSlice())
	if withSrc {
		appendAttr(unix.RTA_SRC, src.AsSlice())
	}
	if ifindex > 0 {
		appendAttr(unix.RTA_OIF, binary.NativeEndian.AppendUint32(nil, uint32(ifindex)))
	}
	if fwmark != 0 {
		appendAttr(unix.RTA_MARK, binary.NativeEndian.AppendUint32(nil, fwmark))
	}
	header := unix.NlMsghdr{
		Len:   uint32(len(buf)),
		Type:  unix.RTM_GETROUTE,
		Flags: unix.NLM_F_REQUEST,
		Seq:   seq,
	}
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(&header)), unix.SizeofNlMsghdr))
	return buf, nil
}

// routeReply is the part of an RTM_GETROUTE answer the checker needs.
type routeReply struct {
	errno    unix.Errno
	hasErrno bool
	family   uint8
	rtmType  uint8
	table    uint32
	oif      int
}

// parseRouteReply looks for the answer to seq in buf. found is false when buf
// only holds other messages.
func parseRouteReply(buf []byte, seq uint32) (reply routeReply, found bool, err error) {
	messages, err := syscall.ParseNetlinkMessage(buf)
	if err != nil {
		return reply, false, fmt.Errorf("netlink parse: %w", err)
	}
	for i := range messages {
		message := &messages[i]
		if message.Header.Seq != seq {
			continue
		}
		switch message.Header.Type {
		case unix.NLMSG_ERROR:
			if len(message.Data) < 4 {
				return reply, true, errors.New("netlink: short error message")
			}
			code := int32(binary.NativeEndian.Uint32(message.Data[:4]))
			if code == 0 {
				return reply, true, errors.New("netlink: unexpected acknowledgement")
			}
			if code > 0 {
				code = -code
			}
			reply.errno, reply.hasErrno = unix.Errno(-code), true
			return reply, true, nil
		case unix.RTM_NEWROUTE:
			if len(message.Data) < unix.SizeofRtMsg {
				return reply, true, errors.New("netlink: short route message")
			}
			rt := (*unix.RtMsg)(unsafe.Pointer(&message.Data[0]))
			reply.family, reply.rtmType, reply.table = rt.Family, rt.Type, uint32(rt.Table)
			attrs, err := syscall.ParseNetlinkRouteAttr(message)
			if err != nil {
				return reply, true, fmt.Errorf("netlink route attributes: %w", err)
			}
			for _, attr := range attrs {
				switch attr.Attr.Type {
				case unix.RTA_TABLE:
					if len(attr.Value) >= 4 {
						reply.table = binary.NativeEndian.Uint32(attr.Value[:4])
					}
				case unix.RTA_OIF:
					if len(attr.Value) >= 4 {
						reply.oif = int(binary.NativeEndian.Uint32(attr.Value[:4]))
					}
				}
			}
			return reply, true, nil
		default:
			return reply, true, fmt.Errorf("netlink: unexpected message type %d", message.Header.Type)
		}
	}
	return reply, false, nil
}

// classifyRouteReply returns nil when the kernel found a real route, else a
// noRouteError.
func classifyRouteReply(reply routeReply) error {
	if reply.hasErrno {
		return &noRouteError{reason: reply.errno.Error()}
	}
	if reply.rtmType != unix.RTN_UNICAST && reply.rtmType != unix.RTN_LOCAL {
		return &noRouteError{reason: fmt.Sprintf("route type %d", reply.rtmType)}
	}
	if reply.family == unix.AF_INET && reply.table == unix.RT_TABLE_UNSPEC {
		return &noRouteError{reason: "no route through the interface (on-link fallback)"}
	}
	return nil
}
