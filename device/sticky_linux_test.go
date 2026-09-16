package device

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestNetlinkDefaultRouteDetectsDefaultAndSkipsSpecific(t *testing.T) {
	defaultMsg := netlinkRouteMessage(0)
	specificMsg := netlinkRouteMessage(24)
	hdr := unix.NlMsghdr{Len: uint32(len(defaultMsg))}
	if !netlinkDefaultRoute(defaultMsg, hdr) {
		t.Fatal("default route (dst_len=0) was not detected")
	}
	hdr.Len = uint32(len(specificMsg))
	if netlinkDefaultRoute(specificMsg, hdr) {
		t.Fatal("specific route (dst_len=24) was treated as default")
	}
}

func netlinkRouteMessage(dstLen uint8) []byte {
	var msg struct {
		hdr unix.NlMsghdr
		rt  unix.RtMsg
	}
	msg.hdr.Len = uint32(unsafe.Sizeof(msg))
	msg.rt.Family = unix.AF_INET
	msg.rt.Dst_len = dstLen
	buf := make([]byte, unsafe.Sizeof(msg))
	copy(buf, (*[unsafe.Sizeof(msg)]byte)(unsafe.Pointer(&msg))[:])
	return buf
}
