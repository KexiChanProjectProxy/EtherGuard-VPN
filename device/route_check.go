package device

import (
	"errors"
	"net/netip"
	"strconv"
	"sync"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

// noRouteError is a definitive kernel answer that a leg has no usable route.
// Any other error from routeChecker.routable means the lookup itself failed.
type noRouteError struct {
	reason string
}

func (e *noRouteError) Error() string {
	return "no route: " + e.reason
}

// routeChecker asks the kernel whether a datagram from src out of ifindex can
// reach dst over a real route. An invalid src and ifindex 0 ask about the
// kernel's own choice, which is what an unpinned send uses.
type routeChecker interface {
	routable(dst, src netip.Addr, ifindex int) error
}

type routeKey struct {
	dst     netip.Addr
	src     netip.Addr
	ifindex int
}

// routeMemo caches route answers for one probing round or one STUN discovery,
// so many peers and pairs cost a few lookups. It is safe for concurrent use.
// A nil memo, or one without a checker, treats every leg as routable.
type routeMemo struct {
	mu    sync.Mutex
	check routeChecker
	log   *Logger
	seen  map[routeKey]bool
}

func newRouteMemo(check routeChecker, log *Logger) *routeMemo {
	if check == nil {
		return nil
	}
	return &routeMemo{check: check, log: log, seen: make(map[routeKey]bool)}
}

// routable reports whether the leg from local (nil: the kernel default route)
// to remote may be probed. Only a definitive no-route answer removes a leg;
// lookup failures keep it.
func (m *routeMemo) routable(local *stunSource, remote netip.Addr) bool {
	if m == nil {
		return true
	}
	key := routeKey{dst: remote.Unmap()}
	if local != nil {
		key.src = local.ip.Unmap()
		key.ifindex = local.ifindex
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok, cached := m.seen[key]; cached {
		return ok
	}
	err := m.check.routable(key.dst, key.src, key.ifindex)
	var noRoute *noRouteError
	ok := err == nil || !errors.As(err, &noRoute)
	m.seen[key] = ok
	if m.log != nil && err != nil {
		src, ifindex := "default", "0"
		if local != nil {
			src, ifindex = local.String(), strconv.Itoa(local.ifindex)
		}
		if ok {
			m.log.Verbosef("Route check failed, keeping leg: src=%s ifindex=%s dst=%s error=%v", src, ifindex, key.dst, err)
		} else {
			m.log.Verbosef("Route check skipped leg: src=%s ifindex=%s dst=%s reason=%s", src, ifindex, key.dst, noRoute.reason)
		}
	}
	return ok
}

// routeCheckerFor picks the route checker for a round: the test override, else
// the platform checker for real socket binds. Other binds never ask the kernel.
func (device *Device) routeCheckerFor(bind conn.Bind) routeChecker {
	if device == nil {
		return nil
	}
	if device.routeCheck != nil {
		return device.routeCheck
	}
	return device.platformRouteChecker(bind)
}

func (device *Device) currentFwmark() uint32 {
	device.net.RLock()
	defer device.net.RUnlock()
	return device.net.fwmark
}
