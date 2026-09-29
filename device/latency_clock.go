package device

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// sentPingRegistryCap bounds how many recent routing pings are remembered.
const sentPingRegistryCap = 256

// sentPingRegistry maps the wall-clock stamp of a routing ping this node sent
// to the local monotonic instant it was built, so an echoed PingTime yields a
// round trip measured on one clock. Entries are not consumed on lookup: one
// spread ping is answered by every peer. The zero value is ready to use.
type sentPingRegistry struct {
	mu      sync.Mutex
	entries map[int64]time.Time // wall UnixNano -> monotonic send time
	order   []int64
}

// record remembers a ping and drops entries older than ttl (when positive) or
// beyond the cap, oldest first.
func (r *sentPingRegistry) record(wall, mono time.Time, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[int64]time.Time)
	}
	key := wall.UnixNano()
	if _, ok := r.entries[key]; !ok {
		r.order = append(r.order, key)
	}
	r.entries[key] = mono
	for len(r.order) > 0 {
		oldest := r.order[0]
		sentAt, ok := r.entries[oldest]
		if ok && len(r.order) <= sentPingRegistryCap && (ttl <= 0 || mono.Sub(sentAt) <= ttl) {
			break
		}
		delete(r.entries, oldest)
		r.order = r.order[1:]
	}
}

// lookup returns the monotonic send time of the ping stamped wall.
func (r *sentPingRegistry) lookup(wall time.Time) (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	mono, ok := r.entries[wall.UnixNano()]
	return mono, ok
}

func (r *sentPingRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

const (
	// clockSkewWarnThreshold is the estimated skew, in seconds, between this
	// node's and a peer's corrected clocks that is reported as an error.
	clockSkewWarnThreshold = 0.100
	// clockWarnInterval limits clock errors to one per peer per interval.
	clockWarnInterval = 10 * time.Minute
)

// oneWaySample is a peer's filtered raw one-way delta for this node's pings,
// measured on the peer's clock minus this node's clock.
type oneWaySample struct {
	raw float64
	at  time.Time
}

// correctOneWay estimates the inbound one-way latency from raw, the delta of
// the peer's ping measured as this node's clock minus the peer's. With a fresh
// reverse sample the two deltas' clock offsets cancel: the estimate is half
// the round trip and skew is how far this node's clock runs ahead of the
// peer's. Without one it returns raw clamped at zero and corrected is false.
func correctOneWay(raw float64, reverse *oneWaySample, now time.Time, maxAge time.Duration) (oneWay, skew float64, corrected bool) {
	if reverse != nil && !math.IsNaN(reverse.raw) && !math.IsInf(reverse.raw, 0) && (maxAge <= 0 || now.Sub(reverse.at) <= maxAge) {
		return (raw + reverse.raw) / 2, (raw - reverse.raw) / 2, true
	}
	return math.Max(raw, 0), 0, false
}

// reverseSampleMaxAge is how long a peer's reverse sample stays usable: three
// ping rounds, bounded by the peer alive timeout.
func (device *Device) reverseSampleMaxAge() time.Duration {
	route := device.EdgeConfig.DynamicRoute
	interval := mtypes.S2TD(route.SendPingInterval) * 3
	alive := mtypes.S2TD(route.PeerAliveTimeout)
	switch {
	case interval <= 0:
		return alive
	case alive > 0 && alive < interval:
		return alive
	}
	return interval
}

// logThrottle admits one event per interval. The zero value is ready to use.
type logThrottle struct {
	last atomic.Int64
}

func (t *logThrottle) allow(now time.Time, every time.Duration) bool {
	for {
		last := t.last.Load()
		if last != 0 && now.Sub(time.Unix(0, last)) < every {
			return false
		}
		if t.last.CompareAndSwap(last, now.UnixNano()) {
			return true
		}
	}
}

func (device *Device) lookupPeerByID(id mtypes.Vertex) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()
	return device.peers.IDMap[id]
}
