package device

import (
	"sync"
	"time"
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
