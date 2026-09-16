package main

import (
	"log"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type ClusterVersion struct {
	HLC    uint64        `json:"hlc"`
	Origin mtypes.Vertex `json:"origin"`
}

func (v ClusterVersion) Less(o ClusterVersion) bool {
	if v.HLC != o.HLC {
		return v.HLC < o.HLC
	}
	return v.Origin < o.Origin
}

func (v ClusterVersion) IsZero() bool {
	return v.HLC == 0 && v.Origin == 0
}

func (v ClusterVersion) Newer(o ClusterVersion) bool {
	return o.Less(v)
}

type hlcClock struct {
	mu           sync.Mutex
	last         uint64
	now          func() time.Time
	maxSkew      time.Duration
	lastClampLog time.Time
	logf         func(string, ...any)
}

func newHLCClock(now func() time.Time, highWater uint64) *hlcClock {
	last := hlcFromWallMS(uint64(now().UnixMilli()))
	if highWater > last {
		last = highWater
	}
	return &hlcClock{
		last:    last,
		now:     now,
		maxSkew: time.Hour,
		logf:    log.Printf,
	}
}

func (c *hlcClock) Next() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	wallMS := uint64(c.now().UnixMilli())
	lastWallMS := hlcWallMS(c.last)
	if wallMS > lastWallMS {
		c.last = hlcFromWallMS(wallMS)
		return c.last
	}
	if c.last&0xffff == 0xffff {
		c.last = hlcFromWallMS(lastWallMS + 1)
		return c.last
	}
	c.last++
	return c.last
}

func (c *hlcClock) Observe(remote uint64) {
	c.mu.Lock()
	now := c.now()
	ceiling := hlcFromWallMS(uint64(now.UnixMilli()) + uint64(c.maxSkew/time.Millisecond))
	clamped := remote > ceiling
	observed := remote
	if clamped {
		observed = ceiling
	}
	if observed > c.last {
		c.last = observed
	}
	shouldLog := clamped && (c.lastClampLog.IsZero() || now.Sub(c.lastClampLog) >= time.Minute)
	var logf func(string, ...any)
	if shouldLog {
		c.lastClampLog = now
		logf = c.logf
	}
	c.mu.Unlock()

	if logf != nil {
		logf("cluster HLC remote value %d exceeds skew ceiling %d; clamped", remote, ceiling)
	}
}

func (c *hlcClock) Current() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

func hlcWallMS(h uint64) uint64 {
	return h >> 16
}

func hlcFromWallMS(ms uint64) uint64 {
	return ms << 16
}
