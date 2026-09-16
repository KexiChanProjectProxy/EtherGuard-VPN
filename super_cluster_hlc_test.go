package main

import (
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestHLCMonotonicWithFrozenClock(t *testing.T) {
	// Given a hybrid clock whose wall clock does not advance.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	clock := newHLCClock(func() time.Time { return now }, 0)
	previous := clock.Current()

	// When values are minted repeatedly.
	for range 1000 {
		current := clock.Next()

		// Then every value is strictly newer than the preceding value.
		if current <= previous {
			t.Fatalf("Next() = %d after %d", current, previous)
		}
		previous = current
	}
}

func TestHLCObserveJumpsForward(t *testing.T) {
	// Given a local clock and a remote value 30 seconds ahead.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	clock := newHLCClock(func() time.Time { return now }, 0)
	remote := hlcFromWallMS(uint64(now.UnixMilli())+uint64((30*time.Second)/time.Millisecond)) | 42

	// When the remote value is observed and a local value is minted.
	clock.Observe(remote)
	got := clock.Next()

	// Then the local value follows the observed value.
	if got <= remote {
		t.Fatalf("Next() = %d, want greater than observed %d", got, remote)
	}
}

func TestHLCCounterOverflowRollsWall(t *testing.T) {
	// Given a frozen clock whose logical counter is exhausted.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	clock := newHLCClock(func() time.Time { return now }, 0)
	wallMS := uint64(now.UnixMilli())
	clock.mu.Lock()
	clock.last = hlcFromWallMS(wallMS) | 0xffff
	clock.mu.Unlock()

	// When the next value is minted.
	got := clock.Next()

	// Then the wall component advances by one millisecond and the counter resets.
	want := hlcFromWallMS(wallMS + 1)
	if got != want {
		t.Fatalf("Next() = %d, want %d", got, want)
	}
}

func TestClusterVersionTotalOrder(t *testing.T) {
	// Given versions with equal HLCs, different origins, and the zero value.
	zero := ClusterVersion{}
	lowerOrigin := ClusterVersion{HLC: 42, Origin: mtypes.Vertex(1)}
	higherOrigin := ClusterVersion{HLC: 42, Origin: mtypes.Vertex(2)}
	originOnly := ClusterVersion{Origin: mtypes.Vertex(1)}

	// When the versions are compared, then HLC is primary and larger origin wins ties.
	if !lowerOrigin.Less(higherOrigin) {
		t.Fatal("lower origin must sort before higher origin for equal HLC")
	}
	if higherOrigin.Less(lowerOrigin) {
		t.Fatal("higher origin must not sort before lower origin for equal HLC")
	}
	if !higherOrigin.Newer(lowerOrigin) || lowerOrigin.Newer(higherOrigin) {
		t.Fatal("Newer must be the inverse ordering of Less")
	}
	if lowerOrigin.Less(lowerOrigin) {
		t.Fatal("a version must not be less than itself")
	}
	if !zero.IsZero() || lowerOrigin.IsZero() {
		t.Fatal("IsZero did not identify only the zero value")
	}
	if !zero.Less(originOnly) {
		t.Fatal("zero version must sort before every non-zero version")
	}
}

func TestHLCObserveClampsExcessiveSkew(t *testing.T) {
	// Given a frozen clock, a logging hook, and a remote value 25 hours ahead.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	clock := newHLCClock(func() time.Time { return now }, 0)
	logCalls := 0
	clock.logf = func(string, ...any) { logCalls++ }
	remote := hlcFromWallMS(uint64(now.UnixMilli()) + uint64((25*time.Hour)/time.Millisecond))

	// When the excessive value is observed twice within the same minute.
	clock.Observe(remote)
	clock.Observe(remote)

	// Then the value is clamped to the skew ceiling and the warning is rate-limited.
	ceiling := hlcFromWallMS(uint64(now.UnixMilli()) + uint64(clock.maxSkew/time.Millisecond))
	if got := clock.Current(); got > ceiling {
		t.Fatalf("Current() = %d, want at most %d", got, ceiling)
	}
	if logCalls != 1 {
		t.Fatalf("log calls = %d, want 1", logCalls)
	}
}

func TestHLCHighWaterRestart(t *testing.T) {
	// Given a persisted high-water mark five minutes ahead of the wall clock.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	highWater := hlcFromWallMS(uint64(now.UnixMilli()) + uint64((5*time.Minute)/time.Millisecond))
	clock := newHLCClock(func() time.Time { return now }, highWater)

	// When the restarted clock mints its first value.
	got := clock.Next()

	// Then it advances beyond the persisted high-water mark.
	if got <= highWater {
		t.Fatalf("Next() = %d, want greater than high-water %d", got, highWater)
	}
}

func TestHLCConcurrentNextIsMonotonic(t *testing.T) {
	// Given a frozen clock shared by concurrent callers.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	clock := newHLCClock(func() time.Time { return now }, 0)
	const goroutines = 16
	const callsPerGoroutine = 250
	values := make(chan uint64, goroutines*callsPerGoroutine)

	// When all callers mint values concurrently.
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range callsPerGoroutine {
				values <- clock.Next()
			}
		}()
	}
	wg.Wait()
	close(values)

	// Then every collected value is unique and strictly ordered after sorting.
	ordered := make([]uint64, 0, goroutines*callsPerGoroutine)
	for value := range values {
		ordered = append(ordered, value)
	}
	if len(ordered) != goroutines*callsPerGoroutine {
		t.Fatalf("collected %d values, want %d", len(ordered), goroutines*callsPerGoroutine)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for i := 1; i < len(ordered); i++ {
		if ordered[i] <= ordered[i-1] {
			t.Fatalf("values[%d] = %d after %d", i, ordered[i], ordered[i-1])
		}
	}
}
