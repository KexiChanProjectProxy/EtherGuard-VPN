package path

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func newNTPTestGraph(t *testing.T) *IG {
	t.Helper()
	g, err := NewGraph(0, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	return g
}

func TestGetCurrentTimeAppliesNTPOffset(t *testing.T) {
	g := newNTPTestGraph(t)
	g.ntp_offset.Store(int64(250 * time.Millisecond))

	skew := g.GetCurrentTime().Sub(time.Now())

	if skew < 240*time.Millisecond || skew > 260*time.Millisecond {
		t.Fatalf("offset applied = %v, want about 250ms", skew)
	}
	if g.NTPOffset() != 250*time.Millisecond {
		t.Fatalf("NTPOffset = %v", g.NTPOffset())
	}
}

func TestWallTimeStripsMonotonicReading(t *testing.T) {
	g := newNTPTestGraph(t)
	now := time.Now()
	wall := g.WallTime(now)
	if strings.Contains(wall.String(), "m=") {
		t.Fatalf("wall time kept a monotonic reading: %s", wall)
	}
	if !wall.Equal(now) {
		t.Fatalf("wall = %v, want %v with zero offset", wall, now)
	}
}

func TestNTPOffsetConcurrentReadWrite(t *testing.T) {
	g := newNTPTestGraph(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				g.ntp_offset.Store(int64(i * j))
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = g.GetCurrentTime()
			}
		}()
	}
	wg.Wait()
}
