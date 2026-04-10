package path

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestNTPProgressSnapshotShowsCycleAndQueryState(t *testing.T) {
	g, err := NewGraph(1, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{UseNTP: true, Servers: []string{"a"}}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("NewGraph(): %v", err)
	}
	g.EnableProgressSnapshots(true)
	now := time.Now().UnixNano()
	atomic.StoreInt64(&g.ntpProgress.lastCycleStart, now)
	atomic.StoreInt64(&g.ntpProgress.cycleWaitSince, now)
	atomic.StoreInt64(&g.ntpProgress.lastQueryStart, now)
	atomic.StoreInt64(&g.ntpProgress.inFlight, 2)
	lines := strings.Join(g.ProgressSnapshotLines(), "\n")
	if !strings.Contains(lines, "ntp_cycle_wait_since=") {
		t.Fatalf("snapshot missing cycle wait: %s", lines)
	}
	if !strings.Contains(lines, "last_ntp_query_start=") || !strings.Contains(lines, "in_flight=2") {
		t.Fatalf("snapshot missing query state: %s", lines)
	}
}
