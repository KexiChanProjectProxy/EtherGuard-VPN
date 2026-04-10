package path

import (
	"fmt"
	"sync/atomic"
	"time"
)

type ntpProgressTracker struct {
	enabled AtomicBoolCompat

	routineSleepSince int64
	lastRoutineWakeAt int64

	cycleWaitSince int64
	lastCycleStart int64
	lastCycleDone  int64
	lastCycleCount int64

	inFlight        int64
	lastQueryStart  int64
	lastQueryDone   int64
	lastSuccessAt   int64
	lastFailureAt   int64
	lastQueryRTT    int64
	lastQueryOffset int64
	lastQueryError  int64
}

type AtomicBoolCompat struct{ value int32 }

func (a *AtomicBoolCompat) Get() bool {
	return atomic.LoadInt32(&a.value) != 0
}

func (a *AtomicBoolCompat) Set(v bool) {
	if v {
		atomic.StoreInt32(&a.value, 1)
		return
	}
	atomic.StoreInt32(&a.value, 0)
}

func (g *IG) EnableProgressSnapshots(enabled bool) {
	g.ntpProgress.enabled.Set(enabled)
	if enabled {
		return
	}
	atomic.StoreInt64(&g.ntpProgress.routineSleepSince, 0)
	atomic.StoreInt64(&g.ntpProgress.cycleWaitSince, 0)
	atomic.StoreInt64(&g.ntpProgress.inFlight, 0)
}

func formatNTPTimeField(now time.Time, label string, unixNano int64) string {
	if unixNano == 0 {
		return label + "=never"
	}
	stamp := time.Unix(0, unixNano).UTC()
	return fmt.Sprintf("%s=%s ago=%s", label, stamp.Format(time.RFC3339Nano), now.Sub(stamp).Round(time.Millisecond))
}

func formatNTPWaitField(now time.Time, label string, unixNano int64) string {
	if unixNano == 0 {
		return label + "=idle"
	}
	stamp := time.Unix(0, unixNano).UTC()
	return fmt.Sprintf("%s=%s blocked_for=%s", label, stamp.Format(time.RFC3339Nano), now.Sub(stamp).Round(time.Millisecond))
}

func (g *IG) ProgressSnapshotLines() []string {
	if !g.ntpProgress.enabled.Get() {
		return nil
	}
	now := time.Now().UTC()
	return []string{
		fmt.Sprintf("ntp_enabled=%t server_count=%d offset=%s", g.ntp_info.UseNTP, len(g.ntp_servers.Keys()), g.ntp_offset.Round(time.Microsecond)),
		formatNTPWaitField(now, "ntp_routine_sleep_since", atomic.LoadInt64(&g.ntpProgress.routineSleepSince)),
		formatNTPTimeField(now, "last_ntp_routine_wake", atomic.LoadInt64(&g.ntpProgress.lastRoutineWakeAt)),
		formatNTPWaitField(now, "ntp_cycle_wait_since", atomic.LoadInt64(&g.ntpProgress.cycleWaitSince)),
		formatNTPTimeField(now, "last_ntp_cycle_start", atomic.LoadInt64(&g.ntpProgress.lastCycleStart)) + fmt.Sprintf(" count=%d", atomic.LoadInt64(&g.ntpProgress.lastCycleCount)),
		formatNTPTimeField(now, "last_ntp_cycle_done", atomic.LoadInt64(&g.ntpProgress.lastCycleDone)),
		formatNTPTimeField(now, "last_ntp_query_start", atomic.LoadInt64(&g.ntpProgress.lastQueryStart)) + fmt.Sprintf(" in_flight=%d", atomic.LoadInt64(&g.ntpProgress.inFlight)),
		formatNTPTimeField(now, "last_ntp_query_done", atomic.LoadInt64(&g.ntpProgress.lastQueryDone)) + fmt.Sprintf(" rtt=%s offset=%s", time.Duration(atomic.LoadInt64(&g.ntpProgress.lastQueryRTT)).Round(time.Microsecond), time.Duration(atomic.LoadInt64(&g.ntpProgress.lastQueryOffset)).Round(time.Microsecond)),
		formatNTPTimeField(now, "last_ntp_success", atomic.LoadInt64(&g.ntpProgress.lastSuccessAt)),
		formatNTPTimeField(now, "last_ntp_failure", atomic.LoadInt64(&g.ntpProgress.lastFailureAt)) + fmt.Sprintf(" last_failure_after_init=%s", time.Duration(atomic.LoadInt64(&g.ntpProgress.lastQueryError)).Round(time.Microsecond)),
	}
}
