package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type superEventProgress struct {
	enabled bool

	registerFanInWaitSince int64
	lastRegisterFanInAt    int64
	lastRegisterFanInWait  int64
	lastRegisterDepth      int64

	pongFanInWaitSince int64
	lastPongFanInAt    int64
	lastPongFanInWait  int64
	lastPongDepth      int64

	loopWaitSince       int64
	lastLoopRegisterAt  int64
	lastLoopPongAt      int64
	lastLoopRegisterLen int64
	lastLoopPongLen     int64

	timeoutSleepSince int64
	lastTimeoutTickAt int64

	pushSettingsSleepSince int64
	lastPushSettingsAt     int64

	mu               sync.Mutex
	lastFanOutAt     int64
	lastFanOutAction string
}

func newSuperEventProgress(enabled bool) *superEventProgress {
	return &superEventProgress{enabled: enabled}
}

func (p *superEventProgress) trace(kind string, phase string, depth int, _ int, wait time.Duration) {
	if p == nil || !p.enabled {
		return
	}
	now := time.Now()
	switch kind + ":" + phase {
	case "register:fan-in-begin":
		atomic.StoreInt64(&p.registerFanInWaitSince, now.UnixNano())
		atomic.StoreInt64(&p.lastRegisterDepth, int64(depth))
	case "register:fan-in-end":
		atomic.StoreInt64(&p.registerFanInWaitSince, 0)
		atomic.StoreInt64(&p.lastRegisterFanInAt, now.UnixNano())
		atomic.StoreInt64(&p.lastRegisterFanInWait, wait.Nanoseconds())
		atomic.StoreInt64(&p.lastRegisterDepth, int64(depth))
	case "pong:fan-in-begin":
		atomic.StoreInt64(&p.pongFanInWaitSince, now.UnixNano())
		atomic.StoreInt64(&p.lastPongDepth, int64(depth))
	case "pong:fan-in-end":
		atomic.StoreInt64(&p.pongFanInWaitSince, 0)
		atomic.StoreInt64(&p.lastPongFanInAt, now.UnixNano())
		atomic.StoreInt64(&p.lastPongFanInWait, wait.Nanoseconds())
		atomic.StoreInt64(&p.lastPongDepth, int64(depth))
	}
}

func (p *superEventProgress) loopWaitStart() {
	if p == nil || !p.enabled {
		return
	}
	atomic.StoreInt64(&p.loopWaitSince, time.Now().UnixNano())
}

func (p *superEventProgress) loopReceived(kind string, depth int) {
	if p == nil || !p.enabled {
		return
	}
	now := time.Now().UnixNano()
	atomic.StoreInt64(&p.loopWaitSince, 0)
	switch kind {
	case "register":
		atomic.StoreInt64(&p.lastLoopRegisterAt, now)
		atomic.StoreInt64(&p.lastLoopRegisterLen, int64(depth))
	case "pong":
		atomic.StoreInt64(&p.lastLoopPongAt, now)
		atomic.StoreInt64(&p.lastLoopPongLen, int64(depth))
	}
}

func (p *superEventProgress) recordFanOut(action string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.lastFanOutAt = time.Now().UnixNano()
	p.lastFanOutAction = action
}

func (p *superEventProgress) timeoutSleepStart() {
	if p == nil || !p.enabled {
		return
	}
	atomic.StoreInt64(&p.timeoutSleepSince, time.Now().UnixNano())
}

func (p *superEventProgress) timeoutTick() {
	if p == nil || !p.enabled {
		return
	}
	now := time.Now().UnixNano()
	atomic.StoreInt64(&p.timeoutSleepSince, 0)
	atomic.StoreInt64(&p.lastTimeoutTickAt, now)
}

func (p *superEventProgress) pushSettingsSleepStart() {
	if p == nil || !p.enabled {
		return
	}
	atomic.StoreInt64(&p.pushSettingsSleepSince, time.Now().UnixNano())
}

func (p *superEventProgress) pushSettingsTick() {
	if p == nil || !p.enabled {
		return
	}
	now := time.Now().UnixNano()
	atomic.StoreInt64(&p.pushSettingsSleepSince, 0)
	atomic.StoreInt64(&p.lastPushSettingsAt, now)
}

func formatSuperTimeField(now time.Time, label string, unixNano int64) string {
	if unixNano == 0 {
		return label + "=never"
	}
	stamp := time.Unix(0, unixNano).UTC()
	return fmt.Sprintf("%s=%s ago=%s", label, stamp.Format(time.RFC3339Nano), now.Sub(stamp).Round(time.Millisecond))
}

func formatSuperWaitField(now time.Time, label string, unixNano int64) string {
	if unixNano == 0 {
		return label + "=idle"
	}
	stamp := time.Unix(0, unixNano).UTC()
	return fmt.Sprintf("%s=%s blocked_for=%s", label, stamp.Format(time.RFC3339Nano), now.Sub(stamp).Round(time.Millisecond))
}

func (p *superEventProgress) snapshotLines(eventsCapRegister int, eventsLenRegister int, eventsCapPong int, eventsLenPong int) []string {
	if p == nil || !p.enabled {
		return nil
	}
	now := time.Now().UTC()
	p.mu.Lock()
	lastFanOutAt := p.lastFanOutAt
	lastFanOutAction := p.lastFanOutAction
	p.mu.Unlock()
	return []string{
		fmt.Sprintf("register_queue depth=%d cap=%d", eventsLenRegister, eventsCapRegister),
		formatSuperWaitField(now, "register_fan_in_wait_since", atomic.LoadInt64(&p.registerFanInWaitSince)),
		formatSuperTimeField(now, "last_register_fan_in", atomic.LoadInt64(&p.lastRegisterFanInAt)) + fmt.Sprintf(" last_wait=%s last_depth=%d", time.Duration(atomic.LoadInt64(&p.lastRegisterFanInWait)).Round(time.Microsecond), atomic.LoadInt64(&p.lastRegisterDepth)),
		fmt.Sprintf("pong_queue depth=%d cap=%d", eventsLenPong, eventsCapPong),
		formatSuperWaitField(now, "pong_fan_in_wait_since", atomic.LoadInt64(&p.pongFanInWaitSince)),
		formatSuperTimeField(now, "last_pong_fan_in", atomic.LoadInt64(&p.lastPongFanInAt)) + fmt.Sprintf(" last_wait=%s last_depth=%d", time.Duration(atomic.LoadInt64(&p.lastPongFanInWait)).Round(time.Microsecond), atomic.LoadInt64(&p.lastPongDepth)),
		formatSuperWaitField(now, "event_loop_wait_since", atomic.LoadInt64(&p.loopWaitSince)),
		formatSuperTimeField(now, "last_register_dispatch", atomic.LoadInt64(&p.lastLoopRegisterAt)) + fmt.Sprintf(" queue_depth_after=%d", atomic.LoadInt64(&p.lastLoopRegisterLen)),
		formatSuperTimeField(now, "last_pong_dispatch", atomic.LoadInt64(&p.lastLoopPongAt)) + fmt.Sprintf(" queue_depth_after=%d", atomic.LoadInt64(&p.lastLoopPongLen)),
		formatSuperTimeField(now, "last_super_fan_out", lastFanOutAt) + fmt.Sprintf(" action=%s", lastFanOutAction),
		formatSuperWaitField(now, "timeout_check_sleep_since", atomic.LoadInt64(&p.timeoutSleepSince)),
		formatSuperTimeField(now, "last_timeout_check_tick", atomic.LoadInt64(&p.lastTimeoutTickAt)),
		formatSuperWaitField(now, "push_settings_sleep_since", atomic.LoadInt64(&p.pushSettingsSleepSince)),
		formatSuperTimeField(now, "last_push_settings_tick", atomic.LoadInt64(&p.lastPushSettingsAt)),
	}
}
