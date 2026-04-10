package device

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type superEventTraceHook func(kind string, phase string, depth int, capacity int, wait time.Duration)

type deviceProgressTracker struct {
	enabled AtomicBool

	sendProducerWaitSince int64
	lastSendProducerAt    int64
	lastSendProducerWait  int64
	lastSendQueueDepth    int64

	sendWorkerWaitSince int64
	lastSendWorkerAt    int64
	lastSendWorkerWait  int64
	lastSendWorkerDepth int64

	tunReadWaitSince int64
	lastTunReadAt    int64
	lastTunReadWait  int64
	lastTunReadBytes int64

	tapWriteWaitSince int64
	lastTapWriteAt    int64
	lastTapWriteWait  int64
	lastTapWriteBytes int64
	lastTapWriteDepth int64

	tapFlushWaitSince int64
	lastTapFlushAt    int64
	lastTapFlushWait  int64
	lastTapFlushDepth int64

	mu              sync.Mutex
	superEventTrace superEventTraceHook
}

func (p *deviceProgressTracker) configure(enabled bool) {
	p.enabled.Set(enabled)
	if enabled {
		return
	}
	atomic.StoreInt64(&p.sendProducerWaitSince, 0)
	atomic.StoreInt64(&p.sendWorkerWaitSince, 0)
	atomic.StoreInt64(&p.tunReadWaitSince, 0)
	atomic.StoreInt64(&p.tapWriteWaitSince, 0)
	atomic.StoreInt64(&p.tapFlushWaitSince, 0)
	p.mu.Lock()
	p.superEventTrace = nil
	p.mu.Unlock()
}

func (p *deviceProgressTracker) setSuperEventTraceHook(hook superEventTraceHook) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.superEventTrace = hook
}

func (p *deviceProgressTracker) traceSuperEvent(kind string, phase string, depth int, capacity int, wait time.Duration) {
	p.mu.Lock()
	hook := p.superEventTrace
	p.mu.Unlock()
	if hook != nil {
		hook(kind, phase, depth, capacity, wait)
	}
}

func (p *deviceProgressTracker) sendProducerWaitStart(depth int) time.Time {
	if !p.enabled.Get() {
		return time.Time{}
	}
	now := time.Now()
	atomic.StoreInt64(&p.sendProducerWaitSince, now.UnixNano())
	atomic.StoreInt64(&p.lastSendQueueDepth, int64(depth))
	return now
}

func (p *deviceProgressTracker) sendProducerWaitDone(start time.Time, depth int) {
	if start.IsZero() {
		return
	}
	now := time.Now()
	atomic.StoreInt64(&p.sendProducerWaitSince, 0)
	atomic.StoreInt64(&p.lastSendProducerAt, now.UnixNano())
	atomic.StoreInt64(&p.lastSendProducerWait, now.Sub(start).Nanoseconds())
	atomic.StoreInt64(&p.lastSendQueueDepth, int64(depth))
}

func (p *deviceProgressTracker) sendWorkerWaitStart(depth int) time.Time {
	if !p.enabled.Get() {
		return time.Time{}
	}
	now := time.Now()
	atomic.StoreInt64(&p.sendWorkerWaitSince, now.UnixNano())
	atomic.StoreInt64(&p.lastSendWorkerDepth, int64(depth))
	return now
}

func (p *deviceProgressTracker) sendWorkerWaitDone(start time.Time, depth int) {
	if start.IsZero() {
		return
	}
	now := time.Now()
	atomic.StoreInt64(&p.sendWorkerWaitSince, 0)
	atomic.StoreInt64(&p.lastSendWorkerAt, now.UnixNano())
	atomic.StoreInt64(&p.lastSendWorkerWait, now.Sub(start).Nanoseconds())
	atomic.StoreInt64(&p.lastSendWorkerDepth, int64(depth))
}

func (p *deviceProgressTracker) tunReadWaitStart() time.Time {
	if !p.enabled.Get() {
		return time.Time{}
	}
	now := time.Now()
	atomic.StoreInt64(&p.tunReadWaitSince, now.UnixNano())
	return now
}

func (p *deviceProgressTracker) tunReadWaitDone(start time.Time, size int) {
	if start.IsZero() {
		return
	}
	now := time.Now()
	atomic.StoreInt64(&p.tunReadWaitSince, 0)
	atomic.StoreInt64(&p.lastTunReadAt, now.UnixNano())
	atomic.StoreInt64(&p.lastTunReadWait, now.Sub(start).Nanoseconds())
	atomic.StoreInt64(&p.lastTunReadBytes, int64(size))
}

func (p *deviceProgressTracker) tapWriteWaitStart(depth int) time.Time {
	if !p.enabled.Get() {
		return time.Time{}
	}
	now := time.Now()
	atomic.StoreInt64(&p.tapWriteWaitSince, now.UnixNano())
	atomic.StoreInt64(&p.lastTapWriteDepth, int64(depth))
	return now
}

func (p *deviceProgressTracker) tapWriteWaitDone(start time.Time, depth int, bytes int) {
	if start.IsZero() {
		return
	}
	now := time.Now()
	atomic.StoreInt64(&p.tapWriteWaitSince, 0)
	atomic.StoreInt64(&p.lastTapWriteAt, now.UnixNano())
	atomic.StoreInt64(&p.lastTapWriteWait, now.Sub(start).Nanoseconds())
	atomic.StoreInt64(&p.lastTapWriteBytes, int64(bytes))
	atomic.StoreInt64(&p.lastTapWriteDepth, int64(depth))
}

func (p *deviceProgressTracker) tapFlushWaitStart(depth int) time.Time {
	if !p.enabled.Get() {
		return time.Time{}
	}
	now := time.Now()
	atomic.StoreInt64(&p.tapFlushWaitSince, now.UnixNano())
	atomic.StoreInt64(&p.lastTapFlushDepth, int64(depth))
	return now
}

func (p *deviceProgressTracker) tapFlushWaitDone(start time.Time, depth int) {
	if start.IsZero() {
		return
	}
	now := time.Now()
	atomic.StoreInt64(&p.tapFlushWaitSince, 0)
	atomic.StoreInt64(&p.lastTapFlushAt, now.UnixNano())
	atomic.StoreInt64(&p.lastTapFlushWait, now.Sub(start).Nanoseconds())
	atomic.StoreInt64(&p.lastTapFlushDepth, int64(depth))
}

func formatProgressTimeField(now time.Time, label string, unixNano int64) string {
	if unixNano == 0 {
		return label + "=never"
	}
	stamp := time.Unix(0, unixNano).UTC()
	return fmt.Sprintf("%s=%s ago=%s", label, stamp.Format(time.RFC3339Nano), now.Sub(stamp).Round(time.Millisecond))
}

func formatProgressWaitField(now time.Time, label string, unixNano int64) string {
	if unixNano == 0 {
		return label + "=idle"
	}
	stamp := time.Unix(0, unixNano).UTC()
	return fmt.Sprintf("%s=%s blocked_for=%s", label, stamp.Format(time.RFC3339Nano), now.Sub(stamp).Round(time.Millisecond))
}

func (device *Device) EnableProgressSnapshots(enabled bool) {
	device.progress.configure(enabled)
}

func (device *Device) SetSuperEventTraceHook(hook func(kind string, phase string, depth int, capacity int, wait time.Duration)) {
	device.progress.setSuperEventTraceHook(hook)
}

func (device *Device) ShutdownTraceSnapshot() []string {
	return device.shutdownTraceSnapshot()
}

func (device *Device) ProgressSnapshotLines() []string {
	if !device.progress.enabled.Get() {
		return nil
	}
	now := time.Now().UTC()
	return []string{
		fmt.Sprintf("device_id=%s is_super=%t state=%s", device.ID.ToString(), device.IsSuperNode, device.deviceState()),
		fmt.Sprintf("send_queue depth=%d cap=%d", len(device.chan_send_packet), cap(device.chan_send_packet)),
		formatProgressWaitField(now, "send_producer_wait_since", atomic.LoadInt64(&device.progress.sendProducerWaitSince)),
		formatProgressTimeField(now, "last_send_enqueue", atomic.LoadInt64(&device.progress.lastSendProducerAt)) + fmt.Sprintf(" last_wait=%s last_depth=%d", time.Duration(atomic.LoadInt64(&device.progress.lastSendProducerWait)).Round(time.Microsecond), atomic.LoadInt64(&device.progress.lastSendQueueDepth)),
		formatProgressWaitField(now, "send_worker_wait_since", atomic.LoadInt64(&device.progress.sendWorkerWaitSince)),
		formatProgressTimeField(now, "last_send_dequeue", atomic.LoadInt64(&device.progress.lastSendWorkerAt)) + fmt.Sprintf(" last_wait=%s last_depth=%d", time.Duration(atomic.LoadInt64(&device.progress.lastSendWorkerWait)).Round(time.Microsecond), atomic.LoadInt64(&device.progress.lastSendWorkerDepth)),
		formatProgressWaitField(now, "tun_read_wait_since", atomic.LoadInt64(&device.progress.tunReadWaitSince)),
		formatProgressTimeField(now, "last_tun_read", atomic.LoadInt64(&device.progress.lastTunReadAt)) + fmt.Sprintf(" last_wait=%s bytes=%d", time.Duration(atomic.LoadInt64(&device.progress.lastTunReadWait)).Round(time.Microsecond), atomic.LoadInt64(&device.progress.lastTunReadBytes)),
		formatProgressWaitField(now, "tap_write_wait_since", atomic.LoadInt64(&device.progress.tapWriteWaitSince)),
		formatProgressTimeField(now, "last_tap_write", atomic.LoadInt64(&device.progress.lastTapWriteAt)) + fmt.Sprintf(" last_wait=%s bytes=%d inbound_depth=%d", time.Duration(atomic.LoadInt64(&device.progress.lastTapWriteWait)).Round(time.Microsecond), atomic.LoadInt64(&device.progress.lastTapWriteBytes), atomic.LoadInt64(&device.progress.lastTapWriteDepth)),
		formatProgressWaitField(now, "tap_flush_wait_since", atomic.LoadInt64(&device.progress.tapFlushWaitSince)),
		formatProgressTimeField(now, "last_tap_flush", atomic.LoadInt64(&device.progress.lastTapFlushAt)) + fmt.Sprintf(" last_wait=%s inbound_depth=%d", time.Duration(atomic.LoadInt64(&device.progress.lastTapFlushWait)).Round(time.Microsecond), atomic.LoadInt64(&device.progress.lastTapFlushDepth)),
	}
}
