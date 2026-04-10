package device

import (
	"fmt"
	"os"
	"sync"
	"time"
)

const defaultShutdownTraceLimit = 64

type shutdownTraceBuffer struct {
	enabled AtomicBool

	mu     sync.Mutex
	limit  int
	hook   func(string)
	events []string
	next   int
	count  int
}

func (b *shutdownTraceBuffer) configure(enabled bool, limit int, hook func(string)) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.enabled.Set(enabled)
	b.hook = hook
	b.limit = limit
	b.events = nil
	b.next = 0
	b.count = 0
	if enabled {
		if limit <= 0 {
			limit = defaultShutdownTraceLimit
		}
		b.limit = limit
		b.events = make([]string, limit)
	}
}

func (b *shutdownTraceBuffer) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.count == 0 {
		return nil
	}
	items := make([]string, 0, b.count)
	if b.count < len(b.events) {
		items = append(items, b.events[:b.count]...)
		return items
	}
	items = append(items, b.events[b.next:]...)
	items = append(items, b.events[:b.next]...)
	return items
}

func (b *shutdownTraceBuffer) emit(event string) {
	b.mu.Lock()
	hook := b.hook
	enabled := b.enabled.Get() && b.limit > 0
	if enabled {
		b.events[b.next] = event
		b.next = (b.next + 1) % b.limit
		if b.count < b.limit {
			b.count++
		}
	}
	b.mu.Unlock()

	if hook != nil {
		hook(event)
	}
}

func (device *Device) initShutdownTraceFromEnv() {
	if os.Getenv("EG_SHUTDOWN_TRACE") == "" {
		return
	}
	device.shutdownTrace.configure(true, defaultShutdownTraceLimit, nil)
}

func (device *Device) setShutdownTraceForTest(enabled bool, hook func(string)) {
	device.shutdownTrace.configure(enabled, defaultShutdownTraceLimit, hook)
}

func (device *Device) shutdownTraceSnapshot() []string {
	return device.shutdownTrace.snapshot()
}

func (device *Device) traceShutdownf(format string, args ...interface{}) {
	if !device.shutdownTrace.enabled.Get() {
		device.shutdownTrace.mu.Lock()
		hook := device.shutdownTrace.hook
		device.shutdownTrace.mu.Unlock()
		if hook == nil {
			return
		}
	}
	event := fmt.Sprintf("%s shutdown-trace %s", time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf(format, args...))
	device.shutdownTrace.emit(event)
}
