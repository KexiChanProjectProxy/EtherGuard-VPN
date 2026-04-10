package device

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
)

type progressTestTap struct {
	readBlock  chan struct{}
	writeBlock chan struct{}
	flushBlock chan struct{}
	events     chan tap.Event
}

func newProgressTestTap() *progressTestTap {
	dev := &progressTestTap{
		readBlock:  make(chan struct{}),
		writeBlock: make(chan struct{}),
		flushBlock: make(chan struct{}),
		events:     make(chan tap.Event, 1),
	}
	dev.events <- tap.EventUp
	return dev
}

func (t *progressTestTap) Read([]byte, int) (int, error) {
	if _, ok := <-t.readBlock; !ok {
		return 0, errors.New("tap closed")
	}
	return 0, nil
}
func (t *progressTestTap) Write([]byte, int) (int, error) {
	if _, ok := <-t.writeBlock; !ok {
		return 0, errors.New("tap closed")
	}
	return 0, nil
}
func (t *progressTestTap) Flush() error {
	if _, ok := <-t.flushBlock; !ok {
		return errors.New("tap closed")
	}
	return nil
}
func (t *progressTestTap) MTU() (int, error)      { return 1500, nil }
func (t *progressTestTap) Name() (string, error)  { return "progress", nil }
func (t *progressTestTap) Events() chan tap.Event { return t.events }
func (t *progressTestTap) Close() error {
	close(t.readBlock)
	close(t.writeBlock)
	close(t.flushBlock)
	return nil
}

func newProgressTestDevice(t *testing.T) *Device {
	t.Helper()
	graph, err := path.NewGraph(1, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("NewGraph(): %v", err)
	}
	dev := NewDevice(newProgressTestTap(), 1, &shutdownTraceTestBind{}, NewLogger(LogLevelSilent, "test"), graph, false, "", &mtypes.EdgeConfig{NodeID: 1, DefaultTTL: 1, ListenPort: 0, AfPrefer: 4, LogLevel: mtypes.LoggerInfo{}, Interface: mtypes.InterfaceConf{MTU: DefaultMTU}, DynamicRoute: mtypes.DynamicRouteInfo{PeerAliveTimeout: 5, ConnNextTry: 1, DupCheckTimeout: 1}}, nil, nil, "test")
	return dev
}

func TestProgressSnapshotDisabledByDefaultAndAfterDisable(t *testing.T) {
	device := newProgressTestDevice(t)
	t.Cleanup(func() { device.Close() })

	if lines := device.ProgressSnapshotLines(); lines != nil {
		t.Fatalf("ProgressSnapshotLines() default = %#v, want nil", lines)
	}

	device.EnableProgressSnapshots(true)
	if lines := device.ProgressSnapshotLines(); len(lines) == 0 {
		t.Fatal("ProgressSnapshotLines() enabled returned no snapshot lines")
	}

	device.EnableProgressSnapshots(false)
	if lines := device.ProgressSnapshotLines(); lines != nil {
		t.Fatalf("ProgressSnapshotLines() after disable = %#v, want nil", lines)
	}
}

func TestQueueProgressSnapshotShowsBlockedProducerAndIdleWorker(t *testing.T) {
	device := newProgressTestDevice(t)
	t.Cleanup(func() { device.Close() })
	device.EnableProgressSnapshots(true)
	start := device.progress.sendProducerWaitStart(cap(device.chan_send_packet))
	device.progress.sendWorkerWaitStart(0)
	time.Sleep(5 * time.Millisecond)
	lines := strings.Join(device.ProgressSnapshotLines(), "\n")
	if !strings.Contains(lines, "send_queue depth=0 cap=32768") {
		t.Fatalf("snapshot missing queue depth: %s", lines)
	}
	if !strings.Contains(lines, "send_producer_wait_since=") || !strings.Contains(lines, "blocked_for=") {
		t.Fatalf("snapshot missing producer wait: %s", lines)
	}
	if !strings.Contains(lines, "send_worker_wait_since=") {
		t.Fatalf("snapshot missing worker wait: %s", lines)
	}
	device.progress.sendProducerWaitDone(start, cap(device.chan_send_packet))
}

func TestProgressSnapshotShowsTapWriteAndFlushWaits(t *testing.T) {
	device := newProgressTestDevice(t)
	t.Cleanup(func() { device.Close() })
	device.EnableProgressSnapshots(true)
	writeStart := device.progress.tapWriteWaitStart(3)
	flushStart := device.progress.tapFlushWaitStart(0)
	time.Sleep(5 * time.Millisecond)
	lines := strings.Join(device.ProgressSnapshotLines(), "\n")
	if !strings.Contains(lines, "tap_write_wait_since=") {
		t.Fatalf("snapshot missing tap write wait: %s", lines)
	}
	if !strings.Contains(lines, "tap_flush_wait_since=") {
		t.Fatalf("snapshot missing tap flush wait: %s", lines)
	}
	device.progress.tapWriteWaitDone(writeStart, 3, 128)
	device.progress.tapFlushWaitDone(flushStart, 0)
	lines = strings.Join(device.ProgressSnapshotLines(), "\n")
	if !strings.Contains(lines, "last_tap_write=") || !strings.Contains(lines, "bytes=128") {
		t.Fatalf("snapshot missing tap write completion: %s", lines)
	}
	if !strings.Contains(lines, "last_tap_flush=") {
		t.Fatalf("snapshot missing tap flush completion: %s", lines)
	}
}
