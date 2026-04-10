package main

import (
	"strings"
	"testing"
	"time"
)

func TestSuperProgressSnapshotShowsFanInAndLoopState(t *testing.T) {
	progress := newSuperEventProgress(true)
	progress.trace("register", "fan-in-begin", 3, 32, 0)
	progress.loopWaitStart()
	progress.recordFanOut("PushNhTable")
	time.Sleep(5 * time.Millisecond)
	lines := strings.Join(progress.snapshotLines(32, 3, 32, 1), "\n")
	for _, want := range []string{"register_queue depth=3 cap=32", "register_fan_in_wait_since=", "event_loop_wait_since=", "action=PushNhTable"} {
		if !strings.Contains(lines, want) {
			t.Fatalf("snapshot missing %q\n%s", want, lines)
		}
	}
}

func TestSuperProgressSnapshotDisabledIsEmpty(t *testing.T) {
	progress := newSuperEventProgress(false)
	progress.trace("register", "fan-in-begin", 3, 32, 0)
	progress.loopWaitStart()
	progress.recordFanOut("PushNhTable")
	if lines := progress.snapshotLines(32, 3, 32, 1); lines != nil {
		t.Fatalf("snapshotLines() disabled = %#v, want nil", lines)
	}
}

func TestSuperModeCaptureIncludesProgressSections(t *testing.T) {
	dir := t.TempDir()
	capture := newSuperModeHangCapture(dir, "")
	capture.addSection("super-events", func() []string {
		return []string{"register_queue depth=1 cap=32", "event_loop_wait_since=idle"}
	})
	if err := capture.triggerCapture(testHangCaptureTriggerManual); err != nil {
		t.Fatalf("triggerCapture() error = %v", err)
	}
	body := captureBodyByTrigger(t, dir, testHangCaptureTriggerManual)
	for _, want := range []string{"[super-events]", "register_queue depth=1 cap=32", "[goroutines]"} {
		if !strings.Contains(body, want) {
			t.Fatalf("capture body missing %q\n%s", want, body)
		}
	}
}

func TestSuperModeCaptureOmitsProgressSectionsWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	capture := newSuperModeHangCapture(dir, "")
	disabledProgress := newSuperEventProgress(false)
	capture.addSection("super-events", func() []string {
		return disabledProgress.snapshotLines(32, 0, 32, 0)
	})
	if err := capture.triggerCapture(testHangCaptureTriggerManual); err != nil {
		t.Fatalf("triggerCapture() error = %v", err)
	}
	body := captureBodyByTrigger(t, dir, testHangCaptureTriggerManual)
	if strings.Contains(body, "[super-events]") {
		t.Fatalf("capture body unexpectedly included disabled super progress section\n%s", body)
	}
	if !strings.Contains(body, "[goroutines]") {
		t.Fatalf("capture body missing goroutine section\n%s", body)
	}
}
