package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testHangCaptureTriggerManual   = "manual"
	testHangCaptureTriggerShutdown = "shutdown-device-wait"
	testHangCaptureTriggerSignal   = "shutdown-signal"
	testHangCaptureTriggerError    = "runtime-error"
)

func hasGoroutineDump(body string) bool {
	return strings.Contains(body, "goroutine ") && strings.Contains(body, "runtime/pprof")
}

func readCaptureArtifacts(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q) error = %v", dir, err)
	}
	artifacts := make(map[string]string, len(entries))
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("ReadFile(%q) error = %v", entry.Name(), err)
		}
		artifacts[entry.Name()] = string(body)
	}
	return artifacts
}

func captureBodyByTrigger(t *testing.T, dir string, trigger string) string {
	t.Helper()
	artifacts := readCaptureArtifacts(t, dir)
	if len(artifacts) != 1 {
		t.Fatalf("capture count = %d, want 1", len(artifacts))
	}
	for name, body := range artifacts {
		if !strings.HasSuffix(name, "-"+sanitizeCaptureTrigger(trigger)+".txt") {
			t.Fatalf("capture file name = %q, want suffix %q", name, "-"+sanitizeCaptureTrigger(trigger)+".txt")
		}
		return body
	}
	return ""
}

type failingHangCaptureWriter struct {
	err error
}

func (w failingHangCaptureWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

func (w failingHangCaptureWriter) Close() error {
	return nil
}

func TestSuperModeHangCaptureEnabled(t *testing.T) {
	dir := t.TempDir()
	capture := newSuperModeHangCapture(dir, "127.0.0.1:6060")

	if err := capture.triggerCapture(testHangCaptureTriggerManual); err != nil {
		t.Fatalf("triggerCapture() error = %v", err)
	}

	body := captureBodyByTrigger(t, dir, testHangCaptureTriggerManual)
	if !strings.Contains(body, "trigger="+testHangCaptureTriggerManual) {
		t.Fatalf("capture body missing trigger header: %q", body)
	}
	if !strings.Contains(body, "pprof=127.0.0.1:6060") {
		t.Fatalf("capture body missing pprof metadata: %q", body)
	}
	if !hasGoroutineDump(body) {
		t.Fatalf("capture body missing goroutine dump: %q", body)
	}
}

func TestSuperModeHangCaptureDisabled(t *testing.T) {
	capture := newSuperModeHangCapture("", "")

	if err := capture.triggerCapture(testHangCaptureTriggerManual); err != nil {
		t.Fatalf("triggerCapture() error = %v", err)
	}

	term := make(chan os.Signal, 1)
	term <- os.Interrupt
	reason, err := capture.captureOnShutdown(term, nil)
	if err != nil {
		t.Fatalf("captureOnShutdown() error = %v", err)
	}
	if reason != testHangCaptureTriggerSignal {
		t.Fatalf("shutdown reason = %q, want %q", reason, testHangCaptureTriggerSignal)
	}
}

func TestSuperModeShutdownCaptureEnabled(t *testing.T) {
	dir := t.TempDir()
	capture := newSuperModeHangCapture(dir, "")
	deviceWait := make(chan int, 1)
	deviceWait <- 0

	reason, err := capture.captureOnShutdown(nil, nil, deviceWait)
	if err != nil {
		t.Fatalf("captureOnShutdown() error = %v", err)
	}
	if reason != testHangCaptureTriggerShutdown {
		t.Fatalf("shutdown reason = %q, want %q", reason, testHangCaptureTriggerShutdown)
	}
	body := captureBodyByTrigger(t, dir, testHangCaptureTriggerShutdown)
	if !hasGoroutineDump(body) {
		t.Fatalf("shutdown capture missing goroutine dump: %q", body)
	}
}

func TestSuperModeShutdownCaptureRuntimeErrorReturnsCause(t *testing.T) {
	dir := t.TempDir()
	capture := newSuperModeHangCapture(dir, "")
	wantErr := errors.New("runtime failure")
	errCh := make(chan error, 1)
	errCh <- wantErr

	reason, err := capture.captureOnShutdown(nil, errCh)
	if reason != testHangCaptureTriggerError {
		t.Fatalf("captureOnShutdown() reason = %q, want %q", reason, testHangCaptureTriggerError)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("captureOnShutdown() error = %v, want %v", err, wantErr)
	}
	body := captureBodyByTrigger(t, dir, testHangCaptureTriggerError)
	if !hasGoroutineDump(body) {
		t.Fatalf("runtime-error capture missing goroutine dump: %q", body)
	}
}

func TestSuperModeHangCaptureWriteFailure(t *testing.T) {
	capture := newSuperModeHangCapture(t.TempDir(), "")
	wantErr := errors.New("artifact write failed")
	capture.newArtifact = func(trigger string) (io.WriteCloser, string, error) {
		return failingHangCaptureWriter{err: wantErr}, fmt.Sprintf("%s/%s.txt", t.TempDir(), trigger), nil
	}

	err := capture.triggerCapture(testHangCaptureTriggerManual)
	if !errors.Is(err, wantErr) {
		t.Fatalf("triggerCapture() error = %v, want %v", err, wantErr)
	}

	errCh := make(chan error, 1)
	errCh <- errors.New("device failure")
	done := make(chan struct{})
	reasonResult := make(chan string, 1)
	result := make(chan error, 1)
	go func() {
		defer close(done)
		reason, err := capture.captureOnShutdown(nil, errCh)
		reasonResult <- reason
		result <- err
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("captureOnShutdown() did not return after error trigger")
	}
	if reason := <-reasonResult; reason != testHangCaptureTriggerError {
		t.Fatalf("captureOnShutdown() reason = %q, want %q", reason, testHangCaptureTriggerError)
	}
	err = <-result
	if !errors.Is(err, wantErr) {
		t.Fatalf("captureOnShutdown() error = %v, want wrapped %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "device failure") {
		t.Fatalf("captureOnShutdown() error = %v, want runtime cause included", err)
	}
}

func TestSuperModeHangCaptureFromEnvDisabled(t *testing.T) {
	t.Setenv(ENV_EG_SUPER_CAPTURE_DIR, "")
	capture := newSuperModeHangCaptureFromEnv("")
	if capture.enabled {
		t.Fatal("capture.enabled = true, want false")
	}
}

func TestSuperModeHangCaptureExistingDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("Chmod(%q) error = %v", dir, err)
	}
	capture := newSuperModeHangCapture(dir, "")

	if err := capture.triggerCapture(testHangCaptureTriggerManual); err != nil {
		t.Fatalf("triggerCapture() error = %v", err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(%q) error = %v", dir, err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("capture dir permissions = %o, want 700", got)
	}
}
