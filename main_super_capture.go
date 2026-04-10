/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
)

const (
	superModeCaptureFilePrefix = "super-capture"
)

var superModeCaptureSignal = syscall.SIGUSR1

type superModeHangCapture struct {
	enabled        bool
	outputDir      string
	pprofAddr      string
	newArtifact    func(string) (io.WriteCloser, string, error)
	writeGoroutine func(string, io.Writer) error
	now            func() time.Time
	sections       []captureSection

	mu       sync.Mutex
	sequence uint64
}

type captureSection struct {
	name string
	load func() []string
}

func newSuperModeHangCaptureFromEnv(pprofAddr string) *superModeHangCapture {
	return newSuperModeHangCapture(os.Getenv(ENV_EG_SUPER_CAPTURE_DIR), pprofAddr)
}

func newSuperModeHangCapture(outputDir string, pprofAddr string) *superModeHangCapture {
	outputDir = strings.TrimSpace(outputDir)
	capture := &superModeHangCapture{
		enabled:   outputDir != "",
		outputDir: outputDir,
		pprofAddr: pprofAddr,
		now:       time.Now,
	}
	capture.newArtifact = capture.openArtifact
	capture.writeGoroutine = capture.writeArtifact
	return capture
}

func (capture *superModeHangCapture) armSignalHandler(logger *device.Logger) func() {
	if capture == nil || !capture.enabled {
		return func() {}
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, superModeCaptureSignal)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case sig := <-ch:
				if sig == nil {
					continue
				}
				if err := capture.triggerCapture("signal-" + strings.ToLower(sig.String())); err != nil && logger != nil {
					logger.Errorf("Failed to write Super Mode capture: %v", err)
				}
			}
		}
	}()
	return func() {
		close(stop)
		signal.Stop(ch)
	}
}

func (capture *superModeHangCapture) captureOnShutdown(term <-chan os.Signal, errs <-chan error, waits ...<-chan int) (string, error) {
	select {
	case <-term:
		return capture.finishShutdownCapture("shutdown-signal", nil)
	case err := <-errs:
		return capture.finishShutdownCapture("runtime-error", err)
	default:
	}

	if len(waits) == 0 {
		return "", nil
	}

	select {
	case <-term:
		return capture.finishShutdownCapture("shutdown-signal", nil)
	case err := <-errs:
		return capture.finishShutdownCapture("runtime-error", err)
	case <-waits[0]:
		return capture.finishShutdownCapture("shutdown-device-wait", nil)
	case <-waitChannelAt(waits, 1):
		return capture.finishShutdownCapture("shutdown-device-wait", nil)
	}
}

func (capture *superModeHangCapture) finishShutdownCapture(trigger string, shutdownErr error) (string, error) {
	captureErr := capture.triggerCapture(trigger)
	switch {
	case shutdownErr == nil:
		return trigger, captureErr
	case captureErr == nil:
		return trigger, shutdownErr
	default:
		return trigger, errors.Join(shutdownErr, captureErr)
	}
}

func (capture *superModeHangCapture) triggerCapture(trigger string) error {
	if capture == nil || !capture.enabled {
		return nil
	}

	capture.mu.Lock()
	defer capture.mu.Unlock()

	writer, artifactPath, err := capture.newArtifact(trigger)
	if err != nil {
		return err
	}

	writeErr := capture.writeGoroutine(trigger, writer)
	closeErr := writer.Close()
	if writeErr != nil {
		capture.removeArtifact(artifactPath)
		return writeErr
	}
	if closeErr != nil {
		capture.removeArtifact(artifactPath)
		return closeErr
	}
	return nil
}

func (capture *superModeHangCapture) addSection(name string, load func() []string) {
	if capture == nil || !capture.enabled || load == nil {
		return
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.sections = append(capture.sections, captureSection{name: name, load: load})
}

func (capture *superModeHangCapture) openArtifact(trigger string) (io.WriteCloser, string, error) {
	if err := os.MkdirAll(capture.outputDir, 0o700); err != nil {
		return nil, "", err
	}
	info, err := os.Lstat(capture.outputDir)
	if err != nil {
		return nil, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, "", fmt.Errorf("capture output path %q must not be a symlink", capture.outputDir)
	}
	if !info.IsDir() {
		return nil, "", fmt.Errorf("capture output path %q is not a directory", capture.outputDir)
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(capture.outputDir, 0o700); err != nil {
			return nil, "", err
		}
		info, err = os.Stat(capture.outputDir)
		if err != nil {
			return nil, "", err
		}
		if info.Mode().Perm() != 0o700 {
			return nil, "", fmt.Errorf("capture output path %q permissions = %o, want 700", capture.outputDir, info.Mode().Perm())
		}
	}
	artifactPath := capture.nextArtifactPath(trigger)
	file, err := os.OpenFile(artifactPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", err
	}
	return file, artifactPath, nil
}

func (capture *superModeHangCapture) nextArtifactPath(trigger string) string {
	capture.sequence++
	stamp := capture.now().UTC().Format("20060102T150405.000000000Z")
	name := fmt.Sprintf("%s-%s-%d-%06d-%s.txt", superModeCaptureFilePrefix, stamp, os.Getpid(), capture.sequence, sanitizeCaptureTrigger(trigger))
	return filepath.Join(capture.outputDir, name)
}

func sanitizeCaptureTrigger(trigger string) string {
	trigger = strings.ToLower(strings.TrimSpace(trigger))
	if trigger == "" {
		return "unknown"
	}
	var builder strings.Builder
	for _, r := range trigger {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		default:
			builder.WriteByte('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func (capture *superModeHangCapture) writeArtifact(trigger string, writer io.Writer) error {
	_, err := fmt.Fprintf(writer, "trigger=%s\npprof=%s\ncaptured_at=%s\npid=%d\n", trigger, capture.pprofAddr, capture.now().UTC().Format(time.RFC3339Nano), os.Getpid())
	if err != nil {
		return err
	}
	for _, section := range capture.sections {
		lines := section.load()
		if len(lines) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(writer, "\n[%s]\n", section.name); err != nil {
			return err
		}
		for _, line := range lines {
			if _, err := fmt.Fprintln(writer, line); err != nil {
				return err
			}
		}
	}
	if _, err := io.WriteString(writer, "\n[goroutines]\n"); err != nil {
		return err
	}
	return pprof.Lookup("goroutine").WriteTo(writer, 2)
}

func (capture *superModeHangCapture) removeArtifact(artifactPath string) {
	if artifactPath == "" {
		return
	}
	_ = os.Remove(artifactPath)
}

func waitChannelAt(channels []<-chan int, index int) <-chan int {
	if index >= len(channels) {
		return nil
	}
	return channels[index]
}
