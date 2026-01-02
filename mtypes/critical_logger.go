/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package mtypes

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// CriticalLogger handles critical errors and deadlock detection
type CriticalLogger struct {
	logger          *log.Logger
	mu              sync.Mutex
	lastActivity    time.Time
	deadlockTimeout time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	stopped         bool
}

// NewCriticalLogger creates a new critical logger with deadlock detection
func NewCriticalLogger(deadlockTimeout time.Duration) *CriticalLogger {
	ctx, cancel := context.WithCancel(context.Background())
	cl := &CriticalLogger{
		logger:          log.New(os.Stderr, "[CRITICAL] ", log.Ldate|log.Ltime|log.Lmicroseconds|log.Lshortfile),
		lastActivity:    time.Now(),
		deadlockTimeout: deadlockTimeout,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start deadlock monitor
	go cl.deadlockMonitor()

	return cl
}

// UpdateActivity updates the last activity timestamp
func (cl *CriticalLogger) UpdateActivity() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.lastActivity = time.Now()
}

// LogCritical logs a critical error with stack trace
func (cl *CriticalLogger) LogCritical(format string, args ...interface{}) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	msg := fmt.Sprintf(format, args...)
	cl.logger.Printf("CRITICAL ERROR: %s\n", msg)
	cl.logger.Printf("Stack trace:\n%s\n", string(debug.Stack()))
}

// LogFatal logs a fatal error and triggers program exit
func (cl *CriticalLogger) LogFatal(format string, args ...interface{}) {
	cl.LogCritical(format, args...)
	cl.logger.Printf("Program will exit and restart in 3 seconds...\n")
	time.Sleep(3 * time.Second)
	os.Exit(1)
}

// LogPanic recovers from a panic, logs it, and triggers exit
func (cl *CriticalLogger) RecoverPanic() {
	if r := recover(); r != nil {
		cl.mu.Lock()
		defer cl.mu.Unlock()

		cl.logger.Printf("PANIC RECOVERED: %v\n", r)
		cl.logger.Printf("Stack trace:\n%s\n", string(debug.Stack()))
		cl.logger.Printf("Program will exit and restart in 3 seconds...\n")

		time.Sleep(3 * time.Second)
		os.Exit(1)
	}
}

// deadlockMonitor monitors for potential deadlocks
func (cl *CriticalLogger) deadlockMonitor() {
	ticker := time.NewTicker(cl.deadlockTimeout / 2)
	defer ticker.Stop()

	for {
		select {
		case <-cl.ctx.Done():
			return
		case <-ticker.C:
			cl.mu.Lock()
			if time.Since(cl.lastActivity) > cl.deadlockTimeout {
				cl.logger.Printf("DEADLOCK DETECTED: No activity for %v\n", time.Since(cl.lastActivity))
				cl.logger.Printf("Stack trace:\n%s\n", string(debug.Stack()))
				cl.logger.Printf("Program will exit and restart in 3 seconds...\n")
				cl.mu.Unlock()

				time.Sleep(3 * time.Second)
				os.Exit(1)
			}
			cl.mu.Unlock()
		}
	}
}

// Stop stops the critical logger and deadlock monitor
func (cl *CriticalLogger) Stop() {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	if !cl.stopped {
		cl.stopped = true
		cl.cancel()
	}
}
