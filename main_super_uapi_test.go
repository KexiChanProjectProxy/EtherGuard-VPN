package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
)

type testMainUAPILogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *testMainUAPILogSink) Printf(format string, args ...interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(&s.buf, format, args...)
	s.buf.WriteByte('\n')
}

func (s *testMainUAPILogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type testUAPIListener struct {
	mu      sync.Mutex
	results []testUAPIAcceptResult
	addr    net.Addr
}

type testUAPIAcceptResult struct {
	conn net.Conn
	err  error
}

func (l *testUAPIListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.results) == 0 {
		return nil, errors.New("no more accepts")
	}
	result := l.results[0]
	l.results = l.results[1:]
	return result.conn, result.err
}

func (l *testUAPIListener) Close() error { return nil }

func (l *testUAPIListener) Addr() net.Addr { return l.addr }

type testUAPIAddr string

func (a testUAPIAddr) Network() string { return "unix" }

func (a testUAPIAddr) String() string { return string(a) }

func newTestMainUAPILogger(sink *testMainUAPILogSink) *device.Logger {
	return &device.Logger{
		Verbosef: sink.Printf,
		Errorf:   sink.Printf,
	}
}

func TestUAPIAcceptTraceEnabled(t *testing.T) {
	t.Setenv("EG_UAPI_TRACE", "1")
	sink := &testMainUAPILogSink{}
	logger := newTestMainUAPILogger(sink)
	client, server := net.Pipe()
	listenerErr := errors.New("accept closed")
	listener := &testUAPIListener{
		addr: testUAPIAddr("uapi-test"),
		results: []testUAPIAcceptResult{
			{conn: server},
			{err: listenerErr},
		},
	}
	errCh := make(chan error, 1)
	handled := make(chan time.Time, 1)

	serveUAPI(listener, logger, errCh, func(conn net.Conn, acceptedAt time.Time) {
		handled <- acceptedAt
		conn.Close()
		client.Close()
	})

	select {
	case acceptedAt := <-handled:
		if acceptedAt.IsZero() {
			t.Fatal("acceptedAt is zero, want timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("serveUAPI did not dispatch accepted connection")
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, listenerErr) {
			t.Fatalf("accept loop err = %v, want %v", err, listenerErr)
		}
	case <-time.After(time.Second):
		t.Fatal("serveUAPI did not forward accept error")
	}

	logs := sink.String()
	for _, want := range []string{
		"UAPI trace: accept wait-begin local=uapi-test",
		"UAPI trace: accept wait-end local=uapi-test duration=",
		"UAPI trace: accept dispatch remote=pipe",
		"err=accept closed",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs missing %q\nfull logs:\n%s", want, logs)
		}
	}
}

func TestUAPIAcceptTraceDisabled(t *testing.T) {
	t.Setenv("EG_UAPI_TRACE", "")
	sink := &testMainUAPILogSink{}
	logger := newTestMainUAPILogger(sink)
	listenerErr := errors.New("accept closed")
	listener := &testUAPIListener{
		addr:    testUAPIAddr("uapi-test"),
		results: []testUAPIAcceptResult{{err: listenerErr}},
	}
	errCh := make(chan error, 1)

	serveUAPI(listener, logger, errCh, func(net.Conn, time.Time) {
		t.Fatal("handleConn should not be called")
	})

	select {
	case err := <-errCh:
		if !errors.Is(err, listenerErr) {
			t.Fatalf("accept loop err = %v, want %v", err, listenerErr)
		}
	case <-time.After(time.Second):
		t.Fatal("serveUAPI did not forward accept error")
	}

	if logs := sink.String(); logs != "" {
		t.Fatalf("trace logs = %q, want empty", logs)
	}
}
