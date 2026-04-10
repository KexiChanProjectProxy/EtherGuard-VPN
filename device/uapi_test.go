package device

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type testUAPILogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *testUAPILogSink) Printf(format string, args ...interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fmt.Fprintf(&s.buf, format, args...)
	s.buf.WriteByte('\n')
}

func (s *testUAPILogSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func newTestUAPILogger(sink *testUAPILogSink) *Logger {
	return &Logger{
		Verbosef: sink.Printf,
		Errorf:   sink.Printf,
	}
}

type testUAPIConn struct {
	reader *bytes.Reader
	writes bytes.Buffer
}

func newTestUAPIConn(input string) *testUAPIConn {
	return &testUAPIConn{reader: bytes.NewReader([]byte(input))}
}

func (c *testUAPIConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *testUAPIConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *testUAPIConn) Close() error                     { return nil }
func (c *testUAPIConn) LocalAddr() net.Addr              { return testUAPIAddr("local") }
func (c *testUAPIConn) RemoteAddr() net.Addr             { return testUAPIAddr("pipe") }
func (c *testUAPIConn) SetDeadline(time.Time) error      { return nil }
func (c *testUAPIConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testUAPIConn) SetWriteDeadline(time.Time) error { return nil }

type testUAPIAddr string

func (a testUAPIAddr) Network() string { return "test" }
func (a testUAPIAddr) String() string  { return string(a) }

func TestUAPITraceEnabledGetAndSet(t *testing.T) {
	t.Setenv(envEGUAPITrace, "1")
	sink := &testUAPILogSink{}
	device := &Device{log: newTestUAPILogger(sink)}

	getConn := newTestUAPIConn("get=1\n\n")
	device.IpcHandleWithAcceptedAt(getConn, time.Now().Add(-5*time.Millisecond))
	if !strings.Contains(getConn.writes.String(), "errno=0") {
		t.Fatalf("get reply = %q, want errno=0", getConn.writes.String())
	}

	setConn := newTestUAPIConn("set=1\n\n")
	device.IpcHandleWithAcceptedAt(setConn, time.Now().Add(-5*time.Millisecond))
	if !strings.Contains(setConn.writes.String(), "errno=0") {
		t.Fatalf("set reply = %q, want errno=0", setConn.writes.String())
	}

	logs := sink.String()
	for _, want := range []string{
		"UAPI trace: handle begin",
		"accept-to-handle=",
		"UAPI trace: handle dispatch begin remote=pipe op=get",
		"UAPI trace: get ipcMutex wait-begin mode=read",
		"UAPI trace: get ipcMutex wait-end mode=read wait=",
		"UAPI trace: get serialize begin peers=0",
		"UAPI trace: get serialize end peers=0 duration=",
		"UAPI trace: get write begin bytes=",
		"UAPI trace: get write end bytes=",
		"UAPI trace: get ipcMutex hold-end mode=read held=",
		"UAPI trace: handle dispatch begin remote=pipe op=set",
		"UAPI trace: set ipcMutex wait-begin mode=write",
		"UAPI trace: set ipcMutex wait-end mode=write wait=",
		"UAPI trace: set apply begin",
		"UAPI trace: set apply end lines=1 duration=",
		"UAPI trace: set ipcMutex hold-end mode=write held=",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("logs missing %q\nfull logs:\n%s", want, logs)
		}
	}
}

func TestUAPITraceDisabled(t *testing.T) {
	t.Setenv(envEGUAPITrace, "")
	sink := &testUAPILogSink{}
	device := &Device{log: newTestUAPILogger(sink)}

	conn := newTestUAPIConn("get=1\n\n")
	device.IpcHandleWithAcceptedAt(conn, time.Now())

	if logs := sink.String(); logs != "" {
		t.Fatalf("trace logs = %q, want empty", logs)
	}
}
