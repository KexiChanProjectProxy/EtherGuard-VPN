package device

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestSuperHTTPRuntimeFailoverAfterThreeReportFailures(t *testing.T) {
	// Given
	clock := newFailoverTestClock(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	allowReports := make(chan struct{})
	staleRegisterStarted := make(chan struct{})
	releaseStaleRegister := make(chan struct{})
	var allowOnce, releaseOnce, staleOnce sync.Once
	a := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, call int32, _ mtypes.ControlV2RegisterRequest) {
			if call == 1 {
				writeFailoverSnapshot(writer, failoverSnapshot(10, 20*time.Millisecond))
				return
			}
			staleOnce.Do(func() { close(staleRegisterStarted) })
			<-releaseStaleRegister
			writeFailoverSnapshot(writer, failoverSnapshot(999, 20*time.Millisecond))
		},
		Report: func(writer http.ResponseWriter, _ *http.Request, _ int32) {
			<-allowReports
			http.Error(writer, "failed", http.StatusInternalServerError)
		},
	})
	b := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, _ int32, _ mtypes.ControlV2RegisterRequest) {
			writeFailoverSnapshot(writer, failoverSnapshot(2, 20*time.Millisecond))
		},
	})
	handle := startFailoverRuntime(t, failoverRuntimeConfig{URLs: []string{a.URL(), b.URL()}, Clock: clock})
	t.Cleanup(func() {
		allowOnce.Do(func() { close(allowReports) })
		releaseOnce.Do(func() { close(releaseStaleRegister) })
	})
	waitRuntimeCondition(t, time.Second, func() bool { return a.registerCalls.Load() == 1 })
	handle.runtime.requestReregistration(handle.ctx, handle.ready, handle.runtime.client.Epoch())
	select {
	case <-staleRegisterStarted:
	case <-time.After(time.Second):
		t.Fatal("stale A re-register did not start")
	}

	// When
	allowOnce.Do(func() { close(allowReports) })
	waitRuntimeCondition(t, 5*time.Second, func() bool { return b.registerCalls.Load() == 1 })

	// Then
	if got := a.reportCalls.Load(); got != 3 {
		t.Fatalf("A report failures = %d, want exactly 3", got)
	}
	if got := mtypes.Vertex(b.lastNodeID.Load()); got != 47100 {
		t.Fatalf("B register NodeID = %v, want 47100", got)
	}
	if handle.runtime.client.BaseURL != b.URL() {
		t.Fatalf("client base = %q, want %q", handle.runtime.client.BaseURL, b.URL())
	}
	releaseOnce.Do(func() { close(releaseStaleRegister) })
	waitRuntimeCondition(t, time.Second, func() bool {
		current := handle.runtime.client.Current()
		return current != nil && current.Revision == 2
	})
}

func TestSuperHTTPRuntimeFailoverAfterNoSuccessWindow(t *testing.T) {
	// Given
	clock := newFailoverTestClock(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	a := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, _ int32, _ mtypes.ControlV2RegisterRequest) {
			writeFailoverSnapshot(writer, failoverSnapshot(1, 20*time.Millisecond))
		},
		Report: func(writer http.ResponseWriter, _ *http.Request, _ int32) {
			clock.Advance(15 * time.Second)
			http.Error(writer, "failed", http.StatusInternalServerError)
		},
	})
	b := newFailoverTestServer(t, failoverServerConfig{})
	handle := startFailoverRuntime(t, failoverRuntimeConfig{URLs: []string{a.URL(), b.URL()}, Clock: clock})

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return b.registerCalls.Load() == 1 })

	// Then
	if got := a.reportCalls.Load(); got != 1 {
		t.Fatalf("A report failures before time-window rotation = %d, want 1", got)
	}
	if handle.runtime.client.BaseURL != b.URL() {
		t.Fatalf("client base = %q, want %q", handle.runtime.client.BaseURL, b.URL())
	}
}

func TestSuperHTTPRuntimeUnknownPeerDoesNotCountAsFailure(t *testing.T) {
	// Given
	clock := newFailoverTestClock(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	a := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, call int32, _ mtypes.ControlV2RegisterRequest) {
			writeFailoverSnapshot(writer, failoverSnapshot(uint64(call), 20*time.Millisecond))
		},
		Report: func(writer http.ResponseWriter, _ *http.Request, _ int32) {
			http.Error(writer, "report: control state: unknown peer", http.StatusBadRequest)
		},
	})
	b := newFailoverTestServer(t, failoverServerConfig{})
	handle := startFailoverRuntime(t, failoverRuntimeConfig{URLs: []string{a.URL(), b.URL()}, Clock: clock})

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return a.reportCalls.Load() >= 6 })

	// Then
	if got := a.registerCalls.Load(); got != 2 {
		t.Fatalf("same-epoch register attempts = %d, want initial plus one throttled retry", got)
	}
	if got := b.registerCalls.Load(); got != 0 {
		t.Fatalf("B register attempts = %d, want 0", got)
	}
	handle.runtime.mu.RLock()
	failures := handle.runtime.selector.consecutiveReportFailures
	handle.runtime.mu.RUnlock()
	if failures != 0 || handle.runtime.client.Epoch() != 0 {
		t.Fatalf("unknown-peer state = failures %d, epoch %d; want 0, 0", failures, handle.runtime.client.Epoch())
	}
}

func TestSuperHTTPRuntimeReregisterBypassesThrottleOnSwitch(t *testing.T) {
	// Given
	clock := newFailoverTestClock(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	allowReports := make(chan struct{})
	var allowOnce sync.Once
	a := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, call int32, _ mtypes.ControlV2RegisterRequest) {
			writeFailoverSnapshot(writer, failoverSnapshot(uint64(call), 20*time.Millisecond))
		},
		Report: func(writer http.ResponseWriter, _ *http.Request, _ int32) {
			<-allowReports
			http.Error(writer, "failed", http.StatusInternalServerError)
		},
	})
	b := newFailoverTestServer(t, failoverServerConfig{})
	handle := startFailoverRuntime(t, failoverRuntimeConfig{URLs: []string{a.URL(), b.URL()}, Clock: clock})
	t.Cleanup(func() { allowOnce.Do(func() { close(allowReports) }) })
	waitRuntimeCondition(t, time.Second, func() bool { return a.registerCalls.Load() == 1 })
	handle.runtime.requestReregistration(handle.ctx, handle.ready, handle.runtime.client.Epoch())
	waitRuntimeCondition(t, time.Second, func() bool { return a.registerCalls.Load() == 2 })

	// When
	allowOnce.Do(func() { close(allowReports) })
	waitRuntimeCondition(t, 5*time.Second, func() bool { return b.registerCalls.Load() == 1 })

	// Then
	if got := a.reportCalls.Load(); got != 3 {
		t.Fatalf("A report failures = %d, want 3", got)
	}
	if handle.runtime.client.Epoch() != 1 {
		t.Fatalf("client epoch = %d, want 1", handle.runtime.client.Epoch())
	}
}

func TestSuperHTTPRuntimeStaleEpochRegisterIgnored(t *testing.T) {
	// Given
	clock := newFailoverTestClock(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	bStarted := make(chan struct{})
	releaseB := make(chan struct{})
	var releaseOnce sync.Once
	b := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, _ int32, _ mtypes.ControlV2RegisterRequest) {
			close(bStarted)
			<-releaseB
			writeFailoverSnapshot(writer, failoverSnapshot(100, time.Second))
		},
	})
	c := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, _ int32, _ mtypes.ControlV2RegisterRequest) {
			writeFailoverSnapshot(writer, failoverSnapshot(2, time.Second))
		},
	})
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID:   47100,
		NodeName: "stale-register-edge",
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      []string{"http://127.0.0.1:1", b.URL(), c.URL()},
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: "failover-key",
		},
	})
	runtime.SetClockForTest(clock.Now)
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseB) }) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := superHTTPReady{port: 51820}
	epochB := runtime.client.SwitchBase(b.URL())
	runtime.requestReregistration(ctx, ready, epochB)
	select {
	case <-bStarted:
	case <-time.After(time.Second):
		t.Fatal("epoch-B register did not start")
	}

	// When
	epochC := runtime.client.SwitchBase(c.URL())
	runtime.requestReregistration(ctx, ready, epochC)
	waitRuntimeCondition(t, time.Second, func() bool { return c.registerCalls.Load() == 1 })
	releaseOnce.Do(func() { close(releaseB) })
	runtime.reregisterWG.Wait()

	// Then
	current := runtime.client.Current()
	if current == nil || current.Revision != 2 {
		t.Fatalf("current snapshot after stale epoch completion = %+v, want revision 2", current)
	}
	if runtime.client.Epoch() != epochC {
		t.Fatalf("client epoch = %d, want %d", runtime.client.Epoch(), epochC)
	}
}

func TestSuperHTTPRuntimeNoRotateWithSingleURL(t *testing.T) {
	// Given
	clock := newFailoverTestClock(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	a := newFailoverTestServer(t, failoverServerConfig{
		Register: func(writer http.ResponseWriter, _ *http.Request, _ int32, _ mtypes.ControlV2RegisterRequest) {
			http.Error(writer, "down", http.StatusServiceUnavailable)
		},
		Report: func(writer http.ResponseWriter, _ *http.Request, _ int32) {
			http.Error(writer, "down", http.StatusServiceUnavailable)
		},
	})
	handle := startFailoverRuntime(t, failoverRuntimeConfig{
		URLs:           []string{a.URL()},
		Clock:          clock,
		ReportInterval: 10 * time.Millisecond,
	})

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return a.reportCalls.Load() >= 4 })

	// Then
	if handle.runtime.client.BaseURL != a.URL() || handle.runtime.client.Epoch() != 0 {
		t.Fatalf("single-URL runtime moved to %q epoch %d", handle.runtime.client.BaseURL, handle.runtime.client.Epoch())
	}
}
