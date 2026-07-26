package device

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestSuperHTTPRuntimeStartsAfterReadyAndReports(t *testing.T) {
	// Given
	var registered atomic.Int32
	var reported atomic.Int32
	snapshot := runtimeTestSnapshot(t, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/edge/v2/register":
			registered.Add(1)
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/edge/v2/report":
			reported.Add(1)
			w.WriteHeader(http.StatusAccepted)
		case "/edge/v2/snapshot":
			_ = json.NewEncoder(w).Encode(snapshot)
		case "/edge/v2/events":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID: 10, NodeName: "edge-10", DefaultTTL: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{APIUrl: server.URL, APIPrefix: "/edge/v2", NodeID: 99, ControlPSKey: "key"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// When
	runtime.Start(ctx)
	time.Sleep(30 * time.Millisecond)
	if registered.Load() != 0 {
		t.Fatalf("register happened before bind readiness")
	}
	runtime.MarkReady(51820, 0, net.ParseIP("10.0.0.10"), nil)

	// Then
	waitRuntimeCondition(t, time.Second, func() bool { return registered.Load() > 0 && reported.Load() > 0 })
}

func TestSuperHTTPRuntimeSyncFallsBackToPollingAndStops(t *testing.T) {
	// Given
	var revision atomic.Uint64
	var snapshots atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/edge/v2/register":
			_ = json.NewEncoder(w).Encode(runtimeTestSnapshot(t, 1))
		case "/edge/v2/snapshot":
			snapshots.Add(1)
			rev := revision.Add(1) + 1
			_ = json.NewEncoder(w).Encode(runtimeTestSnapshot(t, rev))
		case "/edge/v2/events":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "/edge/v2/report":
			w.WriteHeader(http.StatusAccepted)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID: 11, NodeName: "edge-11", DefaultTTL: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{APIUrl: server.URL, APIPrefix: "/edge/v2", NodeID: 99, ControlPSKey: "key"},
	})
	ctx, cancel := context.WithCancel(context.Background())
	runtime.Start(ctx)
	runtime.MarkReady(51821, 0, net.ParseIP("10.0.0.11"), nil)

	// When
	waitRuntimeCondition(t, time.Second, func() bool { return snapshots.Load() >= 2 })
	cancel()

	// Then
	select {
	case <-runtime.Done():
	case <-time.After(time.Second):
		t.Fatal("runtime goroutines did not stop")
	}
}

func TestSuperHTTPRuntimeApplySnapshotSerializesConcurrentCalls(t *testing.T) {
	// Given
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{})
	first := runtimeTestSnapshot(t, 1)
	second := runtimeTestSnapshot(t, 2)
	second.Parameters.PollInterval = 20 * time.Millisecond
	start := make(chan struct{})
	var wg sync.WaitGroup

	// When
	for index := 0; index < 32; index++ {
		wg.Add(1)
		snapshot := first
		if index%2 != 0 {
			snapshot = second
		}
		go func() {
			defer wg.Done()
			<-start
			runtime.applySnapshot(snapshot)
		}()
	}
	close(start)
	wg.Wait()

	// Then
	runtime.mu.RLock()
	interval := runtime.parameters.PollInterval
	runtime.mu.RUnlock()
	if interval != first.Parameters.PollInterval && interval != second.Parameters.PollInterval {
		t.Fatalf("unexpected final poll interval %v", interval)
	}
}

func runtimeTestSnapshot(t *testing.T, revision uint64) *mtypes.ControlV2Snapshot {
	t.Helper()
	return &mtypes.ControlV2Snapshot{
		Revision: revision,
		IssuedAt: time.Now(),
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        10 * time.Millisecond,
			STUNRequestTimeout:  5 * time.Millisecond,
			STUNRefreshInterval: time.Hour,
			ReportInterval:      10 * time.Millisecond,
			HeartbeatInterval:   time.Second,
		},
	}
}

func waitRuntimeCondition(t *testing.T, timeout time.Duration, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("runtime condition timed out")
}
