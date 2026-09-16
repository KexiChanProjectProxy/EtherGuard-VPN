package device

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type failoverTestClock struct {
	nanos atomic.Int64
}

func newFailoverTestClock(now time.Time) *failoverTestClock {
	clock := &failoverTestClock{}
	clock.nanos.Store(now.UnixNano())
	return clock
}

func (clock *failoverTestClock) Now() time.Time {
	return time.Unix(0, clock.nanos.Load()).UTC()
}

func (clock *failoverTestClock) Advance(elapsed time.Duration) {
	clock.nanos.Add(int64(elapsed))
}

type failoverServerConfig struct {
	Register func(http.ResponseWriter, *http.Request, int32, mtypes.ControlV2RegisterRequest)
	Report   func(http.ResponseWriter, *http.Request, int32)
	Snapshot func(http.ResponseWriter, *http.Request)
	Events   func(http.ResponseWriter, *http.Request)
}

type failoverTestServer struct {
	server        *httptest.Server
	registerCalls atomic.Int32
	reportCalls   atomic.Int32
	lastNodeID    atomic.Uint32
}

func newFailoverTestServer(t *testing.T, config failoverServerConfig) *failoverTestServer {
	t.Helper()
	super := &failoverTestServer{}
	super.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/edge/v2/register":
			var register mtypes.ControlV2RegisterRequest
			if err := json.NewDecoder(request.Body).Decode(&register); err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}
			call := super.registerCalls.Add(1)
			super.lastNodeID.Store(uint32(register.NodeID))
			if config.Register != nil {
				config.Register(writer, request, call, register)
				return
			}
			writeFailoverSnapshot(writer, failoverSnapshot(uint64(call), 20*time.Millisecond))
		case "/edge/v2/report":
			call := super.reportCalls.Add(1)
			if config.Report != nil {
				config.Report(writer, request, call)
				return
			}
			writer.WriteHeader(http.StatusAccepted)
		case "/edge/v2/snapshot":
			if config.Snapshot != nil {
				config.Snapshot(writer, request)
				return
			}
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		case "/edge/v2/events":
			if config.Events != nil {
				config.Events(writer, request)
				return
			}
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(super.server.Close)
	return super
}

func (super *failoverTestServer) URL() string {
	return super.server.URL
}

func failoverSnapshot(revision uint64, reportInterval time.Duration) *mtypes.ControlV2Snapshot {
	return &mtypes.ControlV2Snapshot{
		Revision: revision,
		IssuedAt: time.Unix(int64(revision), 0).UTC(),
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        time.Hour,
			STUNRefreshInterval: time.Hour,
			ReportInterval:      reportInterval,
			HeartbeatInterval:   time.Hour,
		},
	}
}

func writeFailoverSnapshot(writer http.ResponseWriter, snapshot *mtypes.ControlV2Snapshot) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(snapshot)
}

type failoverRuntimeConfig struct {
	URLs           []string
	Clock          *failoverTestClock
	StartIndex     int
	ReportInterval time.Duration
}

type failoverRuntimeHandle struct {
	runtime *SuperHTTPRuntime
	ctx     context.Context
	cancel  context.CancelFunc
	ready   superHTTPReady
}

func startFailoverRuntime(t *testing.T, config failoverRuntimeConfig) *failoverRuntimeHandle {
	t.Helper()
	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		NodeID:     47100,
		NodeName:   "failover-edge",
		DefaultTTL: 64,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      append([]string(nil), config.URLs...),
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: "failover-key",
		},
	}, WithStartIndex(config.StartIndex))
	if config.Clock != nil {
		runtime.SetClockForTest(config.Clock.Now)
	}
	if config.ReportInterval > 0 {
		runtime.parameters.ReportInterval = config.ReportInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	ready := superHTTPReady{port: 51820, v4: net.ParseIP("10.0.0.10")}
	runtime.Start(ctx)
	runtime.MarkReady(ready.port, ready.fwmark, ready.v4, ready.v6)
	handle := &failoverRuntimeHandle{runtime: runtime, ctx: ctx, cancel: cancel, ready: ready}
	t.Cleanup(func() {
		cancel()
		select {
		case <-runtime.Done():
		case <-time.After(time.Second):
			t.Errorf("failover runtime did not stop")
		}
	})
	return handle
}
