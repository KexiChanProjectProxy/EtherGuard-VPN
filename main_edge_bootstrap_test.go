package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

func edgeBootstrapConfig(serverURL string) mtypes.EdgeConfigV2 {
	return mtypes.EdgeConfigV2{
		NodeID: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       serverURL,
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "test-control-key",
		},
	}
}

func TestEdgeBootstrapExpandsPolicyInDeclaredOrder(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/edge/v2/bootstrap" {
			t.Fatalf("bootstrap path = %q", request.URL.Path)
		}
		_, _ = fmt.Fprint(w, `{"ListenPortPriority":[{"port":41001},{"range":{"from":41002,"to":41003}},{"port":41001}]}`)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	// When
	ports, _, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

	// Then
	if err != nil {
		t.Fatalf("bootstrap initial bind: %v", err)
	}
	want := []uint16{41001, 41002, 41003}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("candidate ports = %v, want %v", ports, want)
	}
}

func TestEdgeBootstrapReturnsStatusErrorForWrongResponse(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	// When
	_, _, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

	// Then
	var statusErr *device.BootstrapStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("bootstrap error = %v, want BootstrapStatusError", err)
	}
}

func TestEdgeBootstrapReturnsDecodeErrorForMalformedResponse(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "{")
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	// When
	_, _, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

	// Then
	var decodeErr *device.BootstrapDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("bootstrap error = %v, want BootstrapDecodeError", err)
	}
}

func TestEdgeBootstrapReturnsInvalidPolicyErrorForEmptyPolicy(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ListenPortPriority":[]}`)
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	// When
	_, _, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

	// Then
	var policyErr *device.BootstrapInvalidPolicyError
	if !errors.As(err, &policyErr) {
		t.Fatalf("bootstrap error = %v, want BootstrapInvalidPolicyError", err)
	}
}

func TestEdgeBootstrapReturnsContextDeadlineForSlowServer(t *testing.T) {
	// Given
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)

	// When
	_, _, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

	// Then
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrap error = %v, want context deadline exceeded", err)
	}
}

func TestBootstrapFirstURLHangsSecondHealthy(t *testing.T) {
	// Given
	first := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(first.Close)
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"ListenPortPriority":[{"port":42001}]}`)
	}))
	t.Cleanup(second.Close)
	config := edgeBootstrapConfig(first.URL)
	config.SuperNodeV2.APIUrls = []string{second.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	// When
	ports, startIdx, err := bootstrapInitialBind(ctx, config)

	// Then
	if err != nil {
		t.Fatalf("bootstrap initial bind: %v", err)
	}
	if startIdx != 1 {
		t.Fatalf("bootstrap start index = %d, want 1", startIdx)
	}
	if want := []uint16{42001}; !reflect.DeepEqual(ports, want) {
		t.Fatalf("candidate ports = %v, want %v", ports, want)
	}
}

func TestBootstrapAllURLsFail(t *testing.T) {
	// Given
	var firstRequests atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstRequests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(first.Close)
	var secondRequests atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondRequests.Add(1)
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	t.Cleanup(second.Close)
	config := validEdgeTemplate()
	config.SuperNodeV2.APIUrl = first.URL
	config.SuperNodeV2.APIUrls = []string{second.URL}
	body, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("marshal edge config: %v", err)
	}
	configPath := filepath.Join(t.TempDir(), "edge.yaml")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatalf("write edge config: %v", err)
	}
	var deviceConstructionAttempts atomic.Int32

	// When
	err = runEdge(edgeRunConfig{
		configPath: configPath,
		bindmode:   "std",
		beforeInitialBindDevice: func() {
			deviceConstructionAttempts.Add(1)
		},
	})

	// Then
	if err == nil {
		t.Fatal("bootstrap unexpectedly succeeded")
	}
	var statusErr *device.BootstrapStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("bootstrap error = %v, want final URL status %d", err, http.StatusGatewayTimeout)
	}
	if firstRequests.Load() != 1 || secondRequests.Load() != 1 {
		t.Fatalf("bootstrap request counts = (%d, %d), want (1, 1)", firstRequests.Load(), secondRequests.Load())
	}
	if deviceConstructionAttempts.Load() != 0 {
		t.Fatalf("device construction attempts = %d, want 0", deviceConstructionAttempts.Load())
	}
}

func TestBootstrapDecodeErrorStopsIteration(t *testing.T) {
	// Given
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "{")
	}))
	t.Cleanup(first.Close)
	var secondRequests atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondRequests.Add(1)
		_, _ = fmt.Fprint(w, `{"ListenPortPriority":[{"port":43001}]}`)
	}))
	t.Cleanup(second.Close)
	config := edgeBootstrapConfig(first.URL)
	config.SuperNodeV2.APIUrls = []string{second.URL}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)

	// When
	ports, startIdx, err := bootstrapInitialBind(ctx, config)

	// Then
	var decodeErr *device.BootstrapDecodeError
	if !errors.As(err, &decodeErr) {
		t.Fatalf("bootstrap error = %v, want BootstrapDecodeError", err)
	}
	if ports != nil || startIdx != 0 {
		t.Fatalf("bootstrap result = (%v, %d), want (nil, 0)", ports, startIdx)
	}
	if secondRequests.Load() != 0 {
		t.Fatalf("second URL requests = %d, want 0", secondRequests.Load())
	}
}
