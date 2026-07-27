package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
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
	ports, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

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
	_, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

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
	_, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

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
	_, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

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
	_, err := bootstrapInitialBind(ctx, edgeBootstrapConfig(server.URL))

	// Then
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bootstrap error = %v, want context deadline exceeded", err)
	}
}
