package device

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
)

type initialBindScript struct {
	mu       sync.Mutex
	attempts []uint16
	errors   []error
	active   bool
	portZero uint16
}

func (bind *initialBindScript) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.attempts = append(bind.attempts, port)
	if len(bind.errors) > 0 {
		err := bind.errors[0]
		bind.errors = bind.errors[1:]
		if err != nil {
			return nil, 0, err
		}
	}
	bind.active = true
	if port == 0 {
		return nil, bind.portZero, nil
	}
	return nil, port, nil
}

func (bind *initialBindScript) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	bind.active = false
	return nil
}

func (bind *initialBindScript) SetMark(uint32) error { return nil }

func (bind *initialBindScript) Send([]byte, conn.Endpoint) error { return nil }

func (bind *initialBindScript) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, errors.New("initial bind test endpoint is unused")
}

func (bind *initialBindScript) EnabledAf() conn.EnabledAf {
	return conn.EnabledAf{IPv4: true}
}

func (bind *initialBindScript) state() ([]uint16, bool) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	return append([]uint16(nil), bind.attempts...), bind.active
}

func newInitialBindPolicyDevice(t *testing.T, bind *initialBindScript, candidates []uint16) (*Device, <-chan InitialBindResult) {
	t.Helper()

	// Given
	tapDevice, err := tap.CreateDummyTAP()
	if err != nil {
		t.Fatalf("create dummy tap: %v", err)
	}
	graph, err := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("create graph: %v", err)
	}
	config := &mtypes.EdgeConfig{
		NodeID:     1,
		NodeName:   "initial-bind-test",
		DefaultTTL: 64,
		Interface:  mtypes.InterfaceConf{MTU: 1400},
		DynamicRoute: mtypes.DynamicRouteInfo{
			DupCheckTimeout: 1,
		},
	}
	results := make(chan InitialBindResult, 1)
	device := NewDeviceWithInitialBind(tapDevice, 1, bind, NewLogger(LogLevelSilent, "initial-bind-test"), graph, "", config, "test", InitialBindPolicy{
		Candidates: candidates,
		Results:    results,
	})
	t.Cleanup(device.Close)
	return device, results
}

func TestInitialBindPolicyUsesOrderedCandidatesAndEphemeralFallback(t *testing.T) {
	tests := []struct {
		name         string
		candidates   []uint16
		errors       []error
		portZero     uint16
		wantAttempts []uint16
		wantPort     uint16
		wantErr      error
		wantActive   bool
	}{
		{
			name:         "binds the first free candidate",
			candidates:   []uint16{41001, 41002},
			portZero:     53001,
			wantAttempts: []uint16{41001},
			wantPort:     41001,
			wantActive:   true,
		},
		{
			name:         "advances after address in use",
			candidates:   []uint16{41001, 41002},
			errors:       []error{fmt.Errorf("first candidate: %w", syscall.EADDRINUSE), nil},
			portZero:     53002,
			wantAttempts: []uint16{41001, 41002},
			wantPort:     41002,
			wantActive:   true,
		},
		{
			name:         "uses port zero after every candidate is occupied",
			candidates:   []uint16{41001, 41002},
			errors:       []error{fmt.Errorf("first candidate: %w", syscall.EADDRINUSE), fmt.Errorf("second candidate: %w", syscall.EADDRINUSE), nil},
			portZero:     53003,
			wantAttempts: []uint16{41001, 41002, 0},
			wantPort:     53003,
			wantActive:   true,
		},
		{
			name:         "stops on permission denied without a listener",
			candidates:   []uint16{41001, 41002},
			errors:       []error{fmt.Errorf("first candidate: %w", syscall.EACCES)},
			portZero:     53004,
			wantAttempts: []uint16{41001},
			wantErr:      syscall.EACCES,
			wantActive:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			bind := &initialBindScript{errors: test.errors, portZero: test.portZero}
			device, results := newInitialBindPolicyDevice(t, bind, test.candidates)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			t.Cleanup(cancel)

			// When
			var result InitialBindResult
			select {
			case result = <-results:
			case <-ctx.Done():
				t.Fatal("initial bind result timed out")
			}

			// Then
			if !errors.Is(result.Err, test.wantErr) {
				t.Fatalf("initial bind error = %v, want errors.Is(_, %v)", result.Err, test.wantErr)
			}
			if result.Port != test.wantPort {
				t.Fatalf("reported port = %d, want %d", result.Port, test.wantPort)
			}
			attempts, active := bind.state()
			if !reflect.DeepEqual(attempts, test.wantAttempts) {
				t.Fatalf("bind attempts = %v, want %v", attempts, test.wantAttempts)
			}
			if active != test.wantActive {
				t.Fatalf("listener active = %t, want %t", active, test.wantActive)
			}
			if result.Err == nil {
				device.net.RLock()
				port := device.net.port
				device.net.RUnlock()
				if port != test.wantPort {
					t.Fatalf("device port before readiness = %d, want %d", port, test.wantPort)
				}
				runtime := NewSuperHTTPRuntime(device, mtypes.EdgeConfigV2{})
				device.superHTTP = runtime
				device.SuperHTTPReady()
				ready := <-runtime.ready
				if ready.port != int(test.wantPort) {
					t.Fatalf("SuperHTTP ready port = %d, want %d", ready.port, test.wantPort)
				}
				device.applySuperHTTPSnapshot(&mtypes.ControlV2Snapshot{}, 0)
				attempts, _ = bind.state()
				if !reflect.DeepEqual(attempts, test.wantAttempts) {
					t.Fatalf("snapshot bind attempts = %v, want %v", attempts, test.wantAttempts)
				}
			}
		})
	}
}
