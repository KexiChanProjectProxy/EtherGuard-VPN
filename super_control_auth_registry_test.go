package main

import (
	"net/http"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestControlAuthRegisterTestKeyOverridesRegistryCredential(t *testing.T) {
	const (
		nodeID mtypes.Vertex = 42
		keyV1                = "registry-key-v1"
		keyV2                = "test-key-v2"
	)
	tests := []struct {
		name       string
		signingKey string
		wantError  bool
	}{
		{name: "rejects superseded registry key", signingKey: keyV1, wantError: true},
		{name: "accepts replacement test key", signingKey: keyV2, wantError: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			clock := newFakeClock()
			state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
			auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
			state.SetPreAuthorized(nodeID, keyV1)
			auth.RegisterTestKey(nodeID, keyV2)

			// When
			request := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, test.signingKey, clock)
			_, _, err := auth.Verify(request)

			// Then
			if test.wantError && err == nil {
				t.Fatalf("Verify accepted superseded registry key %q", test.signingKey)
			}
			if !test.wantError && err != nil {
				t.Fatalf("Verify rejected replacement test key %q: %v", test.signingKey, err)
			}
		})
	}
}
