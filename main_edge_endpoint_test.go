package main

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestInitialPeerEndpointErrorIsRecoverableInP2PMode(t *testing.T) {
	// Given
	lookupErr := fmt.Errorf("dial udp6: %w", syscall.ENETUNREACH)

	// When
	err := initialPeerEndpointError(true, lookupErr)

	// Then
	if err != nil {
		t.Fatalf("P2P startup treated an unreachable peer endpoint as fatal: %v", err)
	}
}

func TestInitialPeerEndpointErrorRemainsFatalOutsideP2PMode(t *testing.T) {
	// Given
	lookupErr := fmt.Errorf("dial udp6: %w", syscall.ENETUNREACH)

	// When
	err := initialPeerEndpointError(false, lookupErr)

	// Then
	if !errors.Is(err, lookupErr) {
		t.Fatalf("static mode discarded endpoint setup error: %v", err)
	}
}

func TestInitialPeerEndpointErrorRejectsInvalidP2PEndpoint(t *testing.T) {
	// Given
	lookupErr := errors.New("missing port in address")

	// When
	err := initialPeerEndpointError(true, lookupErr)

	// Then
	if !errors.Is(err, lookupErr) {
		t.Fatalf("P2P startup discarded a permanent endpoint configuration error: %v", err)
	}
}

func TestStaticAndP2PEdgeFixturesParseWithoutLegacySuper(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		useP2P bool
	}{
		{name: "static", path: "example_config/static_mode/EgNet_edge1.yaml", useP2P: false},
		{name: "p2p", path: "example_config/p2p_mode/EgNet_edge1.yaml", useP2P: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			var cfg mtypes.EdgeConfig

			// When
			err := mtypes.ReadYaml(tc.path, &cfg)

			// Then
			if err != nil {
				t.Fatalf("parse fixture: %v", err)
			}
			if cfg.DynamicRoute.P2P.UseP2P != tc.useP2P {
				t.Fatalf("UseP2P = %t, want %t", cfg.DynamicRoute.P2P.UseP2P, tc.useP2P)
			}
			if cfg.SuperNodeV2Enabled {
				t.Fatal("legacy fixture unexpectedly enables v2 Super mode")
			}
		})
	}
}
