package main

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
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
