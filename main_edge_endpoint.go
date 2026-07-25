package main

import (
	"errors"
	"net"
	"syscall"
)

func initialPeerEndpointError(useP2P bool, err error) error {
	if err == nil || (useP2P && retryableEndpointError(err)) {
		return nil
	}
	return err
}

func retryableEndpointError(err error) bool {
	if errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary())
}
