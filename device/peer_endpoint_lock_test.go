package device

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type blockingEndpoint struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (e *blockingEndpoint) ClearSrc() {}

func (e *blockingEndpoint) SrcToString() string { return "127.0.0.1:1000" }

func (e *blockingEndpoint) DstToString() string {
	e.once.Do(func() {
		close(e.entered)
		<-e.release
	})
	return "127.0.0.1:1000"
}

func (e *blockingEndpoint) DstToBytes() []byte { return net.IPv4(127, 0, 0, 1) }

func (e *blockingEndpoint) DstIP() net.IP { return net.IPv4(127, 0, 0, 1) }

func (e *blockingEndpoint) SrcIP() net.IP { return nil }

func TestSetEndpointFromPacket_doesNotHoldPeerLockDuringLocalAddressProbe(t *testing.T) {
	// Given
	endpoint := &blockingEndpoint{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	peer := &Peer{
		ID:     mtypes.NodeID_SuperNode,
		device: &Device{EdgeConfig: &mtypes.EdgeConfig{}},
	}
	setDone := make(chan struct{})
	go func() {
		peer.SetEndpointFromPacket(endpoint)
		close(setDone)
	}()
	<-endpoint.entered

	// When
	endpointUpdated := make(chan bool, 1)
	go func() {
		peer.RLock()
		endpointUpdated <- peer.endpoint == endpoint
		peer.RUnlock()
	}()

	// Then
	select {
	case updated := <-endpointUpdated:
		if !updated {
			t.Fatal("peer endpoint was not updated before local-address discovery")
		}
	case <-time.After(250 * time.Millisecond):
		close(endpoint.release)
		<-setDone
		t.Fatal("peer read lock was blocked by local-address discovery")
	}
	close(endpoint.release)
	<-setDone
}
