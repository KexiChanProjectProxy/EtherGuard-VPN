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

type staticTestEndpoint struct {
	dst net.IP
	src net.IP
}

func (e staticTestEndpoint) ClearSrc() {}

func (e staticTestEndpoint) SrcToString() string { return net.JoinHostPort(e.src.String(), "1") }

func (e staticTestEndpoint) DstToString() string { return net.JoinHostPort(e.dst.String(), "51820") }

func (e staticTestEndpoint) DstToBytes() []byte { return e.dst }

func (e staticTestEndpoint) DstIP() net.IP { return e.dst }

func (e staticTestEndpoint) SrcIP() net.IP { return e.src }

func TestSetEndpointFromPacketSkipsDifferentIPWhileAlive(t *testing.T) {
	now := time.Now()
	current := staticTestEndpoint{dst: net.ParseIP("192.0.2.10"), src: net.ParseIP("192.0.2.1")}
	other := staticTestEndpoint{dst: net.ParseIP("192.0.2.20"), src: net.ParseIP("192.0.2.1")}
	sameIPNewPort := staticTestEndpoint{dst: net.ParseIP("192.0.2.10"), src: net.ParseIP("192.0.2.1")}
	peer := &Peer{device: &Device{EdgeConfig: &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{PeerAliveTimeout: 70}}}}
	peer.LastPacketReceivedAdd1Sec.Store(&now)
	peer.endpoint = current

	peer.SetEndpointFromPacket(other)
	if !peer.endpoint.DstIP().Equal(current.dst) {
		t.Fatalf("roamed to %v while alive, want %v", peer.endpoint.DstIP(), current.dst)
	}

	peer.SetEndpointFromPacket(sameIPNewPort)
	if !peer.endpoint.DstIP().Equal(current.dst) {
		t.Fatalf("same-IP roam lost dest %v", peer.endpoint.DstIP())
	}
}

func TestPeerEndpointRetryHeldDuringHandshakeGrace(t *testing.T) {
	peer := &Peer{}
	if peerEndpointRetryHeld(peer) {
		t.Fatal("zero lastEndpointChange should not hold retry")
	}
	peer.lastEndpointChange.Store(time.Now().UnixNano())
	if !peerEndpointRetryHeld(peer) {
		t.Fatal("fresh endpoint change should hold retry")
	}
	peer.lastEndpointChange.Store(time.Now().Add(-endpointHandshakeGrace - time.Second).UnixNano())
	if peerEndpointRetryHeld(peer) {
		t.Fatal("expired handshake grace still holding retry")
	}
}
