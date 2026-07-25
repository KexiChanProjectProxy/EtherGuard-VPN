package device

import (
	"fmt"
	"runtime"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

func (device *Device) enqueuePacket(params *packet_send_params) {
	select {
	case device.chan_send_packet <- params:
	default:
		device.PutMessageBuffer(params.elem.buffer)
		device.PutOutboundElement(params.elem)
		device.sendQueueDrops.Add(1)
	}
}

func (device *Device) signalEndpointRetry() {
	select {
	case device.event_tryendpoint <- struct{}{}:
	default:
	}
}

func (peer *Peer) AddEndpointRetry(connURL string, static bool) {
	peer.Lock()
	peer.StaticConn = static
	peer.ConnURL = connURL
	if peer.device != nil {
		peer.ConnAF = peer.device.enabledAf
	}
	peer.Unlock()

	peer.endpoint_trylist.Lock()
	defer peer.endpoint_trylist.Unlock()
	if _, exists := peer.endpoint_trylist.trymap_super[connURL]; exists {
		return
	}
	peer.endpoint_trylist.trymap_super[connURL] = &endpoint_tryitem{
		URL:     connURL,
		lastTry: time.Time{},
	}
}

func (peer *Peer) endpointRetryConfig() (static bool, connURL string, connAF conn.EnabledAf) {
	peer.RLock()
	defer peer.RUnlock()
	return peer.StaticConn, peer.ConnURL, peer.ConnAF
}

func (peer *Peer) acceptsDiscoveredEndpoints() bool {
	peer.RLock()
	defer peer.RUnlock()
	return !peer.StaticConn
}

func (device *Device) retryPeersSnapshot() []*Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()
	peers := make([]*Peer, 0, len(device.peers.IDMap))
	for _, peer := range device.peers.IDMap {
		peers = append(peers, peer)
	}
	return peers
}

func (device *Device) allPeersSnapshot() []*Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()
	peers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peers = append(peers, peer)
	}
	return peers
}

func (device *Device) activeListenPort() int {
	device.net.RLock()
	defer device.net.RUnlock()
	return int(device.net.port)
}

func (device *Device) logQueueState() {
	if !device.LogLevel.LogInternal {
		return
	}
	fmt.Printf(
		"Internal: Packet dispatch state queued=%d capacity=%d dropped_since_last=%d goroutines=%d\n",
		len(device.chan_send_packet),
		cap(device.chan_send_packet),
		device.sendQueueDrops.Swap(0),
		runtime.NumGoroutine(),
	)
}
