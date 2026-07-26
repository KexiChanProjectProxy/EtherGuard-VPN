package device

import (
	"encoding/hex"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestFilterWindowUsesEdgeDampingRadius(t *testing.T) {
	// Given
	window := filterwindow{device: &Device{dampingFilterRadius: 1}}

	// When
	window.Push(5)
	window.Push(1)
	actual := window.Push(3)

	// Then
	if actual != 3 {
		t.Fatalf("filtered value = %v, want 3", actual)
	}
}

func TestHandlePublicKeyLineCreatesConfiguredEdgePeer(t *testing.T) {
	// Given
	var publicKey NoisePublicKey
	publicKey[0] = 1
	device := &Device{
		EdgeConfig: &mtypes.EdgeConfig{Peers: []mtypes.PeerInfo{{
			NodeID: 12,
			PubKey: publicKey.ToString(),
		}}},
		LogLevel: mtypes.LoggerInfo{},
		log:      NewLogger(LogLevelSilent, "test"),
	}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	device.peers.SuperPeer = make(map[NoisePublicKey]*Peer)
	configuredPeer := &ipcSetPeer{}

	// When
	err := device.handlePublicKeyLine(configuredPeer, hex.EncodeToString(publicKey[:]))

	// Then
	if err != nil {
		t.Fatalf("handlePublicKeyLine: %v", err)
	}
	if !configuredPeer.created || configuredPeer.Peer == nil || configuredPeer.Peer.ID != 12 {
		t.Fatalf("configured peer = %+v, want newly created peer 12", configuredPeer.Peer)
	}
}
