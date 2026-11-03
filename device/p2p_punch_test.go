package device

import (
	"net/netip"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

const (
	punchTestCurrent    = "203.0.113.11:3001"
	punchTestAdvertised = "203.0.113.12:50000"
)

func advertise(t *testing.T, device *Device, peer *Peer, pub NoisePublicKey, url string) {
	t.Helper()
	err := device.process_BoardcastPeerMsg(peer, mtypes.BoardcastPeerMsg{NodeID: peer.ID, PubKey: pub, ConnURL: url})
	if err != nil {
		t.Fatalf("process_BoardcastPeerMsg: %v", err)
	}
}

func giveTestKeypair(peer *Peer) {
	peer.keypairs.current = &Keypair{created: time.Now()}
}

func killTestPeer(peer *Peer) {
	dead := time.Now().Add(-time.Hour)
	peer.LastPacketReceivedAdd1Sec.Store(&dead)
}

func assertNothingQueued(t *testing.T, device *Device) {
	t.Helper()
	time.Sleep(20 * time.Millisecond)
	if queued := len(device.chan_send_packet); queued != 0 {
		t.Fatalf("queued %d packets, want none", queued)
	}
}

func TestBoardcastPeerAlivePeerPingsNewURLOnce(t *testing.T) {
	for name, pure := range map[string]bool{"p2p": false, "pure p2p": true} {
		t.Run(name, func(t *testing.T) {
			// Given a live peer with a session and a prober-pinned endpoint
			device, peer, pub := newBroadcastReceiver(t)
			device.EdgeConfig.DynamicRoute.P2P.PureP2P = pure
			device.EdgeConfig.DynamicRoute.SendPingInterval = 60
			giveTestKeypair(peer)
			peer.endpointPinned.Store(true)

			// When a new address is advertised twice
			advertise(t, device, peer, pub, punchTestAdvertised)
			advertise(t, device, peer, pub, punchTestAdvertised)

			// Then one probe ping goes there and nothing else moves
			if queued := len(device.chan_send_packet); queued != 1 {
				t.Fatalf("queued %d packets, want 1", queued)
			}
			params := <-device.chan_send_packet
			if params.elem.endpoint == nil || params.elem.endpoint.DstToString() != punchTestAdvertised {
				t.Fatalf("ping endpoint = %v, want %s", params.elem.endpoint, punchTestAdvertised)
			}
			ping, err := mtypes.ParsePingMsg(params.elem.packet[path.EgHeaderLen:])
			if err != nil || ping.RequestID == 0 {
				t.Fatalf("ping = %+v err=%v, want a probe that stays out of latency state", ping, err)
			}
			device.PutMessageBuffer(params.elem.buffer)
			device.PutOutboundElement(params.elem)
			if got := peer.GetEndpointDstStr(); got != punchTestCurrent {
				t.Fatalf("stored endpoint = %s", got)
			}
			if !peer.endpointPinned.Load() {
				t.Fatal("prober pin was cleared")
			}
			advertised := peer.advertised.candidates(time.Now(), time.Minute)
			if len(advertised) != 1 || advertised[0].address != punchTestAdvertised {
				t.Fatalf("advertised = %+v", advertised)
			}
		})
	}
}

func TestBoardcastPeerAlivePeerPingsAgainAfterInterval(t *testing.T) {
	// Given a limiter with an interval that has already passed
	device, peer, pub := newBroadcastReceiver(t)
	device.EdgeConfig.DynamicRoute.SendPingInterval = 0.001
	giveTestKeypair(peer)
	advertise(t, device, peer, pub, punchTestAdvertised)
	time.Sleep(5 * time.Millisecond)

	// When
	advertise(t, device, peer, pub, punchTestAdvertised)

	// Then
	if queued := len(device.chan_send_packet); queued != 2 {
		t.Fatalf("queued %d packets, want 2", queued)
	}
}

func TestAdvertisedPingLimiterUsesDefaultWhenIntervalUnset(t *testing.T) {
	// Given SendPingInterval 0
	device, peer, pub := newBroadcastReceiver(t)
	device.EdgeConfig.DynamicRoute.SendPingInterval = 0
	giveTestKeypair(peer)

	// When
	advertise(t, device, peer, pub, punchTestAdvertised)
	advertise(t, device, peer, pub, punchTestAdvertised)

	// Then the limiter still holds
	if queued := len(device.chan_send_packet); queued != 1 {
		t.Fatalf("queued %d packets, want 1", queued)
	}
}

func TestAdvertisedPingLimiterIsBounded(t *testing.T) {
	var limiter advertisedPingLimiter
	now := time.Now()
	for i := 0; i < maxAdvertisedPingEntries; i++ {
		if !limiter.allow(netip.AddrPortFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}), 1).String(), now, time.Minute) {
			t.Fatalf("entry %d refused", i)
		}
	}
	if limiter.allow("198.51.100.1:1", now, time.Minute) {
		t.Fatal("limiter grew past its bound")
	}
	if !limiter.allow("198.51.100.1:1", now.Add(time.Hour), time.Minute) {
		t.Fatal("expired entries were not pruned")
	}
	if len(limiter.sent) != 1 {
		t.Fatalf("entries = %d, want 1", len(limiter.sent))
	}
}

func TestBoardcastPeerAlivePeerSkipsPing(t *testing.T) {
	cases := map[string]struct {
		url     string
		keypair bool
		prepare func(device *Device)
	}{
		"without keypair":  {url: punchTestAdvertised},
		"current endpoint": {url: punchTestCurrent, keypair: true},
		"blacklisted": {url: punchTestAdvertised, keypair: true, prepare: func(device *Device) {
			device.setEndpointBlacklist([]netip.Prefix{netip.MustParsePrefix("203.0.113.12/32")})
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Given
			device, peer, pub := newBroadcastReceiver(t)
			if tc.keypair {
				giveTestKeypair(peer)
			}
			if tc.prepare != nil {
				tc.prepare(device)
			}

			// When
			advertise(t, device, peer, pub, tc.url)

			// Then
			assertNothingQueued(t, device)
		})
	}
}

func TestBoardcastPeerDeadPeerSwitchesAndPunchesImmediately(t *testing.T) {
	for name, pure := range map[string]bool{"p2p": false, "pure p2p": true} {
		t.Run(name, func(t *testing.T) {
			// Given a dead peer whose try-list already holds an older address
			device, peer, pub := newBroadcastReceiver(t)
			device.EdgeConfig.DynamicRoute.P2P.PureP2P = pure
			killTestPeer(peer)
			peer.endpoint_trylist.UpdateP2P("203.0.113.99:3001")

			// When
			advertise(t, device, peer, pub, punchTestAdvertised)

			// Then the endpoint moved without GetNextTry reaching the address
			if got := peer.GetEndpointDstStr(); got != punchTestAdvertised {
				t.Fatalf("stored endpoint = %s, want %s", got, punchTestAdvertised)
			}
			if !peerEndpointRetryHeld(peer) {
				t.Fatal("handshake grace not armed")
			}
			peer.endpoint_trylist.RLock()
			item := peer.endpoint_trylist.trymap_p2p[punchTestAdvertised]
			peer.endpoint_trylist.RUnlock()
			if item == nil || item.firstTry.IsZero() {
				t.Fatalf("try-list entry = %+v, want it marked as tried", item)
			}
			// and the burst pings on the stored endpoint
			select {
			case params := <-device.chan_send_packet:
				if params.elem.Type != path.PingPacket || params.elem.endpoint != nil {
					t.Fatalf("queued %v to %v, want a ping on the stored endpoint", params.elem.Type, params.elem.endpoint)
				}
				device.PutMessageBuffer(params.elem.buffer)
				device.PutOutboundElement(params.elem)
			case <-time.After(2 * time.Second):
				t.Fatal("no punch burst")
			}
		})
	}
}

func TestBoardcastPeerDeadPeerBurstsOncePerGraceWindow(t *testing.T) {
	// Given a dead peer already on the advertised address, where
	// SetEndpointFromConnURL itself would not arm the grace
	device, peer, pub := newBroadcastReceiver(t)
	killTestPeer(peer)

	// When the same address is advertised repeatedly
	for i := 0; i < 5; i++ {
		advertise(t, device, peer, pub, punchTestCurrent)
	}

	// Then one burst runs
	time.Sleep(50 * time.Millisecond)
	if queued := len(device.chan_send_packet); queued != 1 {
		t.Fatalf("queued %d pings, want 1 burst of 1", queued)
	}
}

func TestBoardcastPeerDeadPeerUnderGraceOnlyQueues(t *testing.T) {
	// Given a dead peer inside the handshake grace
	device, peer, pub := newBroadcastReceiver(t)
	killTestPeer(peer)
	peer.lastEndpointChange.Store(time.Now().UnixNano())

	// When
	advertise(t, device, peer, pub, punchTestAdvertised)

	// Then the address only joins the try-list
	if got := peer.GetEndpointDstStr(); got != punchTestCurrent {
		t.Fatalf("stored endpoint = %s", got)
	}
	peer.endpoint_trylist.RLock()
	_, listed := peer.endpoint_trylist.trymap_p2p[punchTestAdvertised]
	peer.endpoint_trylist.RUnlock()
	if !listed {
		t.Fatal("address missing from the try-list")
	}
	if len(device.event_tryendpoint) == 0 {
		t.Fatal("no retry signalled")
	}
	assertNothingQueued(t, device)
}

func TestBoardcastPeerDeadPeerIgnoresBlacklistedURL(t *testing.T) {
	// Given
	device, peer, pub := newBroadcastReceiver(t)
	killTestPeer(peer)
	peer.ConnURL = punchTestCurrent
	device.setEndpointBlacklist([]netip.Prefix{netip.MustParsePrefix("203.0.113.12/32")})

	// When
	advertise(t, device, peer, pub, punchTestAdvertised)

	// Then neither the endpoint nor the retry configuration moved
	if got := peer.GetEndpointDstStr(); got != punchTestCurrent {
		t.Fatalf("stored endpoint = %s", got)
	}
	if peer.ConnURL != punchTestCurrent {
		t.Fatalf("ConnURL = %s", peer.ConnURL)
	}
	assertNothingQueued(t, device)
}
