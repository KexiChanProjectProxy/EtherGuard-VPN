package device

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"github.com/KusakabeSi/EtherGuard-VPN/tap"
)

const (
	replyTestStored  = "203.0.113.20:3001"
	replyTestArrival = "198.51.100.30:40000"
)

// sendRecordingBind records datagram destinations; senders run concurrently.
type sendRecordingBind struct {
	*pinningSTUNFake
	sendMu sync.Mutex
	sent   []string
}

func (b *sendRecordingBind) Send(_ []byte, endpoint conn.Endpoint) error {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	b.sent = append(b.sent, endpoint.DstToString())
	return nil
}

func (b *sendRecordingBind) destinations() []string {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	return append([]string(nil), b.sent...)
}

// settledDestinations waits for want datagrams, then long enough to catch any
// surplus one from the encryption and sender goroutines.
func (b *sendRecordingBind) settledDestinations(want int) []string {
	deadline := time.Now().Add(2 * time.Second)
	for len(b.destinations()) < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	return b.destinations()
}

type replyTestEdge struct {
	device *Device
	bind   *sendRecordingBind
	public NoisePublicKey
}

func newReplyTestEdge(t *testing.T, id mtypes.Vertex) *replyTestEdge {
	t.Helper()
	tapDevice, err := tap.CreateDummyTAP()
	if err != nil {
		t.Fatalf("dummy tap: %v", err)
	}
	graph, err := path.NewGraph(3, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	config := &mtypes.EdgeConfig{
		NodeID:     id,
		DefaultTTL: 64,
		Interface:  mtypes.InterfaceConf{MTU: 1400},
		DynamicRoute: mtypes.DynamicRouteInfo{
			PeerAliveTimeout: 70,
			DupCheckTimeout:  1,
			P2P:              mtypes.P2PInfo{UseP2P: true},
		},
	}
	bind := &sendRecordingBind{pinningSTUNFake: newPinningSTUNFake(uint16(3000 + int(id)))}
	device := NewDevice(tapDevice, id, bind, NewLogger(LogLevelSilent, "reply-test"), graph, "", config, "test")
	t.Cleanup(device.Close)
	private, public := RandomKeyPair()
	if err := device.SetPrivateKey(private); err != nil {
		t.Fatalf("private key: %v", err)
	}
	if err := device.Up(); err != nil {
		t.Fatalf("up: %v", err)
	}
	return &replyTestEdge{device: device, bind: bind, public: public}
}

// newReplyTestPair returns a responder with stored endpoint replyTestStored and
// a remote that can produce real initiations for it.
func newReplyTestPair(t *testing.T) (local *replyTestEdge, remote *replyTestEdge, remoteAtLocal, localAtRemote *Peer) {
	t.Helper()
	local = newReplyTestEdge(t, 1)
	remote = newReplyTestEdge(t, 2)
	var err error
	if remoteAtLocal, err = local.device.NewPeer(remote.public, 2, false, 0); err != nil {
		t.Fatalf("new peer: %v", err)
	}
	if localAtRemote, err = remote.device.NewPeer(local.public, 1, false, 0); err != nil {
		t.Fatalf("new peer: %v", err)
	}
	remoteAtLocal.endpoint, _ = local.bind.ParseEndpoint(replyTestStored)
	return local, remote, remoteAtLocal, localAtRemote
}

func setPeerLastPacket(peer *Peer, at time.Time) {
	peer.LastPacketReceivedAdd1Sec.Store(&at)
}

// establishSession completes a real handshake that local initiated, which
// makes the keypair current at once.
func establishSession(t *testing.T, local, remote *replyTestEdge, remoteAtLocal, localAtRemote *Peer) *Keypair {
	t.Helper()
	initiation, err := local.device.CreateMessageInitiation(remoteAtLocal)
	if err != nil {
		t.Fatalf("create initiation: %v", err)
	}
	if remote.device.ConsumeMessageInitiation(initiation) == nil {
		t.Fatal("remote rejected the initiation")
	}
	response, err := remote.device.CreateMessageResponse(localAtRemote)
	if err != nil {
		t.Fatalf("create response: %v", err)
	}
	if local.device.ConsumeMessageResponse(response) == nil {
		t.Fatal("local rejected the response")
	}
	if err := remoteAtLocal.BeginSymmetricSession(); err != nil {
		t.Fatalf("begin session: %v", err)
	}
	keypair := remoteAtLocal.keypairs.Current()
	if keypair == nil {
		t.Fatal("initiator has no current keypair")
	}
	return keypair
}

// consumeRemoteInitiation feeds local a fresh initiation from remote, past the
// per-peer initiation rate limit.
func consumeRemoteInitiation(t *testing.T, local, remote *replyTestEdge, remoteAtLocal, localAtRemote *Peer) {
	t.Helper()
	time.Sleep(HandshakeInitationRate + 10*time.Millisecond)
	initiation, err := remote.device.CreateMessageInitiation(localAtRemote)
	if err != nil {
		t.Fatalf("create initiation: %v", err)
	}
	if local.device.ConsumeMessageInitiation(initiation) != remoteAtLocal {
		t.Fatal("local rejected the initiation")
	}
}

func TestInitiationFromNewAddressWhileAliveKeepsSession(t *testing.T) {
	for name, pinned := range map[string]bool{"different source IP": false, "pinned": true} {
		t.Run(name, func(t *testing.T) {
			// Given a live session on the stored endpoint
			local, remote, remoteAtLocal, localAtRemote := newReplyTestPair(t)
			keypair := establishSession(t, local, remote, remoteAtLocal, localAtRemote)
			setPeerLastPacket(remoteAtLocal, time.Now())
			remoteAtLocal.endpointPinned.Store(pinned)
			consumeRemoteInitiation(t, local, remote, remoteAtLocal, localAtRemote)
			arrival, _ := local.bind.ParseEndpoint(replyTestArrival)

			// When
			remoteAtLocal.answerHandshakeInitiation(arrival)

			// Then one packet goes to the arrival address and nothing moves
			if sent := local.bind.settledDestinations(1); len(sent) != 1 || sent[0] != replyTestArrival {
				t.Fatalf("sent = %v, want one packet to %s", sent, replyTestArrival)
			}
			if remoteAtLocal.keypairs.Current() != keypair || remoteAtLocal.keypairs.loadNext() != nil {
				t.Fatal("refused initiation changed the keypairs")
			}
			if got := remoteAtLocal.GetEndpointDstStr(); got != replyTestStored {
				t.Fatalf("stored endpoint = %s, want %s", got, replyTestStored)
			}
			if remoteAtLocal.endpointPinned.Load() != pinned {
				t.Fatal("refused initiation changed the prober pin")
			}
			reflexive := remoteAtLocal.reflexive.candidates(time.Now(), time.Minute)
			if len(reflexive) != 1 || reflexive[0].address != replyTestArrival {
				t.Fatalf("reflexive = %+v, want %s", reflexive, replyTestArrival)
			}
		})
	}
}

func TestInitiationFromNewAddressWithoutKeypairSendsNothing(t *testing.T) {
	// Given a peer that looks alive but holds no session
	local, remote, remoteAtLocal, localAtRemote := newReplyTestPair(t)
	setPeerLastPacket(remoteAtLocal, time.Now())
	consumeRemoteInitiation(t, local, remote, remoteAtLocal, localAtRemote)
	arrival, _ := local.bind.ParseEndpoint(replyTestArrival)

	// When
	remoteAtLocal.answerHandshakeInitiation(arrival)

	// Then neither the arrival address nor the stored endpoint gets anything
	if sent := local.bind.settledDestinations(0); len(sent) != 0 {
		t.Fatalf("sent = %v, want nothing", sent)
	}
}

// A prober-pinned peer must still rekey: the initiation comes from the stored
// endpoint itself, so it is not a refusal even though the pin keeps the
// endpoint from being rewritten.
func TestInitiationFromPinnedEndpointStillRekeys(t *testing.T) {
	// Given
	local, remote, remoteAtLocal, localAtRemote := newReplyTestPair(t)
	keypair := establishSession(t, local, remote, remoteAtLocal, localAtRemote)
	setPeerLastPacket(remoteAtLocal, time.Now())
	remoteAtLocal.endpointPinned.Store(true)
	consumeRemoteInitiation(t, local, remote, remoteAtLocal, localAtRemote)
	arrival, _ := local.bind.ParseEndpoint(replyTestStored)

	// When
	remoteAtLocal.answerHandshakeInitiation(arrival)

	// Then the response goes out and the next keypair is derived
	if sent := local.bind.settledDestinations(1); len(sent) != 1 || sent[0] != replyTestStored {
		t.Fatalf("sent = %v, want one response to %s", sent, replyTestStored)
	}
	if remoteAtLocal.keypairs.loadNext() == nil {
		t.Fatal("no next keypair derived")
	}
	if remoteAtLocal.keypairs.Current() != keypair {
		t.Fatal("current keypair replaced before the new one was confirmed")
	}
	if !remoteAtLocal.endpointPinned.Load() {
		t.Fatal("prober pin was cleared")
	}
}

func TestHandshakeResponseGoesToInitiationEndpoint(t *testing.T) {
	// Given a dead peer
	local, remote, remoteAtLocal, localAtRemote := newReplyTestPair(t)
	setPeerLastPacket(remoteAtLocal, time.Now().Add(-time.Hour))
	consumeRemoteInitiation(t, local, remote, remoteAtLocal, localAtRemote)
	arrival, _ := local.bind.ParseEndpoint(replyTestArrival)

	// When
	remoteAtLocal.answerHandshakeInitiation(arrival)

	// Then
	if sent := local.bind.settledDestinations(1); len(sent) != 1 || sent[0] != replyTestArrival {
		t.Fatalf("sent = %v, want one response to %s", sent, replyTestArrival)
	}
	if got := remoteAtLocal.GetEndpointDstStr(); got != replyTestArrival {
		t.Fatalf("stored endpoint = %s, want %s", got, replyTestArrival)
	}
	if remoteAtLocal.keypairs.loadNext() == nil {
		t.Fatal("no session derived for the dead peer")
	}
}

func TestInitiationFromBlacklistedArrivalSendsNothing(t *testing.T) {
	// Given a live session and a blacklist covering the arrival address
	local, remote, remoteAtLocal, localAtRemote := newReplyTestPair(t)
	keypair := establishSession(t, local, remote, remoteAtLocal, localAtRemote)
	setPeerLastPacket(remoteAtLocal, time.Now())
	consumeRemoteInitiation(t, local, remote, remoteAtLocal, localAtRemote)
	local.device.setEndpointBlacklist([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	arrival, _ := local.bind.ParseEndpoint(replyTestArrival)

	// When
	remoteAtLocal.answerHandshakeInitiation(arrival)

	// Then
	if sent := local.bind.settledDestinations(0); len(sent) != 0 {
		t.Fatalf("sent = %v, want nothing", sent)
	}
	if remoteAtLocal.keypairs.Current() != keypair || remoteAtLocal.keypairs.loadNext() != nil {
		t.Fatal("blacklisted initiation changed the keypairs")
	}
	if got := remoteAtLocal.GetEndpointDstStr(); got != replyTestStored {
		t.Fatalf("stored endpoint = %s, want %s", got, replyTestStored)
	}
}
