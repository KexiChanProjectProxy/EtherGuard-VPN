package device

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/pion/stun/v3"
)

type stunTestEndpoint struct{ address string }

func (e stunTestEndpoint) ClearSrc()           {}
func (e stunTestEndpoint) SrcToString() string { return "" }
func (e stunTestEndpoint) DstToString() string { return e.address }
func (e stunTestEndpoint) DstToBytes() []byte  { return []byte(e.address) }
func (e stunTestEndpoint) DstIP() net.IP {
	host, _, _ := net.SplitHostPort(e.address)
	return net.ParseIP(host)
}
func (e stunTestEndpoint) SrcIP() net.IP { return nil }

type sameBindSTUNFake struct {
	port      uint16
	responses map[string]net.IP
	delay     map[string]time.Duration
	incoming  chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newSameBindSTUNFake(port uint16) *sameBindSTUNFake {
	return &sameBindSTUNFake{
		port:      port,
		responses: make(map[string]net.IP),
		delay:     make(map[string]time.Duration),
		incoming:  make(chan []byte, 8),
		closed:    make(chan struct{}),
	}
}

func (b *sameBindSTUNFake) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive}, b.port, nil
}
func (b *sameBindSTUNFake) Close() error {
	b.closeOnce.Do(func() { close(b.closed) })
	return nil
}
func (b *sameBindSTUNFake) SetMark(uint32) error { return nil }
func (b *sameBindSTUNFake) EnabledAf() conn.EnabledAf {
	return conn.EnabledAf46
}
func (b *sameBindSTUNFake) ParseEndpoint(address string) (conn.Endpoint, error) {
	return stunTestEndpoint{address: address}, nil
}
func (b *sameBindSTUNFake) Send(packet []byte, endpoint conn.Endpoint) error {
	var tx [stun.TransactionIDSize]byte
	copy(tx[:], packet[8:20])
	mappedIP, ok := b.responses[endpoint.DstToString()]
	if !ok {
		if endpoint.DstToString() == "[::1]:3478" {
			mappedIP, ok = b.responses["[::1]:3478"]
		}
	}
	if !ok {
		return nil
	}
	response, err := stun.Build(stun.BindingSuccess, stun.NewTransactionIDSetter(tx), &stun.XORMappedAddress{IP: mappedIP, Port: int(b.port)}, stun.Fingerprint)
	if err != nil {
		return err
	}
	delay := b.delay[endpoint.DstToString()]
	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
			b.incoming <- append([]byte(nil), response.Raw...)
		case <-b.closed:
		}
	}()
	return nil
}
func (b *sameBindSTUNFake) receive(packet []byte) (int, conn.Endpoint, error) {
	select {
	case response := <-b.incoming:
		return copy(packet, response), stunTestEndpoint{address: "127.0.0.1:3478"}, nil
	case <-b.closed:
		return 0, nil, net.ErrClosed
	}
}

func TestSuperSTUNDiscoversMappedCandidatesThroughActiveBind(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(43210)
	bind.responses["127.0.0.1:3478"] = net.ParseIP("198.51.100.44")
	bind.responses["[::1]:3478"] = net.ParseIP("2001:db8::44")
	device := &Device{}
	device.net.bind = bind
	device.net.port = bind.port
	manager := NewSuperSTUNManager(device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:127.0.0.1:3478", "stun:[::1]:3478"}, 100*time.Millisecond)

	// Then
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2: %#v", len(candidates), candidates)
	}
	for _, candidate := range candidates {
		_, port, err := net.SplitHostPort(candidate.Address)
		if err != nil {
			t.Fatalf("invalid candidate address %q: %v", candidate.Address, err)
		}
		if port != "43210" {
			t.Fatalf("mapped source port = %s, want active bind port 43210", port)
		}
		if candidate.Source != mtypes.ControlV2CandidateSTUN {
			t.Fatalf("candidate source = %q, want stun", candidate.Source)
		}
	}
}

func TestSuperSTUNFailsOverAfterFirstServerTimeout(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40001)
	bind.responses["127.0.0.2:3478"] = net.ParseIP("203.0.113.7")
	device := &Device{}
	device.net.bind = bind
	device.net.port = bind.port
	manager := NewSuperSTUNManager(device)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go receiveSTUNTestPackets(ctx, manager, bind.receive)

	// When
	candidates := manager.Discover(ctx, []string{"stun:127.0.0.1:3478", "stun:127.0.0.2:3478"}, 20*time.Millisecond)

	// Then
	if len(candidates) != 1 || candidates[0].Address != "203.0.113.7:40001" {
		t.Fatalf("candidates = %#v, want successful second-server mapping", candidates)
	}
}

func TestSuperSTUNAllServersFailPublishesNoMappedCandidates(t *testing.T) {
	// Given
	bind := newSameBindSTUNFake(40002)
	device := &Device{}
	device.net.bind = bind
	device.net.port = bind.port
	manager := NewSuperSTUNManager(device)
	ctx := context.Background()

	// When
	candidates := manager.Discover(ctx, []string{"stun:127.0.0.1:3478"}, time.Millisecond)

	// Then
	if len(candidates) != 0 {
		t.Fatalf("candidates = %#v, want no fabricated mapping", candidates)
	}
}

func receiveSTUNTestPackets(ctx context.Context, manager *SuperSTUNManager, receive conn.ReceiveFunc) {
	buffer := make([]byte, 2048)
	for {
		size, _, err := receive(buffer)
		if err != nil {
			return
		}
		manager.HandlePacket(buffer[:size])
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
