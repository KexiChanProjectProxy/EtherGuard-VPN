package device

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/pion/stun/v3"
)

const stunMagicCookie uint32 = 0x2112A442

var errSuperSTUNManagerClosed = errors.New("STUN manager is closed")

type stunResolver func(context.Context, string) ([]net.IPAddr, error)

type SuperSTUNManager struct {
	device      *Device
	mu          sync.Mutex
	pending     map[[stun.TransactionIDSize]byte]chan stunResult
	resolver    stunResolver
	closeCtx    context.Context
	closeCancel context.CancelFunc
	done        chan struct{}
	closed      bool
}
type stunResult struct {
	address stun.XORMappedAddress
	err     error
}

func NewSuperSTUNManager(device *Device) *SuperSTUNManager {
	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &SuperSTUNManager{
		device:      device,
		pending:     make(map[[stun.TransactionIDSize]byte]chan stunResult),
		resolver:    net.DefaultResolver.LookupIPAddr,
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
		done:        make(chan struct{}),
	}
}

func (manager *SuperSTUNManager) Close() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return
	}
	manager.closed = true
	close(manager.done)
	manager.closeCancel()
	for transactionID := range manager.pending {
		delete(manager.pending, transactionID)
	}
}

func (manager *SuperSTUNManager) Discover(ctx context.Context, servers []string, timeout time.Duration) []mtypes.ControlV2Candidate {
	if timeout <= 0 {
		timeout = time.Second
	}
	candidates := make([]mtypes.ControlV2Candidate, 0, len(servers))
	seen := make(map[string]struct{})
	for _, raw := range servers {
		requestContext, cancel := manager.withTimeout(ctx, timeout)
		addresses, err := manager.resolveAddresses(requestContext, raw)
		if err != nil {
			if requestContext.Err() != nil {
				cancel()
				return candidates
			}
			cancel()
			continue
		}
		for _, address := range addresses {
			mapped, requestErr := manager.request(requestContext, address, timeout)
			if requestErr != nil {
				if requestContext.Err() != nil {
					break
				}
				continue
			}
			candidateAddress := net.JoinHostPort(mapped.IP.String(), strconv.Itoa(mapped.Port))
			if _, ok := seen[candidateAddress]; ok {
				continue
			}
			seen[candidateAddress] = struct{}{}
			candidates = append(candidates, mtypes.ControlV2Candidate{Address: candidateAddress, Source: mtypes.ControlV2CandidateSTUN})
			break
		}
		cancel()
		if ctx.Err() != nil || manager.isClosed() {
			return candidates
		}
	}
	return candidates
}

func (manager *SuperSTUNManager) withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	stop := context.AfterFunc(manager.closeCtx, cancel)
	return requestContext, func() {
		stop()
		cancel()
	}
}

func (manager *SuperSTUNManager) isClosed() bool {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.closed
}

func (manager *SuperSTUNManager) resolveAddresses(ctx context.Context, raw string) ([]string, error) {
	host, port, err := stunServerAddress(raw)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(host); ip != nil {
		return []string{net.JoinHostPort(ip.String(), port)}, nil
	}
	manager.mu.Lock()
	resolver := manager.resolver
	closed := manager.closed
	manager.mu.Unlock()
	if closed {
		return nil, errSuperSTUNManagerClosed
	}
	addresses, err := resolver(ctx, host)
	if err != nil {
		return nil, err
	}
	literals := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address.IP == nil {
			continue
		}
		literals = append(literals, net.JoinHostPort(address.IP.String(), port))
	}
	if len(literals) == 0 {
		return nil, errors.New("STUN resolver returned no IP addresses")
	}
	return literals, nil
}

func (manager *SuperSTUNManager) request(ctx context.Context, address string, timeout time.Duration) (stun.XORMappedAddress, error) {
	requestContext, cancel := manager.withTimeout(ctx, timeout)
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return stun.XORMappedAddress{}, err
	}
	request, err := stun.Build(stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return stun.XORMappedAddress{}, err
	}
	response := make(chan stunResult, 1)
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return stun.XORMappedAddress{}, errSuperSTUNManagerClosed
	}
	manager.pending[request.TransactionID] = response
	manager.mu.Unlock()
	defer func() { manager.mu.Lock(); delete(manager.pending, request.TransactionID); manager.mu.Unlock() }()
	manager.device.net.RLock()
	bind := manager.device.net.bind
	manager.device.net.RUnlock()
	if bind == nil {
		return stun.XORMappedAddress{}, errors.New("STUN bind is unavailable")
	}
	if err := requestContext.Err(); err != nil {
		return stun.XORMappedAddress{}, err
	}
	endpoint, err := bind.ParseEndpoint(address)
	if err != nil {
		return stun.XORMappedAddress{}, err
	}
	if err := bind.Send(request.Raw, endpoint); err != nil {
		return stun.XORMappedAddress{}, err
	}
	select {
	case result := <-response:
		return result.address, result.err
	case <-requestContext.Done():
		return stun.XORMappedAddress{}, requestContext.Err()
	case <-manager.done:
		return stun.XORMappedAddress{}, errSuperSTUNManagerClosed
	}
}
func (manager *SuperSTUNManager) HandlePacket(packet []byte) bool {
	if !looksLikeSTUN(packet) {
		return false
	}
	message := new(stun.Message)
	if err := message.UnmarshalBinary(packet); err != nil || message.Type != stun.BindingSuccess {
		return false
	}
	if err := stun.Fingerprint.Check(message); err != nil {
		return false
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(message); err != nil {
		return false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed {
		return false
	}
	response, ok := manager.pending[message.TransactionID]
	if !ok {
		return false
	}
	select {
	case response <- stunResult{address: mapped}:
	default:
	}
	return true
}
func (manager *SuperSTUNManager) addPendingForTest(transactionID [stun.TransactionIDSize]byte) {
	manager.mu.Lock()
	manager.pending[transactionID] = make(chan stunResult, 1)
	manager.mu.Unlock()
}
func looksLikeSTUN(packet []byte) bool {
	return len(packet) >= 20 && packet[0]&0xc0 == 0 && binary.BigEndian.Uint32(packet[4:8]) == stunMagicCookie
}
func stunServerAddress(raw string) (string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "stun" && parsed.Scheme != "stuns") {
		return "", "", errors.New("invalid STUN URI")
	}
	hostport := parsed.Host
	if hostport == "" {
		hostport = parsed.Opaque
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || port == "" {
		return "", "", errors.New("invalid STUN URI")
	}
	return host, port, nil
}
