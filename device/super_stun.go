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

type SuperSTUNManager struct {
	device  *Device
	mu      sync.Mutex
	pending map[[stun.TransactionIDSize]byte]chan stunResult
}
type stunResult struct {
	address stun.XORMappedAddress
	err     error
}

func NewSuperSTUNManager(device *Device) *SuperSTUNManager {
	return &SuperSTUNManager{device: device, pending: make(map[[stun.TransactionIDSize]byte]chan stunResult)}
}
func (manager *SuperSTUNManager) Discover(ctx context.Context, servers []string, timeout time.Duration) []mtypes.ControlV2Candidate {
	if timeout <= 0 {
		timeout = time.Second
	}
	candidates := make([]mtypes.ControlV2Candidate, 0, len(servers))
	seen := make(map[string]struct{})
	for _, raw := range servers {
		address, err := stunServerAddress(raw)
		if err != nil {
			continue
		}
		mapped, err := manager.request(ctx, address, timeout)
		if err != nil {
			continue
		}
		candidateAddress := net.JoinHostPort(mapped.IP.String(), strconv.Itoa(mapped.Port))
		if _, ok := seen[candidateAddress]; ok {
			continue
		}
		seen[candidateAddress] = struct{}{}
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: candidateAddress, Source: mtypes.ControlV2CandidateSTUN})
	}
	return candidates
}
func (manager *SuperSTUNManager) request(ctx context.Context, address string, timeout time.Duration) (stun.XORMappedAddress, error) {
	request, err := stun.Build(stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return stun.XORMappedAddress{}, err
	}
	response := make(chan stunResult, 1)
	manager.mu.Lock()
	manager.pending[request.TransactionID] = response
	manager.mu.Unlock()
	defer func() { manager.mu.Lock(); delete(manager.pending, request.TransactionID); manager.mu.Unlock() }()
	manager.device.net.RLock()
	bind := manager.device.net.bind
	manager.device.net.RUnlock()
	if bind == nil {
		return stun.XORMappedAddress{}, errors.New("STUN bind is unavailable")
	}
	endpoint, err := bind.ParseEndpoint(address)
	if err != nil {
		return stun.XORMappedAddress{}, err
	}
	if err := bind.Send(request.Raw, endpoint); err != nil {
		return stun.XORMappedAddress{}, err
	}
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case result := <-response:
		return result.address, result.err
	case <-requestContext.Done():
		return stun.XORMappedAddress{}, requestContext.Err()
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
	manager.mu.Lock()
	response, ok := manager.pending[message.TransactionID]
	manager.mu.Unlock()
	if !ok {
		return false
	}
	var mapped stun.XORMappedAddress
	if err := mapped.GetFrom(message); err != nil {
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
func stunServerAddress(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || (parsed.Scheme != "stun" && parsed.Scheme != "stuns") {
		return "", errors.New("invalid STUN URI")
	}
	hostport := parsed.Host
	if hostport == "" {
		hostport = parsed.Opaque
	}
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" || port == "" {
		return "", errors.New("invalid STUN URI")
	}
	return net.JoinHostPort(host, port), nil
}
