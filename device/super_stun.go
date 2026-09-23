package device

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/pion/stun/v3"
)

const stunMagicCookie uint32 = 0x2112A442

var errSuperSTUNManagerClosed = errors.New("STUN manager is closed")

// errSTUNPinRejected reports that the kernel dropped the pinned source of a
// probe (the send fell back to the default route), so a reply must not be
// attributed to the pinned uplink.
var errSTUNPinRejected = errors.New("STUN source pin rejected by kernel")

type stunResolver func(context.Context, string) ([]net.IPAddr, error)

type SuperSTUNManager struct {
	device      *Device
	mu          sync.Mutex
	pending     map[[stun.TransactionIDSize]byte]chan stunResult
	resolver    stunResolver
	sources     func() []stunSource
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
		sources:     device.stunSources,
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

// Discover returns the public (STUN-mapped) candidates of every uplink. It
// always runs one unpinned pass through the kernel's preferred route, and, when
// the bind can pin sources, one concurrent pass per local uplink so machines
// with several default routes learn the public endpoint of every link.
func (manager *SuperSTUNManager) Discover(ctx context.Context, servers []string, timeout time.Duration) []mtypes.ControlV2Candidate {
	if timeout <= 0 {
		timeout = time.Second
	}
	literals := manager.resolveAll(ctx, servers, timeout)
	if len(literals) == 0 {
		return make([]mtypes.ControlV2Candidate, 0)
	}
	slots := []*stunSource{nil}
	if _, ok := manager.currentBind().(conn.EndpointSourcePinner); ok && manager.sources != nil {
		for _, source := range manager.sources() {
			source := source
			slots = append(slots, &source)
		}
	}
	results := make([][]mtypes.ControlV2Candidate, len(slots))
	var wg sync.WaitGroup
	for i := range slots {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = manager.discoverFrom(ctx, literals, timeout, slots[i])
		}(i)
	}
	wg.Wait()
	candidates := make([]mtypes.ControlV2Candidate, 0)
	seen := make(map[string]struct{})
	for _, result := range results {
		for _, candidate := range result {
			if _, ok := seen[candidate.Address]; ok {
				continue
			}
			seen[candidate.Address] = struct{}{}
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

// resolveAll resolves every STUN URI once, preserving configured order.
func (manager *SuperSTUNManager) resolveAll(ctx context.Context, servers []string, timeout time.Duration) []string {
	var literals []string
	for _, raw := range servers {
		if ctx.Err() != nil || manager.isClosed() {
			return nil
		}
		resolveCtx, cancel := manager.withTimeout(ctx, timeout)
		addresses, err := manager.resolveAddresses(resolveCtx, raw)
		cancel()
		if err != nil {
			continue
		}
		literals = append(literals, addresses...)
	}
	return literals
}

// discoverFrom probes every server literal from one slot: the unpinned default
// route when source is nil, otherwise the pinned uplink. Mapped IPs are
// deduplicated and the port-consistency check is scoped to this slot, since
// different uplinks sit behind different NATs.
func (manager *SuperSTUNManager) discoverFrom(ctx context.Context, literals []string, timeout time.Duration, source *stunSource) []mtypes.ControlV2Candidate {
	var candidates []mtypes.ControlV2Candidate
	seenIPs := make(map[string]struct{})
	var mappedPort int
	var portSet bool
	sourceName := "default"
	if source != nil {
		sourceName = source.String()
	}
	for _, address := range literals {
		if source != nil && !sameFamily(address, source.ip) {
			continue
		}
		mapped, err := manager.request(ctx, address, timeout, source)
		if err != nil {
			if ctx.Err() != nil || manager.isClosed() {
				return candidates
			}
			if manager.device != nil && manager.device.log != nil && source != nil {
				manager.device.log.Verbosef("STUN probe failed: source=%s server=%s error=%v", sourceName, address, err)
			}
			continue
		}
		if !portSet {
			mappedPort = mapped.Port
			portSet = true
		} else if mapped.Port != mappedPort {
			if manager.device != nil && manager.device.log != nil {
				manager.device.log.Errorf("STUN mapped port mismatch: source=%s expected %d, got %d from %s", sourceName, mappedPort, mapped.Port, address)
			}
		}
		ipStr := mapped.IP.String()
		if _, ok := seenIPs[ipStr]; ok {
			continue
		}
		seenIPs[ipStr] = struct{}{}
		candidateAddress := net.JoinHostPort(ipStr, strconv.Itoa(mapped.Port))
		if manager.device != nil && manager.device.log != nil {
			manager.device.log.Verbosef("STUN mapped: source=%s server=%s mapped=%s", sourceName, address, candidateAddress)
		}
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: candidateAddress, Source: mtypes.ControlV2CandidateSTUN})
	}
	return candidates
}

func sameFamily(address string, source netip.Addr) bool {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return false
	}
	return addrPort.Addr().Unmap().Is4() == source.Unmap().Is4()
}

func (manager *SuperSTUNManager) currentBind() conn.Bind {
	if manager.device == nil {
		return nil
	}
	manager.device.net.RLock()
	defer manager.device.net.RUnlock()
	return manager.device.net.bind
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

func (manager *SuperSTUNManager) request(ctx context.Context, address string, timeout time.Duration, source *stunSource) (stun.XORMappedAddress, error) {
	requestContext, cancel := manager.withTimeout(ctx, timeout)
	defer cancel()
	if err := requestContext.Err(); err != nil {
		return stun.XORMappedAddress{}, err
	}
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return stun.XORMappedAddress{}, err
	}
	response := make(chan stunResult, 1)
	manager.mu.Lock()
	if manager.closed {
		manager.mu.Unlock()
		return stun.XORMappedAddress{}, errSuperSTUNManagerClosed
	}
	if _, collision := manager.pending[request.TransactionID]; collision {
		manager.mu.Unlock()
		return stun.XORMappedAddress{}, errors.New("STUN transaction ID collision")
	}
	manager.pending[request.TransactionID] = response
	manager.mu.Unlock()
	defer func() { manager.mu.Lock(); delete(manager.pending, request.TransactionID); manager.mu.Unlock() }()
	bind := manager.currentBind()
	if bind == nil {
		return stun.XORMappedAddress{}, errors.New("STUN bind is unavailable")
	}
	if err := requestContext.Err(); err != nil {
		return stun.XORMappedAddress{}, err
	}
	var endpoint conn.Endpoint
	if source != nil {
		pinner, ok := bind.(conn.EndpointSourcePinner)
		if !ok {
			return stun.XORMappedAddress{}, errors.New("STUN bind cannot pin sources")
		}
		endpoint, err = pinner.ParseEndpointFrom(address, source.ip, source.ifindex)
	} else {
		endpoint, err = bind.ParseEndpoint(address)
	}
	if err != nil {
		return stun.XORMappedAddress{}, err
	}
	if err := bind.Send(request.Raw, endpoint); err != nil {
		return stun.XORMappedAddress{}, err
	}
	if source != nil {
		if src := endpoint.SrcIP(); src != nil && src.IsUnspecified() {
			return stun.XORMappedAddress{}, errSTUNPinRejected
		}
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
