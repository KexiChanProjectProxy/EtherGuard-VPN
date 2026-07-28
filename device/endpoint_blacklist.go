package device

import (
	"errors"
	"net"
	"net/netip"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

var errEndpointBlacklisted = errors.New("endpoint IP is blacklisted")

type endpointBlacklist struct {
	prefixes []netip.Prefix
}

func (device *Device) endpointBlacklisted(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return device.endpointAddressBlacklisted(address)
}

func (device *Device) endpointAddressBlacklisted(address netip.Addr) bool {
	blacklist := device.endpointBlacklist.Load()
	if blacklist == nil {
		return false
	}
	unmapped := address.Unmap()
	for _, prefix := range blacklist.prefixes {
		if prefix.Contains(address) || prefix.Contains(unmapped) {
			return true
		}
	}
	return false
}

func (device *Device) endpointURLBlacklisted(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return device.endpointAddressBlacklisted(parsed)
}

func (device *Device) endpointURLBlacklistedReadLocked(address string) bool {
	device.endpointBlacklistMu.RLock()
	defer device.endpointBlacklistMu.RUnlock()
	return device.endpointURLBlacklisted(address)
}

func (device *Device) filterControlCandidates(candidates []mtypes.ControlV2Candidate) []mtypes.ControlV2Candidate {
	device.endpointBlacklistMu.RLock()
	defer device.endpointBlacklistMu.RUnlock()
	filtered := make([]mtypes.ControlV2Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if !device.endpointURLBlacklisted(candidate.Address) {
			filtered = append(filtered, candidate)
		}
	}
	return filtered
}

func (device *Device) filterEndpointURLs(urls []string) []string {
	device.endpointBlacklistMu.RLock()
	defer device.endpointBlacklistMu.RUnlock()
	filtered := make([]string, 0, len(urls))
	for _, url := range urls {
		if !device.endpointURLBlacklisted(url) {
			filtered = append(filtered, url)
		}
	}
	return filtered
}

func (device *Device) applyEndpointBlacklist(parameters mtypes.ControlV2Parameters) {
	prefixes, err := parameters.ParseEndpointBlacklist()
	if err != nil {
		device.log.Errorf("HTTP control endpoint blacklist update rejected: %v", err)
		return
	}
	device.endpointBlacklistMu.Lock()
	device.endpointBlacklist.Store(&endpointBlacklist{prefixes: prefixes})
	for _, peer := range device.allPeersSnapshot() {
		peer.endpoint_trylist.removeBlacklisted()
		peer.Lock()
		if peer.endpoint != nil && device.endpointBlacklisted(peer.endpoint.DstIP()) {
			peer.endpoint = nil
		}
		peer.Unlock()
	}
	device.endpointBlacklistMu.Unlock()
	device.signalEndpointRetry()
}

func (device *Device) logBlacklistedDatagram(ip net.IP) {
	drops := device.blacklistedDatagramDrops.Add(1)
	if drops == 1 || drops&(drops-1) == 0 {
		device.log.Verbosef("Dropped datagram from blacklisted endpoint source=%s drops=%d", ip, drops)
	}
}
