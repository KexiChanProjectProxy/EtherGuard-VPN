package device

import (
	"context"
	"time"
)

// These match the values Super mode ships in its example configuration.
const (
	p2pSTUNRequestTimeout  = 3 * time.Second
	p2pSTUNRefreshInterval = 60 * time.Second
)

// p2pSTUNServers returns the servers this edge should query. Super mode owns
// its own discovery through SuperHTTPRuntime.refreshSTUN.
func (device *Device) p2pSTUNServers() []string {
	route := device.EdgeConfig.DynamicRoute
	if !route.P2P.UseP2P || device.EdgeConfig.SuperNodeV2Enabled {
		return nil
	}
	return route.P2P.STUNServers
}

// RoutineP2PSTUN refreshes the public mappings of the WireGuard socket. A
// failure only leaves the local advertisements in place, so it never blocks
// startup.
func (device *Device) RoutineP2PSTUN() {
	servers := device.p2pSTUNServers()
	if len(servers) == 0 {
		return
	}
	legsChanged := false
	for {
		device.refreshP2PSTUN(context.Background(), servers, legsChanged)
		legsChanged = false
		timer := time.NewTimer(p2pSTUNRefreshInterval)
		select {
		case <-timer.C:
		case <-device.p2pSTUNRefresh:
			timer.Stop()
			legsChanged = true
			// Let a burst of leg changes settle into one pass.
			select {
			case <-time.After(p2pSTUNLegSettle):
			case <-device.closed:
				return
			}
		case <-device.closed:
			timer.Stop()
			return
		}
	}
}

// p2pSTUNLegSettle is how long a STUN pass waits after remote legs changed.
const p2pSTUNLegSettle = 500 * time.Millisecond

// refreshP2PSTUN runs one discovery pass. A pass that finds nothing keeps the
// previous addresses: the mapping may well outlive a STUN server outage. After
// remote legs changed, the result replaces them even when empty, since the
// old mappings may belong to a leg that is gone.
func (device *Device) refreshP2PSTUN(ctx context.Context, servers []string, legsChanged bool) {
	candidates := device.superSTUN.Discover(ctx, servers, p2pSTUNRequestTimeout)
	if len(candidates) == 0 && !legsChanged {
		return
	}
	addresses := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		addresses = append(addresses, candidate.Address)
	}
	addresses = mergeEndpointURLs(addresses, nil)
	device.p2pMapped.Lock()
	device.p2pMapped.addresses = addresses
	device.p2pMapped.Unlock()
	device.log.Verbosef("P2P STUN mapped: addresses=%v", addresses)
}

func (device *Device) p2pMappedEndpointURLs() []string {
	device.p2pMapped.RLock()
	defer device.p2pMapped.RUnlock()
	return append([]string(nil), device.p2pMapped.addresses...)
}

// mergeEndpointURLs joins address lists in order and drops repeats.
func mergeEndpointURLs(lists ...[]string) []string {
	var merged []string
	seen := make(map[string]struct{})
	for _, list := range lists {
		for _, url := range list {
			if _, ok := seen[url]; ok {
				continue
			}
			seen[url] = struct{}{}
			merged = append(merged, url)
		}
	}
	return merged
}
