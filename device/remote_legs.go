/* SPDX-License-Identifier: MIT */

package device

import (
	"fmt"
	"net/netip"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

// attachRemoteLegs wires a bind that relays through leg agents into endpoint
// probing, STUN and leg-loss handling.
func (device *Device) attachRemoteLegs(bind conn.Bind) {
	lister, ok := bind.(conn.RemoteLegLister)
	if !ok {
		return
	}
	device.remoteLegs = lister
	_, device.localPinning = conn.UnwrapBind(bind).(conn.EndpointSourcePinner)
	device.p2pSTUNRefresh = make(chan struct{}, 1)
	if source, ok := bind.(conn.LegEventSource); ok {
		// The bind calls the handler from goroutines that its Close waits
		// for, while the device may hold device.net and peers wait on it.
		// So the handler only queues; a device goroutine does the work.
		device.remoteLegEvents.signal = make(chan struct{}, 1)
		source.SetLegEventHandler(device.queueRemoteLegEvent)
		go device.routineRemoteLegEvents(bind)
	}
}

func (device *Device) queueRemoteLegEvent(event conn.LegEvent) {
	device.remoteLegEvents.Lock()
	device.remoteLegEvents.queue = append(device.remoteLegEvents.queue, event)
	device.remoteLegEvents.Unlock()
	select {
	case device.remoteLegEvents.signal <- struct{}{}:
	default:
	}
}

// routineRemoteLegEvents handles queued leg changes in order until the
// device closes.
func (device *Device) routineRemoteLegEvents(bind conn.Bind) {
	for {
		select {
		case <-device.closed:
			return
		case <-device.remoteLegEvents.signal:
		}
		device.remoteLegEvents.Lock()
		events := device.remoteLegEvents.queue
		device.remoteLegEvents.queue = nil
		device.remoteLegEvents.Unlock()
		for _, event := range events {
			device.onRemoteLegEvent(bind, event)
		}
		if len(events) > 0 {
			// New or lost legs change the public mappings.
			select {
			case device.p2pSTUNRefresh <- struct{}{}:
			default:
			}
		}
	}
}

// onRemoteLegEvent moves peers off a remote leg that went away. Each such peer
// gets an unpinned endpoint for the same remote address, so the session keeps
// going over a local uplink when that address is reachable from here, and the
// retry loop and the prober take over otherwise.
func (device *Device) onRemoteLegEvent(bind conn.Bind, event conn.LegEvent) {
	if event.Up {
		if device.LogLevel.LogControl {
			fmt.Printf("Control: Remote leg %v (%v) up at %v\n", event.Leg.Key(), event.Leg.Name, event.Leg.Addr)
		}
		return
	}
	if device.LogLevel.LogControl {
		fmt.Printf("Control: Remote leg %v (%v) down\n", event.Leg.Key(), event.Leg.Name)
	}
	key := event.Leg.Key()
	lostSrc := event.Leg.Addr.Addr()
	moved := false
	for _, peer := range device.allPeersSnapshot() {
		peer.Lock()
		legEndpoint, ok := peer.endpoint.(conn.LegEndpoint)
		// A leg that changed address comes back under the same key; peers
		// already on the new address stay.
		if !ok || legEndpoint.LegKey() != key || !endpointSrcIs(legEndpoint, lostSrc) {
			peer.Unlock()
			continue
		}
		fallback, err := bind.ParseEndpoint(legEndpoint.DstToString())
		if err == nil {
			peer.endpoint = fallback
		}
		peer.endpointPinned.Store(false)
		peer.Unlock()
		peer.prober.reset()
		moved = true
		if device.log != nil {
			device.log.Verbosef("Remote leg down, peer moved off it: peer=%v leg=%s endpoint=%s", peer.ID, key, legEndpoint.DstToString())
		}
	}
	if moved {
		device.signalEndpointRetry()
	}
}

// sendInitiationViaRemoteLegs copies a handshake initiation for a peer that is
// down to the same address through every remote leg of its family, and
// through the default route when the stored endpoint is itself a leg. The
// retry loop only tries unpinned addresses, so without this the edge could
// never reach a peer, or open a leg's NAT toward it, over a path its own
// uplinks lack. The peer answers the first copy it accepts on that copy's
// path and drops the others as replays.
func (device *Device) sendInitiationViaRemoteLegs(peer *Peer, packet []byte) {
	if device.remoteLegs == nil || peer.IsPeerAlive() {
		return
	}
	peer.RLock()
	current := peer.endpoint
	excluded := peer.disableRoaming
	peer.RUnlock()
	if current == nil || excluded {
		return
	}
	device.net.RLock()
	bind := device.net.bind
	device.net.RUnlock()
	pinner, ok := bind.(conn.EndpointSourcePinner)
	if !ok {
		return
	}
	dst, err := netip.ParseAddrPort(current.DstToString())
	if err != nil {
		return
	}
	currentLeg := ""
	if leg, ok := current.(conn.LegEndpoint); ok {
		currentLeg = leg.LegKey()
		if fallback, err := bind.ParseEndpoint(dst.String()); err == nil {
			peer.SendBufferTo(packet, fallback)
		}
	}
	for _, source := range device.remoteLegSources() {
		if source.ip.Is4() != dst.Addr().Unmap().Is4() || source.ifname == currentLeg {
			continue
		}
		endpoint, err := pinner.ParseEndpointFrom(dst.String(), source.ip, source.ifindex)
		if err != nil {
			continue
		}
		if err := peer.SendBufferTo(packet, endpoint); err != nil {
			device.log.Verbosef("%v - Handshake initiation via remote leg %s failed: %v", peer, source.ifname, err)
		}
	}
}

func endpointSrcIs(endpoint conn.Endpoint, addr netip.Addr) bool {
	src, ok := netip.AddrFromSlice(endpoint.SrcIP())
	return ok && src.Unmap() == addr.Unmap()
}
