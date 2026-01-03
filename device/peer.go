/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"container/list"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"gopkg.in/yaml.v2"
)

const AfPerferVal = 10000

type endpoint_tryitem struct {
	URL      string
	lastTry  time.Time
	firstTry time.Time
}

type endpoint_trylist struct {
	sync.RWMutex
	timeout      time.Duration
	enabledAf    conn.EnabledAf
	peer         *Peer
	trymap_super map[string]*endpoint_tryitem // Legacy: combined map for backward compatibility
	trymap_p2p   map[string]*endpoint_tryitem // Legacy: combined map for backward compatibility

	// Dual-stack endpoint try maps (separated by address family)
	trymap_super_v4 map[string]*endpoint_tryitem // IPv4 supernode endpoints
	trymap_super_v6 map[string]*endpoint_tryitem // IPv6 supernode endpoints
	trymap_p2p_v4   map[string]*endpoint_tryitem // IPv4 P2P discovered endpoints
	trymap_p2p_v6   map[string]*endpoint_tryitem // IPv6 P2P discovered endpoints
}

func NewEndpoint_trylist(peer *Peer, timeout time.Duration, enabledAf conn.EnabledAf) *endpoint_trylist {
	return &endpoint_trylist{
		timeout:         timeout,
		peer:            peer,
		enabledAf:       enabledAf,
		trymap_super:    make(map[string]*endpoint_tryitem),
		trymap_p2p:      make(map[string]*endpoint_tryitem),
		trymap_super_v4: make(map[string]*endpoint_tryitem),
		trymap_super_v6: make(map[string]*endpoint_tryitem),
		trymap_p2p_v4:   make(map[string]*endpoint_tryitem),
		trymap_p2p_v6:   make(map[string]*endpoint_tryitem),
	}
}

func (et *endpoint_trylist) UpdateSuper(urls mtypes.API_connurl, UseLocalIP bool, AfPerfer int) {
	et.Lock()
	defer et.Unlock()
	newmap_super := make(map[string]*endpoint_tryitem)
	newmap_super_v4 := make(map[string]*endpoint_tryitem)
	newmap_super_v6 := make(map[string]*endpoint_tryitem)

	if urls.IsEmpty() {
		if et.peer.device.LogLevel.LogInternal {
			fmt.Printf("Internal: Peer %v : Reset trylist(super) %v\n", et.peer.ID.ToString(), "nil")
		}
	}

	// Check if dual-stack is enabled
	dualStackEnabled := false
	if !et.peer.device.IsSuperNode {
		dualStackEnabled = et.peer.device.EdgeConfig.DualStack.Enabled
	}

	for url, it := range urls.GetList(UseLocalIP) {
		if url == "" {
			continue
		}

		// Try dual-stack lookup if enabled
		if dualStackEnabled && et.enabledAf.IPv4 && et.enabledAf.IPv6 {
			_, v4Addr, _, v6Addr, _, err := conn.LookupIPDualStack(url, et.enabledAf, AfPerfer)
			if err == nil {
				// Add IPv4 endpoint if available
				if v4Addr != "" {
					v4It := it
					if AfPerfer == 4 {
						v4It = v4It - AfPerferVal
					}
					if val, ok := et.trymap_super_v4[v4Addr]; ok {
						newmap_super_v4[v4Addr] = val
					} else {
						newmap_super_v4[v4Addr] = &endpoint_tryitem{
							URL:      v4Addr,
							lastTry:  time.Time{}.Add(mtypes.S2TD(AfPerferVal)).Add(mtypes.S2TD(v4It)),
							firstTry: time.Time{},
						}
					}
					if et.peer.device.LogLevel.LogInternal {
						fmt.Printf("Internal: Peer %v : Add trylist(super,v4) %v\n", et.peer.ID.ToString(), v4Addr)
					}
				}

				// Add IPv6 endpoint if available
				if v6Addr != "" {
					v6It := it
					if AfPerfer == 6 {
						v6It = v6It - AfPerferVal
					}
					if val, ok := et.trymap_super_v6[v6Addr]; ok {
						newmap_super_v6[v6Addr] = val
					} else {
						newmap_super_v6[v6Addr] = &endpoint_tryitem{
							URL:      v6Addr,
							lastTry:  time.Time{}.Add(mtypes.S2TD(AfPerferVal)).Add(mtypes.S2TD(v6It)),
							firstTry: time.Time{},
						}
					}
					if et.peer.device.LogLevel.LogInternal {
						fmt.Printf("Internal: Peer %v : Add trylist(super,v6) %v\n", et.peer.ID.ToString(), v6Addr)
					}
				}
				continue
			}
			// If dual-stack lookup failed, fall through to single lookup
		}

		// Legacy single-AF lookup
		addr, connIP, err := conn.LookupIP(url, et.enabledAf, AfPerfer)
		if err != nil {
			if et.peer.device.LogLevel.LogInternal {
				fmt.Printf("Internal: Peer %v : Update trylist(super) %v error: %v\n", et.peer.ID.ToString(), url, err)
			}
			continue
		}

		adjustedIt := it
		switch AfPerfer {
		case 4:
			if addr == "udp4" {
				adjustedIt = it - AfPerferVal
			}
		case 6:
			if addr == "udp6" {
				adjustedIt = it - AfPerferVal
			}
		}

		// Add to legacy map
		if val, ok := et.trymap_super[url]; ok {
			if et.peer.device.LogLevel.LogInternal {
				fmt.Printf("Internal: Peer %v : Update trylist(super) %v\n", et.peer.ID.ToString(), url)
			}
			newmap_super[url] = val
		} else {
			if et.peer.device.LogLevel.LogInternal {
				fmt.Printf("Internal: Peer %v : New trylist(super) %v\n", et.peer.ID.ToString(), url)
			}
			newmap_super[url] = &endpoint_tryitem{
				URL:      url,
				lastTry:  time.Time{}.Add(mtypes.S2TD(AfPerferVal)).Add(mtypes.S2TD(adjustedIt)),
				firstTry: time.Time{},
			}
		}

		// Also add to AF-specific map
		if addr == "udp4" || addr == "udp" {
			if val, ok := et.trymap_super_v4[connIP]; ok {
				newmap_super_v4[connIP] = val
			} else {
				newmap_super_v4[connIP] = &endpoint_tryitem{
					URL:      connIP,
					lastTry:  time.Time{}.Add(mtypes.S2TD(AfPerferVal)).Add(mtypes.S2TD(adjustedIt)),
					firstTry: time.Time{},
				}
			}
		}
		if addr == "udp6" {
			if val, ok := et.trymap_super_v6[connIP]; ok {
				newmap_super_v6[connIP] = val
			} else {
				newmap_super_v6[connIP] = &endpoint_tryitem{
					URL:      connIP,
					lastTry:  time.Time{}.Add(mtypes.S2TD(AfPerferVal)).Add(mtypes.S2TD(adjustedIt)),
					firstTry: time.Time{},
				}
			}
		}
	}

	et.trymap_super = newmap_super
	et.trymap_super_v4 = newmap_super_v4
	et.trymap_super_v6 = newmap_super_v6
}

func (et *endpoint_trylist) UpdateP2P(url string) {
	_, _, err := conn.LookupIP(url, et.enabledAf, 0)
	if err != nil {
		return
	}
	et.Lock()
	defer et.Unlock()
	if _, ok := et.trymap_p2p[url]; !ok {
		if et.peer.device.LogLevel.LogInternal {
			fmt.Printf("Internal: Peer %v : Add trylist(p2p) %v\n", et.peer.ID.ToString(), url)
		}
		et.trymap_p2p[url] = &endpoint_tryitem{
			URL:      url,
			lastTry:  time.Now(),
			firstTry: time.Time{},
		}
	}
}

func (et *endpoint_trylist) Delete(url string) {
	et.Lock()
	defer et.Unlock()
	delete(et.trymap_super, url)
	delete(et.trymap_p2p, url)
}

func (et *endpoint_trylist) GetNextTry() (bool, string) {
	et.RLock()
	defer et.RUnlock()
	var smallest *endpoint_tryitem
	FastTry := true
	for _, v := range et.trymap_super {
		if smallest == nil || smallest.lastTry.After(v.lastTry) {
			smallest = v
		}
	}
	for url, v := range et.trymap_p2p {
		if v.firstTry.After(time.Time{}) && v.firstTry.Add(et.timeout).Before(time.Now()) {
			if et.peer.device.LogLevel.LogInternal {
				fmt.Printf("Internal: Peer %v : Delete trylist(p2p) %v\n", et.peer.ID.ToString(), url)
			}
			delete(et.trymap_p2p, url)
		}
		if smallest == nil || smallest.lastTry.After(v.lastTry) {
			smallest = v
		}
	}
	if smallest == nil {
		return false, ""
	}
	smallest.lastTry = time.Now()
	if !smallest.firstTry.After(time.Time{}) {
		smallest.firstTry = time.Now()
	}
	if smallest.firstTry.Add(et.timeout).Before(time.Now()) {
		FastTry = false
	}
	return FastTry, smallest.URL
}

type filterwindow struct {
	sync.RWMutex
	device  *Device
	size    int
	element []float64
	value   float64
}

func (f *filterwindow) Push(e float64) float64 {
	f.Resize(f.device.SuperConfig.DampingFilterRadius*2 + 1)
	f.Lock()
	defer f.Unlock()
	if f.size < 3 || e >= mtypes.Infinity {
		f.value = e
		return f.value
	}
	f.element = append(f.element, e)
	if len(f.element) > f.size {
		f.element = f.element[1:]
	}
	elemlen := len(f.element)
	window := f.element
	if elemlen%2 == 0 {
		window = window[1:]
		elemlen -= 1
	}
	if elemlen < 3 {
		f.value = e
		return f.value
	}
	f.value = f.filter(window, 2)

	return f.value
}

func (f *filterwindow) filter(w []float64, lr int) float64 { // find the medium
	elemlen := len(w)
	if elemlen == 0 {
		return mtypes.Infinity
	}
	if elemlen%2 == 0 {
		switch lr {
		case 1:
			w = w[:len(w)-1]
		case 2:
			w = w[1:]
		}
		elemlen -= 1
	}
	if elemlen < 3 {
		return w[0]
	}
	pivot := ((elemlen + 1) / 2) - 1
	w2 := make([]float64, elemlen)
	copy(w2, w)
	sort.Float64s(w2)
	return w2[pivot]
}

func (f *filterwindow) Resize(s uint64) {
	size := int(s)
	f.Lock()
	defer f.Unlock()
	if f.size == size {
		return
	}
	f.size = size
	elemlen := len(f.element)
	if elemlen > f.size {
		f.element = f.element[elemlen-size:]
	}
}

func (f *filterwindow) GetVal() float64 {
	f.RLock()
	defer f.RUnlock()
	return f.value
}

type Peer struct {
	isRunning        AtomicBool
	sync.RWMutex     // Mostly protects endpoint, but is generally taken whenever we modify peer
	keypairs         Keypairs
	handshake        Handshake
	device           *Device
	endpoint         conn.Endpoint    // Primary endpoint (UDP) - points to active AF endpoint
	faketcpEndpoint  conn.Endpoint    // FakeTCP endpoint (fallback) - points to active AF endpoint
	endpoint_trylist *endpoint_trylist
	udpFailed        AtomicBool       // Track if UDP communication has failed
	lastUDPSuccess   atomic.Value     // *time.Time - last successful UDP communication

	// Dual-stack endpoints for IPv4/IPv6 failover
	endpointIPv4        conn.Endpoint // IPv4 UDP endpoint
	endpointIPv6        conn.Endpoint // IPv6 UDP endpoint
	faketcpEndpointIPv4 conn.Endpoint // IPv4 FakeTCP endpoint
	faketcpEndpointIPv6 conn.Endpoint // IPv6 FakeTCP endpoint

	// Dual-stack health tracking
	ipv4Failed      AtomicBool   // Track if IPv4 communication has failed
	ipv6Failed      AtomicBool   // Track if IPv6 communication has failed
	lastIPv4Success atomic.Value // *time.Time - last successful IPv4 communication
	lastIPv6Success atomic.Value // *time.Time - last successful IPv6 communication
	activeAF        atomic.Value // *int - currently active address family (4 or 6)

	// IPv6 recovery tracking for delayed failback
	ipv6RecoveryStartTime atomic.Value // *time.Time - when IPv6 recovery started

	LastPacketReceivedAdd1Sec atomic.Value // *time.Time

	SingleWayLatency filterwindow

	stopping sync.WaitGroup // routines pending stop

	ID               mtypes.Vertex
	AskedForNeighbor bool
	StaticConn       bool //if true, this peer will not write to config file when roaming, and the endpoint will be reset periodically
	ConnURL          string
	ConnAF           conn.EnabledAf

	// These fields are accessed with atomic operations, which must be
	// 64-bit aligned even on 32-bit platforms. Go guarantees that an
	// allocated struct will be 64-bit aligned. So we place
	// atomically-accessed fields up front, so that they can share in
	// this alignment before smaller fields throw it off.
	stats struct {
		txBytes           uint64 // bytes send to peer (endpoint)
		rxBytes           uint64 // bytes received from peer
		lastHandshakeNano int64  // nano seconds since epoch
	}

	disableRoaming bool

	timers struct {
		retransmitHandshake     *Timer
		sendKeepalive           *Timer
		newHandshake            *Timer
		zeroKeyMaterial         *Timer
		persistentKeepalive     *Timer
		handshakeAttempts       uint32
		needAnotherKeepalive    AtomicBool
		sentLastMinuteHandshake AtomicBool
	}

	state struct {
		sync.Mutex // protects against concurrent Start/Stop
	}

	queue struct {
		staged   chan *QueueOutboundElement // staged packets before a handshake is available
		outbound *autodrainingOutboundQueue // sequential ordering of udp transmission
		inbound  *autodrainingInboundQueue  // sequential ordering of tun writing
	}

	cookieGenerator             CookieGenerator
	trieEntries                 list.List
	persistentKeepaliveInterval uint32 // accessed atomically
}

func (device *Device) NewPeer(pk NoisePublicKey, id mtypes.Vertex, isSuper bool, PersistentKeepalive uint32) (*Peer, error) {
	if !isSuper {
		if id < mtypes.NodeID_Special {
			//pass check
		} else {
			return nil, errors.New(fmt.Sprint("ID ", uint32(id), " is a special NodeID"))
		}
	} else {
		if id == mtypes.NodeID_SuperNode {
			//pass check
		} else {
			return nil, errors.New(fmt.Sprint("ID", uint32(id), "is not a supernode NodeID"))
		}
	}

	if device.isClosed() {
		return nil, errors.New("device closed")
	}
	// lock resources
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	// check if over limit
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// create peer
	if device.LogLevel.LogInternal {
		fmt.Println("Internal: Create peer with ID : " + id.ToString() + " and PubKey:" + pk.ToString())
	}
	peer := new(Peer)
	peer.ConnAF = conn.EnabledAf46
	atomic.SwapUint32(&peer.persistentKeepaliveInterval, PersistentKeepalive)
	peer.LastPacketReceivedAdd1Sec.Store(&time.Time{})
	peer.Lock()
	defer peer.Unlock()

	peer.cookieGenerator.Init(pk)
	peer.device = device
	peer.endpoint_trylist = NewEndpoint_trylist(peer, mtypes.S2TD(device.EdgeConfig.DynamicRoute.PeerAliveTimeout), device.enabledAf)
	peer.SingleWayLatency.device = device
	peer.SingleWayLatency.Push(mtypes.Infinity)
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElement, QueueStagedSize)
	// map public key
	oldpeer, ok := device.peers.keyMap[pk]
	if ok {
		if oldpeer.ID != id {
			oldpeer = nil
		}
		return oldpeer, fmt.Errorf("adding existing peer pubkey: %v", pk.ToString())
	}
	_, ok = device.peers.IDMap[id]
	if ok {
		return nil, fmt.Errorf("adding existing peer id: %v", id)
	}
	peer.ID = id

	// pre-compute DH
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// reset endpoint
	peer.endpoint = nil

	// add
	if id == mtypes.NodeID_SuperNode { // To communicate with supernode
		device.peers.SuperPeer[pk] = peer
		device.peers.keyMap[pk] = peer
	} else { // Regular peer, other edgenodes
		device.peers.keyMap[pk] = peer
		device.peers.IDMap[id] = peer
	}

	// start peer
	peer.timersInit()
	if peer.device.isUp() {
		peer.Start()
	}
	return peer, nil
}

func (peer *Peer) IsPeerAlive() bool {
	PeerAliveTimeout := mtypes.S2TD(peer.device.EdgeConfig.DynamicRoute.PeerAliveTimeout)
	if peer.endpoint == nil {
		return false
	}
	if peer.LastPacketReceivedAdd1Sec.Load().(*time.Time).Add(PeerAliveTimeout).Before(time.Now()) {
		return false
	}
	return true
}

// getActiveEndpoint returns the current primary endpoint based on activeAF
func (peer *Peer) getActiveEndpoint() conn.Endpoint {
	activeAFPtr := peer.activeAF.Load()
	if activeAFPtr == nil {
		// No active AF set, return first available
		if peer.endpointIPv6 != nil {
			return peer.endpointIPv6
		}
		return peer.endpointIPv4
	}

	activeAF := *activeAFPtr.(*int)
	if activeAF == 6 && peer.endpointIPv6 != nil && !peer.ipv6Failed.Get() {
		return peer.endpointIPv6
	}
	if activeAF == 4 && peer.endpointIPv4 != nil && !peer.ipv4Failed.Get() {
		return peer.endpointIPv4
	}

	// Fallback to any available endpoint
	if peer.endpointIPv4 != nil && !peer.ipv4Failed.Get() {
		return peer.endpointIPv4
	}
	if peer.endpointIPv6 != nil && !peer.ipv6Failed.Get() {
		return peer.endpointIPv6
	}

	return nil
}

// tryIPv6Send attempts to send buffer via IPv6 endpoint
// Returns (sent bool, error)
func (peer *Peer) tryIPv6Send(buffer []byte) (bool, error) {
	if peer.endpointIPv6 == nil {
		return false, nil
	}

	// Skip if IPv6 is marked as failed
	if peer.ipv6Failed.Get() {
		return false, nil
	}

	err := peer.device.net.bind.Send(buffer, peer.endpointIPv6)
	if err == nil {
		// IPv6 success - update last success time
		now := time.Now()
		peer.lastIPv6Success.Store(&now)
		peer.ipv6Failed.Set(false)

		// Clear recovery timer if we were recovering
		peer.ipv6RecoveryStartTime.Store((*time.Time)(nil))

		if peer.device.LogLevel.LogInternal {
			fmt.Printf("Internal: Sent packet via IPv6 for peer %v\n", peer.ID)
		}
		return true, nil
	}

	// IPv6 failed - mark it and trigger failover
	peer.device.log.Verbosef("IPv6 send failed for peer %v: %v", peer.ID, err)
	peer.ipv6Failed.Set(true)

	// Switch to IPv4 if available
	if peer.endpointIPv4 != nil {
		newAF := 4
		peer.activeAF.Store(&newAF)
		peer.Lock()
		peer.endpoint = peer.endpointIPv4
		peer.faketcpEndpoint = peer.faketcpEndpointIPv4
		peer.Unlock()
		peer.device.log.Verbosef("Failed over from IPv6 to IPv4 for peer %v", peer.ID)
	}

	return false, err
}

// tryIPv4Send attempts to send buffer via IPv4 endpoint
// Returns (sent bool, error)
func (peer *Peer) tryIPv4Send(buffer []byte) (bool, error) {
	if peer.endpointIPv4 == nil {
		return false, nil
	}

	// Skip if IPv4 is marked as failed
	if peer.ipv4Failed.Get() {
		return false, nil
	}

	err := peer.device.net.bind.Send(buffer, peer.endpointIPv4)
	if err == nil {
		// IPv4 success - update last success time
		now := time.Now()
		peer.lastIPv4Success.Store(&now)
		peer.ipv4Failed.Set(false)

		if peer.device.LogLevel.LogInternal {
			fmt.Printf("Internal: Sent packet via IPv4 for peer %v\n", peer.ID)
		}
		return true, nil
	}

	// IPv4 failed - mark it
	peer.device.log.Verbosef("IPv4 send failed for peer %v: %v", peer.ID, err)
	peer.ipv4Failed.Set(true)

	return false, err
}

// tryFakeTCPSend attempts to send via FakeTCP (respecting activeAF)
// Returns (sent bool, error)
func (peer *Peer) tryFakeTCPSend(buffer []byte) (bool, error) {
	if peer.device.net.faketcpBind == nil {
		return false, nil
	}

	activeAFPtr := peer.activeAF.Load()
	if activeAFPtr == nil {
		return false, nil
	}
	activeAF := *activeAFPtr.(*int)

	var faketcpEndpoint conn.Endpoint
	var afName string

	// Try FakeTCP for active AF first
	if activeAF == 6 && peer.faketcpEndpointIPv6 != nil {
		faketcpEndpoint = peer.faketcpEndpointIPv6
		afName = "IPv6"
	} else if activeAF == 4 && peer.faketcpEndpointIPv4 != nil {
		faketcpEndpoint = peer.faketcpEndpointIPv4
		afName = "IPv4"
	} else {
		// Fallback to any available FakeTCP endpoint
		if peer.faketcpEndpointIPv4 != nil {
			faketcpEndpoint = peer.faketcpEndpointIPv4
			afName = "IPv4"
		} else if peer.faketcpEndpointIPv6 != nil {
			faketcpEndpoint = peer.faketcpEndpointIPv6
			afName = "IPv6"
		}
	}

	if faketcpEndpoint == nil {
		return false, nil
	}

	err := peer.device.net.faketcpBind.Send(buffer, faketcpEndpoint)
	if err == nil {
		peer.device.log.Verbosef("Sent packet via FakeTCP %s for peer %v", afName, peer.ID)
		return true, nil
	}

	peer.device.log.Errorf("FakeTCP %s send failed for peer %v: %v", afName, peer.ID, err)
	return false, err
}

func (peer *Peer) SendBuffer(buffer []byte) error {
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	if peer.device.isClosed() {
		return nil
	}

	peer.RLock()
	defer peer.RUnlock()

	// Check if any endpoint is available
	if peer.endpoint == nil && peer.faketcpEndpoint == nil &&
	   peer.endpointIPv4 == nil && peer.endpointIPv6 == nil {
		return errors.New("no known endpoint for peer")
	}

	var err error
	var sent bool

	// Determine if dual-stack is enabled
	dualStackEnabled := false
	if !peer.device.IsSuperNode && peer.endpointIPv4 != nil && peer.endpointIPv6 != nil {
		dualStackEnabled = peer.device.EdgeConfig.DualStack.Enabled
	}

	if dualStackEnabled {
		// Dual-stack failover logic: IPv6 primary, IPv4 hot standby
		activeAFPtr := peer.activeAF.Load()
		if activeAFPtr == nil {
			// Initialize to IPv6 if no active AF is set
			defaultAF := 6
			peer.activeAF.Store(&defaultAF)
			activeAFPtr = peer.activeAF.Load()
		}
		activeAF := *activeAFPtr.(*int)

		if activeAF == 6 {
			// Try IPv6 → IPv4 → FakeTCP
			sent, err = peer.tryIPv6Send(buffer)
			if !sent {
				sent, err = peer.tryIPv4Send(buffer)
			}
			if !sent {
				sent, err = peer.tryFakeTCPSend(buffer)
			}
		} else {
			// activeAF == 4: Try IPv4 → IPv6 (for recovery) → FakeTCP
			sent, err = peer.tryIPv4Send(buffer)
			if !sent {
				// Try IPv6 to check if it has recovered
				sent, err = peer.tryIPv6Send(buffer)
				if sent {
					// IPv6 recovered! Switch back (will be handled in tryIPv6Send)
					peer.device.log.Verbosef("IPv6 recovered for peer %v", peer.ID)
				}
			}
			if !sent {
				sent, err = peer.tryFakeTCPSend(buffer)
			}
		}
	} else {
		// Legacy single-endpoint logic (backward compatibility)
		// Try UDP first if available and not marked as failed
		if peer.endpoint != nil && !peer.udpFailed.Get() {
			err = peer.device.net.bind.Send(buffer, peer.endpoint)
			if err == nil {
				// UDP success - update last success time
				now := time.Now()
				peer.lastUDPSuccess.Store(&now)
				sent = true

				// If UDP was previously failed, mark it as recovered
				if peer.udpFailed.Get() {
					peer.device.log.Verbosef("UDP communication recovered for peer %v", peer.ID)
					peer.udpFailed.Set(false)
				}
			} else {
				// UDP failed - try FakeTCP
				peer.device.log.Verbosef("UDP send failed for peer %v: %v, trying FakeTCP", peer.ID, err)
				peer.udpFailed.Set(true)
			}
		}

		// If UDP failed or was skipped, try FakeTCP
		if !sent && peer.faketcpEndpoint != nil && peer.device.net.faketcpBind != nil {
			err = peer.device.net.faketcpBind.Send(buffer, peer.faketcpEndpoint)
			if err == nil {
				sent = true
				peer.device.log.Verbosef("Sent packet via FakeTCP for peer %v", peer.ID)
			} else {
				peer.device.log.Errorf("FakeTCP send also failed for peer %v: %v", peer.ID, err)
			}
		}
	}

	if sent {
		atomic.AddUint64(&peer.stats.txBytes, uint64(len(buffer)))
		return nil
	}

	return errors.New(fmt.Sprintf("failed to send packet: %v", err))
}

func (peer *Peer) String() string {
	// The awful goo that follows is identical to:
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// except that it is considerably more efficient.
	src := peer.handshake.remoteStatic
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	return string(b)
}

func (peer *Peer) Start() {
	// should never start a peer on a closed device
	if peer.device.isClosed() {
		return
	}

	// prevent simultaneous start/stop operations
	peer.state.Lock()
	defer peer.state.Unlock()

	if peer.isRunning.Get() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	// reset routine state
	peer.stopping.Wait()
	peer.stopping.Add(2)

	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	peer.device.queue.encryption.wg.Add(1) // keep encryption queue open for our writes

	peer.timersStart()

	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)
	go peer.RoutineSequentialSender()
	go peer.RoutineSequentialReceiver()

	peer.isRunning.Set(true)
}

func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// clear key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.loadNext())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.storeNext(nil)
	keypairs.Unlock()

	// clear handshake state

	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	peer.FlushStagedPackets()
}

func (peer *Peer) ExpireCurrentKeypairs() {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		atomic.StoreUint64(&keypairs.current.sendNonce, RejectAfterMessages)
	}
	if keypairs.next != nil {
		next := keypairs.loadNext()
		atomic.StoreUint64(&next.sendNonce, RejectAfterMessages)
	}
	keypairs.Unlock()
}

func (peer *Peer) Stop() {
	peer.state.Lock()
	defer peer.state.Unlock()

	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	peer.timersStop()
	// Signal that RoutineSequentialSender and RoutineSequentialReceiver should exit.
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	peer.stopping.Wait()
	peer.device.queue.encryption.wg.Done() // no more writes to encryption queue from us

	peer.ZeroAndFlushAll()
}

func (peer *Peer) SetPSK(psk NoisePresharedKey) {
	if !peer.device.IsSuperNode && peer.ID < mtypes.NodeID_Special && peer.device.EdgeConfig.DynamicRoute.P2P.UseP2P {
		peer.device.log.Verbosef("Preshared keys disabled in P2P mode.")
		return
	}
	peer.handshake.mutex.Lock()
	peer.handshake.presharedKey = psk
	peer.handshake.mutex.Unlock()
}

func (peer *Peer) SetEndpointFromConnURL(connurl string, af conn.EnabledAf, af_perfer int, static bool) error {
	if peer.device.LogLevel.LogInternal {
		fmt.Printf("Internal: Set endpoint to %v for NodeID: %v static:%v\n", connurl, peer.ID.ToString(), static)
	}

	// Check if dual-stack is enabled
	dualStackEnabled := true
	if !peer.device.IsSuperNode {
		dualStackEnabled = peer.device.EdgeConfig.DualStack.Enabled
	}

	// Check if private IPs are allowed
	allowPrivate := false
	if peer.device.IsSuperNode {
		allowPrivate = peer.device.SuperConfig.AllowPrivateIP
	} else {
		allowPrivate = peer.device.EdgeConfig.AllowPrivateIP
	}

	var err error
	var v4Addr, v6Addr string
	var primaryAF int

	// Try dual-stack lookup if both AFs enabled and dual-stack enabled
	if dualStackEnabled && af.IPv4 && af.IPv6 {
		_, v4Addr, _, v6Addr, primaryAF, err = conn.LookupIPDualStack(connurl, af, af_perfer)
		if err != nil {
			// If dual-stack fails, fall back to single AF lookup
			_, v4Addr, err = conn.LookupIP(connurl, af, af_perfer)
			if err != nil {
				return err
			}
			primaryAF = 4
		}
	} else {
		// Single AF or dual-stack disabled
		_, v4Addr, err = conn.LookupIP(connurl, af, af_perfer)
		if err != nil {
			return err
		}
		primaryAF = 4
		if af.IPv6 && !af.IPv4 {
			primaryAF = 6
			v6Addr = v4Addr
			v4Addr = ""
		}
	}

	// Validate and setup IPv4 endpoint
	if v4Addr != "" {
		host, _, err := net.SplitHostPort(v4Addr)
		if err == nil {
			ip := net.ParseIP(host)
			if ip != nil {
				// Check private IP restriction
				if allowPrivate || !conn.IsPrivateIP(ip) {
					// Set up IPv4 UDP endpoint
					endpoint, err := peer.device.net.bind.ParseEndpoint(v4Addr)
					if err == nil {
						peer.Lock()
						peer.endpointIPv4 = endpoint
						peer.ipv4Failed.Set(false)
						peer.Unlock()
						if peer.device.LogLevel.LogInternal {
							fmt.Printf("Internal: Set IPv4 endpoint to %v for NodeID: %v\n", v4Addr, peer.ID.ToString())
						}
					}

					// Set up IPv4 FakeTCP endpoint if enabled
					if peer.device.net.faketcpBind != nil {
						faketcpEndpoint, err := peer.device.net.faketcpBind.ParseEndpoint(v4Addr)
						if err == nil {
							peer.Lock()
							peer.faketcpEndpointIPv4 = faketcpEndpoint
							peer.Unlock()
						}
					}
				} else if peer.device.LogLevel.LogInternal {
					fmt.Printf("Internal: Skipped private IPv4 endpoint %v for NodeID: %v\n", v4Addr, peer.ID.ToString())
				}
			}
		}
	}

	// Validate and setup IPv6 endpoint
	if v6Addr != "" {
		host, _, err := net.SplitHostPort(v6Addr)
		if err == nil {
			ip := net.ParseIP(host)
			if ip != nil {
				// Check private IP restriction
				if allowPrivate || !conn.IsPrivateIP(ip) {
					// Set up IPv6 UDP endpoint
					endpoint, err := peer.device.net.bind.ParseEndpoint(v6Addr)
					if err == nil {
						peer.Lock()
						peer.endpointIPv6 = endpoint
						peer.ipv6Failed.Set(false)
						peer.Unlock()
						if peer.device.LogLevel.LogInternal {
							fmt.Printf("Internal: Set IPv6 endpoint to %v for NodeID: %v\n", v6Addr, peer.ID.ToString())
						}
					}

					// Set up IPv6 FakeTCP endpoint if enabled
					if peer.device.net.faketcpBind != nil {
						faketcpEndpoint, err := peer.device.net.faketcpBind.ParseEndpoint(v6Addr)
						if err == nil {
							peer.Lock()
							peer.faketcpEndpointIPv6 = faketcpEndpoint
							peer.Unlock()
						}
					}
				} else if peer.device.LogLevel.LogInternal {
					fmt.Printf("Internal: Skipped private IPv6 endpoint %v for NodeID: %v\n", v6Addr, peer.ID.ToString())
				}
			}
		}
	}

	// Ensure at least one endpoint was set
	if peer.endpointIPv4 == nil && peer.endpointIPv6 == nil {
		return fmt.Errorf("failed to set any valid endpoint for %s", connurl)
	}

	// Set active AF and update legacy endpoint fields
	peer.activeAF.Store(&primaryAF)
	peer.StaticConn = static
	peer.ConnURL = connurl
	peer.ConnAF = af

	// Update legacy endpoint field to point to active AF
	peer.Lock()
	if primaryAF == 6 && peer.endpointIPv6 != nil {
		peer.endpoint = peer.endpointIPv6
		peer.faketcpEndpoint = peer.faketcpEndpointIPv6
	} else if peer.endpointIPv4 != nil {
		peer.endpoint = peer.endpointIPv4
		peer.faketcpEndpoint = peer.faketcpEndpointIPv4
	} else {
		// Fallback to whatever is available
		if peer.endpointIPv6 != nil {
			peer.endpoint = peer.endpointIPv6
			peer.faketcpEndpoint = peer.faketcpEndpointIPv6
			primaryAF = 6
			peer.activeAF.Store(&primaryAF)
		}
	}
	peer.Unlock()

	if peer.device.LogLevel.LogInternal {
		fmt.Printf("Internal: Active AF=%v for NodeID: %v\n", primaryAF, peer.ID.ToString())
	}

	return nil
}

func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	if peer.disableRoaming {
		return
	}

	// Validate source IP address
	sourceIP := endpoint.DstIP()
	if sourceIP != nil {
		// Check if private IPs are allowed
		allowPrivate := false
		if peer.device.IsSuperNode {
			allowPrivate = peer.device.SuperConfig.AllowPrivateIP
		} else {
			allowPrivate = peer.device.EdgeConfig.AllowPrivateIP
		}

		// Reject private/non-routable IPs unless explicitly allowed
		if !allowPrivate && conn.IsPrivateIP(sourceIP) {
			if peer.device.LogLevel.LogControl {
				fmt.Printf("Control: Rejected endpoint update from private IP %s for peer %v (set AllowPrivateIP: true to allow)\n", endpoint.DstToString(), peer.ID.ToString())
			}
			return
		}
	}

	peer.Lock()
	defer peer.Unlock()
	if peer.ID == mtypes.NodeID_SuperNode {
		conn, err := net.Dial("udp", endpoint.DstToString())
		if err != nil {
			if peer.device.LogLevel.LogControl {
				fmt.Printf("Control: Set endpoint to peer %v failed: %v", peer.ID, err)
			}
			return
		}
		defer conn.Close()
		if err == nil {
			IP := conn.LocalAddr().(*net.UDPAddr).IP
			if ip4 := IP.To4(); ip4 != nil {
				peer.device.peers.LocalV4 = ip4
			} else {
				peer.device.peers.LocalV6 = IP
			}
		}
	}
	peer.device.SaveToConfig(peer, endpoint)
	peer.endpoint = endpoint

}

func (peer *Peer) GetEndpointSrcStr() string {
	peer.RLock()
	defer peer.RUnlock()
	if peer.endpoint == nil {
		return ""
	}
	return peer.endpoint.SrcToString()
}

func (peer *Peer) GetEndpointDstStr() string {
	peer.RLock()
	defer peer.RUnlock()
	if peer.endpoint == nil {
		return ""
	}
	return peer.endpoint.DstToString()
}

func (device *Device) SaveToConfig(peer *Peer, endpoint conn.Endpoint) {
	if device.IsSuperNode { //Can't use in super mode
		return
	}
	if peer.StaticConn { //static conn do not write new endpoint to config
		return
	}
	if !device.EdgeConfig.DynamicRoute.P2P.UseP2P { //Must in p2p mode
		return
	}
	if peer.endpoint != nil && peer.endpoint.DstIP().Equal(endpoint.DstIP()) { //endpoint changed
		return
	}

	url := endpoint.DstToString()
	foundInFile := false
	pubkeystr := peer.handshake.remoteStatic.ToString()
	pskstr := peer.handshake.presharedKey.ToString()
	if bytes.Equal(peer.handshake.presharedKey[:], make([]byte, 32)) {
		pskstr = ""
	}
	for _, peerfile := range device.EdgeConfig.Peers {
		if peerfile.NodeID == peer.ID && peerfile.PubKey == pubkeystr {
			foundInFile = true
			if !peerfile.Static {
				peerfile.EndPoint = url
			}
		} else if peerfile.NodeID == peer.ID || peerfile.PubKey == pubkeystr {
			panic("Found NodeID match " + peer.ID.ToString() + ", but PubKey Not match %s enrties in config file" + pubkeystr)
		}
	}
	if !foundInFile {
		device.EdgeConfig.Peers = append(device.EdgeConfig.Peers, mtypes.PeerInfo{
			NodeID:   peer.ID,
			PubKey:   pubkeystr,
			PSKey:    pskstr,
			EndPoint: url,
			Static:   false,
		})
	}
	go device.SaveConfig()
}

func (device *Device) SaveConfig() {
	if device.EdgeConfig.DynamicRoute.SaveNewPeers {
		configbytes, _ := yaml.Marshal(device.EdgeConfig)
		ioutil.WriteFile(device.EdgeConfigPath, configbytes, 0644)
	}
}
