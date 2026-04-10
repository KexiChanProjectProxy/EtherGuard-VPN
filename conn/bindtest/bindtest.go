/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package bindtest

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

type AddressFamily uint8

const (
	IPv4 AddressFamily = iota
	IPv6
)

type routedPacket struct {
	payload []byte
	source  ChannelEndpoint
}

type routeErrorKey struct {
	node   int
	family AddressFamily
}

type PacketMutator func(fromNode, toNode int, family AddressFamily, packet []byte) []byte

type ChannelTopology struct {
	mu          sync.RWMutex
	binds       []*ChannelBind
	endpoints   map[string]ChannelEndpoint
	offline     map[int]bool
	routeErrors map[routeErrorKey]error
	mutator     PacketMutator
}

type ChannelBind struct {
	topology         *ChannelTopology
	node             int
	rx4              chan routedPacket
	rx6              chan routedPacket
	closeSignal      chan struct{}
	source4, source6 ChannelEndpoint
}

type ChannelEndpoint struct {
	node   int
	port   uint16
	family AddressFamily
}

var _ conn.Bind = (*ChannelBind)(nil)
var _ conn.Endpoint = ChannelEndpoint{}

func NewChannelTopology(nodes int) *ChannelTopology {
	if nodes < 1 {
		nodes = 1
	}
	topology := &ChannelTopology{
		binds:       make([]*ChannelBind, nodes),
		endpoints:   make(map[string]ChannelEndpoint, nodes*2),
		offline:     make(map[int]bool, nodes),
		routeErrors: make(map[routeErrorKey]error, nodes*2),
	}
	for i := 0; i < nodes; i++ {
		bind := &ChannelBind{
			topology:    topology,
			node:        i,
			rx4:         make(chan routedPacket, 8192),
			rx6:         make(chan routedPacket, 8192),
			closeSignal: make(chan struct{}),
		}
		bind.source4 = ChannelEndpoint{node: i, port: uint16(10000 + i*2), family: IPv4}
		bind.source6 = ChannelEndpoint{node: i, port: uint16(10001 + i*2), family: IPv6}
		topology.binds[i] = bind
		topology.endpoints[bind.source4.DstToString()] = bind.source4
		topology.endpoints[bind.source6.DstToString()] = bind.source6
	}
	return topology
}

func NewIPv6NoRouteError(addr string) error {
	return &net.OpError{
		Op:   "sendto",
		Net:  "udp6",
		Addr: &net.UDPAddr{IP: net.ParseIP(addr)},
		Err:  syscall.ENETUNREACH,
	}
}

func NewChannelBinds() [2]conn.Bind {
	topology := NewChannelTopology(2)
	return [2]conn.Bind{topology.binds[0], topology.binds[1]}
}

func (s *ChannelBind) EnabledAf() conn.EnabledAf {
	return conn.EnabledAf{
		IPv4: true,
		IPv6: true,
	}
}

func (t *ChannelTopology) Bind(node int) *ChannelBind {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if node < 0 || node >= len(t.binds) {
		return nil
	}
	return t.binds[node]
}

func (t *ChannelTopology) Endpoint(node int, family AddressFamily) ChannelEndpoint {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bind := t.binds[node]
	if family == IPv6 {
		return bind.source6
	}
	return bind.source4
}

func (t *ChannelTopology) SetOffline(node int, offline bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.offline[node] = offline
}

func (t *ChannelTopology) IsOffline(node int) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.offline[node]
}

func (t *ChannelTopology) SetRouteError(node int, family AddressFamily, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := routeErrorKey{node: node, family: family}
	if err == nil {
		delete(t.routeErrors, key)
		return
	}
	t.routeErrors[key] = err
}

func (t *ChannelTopology) SetIPv6NoRoute(node int, enabled bool) {
	if enabled {
		t.SetRouteError(node, IPv6, NewIPv6NoRouteError(t.Endpoint(node, IPv6).DstIP().String()))
		return
	}
	t.SetRouteError(node, IPv6, nil)
}

func (t *ChannelTopology) SetPacketMutator(mutator PacketMutator) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.mutator = mutator
}

func (t *ChannelTopology) Pending(node int, family AddressFamily) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	bind := t.binds[node]
	if family == IPv6 {
		return len(bind.rx6)
	}
	return len(bind.rx4)
}

func (c ChannelEndpoint) ClearSrc() {}

func (c ChannelEndpoint) SrcToString() string { return "" }

func (c ChannelEndpoint) DstToString() string {
	return net.JoinHostPort(c.DstIP().String(), strconv.Itoa(int(c.port)))
}

func (c ChannelEndpoint) DstToBytes() []byte {
	return []byte{byte(c.family), byte(c.node >> 8), byte(c.node), byte(c.port >> 8), byte(c.port)}
}

func (c ChannelEndpoint) DstIP() net.IP {
	if c.family == IPv6 {
		return net.ParseIP(fmt.Sprintf("2001:db8::%x", c.node+1))
	}
	return net.IPv4(127, 0, 0, byte(c.node+1))
}

func (c ChannelEndpoint) SrcIP() net.IP { return nil }

func (c *ChannelBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	select {
	case <-c.closeSignal:
		c.closeSignal = make(chan struct{})
	default:
	}
	fns = append(fns, c.makeReceiveFunc(IPv4))
	fns = append(fns, c.makeReceiveFunc(IPv6))
	return fns, c.source4.port, nil
}

func (c *ChannelBind) Close() error {
	if c.closeSignal != nil {
		select {
		case <-c.closeSignal:
		default:
			close(c.closeSignal)
		}
	}
	return nil
}

func (c *ChannelBind) SetMark(mark uint32) error { return nil }

func (c *ChannelBind) makeReceiveFunc(family AddressFamily) conn.ReceiveFunc {
	var ch chan routedPacket
	if family == IPv6 {
		ch = c.rx6
	} else {
		ch = c.rx4
	}
	return func(b []byte) (n int, ep conn.Endpoint, err error) {
		select {
		case <-c.closeSignal:
			return 0, nil, net.ErrClosed
		case rx := <-ch:
			return copy(b, rx.payload), rx.source, nil
		}
	}
}

func (c *ChannelBind) Send(b []byte, ep conn.Endpoint) error {
	channelEndpoint, ok := ep.(ChannelEndpoint)
	if !ok {
		return os.ErrInvalid
	}
	select {
	case <-c.closeSignal:
		return net.ErrClosed
	default:
	}

	c.topology.mu.RLock()
	routeErr := c.topology.routeErrors[routeErrorKey{node: c.node, family: channelEndpoint.family}]
	offline := c.topology.offline[channelEndpoint.node]
	mutator := c.topology.mutator
	if channelEndpoint.node < 0 || channelEndpoint.node >= len(c.topology.binds) {
		c.topology.mu.RUnlock()
		return os.ErrInvalid
	}
	destination := c.topology.binds[channelEndpoint.node]
	c.topology.mu.RUnlock()

	if routeErr != nil {
		return routeErr
	}
	if offline {
		return nil
	}

	payload := append([]byte(nil), b...)
	if mutator != nil {
		payload = mutator(c.node, channelEndpoint.node, channelEndpoint.family, payload)
	}

	packet := routedPacket{
		payload: payload,
		source:  c.source4,
	}
	queue := destination.rx4
	if channelEndpoint.family == IPv6 {
		packet.source = c.source6
		queue = destination.rx6
	}

	select {
	case <-destination.closeSignal:
		return nil
	case queue <- packet:
		return nil
	}
}

func (c *ChannelBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	c.topology.mu.RLock()
	if endpoint, ok := c.topology.endpoints[s]; ok {
		c.topology.mu.RUnlock()
		return endpoint, nil
	}
	c.topology.mu.RUnlock()
	return nil, fmt.Errorf("unknown channel endpoint %q", s)
}
