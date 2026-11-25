/* SPDX-License-Identifier: MIT */

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

// legRediscoverEvery is how many heartbeats pass between uplink scans.
const legRediscoverEvery = 5

func printExampleLegConf() {
	example := mtypes.LegAgentConfig{
		AgentID:    1,
		Listen:     "0.0.0.0:16400",
		Controller: "192.168.1.10:16400",
		Key:        "<base64 32-byte key, the same as the controller's Legs.Key>",
		ListenPort: 16386,
		LogLevel:   "error",
	}
	out, _ := yaml.Marshal(example)
	fmt.Print(string(out))
}

// Leg runs a leg agent: it relays the controller's WireGuard datagrams
// through this machine's uplinks.
func Leg(configPath string, printExample bool, bindmode string) error {
	if printExample {
		printExampleLegConf()
		return nil
	}
	var cfg mtypes.LegAgentConfig
	if err := mtypes.ReadYaml(configPath, &cfg); err != nil {
		return fmt.Errorf("parse leg config %q: %w", configPath, err)
	}
	settings, err := cfg.Validate()
	if err != nil {
		return fmt.Errorf("validate leg config %q: %w", configPath, err)
	}
	logLevel := device.LogLevelError
	switch cfg.LogLevel {
	case "verbose", "debug":
		logLevel = device.LogLevelVerbose
	case "silent":
		logLevel = device.LogLevelSilent
	}
	logger := device.NewLogger(logLevel, fmt.Sprintf("(leg %d) ", cfg.AgentID))
	enabledAf := cfg.DisableAf.Disalbed2Enabled()
	agent := newLegAgent(settings, legAgentOptions{
		wan:        conn.NewDefaultBind(enabledAf, bindmode, cfg.FwMark),
		listenPort: uint16(cfg.ListenPort),
		fwmark:     cfg.FwMark,
		uplinks:    hostUplinks(cfg, enabledAf),
		logger:     logger,
	})
	if err := agent.Start(); err != nil {
		return err
	}
	defer agent.Close()
	logger.Verbosef("Leg agent %d: site socket %s, uplink port %d", settings.AgentID, agent.LocalAddr(), agent.WANPort())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	<-signals
	return nil
}

// hostUplinks returns the uplink scan for this host: discovered interfaces,
// filtered by the configured names and by kernel routes.
func hostUplinks(cfg mtypes.LegAgentConfig, enabledAf conn.EnabledAf) func() ([]device.Uplink, error) {
	listenV4, _ := netip.ParseAddr(cfg.DisableAf.ListenIPv4)
	listenV6, _ := netip.ParseAddr(cfg.DisableAf.ListenIPv6)
	return func() ([]device.Uplink, error) {
		found, err := device.DiscoverUplinks("", enabledAf, listenV4, listenV6)
		if err != nil {
			return nil, err
		}
		var uplinks []device.Uplink
		for _, uplink := range found {
			if len(cfg.Interfaces) > 0 && !slices.Contains(cfg.Interfaces, uplink.Name) {
				continue
			}
			if slices.Contains(cfg.ExcludeInterfaces, uplink.Name) {
				continue
			}
			if device.CheckUplinkRoute(uplink, cfg.FwMark) != nil {
				continue
			}
			uplinks = append(uplinks, uplink)
		}
		return uplinks, nil
	}
}

type legAgentOptions struct {
	wan        conn.Bind
	listenPort uint16
	fwmark     uint32
	uplinks    func() ([]device.Uplink, error)
	logger     *device.Logger
}

type agentLeg struct {
	id     uint8
	uplink device.Uplink
}

// legAgent is the agent side of remote legs.
type legAgent struct {
	settings mtypes.LegAgentSettings
	opts     legAgentOptions
	seq      *conn.LegSequence
	pinner   conn.EndpointSourcePinner

	lan     *net.UDPConn
	wanPort uint16
	stop    chan struct{}
	wg      sync.WaitGroup

	mu sync.RWMutex
	// legs are the announced uplinks; ids keeps each uplink's leg ID stable
	// across scans.
	legs       []agentLeg
	ids        map[string]uint8
	guard      conn.LegReplayGuard
	controller netip.AddrPort // learned from state frames
}

func newLegAgent(settings mtypes.LegAgentSettings, opts legAgentOptions) *legAgent {
	agent := &legAgent{settings: settings, opts: opts, seq: conn.NewLegSequence(), ids: make(map[string]uint8)}
	agent.pinner, _ = opts.wan.(conn.EndpointSourcePinner)
	return agent
}

func (a *legAgent) logf(format string, args ...any) {
	if a.opts.logger != nil {
		a.opts.logger.Verbosef(format, args...)
	}
}

func (a *legAgent) errorf(format string, args ...any) {
	if a.opts.logger != nil {
		a.opts.logger.Errorf(format, args...)
	}
}

// Start opens the sockets, scans the uplinks and starts relaying.
func (a *legAgent) Start() error {
	fns, port, err := a.opts.wan.Open(a.opts.listenPort)
	if err != nil {
		return fmt.Errorf("leg agent uplink socket on port %d: %w", a.opts.listenPort, err)
	}
	if a.opts.fwmark != 0 {
		if err := a.opts.wan.SetMark(a.opts.fwmark); err != nil {
			a.opts.wan.Close()
			return fmt.Errorf("leg agent fwmark: %w", err)
		}
	}
	lan, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(a.settings.Listen))
	if err != nil {
		a.opts.wan.Close()
		return fmt.Errorf("leg agent site socket %s: %w", a.settings.Listen, err)
	}
	a.lan, a.wanPort, a.stop = lan, port, make(chan struct{})
	a.rescan()
	a.wg.Add(2 + len(fns))
	go a.lanLoop()
	go a.heartbeat()
	for _, fn := range fns {
		go a.wanLoop(fn)
	}
	return nil
}

func (a *legAgent) LocalAddr() netip.AddrPort {
	return a.lan.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (a *legAgent) WANPort() uint16 { return a.wanPort }

func (a *legAgent) Close() {
	close(a.stop)
	a.lan.Close()
	a.opts.wan.Close()
	a.wg.Wait()
}

// rescan refreshes the uplink list. Without source pinning only the first
// uplink of each family can be used.
func (a *legAgent) rescan() {
	uplinks, err := a.opts.uplinks()
	if err != nil {
		a.errorf("Leg agent: uplink scan failed: %v", err)
		return
	}
	if a.pinner == nil {
		var have4, have6 bool
		uplinks = slices.DeleteFunc(uplinks, func(uplink device.Uplink) bool {
			if uplink.Addr.Unmap().Is4() {
				keep := !have4
				have4 = true
				return !keep
			}
			keep := !have6
			have6 = true
			return !keep
		})
	}
	if len(uplinks) > conn.MaxLegsPerAgent {
		uplinks = uplinks[:conn.MaxLegsPerAgent]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	used := make(map[uint8]bool)
	legs := make([]agentLeg, 0, len(uplinks))
	var fresh []device.Uplink
	for _, uplink := range uplinks {
		if id, ok := a.ids[legUplinkKey(uplink)]; ok && !used[id] {
			used[id] = true
			legs = append(legs, agentLeg{id: id, uplink: uplink})
			continue
		}
		fresh = append(fresh, uplink)
	}
	for _, uplink := range fresh {
		id := uint8(0)
		for used[id] {
			id++
		}
		used[id] = true
		a.ids[legUplinkKey(uplink)] = id
		legs = append(legs, agentLeg{id: id, uplink: uplink})
	}
	// Forget IDs of uplinks that are gone, so the ID space cannot fill up.
	for key, id := range a.ids {
		if !used[id] {
			delete(a.ids, key)
		}
	}
	slices.SortFunc(legs, func(x, y agentLeg) int { return int(x.id) - int(y.id) })
	if !slices.EqualFunc(legs, a.legs, func(x, y agentLeg) bool { return x.id == y.id && x.uplink == y.uplink }) {
		for _, leg := range legs {
			a.logf("Leg agent: leg %d is %s %s", leg.id, leg.uplink.Name, leg.uplink.Addr)
		}
		if len(legs) == 0 {
			a.errorf("Leg agent: no usable uplinks")
		}
	}
	a.legs = legs
}

func legUplinkKey(uplink device.Uplink) string {
	return uplink.Name + "|" + uplink.Addr.String()
}

// controllerTargets returns where state frames go: the configured controller
// and the address learned from its frames.
func (a *legAgent) controllerTargets() []netip.AddrPort {
	a.mu.RLock()
	defer a.mu.RUnlock()
	var targets []netip.AddrPort
	if a.settings.Controller.IsValid() {
		targets = append(targets, a.settings.Controller)
	}
	if a.controller.IsValid() && a.controller != a.settings.Controller {
		targets = append(targets, a.controller)
	}
	return targets
}

// dataTarget is where relayed datagrams go: the configured controller, else
// the learned one.
func (a *legAgent) dataTarget() (netip.AddrPort, bool) {
	if a.settings.Controller.IsValid() {
		return a.settings.Controller, true
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.controller, a.controller.IsValid()
}

func (a *legAgent) stateFrame() []byte {
	a.mu.RLock()
	infos := make([]conn.LegInfo, 0, len(a.legs))
	for _, leg := range a.legs {
		infos = append(infos, conn.LegInfo{
			LegID: leg.id,
			Name:  leg.uplink.Name,
			Addr:  netip.AddrPortFrom(leg.uplink.Addr, a.wanPort),
		})
	}
	a.mu.RUnlock()
	epoch, counter := a.seq.Next()
	return conn.AppendLegFrame(nil, &a.settings.Key, conn.LegFrame{
		Type: conn.LegFrameState, AgentID: a.settings.AgentID,
		Epoch: epoch, Counter: counter, Body: conn.AppendLegState(nil, infos),
	})
}

func (a *legAgent) sendState() {
	frame := a.stateFrame()
	for _, target := range a.controllerTargets() {
		if _, err := a.lan.WriteToUDPAddrPort(frame, target); err != nil {
			a.logf("Leg agent: state to %s failed: %v", target, err)
		}
	}
}

func (a *legAgent) heartbeat() {
	defer a.wg.Done()
	ticker := time.NewTicker(conn.LegHeartbeatInterval)
	defer ticker.Stop()
	for beat := 1; ; beat++ {
		a.sendState()
		select {
		case <-a.stop:
			return
		case <-ticker.C:
		}
		if beat%legRediscoverEvery == 0 {
			a.rescan()
		}
	}
}

// lanLoop handles frames from the controller.
func (a *legAgent) lanLoop() {
	defer a.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := a.lan.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			a.logf("Leg agent: site socket: %v", err)
			continue
		}
		frame, err := conn.DecodeLegFrame(&a.settings.Key, buf[:n])
		if err != nil {
			a.logf("Leg agent: dropping frame from %s: %v", from, err)
			continue
		}
		switch frame.Type {
		case conn.LegFrameState:
			if frame.AgentID != conn.LegControllerID {
				continue
			}
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			a.mu.Lock()
			fresh := a.guard.Accept(frame.Epoch, frame.Counter, time.Now(), a.settings.HeartbeatTimeout)
			learned := fresh && a.controller != from
			if fresh {
				a.controller = from
			}
			a.mu.Unlock()
			if learned {
				a.logf("Leg agent: controller at %s", from)
				// Answer at once, so a controller that only knows this
				// agent from its own Peers list sees the legs now.
				a.sendState()
			}
		case conn.LegFrameData:
			if frame.AgentID == a.settings.AgentID && frame.Addr.IsValid() {
				a.relayOut(frame)
			}
		}
	}
}

// relayOut sends a datagram from the controller out of the named leg.
func (a *legAgent) relayOut(frame conn.LegFrame) {
	a.mu.RLock()
	var uplink device.Uplink
	found := false
	for _, leg := range a.legs {
		if leg.id == frame.LegID {
			uplink, found = leg.uplink, true
			break
		}
	}
	a.mu.RUnlock()
	if !found || uplink.Addr.Unmap().Is4() != frame.Addr.Addr().Is4() {
		return
	}
	var endpoint conn.Endpoint
	var err error
	if a.pinner != nil {
		endpoint, err = a.pinner.ParseEndpointFrom(frame.Addr.String(), uplink.Addr, uplink.Ifindex)
	} else {
		endpoint, err = a.opts.wan.ParseEndpoint(frame.Addr.String())
	}
	if err != nil {
		a.logf("Leg agent: leg %d to %s: %v", frame.LegID, frame.Addr, err)
		return
	}
	if err := a.opts.wan.Send(frame.Body, endpoint); err != nil {
		a.logf("Leg agent: send on leg %d to %s failed: %v", frame.LegID, frame.Addr, err)
	}
}

// legFor maps the local address a datagram arrived on to a leg. Without
// source information it falls back to the only leg of the family.
func (a *legAgent) legFor(local net.IP, remote netip.Addr) (uint8, bool) {
	addr, ok := netip.AddrFromSlice(local)
	addr = addr.Unmap()
	a.mu.RLock()
	defer a.mu.RUnlock()
	if ok && !addr.IsUnspecified() {
		for _, leg := range a.legs {
			if leg.uplink.Addr.Unmap() == addr {
				return leg.id, true
			}
		}
		return 0, false
	}
	var match []uint8
	for _, leg := range a.legs {
		if leg.uplink.Addr.Unmap().Is4() == remote.Is4() {
			match = append(match, leg.id)
		}
	}
	if len(match) == 1 {
		return match[0], true
	}
	return 0, false
}

// wanLoop relays datagrams from peers to the controller.
func (a *legAgent) wanLoop(fn conn.ReceiveFunc) {
	defer a.wg.Done()
	buf := make([]byte, 65536)
	out := make([]byte, 0, 65536+conn.LegFrameOverhead)
	for {
		n, endpoint, err := fn(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-a.stop:
				return
			default:
			}
			a.logf("Leg agent: uplink socket: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		remote, err := netip.ParseAddrPort(endpoint.DstToString())
		if err != nil {
			continue
		}
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
		legID, ok := a.legFor(endpoint.SrcIP(), remote.Addr())
		if !ok {
			a.logf("Leg agent: datagram from %s on unknown local address %s", remote, endpoint.SrcToString())
			continue
		}
		target, ok := a.dataTarget()
		if !ok {
			continue
		}
		epoch, counter := a.seq.Next()
		out = conn.AppendLegFrame(out[:0], &a.settings.Key, conn.LegFrame{
			Type: conn.LegFrameData, AgentID: a.settings.AgentID, LegID: legID,
			Epoch: epoch, Counter: counter, Addr: remote, Body: buf[:n],
		})
		if _, err := a.lan.WriteToUDPAddrPort(out, target); err != nil {
			a.logf("Leg agent: relay to controller %s failed: %v", target, err)
		}
	}
}
