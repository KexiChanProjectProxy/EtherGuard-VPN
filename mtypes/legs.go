package mtypes

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
)

// LegsConfig is the controller side of remote legs: the edge listens for leg
// agents on its site network and adds their uplinks to its own.
type LegsConfig struct {
	// Listen is the address agents send frames to, for example
	// 0.0.0.0:16400.
	Listen string `yaml:"Listen"`
	// Key is the base64 site key shared with every agent (32 bytes).
	Key string `yaml:"Key"`
	// Peers are agent addresses the controller can reach on its own. Agents
	// that know the controller's address need no entry here: they are learned
	// from their frames.
	Peers []string `yaml:"Peers,omitempty"`
	// HeartbeatTimeout is how many seconds an agent stays up without a
	// state frame; 0 means 6.
	HeartbeatTimeout float64 `yaml:"HeartbeatTimeout,omitempty"`
}

// LegAgentConfig configures a leg agent (-mode leg).
type LegAgentConfig struct {
	// AgentID identifies this agent to the controller, 1 to 65535. It must
	// be unique on the site and stay the same across restarts.
	AgentID uint16 `yaml:"AgentID"`
	// Listen is the site-network address for frames from the controller;
	// empty picks a random port, which only works when Controller is set.
	Listen string `yaml:"Listen"`
	// Controller is the controller's Legs.Listen address as this agent
	// reaches it. Optional when the controller lists this agent in its
	// Legs.Peers.
	Controller string `yaml:"Controller,omitempty"`
	Key        string `yaml:"Key"`
	// ListenPort is the UDP port of the uplink socket that peers reach; 0
	// picks a random port.
	ListenPort int            `yaml:"ListenPort"`
	FwMark     uint32         `yaml:"FwMark,omitempty"`
	DisableAf  conn.EnabledAf `yaml:"DisabledAf"`
	// Interfaces, when set, limits the uplinks to these interface names.
	Interfaces []string `yaml:"Interfaces,omitempty"`
	// ExcludeInterfaces leaves these interfaces out, for example the
	// controller's own VPN tap when the agent runs beside it.
	ExcludeInterfaces []string `yaml:"ExcludeInterfaces,omitempty"`
	HeartbeatTimeout  float64  `yaml:"HeartbeatTimeout,omitempty"`
	LogLevel          string   `yaml:"LogLevel"`
}

func legHeartbeatTimeout(seconds float64) (time.Duration, error) {
	if seconds < 0 {
		return 0, errors.New("HeartbeatTimeout must not be negative")
	}
	if seconds == 0 {
		return conn.DefaultLegHeartbeatTimeout, nil
	}
	timeout := S2TD(seconds)
	if timeout <= conn.LegHeartbeatInterval {
		return 0, fmt.Errorf("HeartbeatTimeout must be longer than the %v heartbeat", conn.LegHeartbeatInterval)
	}
	return timeout, nil
}

// ParseLegAddr parses an ip:port leg address.
func ParseLegAddr(s string) (netip.AddrPort, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

// BindConfig validates c and converts it for conn.NewLegBind.
func (c LegsConfig) BindConfig() (conn.LegConfig, error) {
	var out conn.LegConfig
	listen, err := ParseLegAddr(c.Listen)
	if err != nil {
		return out, fmt.Errorf("Legs.Listen: %w", err)
	}
	if listen.Port() == 0 {
		return out, errors.New("Legs.Listen needs a fixed port")
	}
	key, err := conn.ParseLegKey(c.Key)
	if err != nil {
		return out, fmt.Errorf("Legs.Key: %w", err)
	}
	for i, raw := range c.Peers {
		peer, err := ParseLegAddr(raw)
		if err != nil || peer.Port() == 0 || peer.Addr().IsUnspecified() {
			return out, fmt.Errorf("Legs.Peers[%d]: invalid address %q", i, raw)
		}
		out.Peers = append(out.Peers, peer)
	}
	timeout, err := legHeartbeatTimeout(c.HeartbeatTimeout)
	if err != nil {
		return out, fmt.Errorf("Legs.%w", err)
	}
	out.Listen, out.Key, out.HeartbeatTimeout = listen, key, timeout
	return out, nil
}

// LegAgentSettings is a validated LegAgentConfig.
type LegAgentSettings struct {
	AgentID          uint16
	Listen           netip.AddrPort
	Controller       netip.AddrPort // invalid when not configured
	Key              conn.LegKey
	HeartbeatTimeout time.Duration
}

// Validate checks c and returns the parsed settings.
func (c LegAgentConfig) Validate() (LegAgentSettings, error) {
	var out LegAgentSettings
	if c.AgentID == conn.LegControllerID {
		return out, errors.New("AgentID must be between 1 and 65535")
	}
	out.AgentID = c.AgentID
	var err error
	if c.Listen == "" {
		out.Listen = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	} else if out.Listen, err = ParseLegAddr(c.Listen); err != nil {
		return out, fmt.Errorf("Listen: %w", err)
	}
	if c.Controller != "" {
		if out.Controller, err = ParseLegAddr(c.Controller); err != nil || out.Controller.Port() == 0 || out.Controller.Addr().IsUnspecified() {
			return out, fmt.Errorf("Controller: invalid address %q", c.Controller)
		}
	} else if out.Listen.Port() == 0 {
		return out, errors.New("set Controller, or a fixed Listen port that the controller lists in Legs.Peers")
	}
	if out.Key, err = conn.ParseLegKey(c.Key); err != nil {
		return out, fmt.Errorf("Key: %w", err)
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		return out, fmt.Errorf("ListenPort %d out of range", c.ListenPort)
	}
	if out.HeartbeatTimeout, err = legHeartbeatTimeout(c.HeartbeatTimeout); err != nil {
		return out, err
	}
	return out, nil
}
