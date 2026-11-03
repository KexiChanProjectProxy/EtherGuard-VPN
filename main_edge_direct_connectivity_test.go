package main

import (
	"strings"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/gencfg"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"gopkg.in/yaml.v2"
)

func TestEdgeDirectConnectivityOmittedHydratesDefaults(t *testing.T) {
	legacy := mtypes.EdgeConfig{
		Peers: []mtypes.PeerInfo{{
			NodeID:              2,
			PersistentKeepalive: 0,
			Static:              true,
		}},
	}
	v2 := mtypes.EdgeConfigV2{}

	hydrateV2DirectConnectivity(&legacy, &v2)

	if got, want := v2.DirectConnectivity.PersistentKeepaliveSeconds, float64(25); got != want {
		t.Fatalf("resolved persistent keepalive = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.SendPingInterval, float64(16); got != want {
		t.Fatalf("send ping interval = %v, want %v", got, want)
	}
	// This is the Edge-local dynamic-peer timeout, not the Super-side timeout.
	if got, want := legacy.DynamicRoute.PeerAliveTimeout, float64(70); got != want {
		t.Fatalf("edge peer alive timeout = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.TimeoutCheckInterval, float64(10); got != want {
		t.Fatalf("offline check interval = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.ConnNextTry, float64(5); got != want {
		t.Fatalf("next endpoint try interval = %v, want %v", got, want)
	}
	route := legacy.DynamicRoute
	if route.DisableEndpointSelection || route.EndpointProbeInterval != 16 || route.EndpointSwitchMarginMS != 5 || route.EndpointSwitchMarginPercent != 15 || route.EndpointSwitchRounds != 3 || route.EndpointSwitchPersistRounds != 10 {
		t.Fatalf("endpoint selection defaults = %+v", route)
	}
	if got, want := legacy.Peers[0].PersistentKeepalive, uint32(0); got != want {
		t.Fatalf("static peer keepalive = %v, want %v", got, want)
	}
}

func TestEdgeDirectConnectivityExplicitValuesHydrateBeforeDeviceStartup(t *testing.T) {
	legacy := mtypes.EdgeConfig{}
	v2 := mtypes.EdgeConfigV2{DirectConnectivity: mtypes.ControlV2DirectConnectivity{
		PersistentKeepaliveSeconds: 31,
		PingIntervalSeconds:        17,
		PeerAliveTimeoutSeconds:    71,
		OfflineCheckSeconds:        11,
		NextEndpointTrySeconds:     6,
	}}

	hydrateV2DirectConnectivity(&legacy, &v2)

	if got, want := v2.DirectConnectivity.PersistentKeepaliveSeconds, float64(31); got != want {
		t.Fatalf("resolved persistent keepalive = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.SendPingInterval, float64(17); got != want {
		t.Fatalf("send ping interval = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.PeerAliveTimeout, float64(71); got != want {
		t.Fatalf("edge peer alive timeout = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.TimeoutCheckInterval, float64(11); got != want {
		t.Fatalf("offline check interval = %v, want %v", got, want)
	}
	if got, want := legacy.DynamicRoute.ConnNextTry, float64(6); got != want {
		t.Fatalf("next endpoint try interval = %v, want %v", got, want)
	}
}

func TestEdgeEndpointSelectionExplicitValuesHydrateBeforeDeviceStartup(t *testing.T) {
	legacy := mtypes.EdgeConfig{}
	v2 := mtypes.EdgeConfigV2{DirectConnectivity: mtypes.ControlV2DirectConnectivity{
		DisableEndpointSelection:     true,
		EndpointProbeIntervalSeconds: 7,
		EndpointSwitchMarginMS:       12,
		EndpointSwitchMarginPercent:  25,
		EndpointSwitchRounds:         4,
		EndpointSwitchPersistRounds:  20,
	}}

	hydrateV2DirectConnectivity(&legacy, &v2)

	route := legacy.DynamicRoute
	if !route.DisableEndpointSelection || route.EndpointProbeInterval != 7 || route.EndpointSwitchMarginMS != 12 || route.EndpointSwitchMarginPercent != 25 || route.EndpointSwitchRounds != 4 || route.EndpointSwitchPersistRounds != 20 {
		t.Fatalf("hydrated endpoint selection = %+v", route)
	}
}

func TestExampleEdgeConfigV2EmitsDirectConnectivity(t *testing.T) {
	config, err := gencfg.GetExampleEdgeConfV2("")
	if err != nil {
		t.Fatalf("get example edge config: %v", err)
	}

	encoded, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("marshal example edge config: %v", err)
	}
	if !strings.Contains(string(encoded), "DirectConnectivity:") {
		t.Fatalf("generated edge YAML omits DirectConnectivity:\n%s", encoded)
	}

	var decoded mtypes.EdgeConfigV2
	if err := yaml.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode generated edge config: %v", err)
	}
	if got, want := decoded.DirectConnectivity, (mtypes.ControlV2DirectConnectivity{
		PersistentKeepaliveSeconds:  25,
		PingIntervalSeconds:         16,
		PeerAliveTimeoutSeconds:     70,
		OfflineCheckSeconds:         10,
		NextEndpointTrySeconds:      5,
		EndpointSwitchMarginMS:      5,
		EndpointSwitchMarginPercent: 15,
		EndpointSwitchRounds:        3,
		EndpointSwitchPersistRounds: 10,
	}); got != want {
		t.Fatalf("generated DirectConnectivity = %#v, want %#v", got, want)
	}
}

func TestValidateDynamicRouteEndpointBlacklist(t *testing.T) {
	p2p := func(entries ...string) *mtypes.EdgeConfig {
		return &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{P2P: mtypes.P2PInfo{UseP2P: true}, EndpointBlacklist: entries}}
	}
	cases := []struct {
		name   string
		config *mtypes.EdgeConfig
		ok     bool
	}{
		{"empty", p2p(), true},
		{"ip and cidr", p2p("203.0.113.12", "10.0.0.0/8", "2001:db8::/32"), true},
		{"invalid entry", p2p("not-an-ip"), false},
		{"static mode", &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{EndpointBlacklist: []string{"203.0.113.12"}}}, false},
		{"super mode", func() *mtypes.EdgeConfig { c := p2p("203.0.113.12"); c.SuperNodeV2Enabled = true; return c }(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDynamicRoute(tc.config)
			if (err == nil) != tc.ok {
				t.Fatalf("validateDynamicRoute() error = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestValidateDynamicRoutePureP2P(t *testing.T) {
	config := func(useP2P, pure, super bool, graph mtypes.GraphRecalculateSetting) *mtypes.EdgeConfig {
		return &mtypes.EdgeConfig{
			SuperNodeV2Enabled: super,
			DynamicRoute: mtypes.DynamicRouteInfo{P2P: mtypes.P2PInfo{
				UseP2P:                  useP2P,
				PureP2P:                 pure,
				GraphRecalculateSetting: graph,
			}},
		}
	}
	ignoredGraph := mtypes.GraphRecalculateSetting{StaticMode: true, ManualLatency: mtypes.DistTable{1: {2: 3}}}
	cases := []struct {
		name   string
		config *mtypes.EdgeConfig
		ok     bool
	}{
		{"pure p2p", config(true, true, false, mtypes.GraphRecalculateSetting{}), true},
		{"graph settings ignored", config(true, true, false, ignoredGraph), true},
		{"without UseP2P", config(false, true, false, mtypes.GraphRecalculateSetting{}), false},
		{"with super", config(true, true, true, mtypes.GraphRecalculateSetting{}), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDynamicRoute(tc.config)
			if (err == nil) != tc.ok {
				t.Fatalf("validateDynamicRoute() error = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestApplyPureP2PConfigClearsUnusedSettings(t *testing.T) {
	newConfig := func(pure bool) *mtypes.EdgeConfig {
		return &mtypes.EdgeConfig{
			LogLevel:     mtypes.LoggerInfo{LogNTP: true},
			NextHopTable: mtypes.NextHopTable{1: {2: 2}},
			DynamicRoute: mtypes.DynamicRouteInfo{
				NTPConfig: mtypes.NTPInfo{UseNTP: true, Servers: []string{"pool.ntp.org"}},
				P2P: mtypes.P2PInfo{
					UseP2P:                  true,
					PureP2P:                 pure,
					GraphRecalculateSetting: mtypes.GraphRecalculateSetting{StaticMode: true},
				},
			},
		}
	}

	pure := newConfig(true)
	notes := applyPureP2PConfig(pure)
	if pure.DynamicRoute.NTPConfig.UseNTP || pure.LogLevel.LogNTP || len(pure.NextHopTable) != 0 {
		t.Fatalf("PureP2P config not cleared: %+v", pure)
	}
	if len(notes) != 3 {
		t.Fatalf("notes = %q, want NTP, NextHopTable and graph notes", notes)
	}

	regular := newConfig(false)
	if notes := applyPureP2PConfig(regular); notes != nil {
		t.Fatalf("regular P2P notes = %q, want none", notes)
	}
	if !regular.DynamicRoute.NTPConfig.UseNTP || !regular.LogLevel.LogNTP || len(regular.NextHopTable) != 1 {
		t.Fatalf("regular P2P config changed: %+v", regular)
	}
}
