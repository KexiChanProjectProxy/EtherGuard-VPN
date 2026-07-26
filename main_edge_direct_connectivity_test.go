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
		PersistentKeepaliveSeconds: 25,
		PingIntervalSeconds:        16,
		PeerAliveTimeoutSeconds:    70,
		OfflineCheckSeconds:        10,
		NextEndpointTrySeconds:     5,
	}); got != want {
		t.Fatalf("generated DirectConnectivity = %#v, want %#v", got, want)
	}
}
