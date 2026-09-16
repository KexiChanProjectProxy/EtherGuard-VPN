package main

import (
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestMainEdgeV2EnabledFromLegacyAPIUrl(t *testing.T) {
	// Given
	config := mtypes.EdgeConfigV2{
		NodeID:   1,
		NodeName: "EgNet001",
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       "http://127.0.0.1:3456",
			APIPrefix:    "/edge/v2",
			NodeID:       10,
			ControlPSKey: "control-key",
		},
	}

	// When
	enabled := edgeSuperNodeV2Enabled(config)

	// Then
	if !enabled {
		t.Fatal("legacy APIUrl-only SuperNodeV2 must enable v2 edge mode")
	}
}

func TestMainEdgeV2EnabledFromAPIUrlsOnly(t *testing.T) {
	// Given
	config := mtypes.EdgeConfigV2{
		NodeID:   7,
		NodeName: "edge-007",
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      []string{"https://a.example", "https://b.example"},
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "control-key",
		},
	}

	// When
	enabled := edgeSuperNodeV2Enabled(config)

	// Then
	if !enabled {
		t.Fatal("APIUrls-only SuperNodeV2 must enable v2 edge mode")
	}
}

func TestMainEdgeV2DisabledWithoutSuperURLs(t *testing.T) {
	// Given
	config := mtypes.EdgeConfigV2{NodeID: 7, NodeName: "edge-007"}

	// When
	enabled := edgeSuperNodeV2Enabled(config)

	// Then
	if enabled {
		t.Fatal("empty SuperNodeV2 must not enable v2 edge mode")
	}
}

func TestMainEdgeHydrateV2FromAPIUrlsOnly(t *testing.T) {
	// Given
	v2 := mtypes.EdgeConfigV2{
		NodeID:   7,
		NodeName: "edge-007",
		PrivKey:  "mL5IW0GuqbjgDeOJuPHBU2iJzBPNKhaNEXbIGwwYWWk=",
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      []string{"https://a.example", "https://b.example"},
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "control-key",
		},
	}
	var legacy mtypes.EdgeConfig

	// When
	hydrateV2EdgeConfig(&legacy, &v2)

	// Then
	if !legacy.SuperNodeV2Enabled {
		t.Fatal("hydration must mark SuperNodeV2Enabled without reading SuperNodeV2.APIUrl")
	}
	if legacy.NodeID != v2.NodeID || legacy.NodeName != v2.NodeName || legacy.PrivKey != v2.PrivKey {
		t.Fatalf("hydrated identity = id %v name %q key %q", legacy.NodeID, legacy.NodeName, legacy.PrivKey)
	}
}

func TestMainEdgeLegacyExampleYAMLStillV2Enabled(t *testing.T) {
	// Given
	var config mtypes.EdgeConfigV2
	if err := mtypes.ReadYaml("example_config/super_mode/EgNet_edge001.yaml", &config); err != nil {
		t.Fatalf("load example edge yaml: %v", err)
	}

	// When
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	enabled := edgeSuperNodeV2Enabled(config)

	// Then
	if !enabled {
		t.Fatal("example_config/super_mode/EgNet_edge001.yaml must still enable v2 edge mode")
	}
	if got := config.SuperNodeV2.ResolveAPIUrls(); len(got) != 1 {
		t.Fatalf("ResolveAPIUrls() = %v, want exactly 1 URL", got)
	}
}
