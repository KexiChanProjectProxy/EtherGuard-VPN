package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/gencfg"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestEdgeV2ConfigCarriesPrivateKeyToLegacyConfig(t *testing.T) {
	// Given
	privateKey := "mL5IW0GuqbjgDeOJuPHBU2iJzBPNKhaNEXbIGwwYWWk="
	configPath := filepath.Join(t.TempDir(), "edge.yaml")
	configYAML := []byte(`
PrivKey: ` + privateKey + `
NodeID: 7
NodeName: edge-007
SuperNodeV2:
  APIUrl: https://super.example.com:8443
  APIPrefix: /edge/v2
  NodeID: 1
  ControlPSKey: test-control-key
`)
	if err := os.WriteFile(configPath, configYAML, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	var v2Config mtypes.EdgeConfigV2
	if err := mtypes.ReadYaml(configPath, &v2Config); err != nil {
		t.Fatalf("read v2 config: %v", err)
	}

	// When
	var legacyConfig mtypes.EdgeConfig
	hydrateV2EdgeConfig(&legacyConfig, &v2Config)

	// Then
	if legacyConfig.PrivKey != privateKey {
		t.Fatalf("legacy private key = %q, want %q", legacyConfig.PrivKey, privateKey)
	}
}

func TestExampleEdgeV2ConfigContainsRunnablePrivateKey(t *testing.T) {
	// Given / When
	config, err := gencfg.GetExampleEdgeConfV2("")
	if err != nil {
		t.Fatalf("get example v2 edge config: %v", err)
	}

	// Then
	if config.PrivKey == "" {
		t.Fatal("example v2 edge config has an empty private key")
	}
	if _, err := device.Str2PriKey(config.PrivKey); err != nil {
		t.Fatalf("example v2 edge private key is not decodable: %v", err)
	}
}
