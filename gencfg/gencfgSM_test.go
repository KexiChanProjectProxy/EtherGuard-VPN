package gencfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

func TestGenSuperCfgHTTPOnly(t *testing.T) {
	// Given
	outputDir := t.TempDir()
	inputPath := writeSuperGeneratorInput(t, outputDir)

	// When
	err := GenSuperCfg(inputPath, false)

	// Then
	if err != nil {
		t.Fatalf("GenSuperCfg() error = %v", err)
	}
	superData := readGeneratedFile(t, outputDir, "TestNet_super.yaml")
	for _, obsolete := range []string{"PrivKeyV4:", "PrivKeyV6:", "ListenPort:", "FwMark:", "API_Prefix:"} {
		if strings.Contains(string(superData), obsolete) {
			t.Errorf("generated Super YAML contains obsolete field %q", obsolete)
		}
	}
	var super mtypes.SuperConfigV2
	if err := yaml.Unmarshal(superData, &super); err != nil {
		t.Fatalf("unmarshal generated Super config: %v", err)
	}
	if err := super.Validate(); err != nil {
		t.Fatalf("validate generated Super config: %v", err)
	}
	if super.APIUrl != "http://127.0.0.1:3456" || super.APIPrefix != "/edge/v2" {
		t.Errorf("generated API location = %q %q", super.APIUrl, super.APIPrefix)
	}
	for _, server := range super.STUNServers {
		if err := mtypes.ValidateSTUNURI(server); err != nil {
			t.Errorf("generated STUN server %q invalid: %v", server, err)
		}
	}

	for _, name := range []string{"TestNet_edge1.yaml", "TestNet_edge2.yaml", "TestNet_edge3.yaml"} {
		data := readGeneratedFile(t, outputDir, name)
		for _, obsolete := range []string{"PrivKeyV4:", "PrivKeyV6:", "ListenPort:", "FwMark:", "API_Prefix:", "LegacySuper:", "SuperNode:"} {
			if strings.Contains(string(data), obsolete) {
				t.Errorf("%s contains obsolete field %q", name, obsolete)
			}
		}
		var edge mtypes.EdgeConfigV2
		if err := yaml.Unmarshal(data, &edge); err != nil {
			t.Fatalf("unmarshal %s: %v", name, err)
		}
		if err := edge.Validate(); err != nil {
			t.Fatalf("validate %s: %v", name, err)
		}
		if edge.PrivKey == "" {
			t.Fatalf("generated %s has an empty private key", name)
		}
	}
}

func TestGeneratedControlKeysAreIsolated(t *testing.T) {
	// Given
	outputDir := t.TempDir()
	inputPath := writeSuperGeneratorInput(t, outputDir)

	// When
	if err := GenSuperCfg(inputPath, false); err != nil {
		t.Fatalf("GenSuperCfg() error = %v", err)
	}

	// Then
	var super mtypes.SuperConfigV2
	if err := yaml.Unmarshal(readGeneratedFile(t, outputDir, "TestNet_super.yaml"), &super); err != nil {
		t.Fatalf("unmarshal generated Super config: %v", err)
	}
	peerKeys := make(map[mtypes.Vertex]string, len(super.Peers))
	for _, peer := range super.Peers {
		if _, exists := peerKeys[peer.NodeID]; exists {
			t.Fatalf("duplicate Super peer NodeID %d", peer.NodeID)
		}
		peerKeys[peer.NodeID] = peer.ControlPSKey
	}
	if len(peerKeys) != 3 {
		t.Fatalf("generated Super peer count = %d, want 3", len(peerKeys))
	}

	for _, nodeID := range []mtypes.Vertex{1, 2, 3} {
		var edge mtypes.EdgeConfigV2
		name := "TestNet_edge" + nodeID.ToString() + ".yaml"
		data := readGeneratedFile(t, outputDir, name)
		if err := yaml.Unmarshal(data, &edge); err != nil {
			t.Fatalf("unmarshal %s: %v", name, err)
		}
		if edge.SuperNodeV2.ControlPSKey != peerKeys[nodeID] {
			t.Errorf("edge %d control key does not match its Super peer entry", nodeID)
		}
		for otherID, otherKey := range peerKeys {
			if otherID != nodeID && strings.Contains(string(data), otherKey) {
				t.Errorf("edge %d config contains edge %d control key", nodeID, otherID)
			}
		}
	}
}

// TestGetExampleSuperConfListenPortPriority pins the example Super
// generator output to carry the Super-owned ordered listen-port policy
// exactly as documented. The generated candidate set must expand to
// [16386] so any downstream Edge that registers against an example
// Super sees a single, predictable bind. If this test fails, an
// operator removed the policy from the example config — restore it or
// update the docs contract test that pins the YAML grammar.
//
// GetExampleSuperConf returns a non-nil fs.PathError even when the
// empty template path is requested (the example path is the canonical
// "no template" case). The returned config is the source of truth; we
// assert on cfg.ListenPortPriority directly and ignore the trailing
// sentinel error.
func TestGetExampleSuperConfListenPortPriority(t *testing.T) {
	// Given
	cfg, _ := GetExampleSuperConf("", false)
	// When
	ports, err := cfg.ListenPortPriority.Expand()
	// Then
	if err != nil {
		t.Fatalf("ListenPortPriority.Expand() error = %v", err)
	}
	want := []int{16386}
	if len(ports) != len(want) || ports[0] != want[0] {
		t.Fatalf("example Super policy = %v, want %v", ports, want)
	}
}

func writeSuperGeneratorInput(t *testing.T, outputDir string) string {
	t.Helper()
	input := "Config output dir: " + outputDir + `
Enable generated config overwrite: true
Add NodeID to the interface name: true
ConfigTemplate for super node: ""
ConfigTemplate for edge node: ""
Network name: TestNet
Super Node:
  API URL: http://127.0.0.1:3456
  API prefix: /edge/v2
  STUN servers:
  - stun:203.0.113.10:3478
  - 'stuns:[2001:db8::10]:5349'
  Node ID: 10
Edge Node:
  Node IDs: "[1~3]"
  MacAddress prefix: ""
  IPv4 range: 192.0.2.0/24
  IPv6 range: 2001:db8:1::/64
  IPv6 LL range: fe80::1:0/112
`
	path := filepath.Join(t.TempDir(), "gensuper.yaml")
	if err := os.WriteFile(path, []byte(input), 0o600); err != nil {
		t.Fatalf("write generator input: %v", err)
	}
	return path
}

func readGeneratedFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return data
}
