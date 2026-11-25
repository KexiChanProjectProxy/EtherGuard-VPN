package mtypes

import (
	"testing"
	"time"
)

const testLegKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func TestLegsConfigBindConfig(t *testing.T) {
	cfg, err := LegsConfig{Listen: "0.0.0.0:16400", Key: testLegKey, Peers: []string{"192.168.1.21:16400"}, HeartbeatTimeout: 10}.BindConfig()
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if cfg.Listen.Port() != 16400 || len(cfg.Peers) != 1 || cfg.HeartbeatTimeout != 10*time.Second {
		t.Fatalf("got %+v", cfg)
	}
	if cfg, _ := (LegsConfig{Listen: "0.0.0.0:16400", Key: testLegKey}).BindConfig(); cfg.HeartbeatTimeout != 6*time.Second {
		t.Fatalf("default timeout %v", cfg.HeartbeatTimeout)
	}
	for name, bad := range map[string]LegsConfig{
		"no listen":     {Key: testLegKey},
		"random port":   {Listen: "0.0.0.0:0", Key: testLegKey},
		"bad key":       {Listen: "0.0.0.0:16400", Key: "short"},
		"bad peer":      {Listen: "0.0.0.0:16400", Key: testLegKey, Peers: []string{"host:1"}},
		"unspec peer":   {Listen: "0.0.0.0:16400", Key: testLegKey, Peers: []string{"0.0.0.0:1"}},
		"short timeout": {Listen: "0.0.0.0:16400", Key: testLegKey, HeartbeatTimeout: 1},
	} {
		if _, err := bad.BindConfig(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLegAgentConfigValidate(t *testing.T) {
	settings, err := LegAgentConfig{AgentID: 3, Controller: "192.168.1.10:16400", Key: testLegKey}.Validate()
	if err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if settings.AgentID != 3 || settings.Listen.Port() != 0 || settings.Controller.String() != "192.168.1.10:16400" {
		t.Fatalf("got %+v", settings)
	}
	// Without Controller the controller must reach a fixed port.
	if _, err := (LegAgentConfig{AgentID: 3, Listen: "0.0.0.0:16400", Key: testLegKey}).Validate(); err != nil {
		t.Fatalf("listen-only config: %v", err)
	}
	for name, bad := range map[string]LegAgentConfig{
		"agent id 0":        {Controller: "192.168.1.10:16400", Key: testLegKey},
		"no way to connect": {AgentID: 1, Key: testLegKey},
		"bad controller":    {AgentID: 1, Controller: "nope", Key: testLegKey},
		"bad key":           {AgentID: 1, Controller: "192.168.1.10:16400", Key: ""},
		"bad port":          {AgentID: 1, Controller: "192.168.1.10:16400", Key: testLegKey, ListenPort: 70000},
	} {
		if _, err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
