package mtypes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestControlV2RegisterRequestRoundTrip proves a valid register request
// marshals/unmarshals with all expected fields preserved.
func TestControlV2RegisterRequestRoundTrip(t *testing.T) {
	in := ControlV2RegisterRequest{
		NodeID:         Vertex(7),
		NodeName:       "edge-007",
		Version:        ControlV2ProtocolVersion,
		ListenPort:     51820,
		FwMark:         42,
		LocalV4:        []string{"10.0.0.7"},
		LocalV6:        []string{"fd00::7"},
		PublicV4:       []string{"203.0.113.7:51820"},
		PublicV6:       []string{"[2001:db8::7]:51820"},
		DesiredTTL:     64,
		RequestedAt:    time.Unix(1700000000, 0).UTC(),
		Implementation: "etherguard-go/test",
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal register request: %v", err)
	}
	var out ControlV2RegisterRequest
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal register request: %v", err)
	}
	if out.NodeID != in.NodeID {
		t.Errorf("NodeID lost: got %v want %v", out.NodeID, in.NodeID)
	}
	if out.NodeName != in.NodeName {
		t.Errorf("NodeName lost: got %q want %q", out.NodeName, in.NodeName)
	}
	if out.Version != ControlV2ProtocolVersion {
		t.Errorf("Version lost: got %q want %q", out.Version, ControlV2ProtocolVersion)
	}
	if len(out.LocalV4) != 1 || out.LocalV4[0] != "10.0.0.7" {
		t.Errorf("LocalV4 lost: %v", out.LocalV4)
	}
	if len(out.PublicV4) != 1 || out.PublicV4[0] != "203.0.113.7:51820" {
		t.Errorf("PublicV4 lost: %v", out.PublicV4)
	}
}

// TestControlV2RegisterValidation ensures a register request with a special
// NodeID (broadcast/spread/super/invalid) is rejected with a typed error.
func TestControlV2RegisterValidation(t *testing.T) {
	cases := []struct {
		name   string
		nodeID Vertex
	}{
		{"broadcast", NodeID_Broadcast},
		{"spread", NodeID_Spread},
		{"super", NodeID_SuperNode},
		{"invalid", NodeID_Invalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := ControlV2RegisterRequest{
				NodeID:   tc.nodeID,
				NodeName: "edge-x",
				Version:  ControlV2ProtocolVersion,
			}
			err := req.Validate()
			if err == nil {
				t.Fatalf("expected validation error for NodeID %s", tc.nodeID.ToString())
			}
			if !IsControlV2Error(err) {
				t.Fatalf("expected typed ControlV2Error, got %T: %v", err, err)
			}
		})
	}
}

// TestControlV2RegisterUnsupportedVersion rejects any version other than
// the supported protocol constant.
func TestControlV2RegisterUnsupportedVersion(t *testing.T) {
	req := ControlV2RegisterRequest{
		NodeID:   Vertex(8),
		NodeName: "edge-008",
		Version:  "v1",
	}
	err := req.Validate()
	if err == nil {
		t.Fatalf("expected unsupported-version error")
	}
	if !IsControlV2Error(err) {
		t.Fatalf("expected typed ControlV2Error, got %T", err)
	}
	if got := ErrorCode(err); got != ControlV2ErrUnsupportedVersion {
		t.Fatalf("got code %v, want %v", got, ControlV2ErrUnsupportedVersion)
	}
}

// TestControlV2CandidateValidation covers STUN/local candidates in the
// register/report flow.
func TestControlV2CandidateValidation(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		c := ControlV2Candidate{
			Address: "203.0.113.7:51820",
			Source:  ControlV2CandidateSTUN,
			RTTMS:   35,
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("missing port", func(t *testing.T) {
		c := ControlV2Candidate{Address: "203.0.113.7", Source: ControlV2CandidateSTUN}
		if err := c.Validate(); err == nil {
			t.Fatalf("expected error for missing port")
		}
	})
	t.Run("bad host", func(t *testing.T) {
		c := ControlV2Candidate{Address: "not-an-ip:51820", Source: ControlV2CandidateSTUN}
		if err := c.Validate(); err == nil {
			t.Fatalf("expected error for invalid host")
		}
	})
	t.Run("unknown source", func(t *testing.T) {
		c := ControlV2Candidate{Address: "203.0.113.7:51820", Source: ControlV2CandidateSource("ghost")}
		if err := c.Validate(); err == nil {
			t.Fatalf("expected error for unknown source")
		}
	})
}

// TestControlV2ReportHeartbeat confirms a report carries pong/latency and
// candidate updates with validation.
func TestControlV2ReportHeartbeat(t *testing.T) {
	r := ControlV2ReportRequest{
		NodeID: Vertex(11),
		Pongs: []ControlV2Pong{
			{RequestID: 1, SourceNode: Vertex(11), DestNode: Vertex(12), TimediffMS: 4.2, LatencyMS: 18.0, AliveSeconds: 30},
		},
		Candidates: []ControlV2Candidate{
			{Address: "10.0.0.11:51820", Source: ControlV2CandidateLocal},
			{Address: "203.0.113.11:51820", Source: ControlV2CandidateSTUN, RTTMS: 22},
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Pongs[0].DestNode == Vertex(0) {
		t.Fatalf("DestNode should be set")
	}
}

// TestControlV2ReportRejectsSpecialNodeID asserts report validation rejects
// the same special node IDs as register.
func TestControlV2ReportRejectsSpecialNodeID(t *testing.T) {
	r := ControlV2ReportRequest{NodeID: NodeID_Broadcast}
	if err := r.Validate(); err == nil {
		t.Fatalf("expected validation error for special NodeID")
	}
}

// TestControlV2SnapshotExcludesPSKey proves the snapshot serializes with no
// control PSKey under any field.
func TestControlV2SnapshotExcludesPSKey(t *testing.T) {
	snap := ControlV2Snapshot{
		Revision:   7,
		IssuedAt:   time.Unix(1700000100, 0).UTC(),
		Parameters: validControlV2Parameters(t),
		Peers: []ControlV2Peer{
			{
				NodeID:    Vertex(20),
				NodeName:  "edge-020",
				PubKey:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				PSKey:     "THIS-IS-A-CONTROL-PSKEY-MUST-NOT-LEAK",
				LocalV4:   []string{"10.0.0.20"},
				PublicV4:  []string{"203.0.113.20:51820"},
				LatencyMS: map[Vertex]float64{Vertex(20): 0, Vertex(21): 12.5},
				LastSeen:  time.Unix(1700000000, 0).UTC(),
			},
		},
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(raw), "THIS-IS-A-CONTROL-PSKEY-MUST-NOT-LEAK") {
		t.Fatalf("snapshot JSON leaked control PSKey: %s", raw)
	}
	// PSKey must be json:"-"
	if strings.Contains(string(raw), `"PSKey"`) {
		t.Fatalf("snapshot JSON leaked PSKey field name: %s", raw)
	}
}

// TestControlV2SnapshotRevisionMonotonic asserts the snapshot revision is
// strictly monotonic when applied.
func TestControlV2SnapshotRevisionMonotonic(t *testing.T) {
	a := ControlV2Snapshot{Revision: 5, IssuedAt: time.Now()}
	b := ControlV2Snapshot{Revision: 5, IssuedAt: time.Now()}
	c := ControlV2Snapshot{Revision: 6, IssuedAt: time.Now()}
	if !a.Accepts(&b) {
		t.Fatalf("same revision should be accepted (idempotent)")
	}
	if a.Accepts(&c) && a.Revision >= c.Revision {
		t.Fatalf("newer revision must dominate older one")
	}
}

// TestControlV2EventEnvelope ensures SSE event envelopes preserve their
// revision + event ID for replay.
func TestControlV2EventEnvelope(t *testing.T) {
	ev := ControlV2Event{
		ID:       "evt-42",
		Type:     ControlV2EventPeerChange,
		Revision: 42,
		Data:     ControlV2Peer{NodeID: Vertex(31), NodeName: "edge-031"},
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	if !strings.Contains(string(raw), `"id":"evt-42"`) {
		t.Fatalf("event ID missing: %s", raw)
	}
	if !strings.Contains(string(raw), `"revision":42`) {
		t.Fatalf("revision missing: %s", raw)
	}
	if !strings.Contains(string(raw), `"peer_change"`) && !strings.Contains(string(raw), "PeerChange") {
		t.Fatalf("event type missing: %s", raw)
	}
}

// TestControlV2ParametersParse validates the typed control parameter model
// (STUN list, timing, protocol version).
func TestControlV2ParametersParse(t *testing.T) {
	p, err := ParseControlV2Parameters(strings.NewReader(`{
		"ProtocolVersion": "` + ControlV2ProtocolVersion + `",
		"PollIntervalSeconds": 15,
		"STUNServers": ["stun:1.2.3.4:3478", "stuns:5.6.7.8:5349"],
		"STUNRequestTimeoutMS": 1500,
		"STUNRefreshIntervalSeconds": 60,
		"ReportIntervalSeconds": 10,
		"HeartbeatIntervalSeconds": 25,
		"EventReplay": 128
	}`))
	if err != nil {
		t.Fatalf("parse parameters: %v", err)
	}
	if p.PollInterval <= 0 {
		t.Errorf("PollInterval must be positive, got %v", p.PollInterval)
	}
	if len(p.STUNServers) != 2 {
		t.Fatalf("STUNServers len = %d, want 2", len(p.STUNServers))
	}
	if p.STUNRequestTimeout <= 0 {
		t.Errorf("STUNRequestTimeout must be positive")
	}
}

// TestControlV2ParametersInvalidSTUNURI rejects non-stun schemes and ports.
func TestControlV2ParametersInvalidSTUNURI(t *testing.T) {
	bad := []string{
		`{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":10,"STUNServers":["http://1.2.3.4:80"],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`,
		`{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":10,"STUNServers":["stun:bad-host"],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`,
		`{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":10,"STUNServers":["stun:1.1.1.1:notaport"],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`,
	}
	for i, raw := range bad {
		_, err := ParseControlV2Parameters(strings.NewReader(raw))
		if err == nil {
			t.Fatalf("case %d: expected STUN URI error, got nil for %s", i, raw)
		}
		if !IsControlV2Error(err) {
			t.Fatalf("case %d: expected typed ControlV2Error, got %T", i, err)
		}
	}
}

// TestControlV2ParametersInvalidDuration ensures zero/negative timings are
// rejected.
func TestControlV2ParametersInvalidDuration(t *testing.T) {
	cases := map[string]string{
		"poll": `{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":0,"STUNServers":[],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`,
		"req":  `{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":10,"STUNServers":[],"STUNRequestTimeoutMS":0,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`,
		"rep":  `{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":10,"STUNServers":[],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":-1,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`,
		"hb":   `{"ProtocolVersion":"` + ControlV2ProtocolVersion + `","PollIntervalSeconds":10,"STUNServers":[],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":0,"EventReplay":64}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseControlV2Parameters(strings.NewReader(raw))
			if err == nil {
				t.Fatalf("expected zero-duration error for %s", name)
			}
		})
	}
}

// TestControlV2ParametersUnsupportedVersion rejects a control parameter
// stream that names an unknown protocol version.
func TestControlV2ParametersUnsupportedVersion(t *testing.T) {
	raw := `{"ProtocolVersion":"v9","PollIntervalSeconds":10,"STUNServers":[],"STUNRequestTimeoutMS":1000,"STUNRefreshIntervalSeconds":30,"ReportIntervalSeconds":10,"HeartbeatIntervalSeconds":25,"EventReplay":64}`
	_, err := ParseControlV2Parameters(strings.NewReader(raw))
	if err == nil {
		t.Fatalf("expected unsupported-version error")
	}
	if got := ErrorCode(err); got != ControlV2ErrUnsupportedVersion {
		t.Fatalf("got %v, want %v", got, ControlV2ErrUnsupportedVersion)
	}
}

// TestSuperConfigV2RejectsLegacyUDPFields proves the v2 parser rejects a
// SuperConfig that still carries any of the UDP-only fields.
func TestSuperConfigV2RejectsLegacyUDPFields(t *testing.T) {
	cases := map[string]string{
		"PrivKeyV4": `
NodeName: super
PrivKeyV4: mL5IW0GuqbjgDeOJuPHBU2iJzBPNKhaNEXbIGwwYWWk=
`,
		"PrivKeyV6": `
NodeName: super
PrivKeyV6: +EdOKIoBp/EvIusHDsvXhV1RJYbyN3Qr8nxlz35wl3I=
`,
		"ListenPort": `
NodeName: super
ListenPort: 3000
`,
		"FwMark": `
NodeName: super
FwMark: 7
`,
		"API_Prefix": `
NodeName: super
API_Prefix: /eg_api
`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			var cfg SuperConfigV2
			err := yamlUnmarshal([]byte(body), &cfg)
			if err == nil {
				t.Fatalf("expected legacy-field rejection for %s, parsed %+v", name, cfg)
			}
			if !IsControlV2Error(err) {
				t.Fatalf("expected typed ControlV2Error for %s, got %T", name, err)
			}
		})
	}
}

// TestSuperConfigV2HappyPath parses a complete v2 Super config with API
// URL, management auth, STUN servers, per-Edge peers, and control keys.
func TestSuperConfigV2HappyPath(t *testing.T) {
	body := `
NodeName: super-1
APIUrl: https://super.example.com:8443
APIPrefix: /eg_api
ManagementAuth:
  User: admin
  PasswordHash: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
STUNServers:
  - stun:1.2.3.4:3478
  - stuns:5.6.7.8:5349
STUNRequestTimeoutSeconds: 1.5
STUNRefreshIntervalSeconds: 60
PollIntervalSeconds: 15
ReportIntervalSeconds: 10
HeartbeatIntervalSeconds: 25
EventReplay: 128
PeerAliveTimeoutSeconds: 70
UsePSKForInterEdge: true
DampingFilterRadius: 4
Peers:
  - NodeID: 1
    NodeName: edge-001
    ControlPSKey: iPM8FXfnHVzwjguZHRW9bLNY+h7+B1O2oTJtktptQkI=
    AdditionalCost: 0
  - NodeID: 2
    NodeName: edge-002
    ControlPSKey: juJMQaGAaeSy8aDsXSKNsPZv/nFiPj4h/1G70tGYygs=
    AdditionalCost: 0
`
	var cfg SuperConfigV2
	if err := yamlUnmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("parse v2 super config: %v", err)
	}
	if cfg.NodeName != "super-1" {
		t.Errorf("NodeName: got %q", cfg.NodeName)
	}
	if cfg.APIUrl != "https://super.example.com:8443" {
		t.Errorf("APIUrl: got %q", cfg.APIUrl)
	}
	if len(cfg.Peers) != 2 {
		t.Fatalf("Peers len: got %d, want 2", len(cfg.Peers))
	}
	if cfg.Peers[0].ControlPSKey == "" {
		t.Errorf("ControlPSKey must round-trip")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate v2 super config: %v", err)
	}
}

// TestSuperConfigV2RejectsSpecialNodeID ensures SuperConfig peers reject
// special NodeIDs.
func TestSuperConfigV2RejectsSpecialNodeID(t *testing.T) {
	body := `
NodeName: super-1
Peers:
  - NodeID: 65532
    NodeName: edge-bad
    ControlPSKey: iPM8FXfnHVzwjguZHRW9bLNY+h7+B1O2oTJtktptQkI=
`
	var cfg SuperConfigV2
	if err := yamlUnmarshal([]byte(body), &cfg); err == nil {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected special-NodeID rejection")
		}
	}
}

// TestEdgeConfigV2HappyPath parses a valid v2 Edge config (no Super UDP
// fields; the Super info is HTTP-only with a control PSKey).
func TestEdgeConfigV2HappyPath(t *testing.T) {
	body := `
Interface:
  IType: ether
  Name: eg-edge
  IPv4CIDR: 10.10.0.10/24
  MTU: 1420
NodeID: 10
NodeName: edge-010
LogLevel:
  LogLevel: error
SuperNodeV2:
  APIUrl: https://super.example.com:8443
  APIPrefix: /eg_api
  NodeID: 65530
  ControlPSKey: iPM8FXfnHVzwjguZHRW9bLNY+h7+B1O2oTJtktptQkI=
Peers:
  - NodeID: 20
    PubKey: ZqzLVSbXzjppERslwbf2QziWruW3V/UIx9oqwU8Fn3I=
    EndPoint: 203.0.113.20:51820
`
	var cfg EdgeConfigV2
	if err := yamlUnmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("parse v2 edge config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate v2 edge config: %v", err)
	}
	if cfg.SuperNodeV2.ControlPSKey == "" {
		t.Errorf("SuperNodeV2.ControlPSKey must round-trip")
	}
	if cfg.SuperNodeV2.NodeID != Vertex(65530) {
		t.Errorf("SuperNodeV2.NodeID: got %v", cfg.SuperNodeV2.NodeID)
	}
}

// TestEdgeConfigV2RejectsLegacySuperUDPFields ensures the v2 Edge config
// parser rejects legacy Super UDP-only fields (EndpointV4/PubKeyV4/etc).
func TestEdgeConfigV2RejectsLegacySuperUDPFields(t *testing.T) {
	body := `
NodeID: 10
NodeName: edge-010
LegacySuper:
  EndpointV4: 203.0.113.1:3000
  PubKeyV4: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  PSKey: legacy
SuperNodeV2:
  APIUrl: https://super.example.com:8443
  NodeID: 65530
  ControlPSKey: iPM8FXfnHVzwjguZHRW9bLNY+h7+B1O2oTJtktptQkI=
`
	var cfg EdgeConfigV2
	if err := yamlUnmarshal([]byte(body), &cfg); err == nil {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected rejection of LegacySuper")
		}
	}
}

// TestEdgeConfigV2RequiresSuper proves an Edge config without SuperNodeV2
// fails validation.
func TestEdgeConfigV2RequiresSuper(t *testing.T) {
	body := `
NodeID: 10
NodeName: edge-010
Peers: []
`
	var cfg EdgeConfigV2
	if err := yamlUnmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("parse edge without super: %v", err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected missing SuperNodeV2 error")
	}
}

// TestControlV2ErrorsTyped ensures every validation path returns a typed
// error with a stable code.
func TestControlV2ErrorsTyped(t *testing.T) {
	// Empty API URL
	cfg := SuperConfigV2{NodeName: "x"}
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected missing APIUrl error")
	}
	if !IsControlV2Error(err) {
		t.Fatalf("expected typed error, got %T", err)
	}
}

// validControlV2Parameters constructs a known-good parameter set for tests.
func validControlV2Parameters(t *testing.T) ControlV2Parameters {
	t.Helper()
	return ControlV2Parameters{
		ProtocolVersion:     ControlV2ProtocolVersion,
		PollInterval:        15 * time.Second,
		STUNServers:         []string{"stun:1.2.3.4:3478"},
		STUNRequestTimeout:  1500 * time.Millisecond,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      10 * time.Second,
		HeartbeatInterval:   25 * time.Second,
		EventReplay:         128,
	}
}

// yamlUnmarshal is a thin helper so tests don't import yaml directly.
func yamlUnmarshal(data []byte, out interface{}) error {
	return yamlUnmarshalImpl(data, out)
}
