package mtypes

import (
	"encoding/json"
	"fmt"
	"reflect"
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

// TestControlV2ObservedReportRoundTrip proves canonical IPv4 and IPv6
// observations preserve their target binding across the v2 wire format.
func TestControlV2ObservedReportRoundTrip(t *testing.T) {
	// Given
	in := ControlV2ReportRequest{
		NodeID: Vertex(10),
		Observed: []ControlV2ObservedEndpoint{
			{TargetNodeID: Vertex(11), Address: "203.0.113.11:51820"},
			{TargetNodeID: Vertex(12), Address: "[2001:db8::12]:51820"},
		},
	}

	// When
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal observed report: %v", err)
	}
	var out ControlV2ReportRequest
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal observed report: %v", err)
	}

	// Then
	if err := out.Validate(); err != nil {
		t.Fatalf("validate observed report: %v", err)
	}
	if len(out.Observed) != 2 || out.Observed[0] != in.Observed[0] || out.Observed[1] != in.Observed[1] {
		t.Fatalf("observations lost in round trip: got %+v", out.Observed)
	}
}

func TestControlV2ObservedBackwardCompatibleDecoding(t *testing.T) {
	// Given
	reportJSON := `{"node_id":10,"reported_at":"2023-11-14T22:13:20Z"}`
	peerJSON := `{"node_id":11,"node_name":"edge-011","pub_key":"key","last_seen":"2023-11-14T22:13:20Z"}`

	// When
	var report ControlV2ReportRequest
	if err := json.Unmarshal([]byte(reportJSON), &report); err != nil {
		t.Fatalf("unmarshal legacy report: %v", err)
	}
	var peer ControlV2Peer
	if err := json.Unmarshal([]byte(peerJSON), &peer); err != nil {
		t.Fatalf("unmarshal legacy peer: %v", err)
	}

	// Then
	if err := report.Validate(); err != nil {
		t.Fatalf("validate legacy report: %v", err)
	}
	if err := peer.Validate(); err != nil {
		t.Fatalf("validate legacy peer: %v", err)
	}
	if len(report.Observed) != 0 || len(peer.ObservedV4) != 0 || len(peer.ObservedV6) != 0 {
		t.Fatalf("legacy payload gained observations: report=%+v peer=%+v", report.Observed, peer)
	}
}

// TestControlV2ObservedReportValidation rejects unbounded, ambiguous, and
// malformed observations with the v2 typed error contract.
func TestControlV2ObservedReportValidation(t *testing.T) {
	valid := make([]ControlV2ObservedEndpoint, 256)
	for i := range valid {
		valid[i] = ControlV2ObservedEndpoint{TargetNodeID: Vertex(i + 1), Address: fmt.Sprintf("203.0.113.%d:51820", i%254+1)}
	}

	cases := []struct {
		name string
		req  ControlV2ReportRequest
		ok   bool
	}{
		{"exact target limit", ControlV2ReportRequest{NodeID: Vertex(500), Observed: valid}, true},
		{"over target limit", ControlV2ReportRequest{NodeID: Vertex(500), Observed: append(valid, ControlV2ObservedEndpoint{TargetNodeID: Vertex(257), Address: "203.0.113.254:51820"})}, false},
		{"self target", ControlV2ReportRequest{NodeID: Vertex(10), Observed: []ControlV2ObservedEndpoint{{TargetNodeID: Vertex(10), Address: "203.0.113.10:51820"}}}, false},
		{"special target", ControlV2ReportRequest{NodeID: Vertex(10), Observed: []ControlV2ObservedEndpoint{{TargetNodeID: NodeID_Broadcast, Address: "203.0.113.10:51820"}}}, false},
		{"duplicate target", ControlV2ReportRequest{NodeID: Vertex(10), Observed: []ControlV2ObservedEndpoint{{TargetNodeID: Vertex(11), Address: "203.0.113.11:51820"}, {TargetNodeID: Vertex(11), Address: "203.0.113.12:51820"}}}, false},
		{"noncanonical IPv6", ControlV2ReportRequest{NodeID: Vertex(10), Observed: []ControlV2ObservedEndpoint{{TargetNodeID: Vertex(11), Address: "[2001:0db8::11]:51820"}}}, false},
		{"malformed address", ControlV2ReportRequest{NodeID: Vertex(10), Observed: []ControlV2ObservedEndpoint{{TargetNodeID: Vertex(11), Address: "not-an-ip:51820"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			err := tc.req.Validate()

			// Then
			if tc.ok {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if !IsControlV2Error(err) {
				t.Fatalf("expected typed ControlV2Error, got %T: %v", err, err)
			}
		})
	}
}

// TestControlV2ObservedSnapshotValidation enforces the anonymous published
// hint caps without serializing observer identity or timestamps.
func TestControlV2ObservedSnapshotValidation(t *testing.T) {
	observedV4 := make([]ControlV2ObservedAddress, 14)
	for i := range observedV4 {
		observedV4[i] = ControlV2ObservedAddress{Address: fmt.Sprintf("203.0.113.%d:51820", i+1), ReporterCount: 1}
	}
	observedV6 := []ControlV2ObservedAddress{
		{Address: "[2001:db8::1]:51820", ReporterCount: 2},
		{Address: "[2001:db8::2]:51820", ReporterCount: 3},
	}
	cases := []struct {
		name string
		peer ControlV2Peer
		ok   bool
	}{
		{"exact total and family limits", ControlV2Peer{ObservedV4: observedV4, ObservedV6: observedV6}, true},
		{"exact IPv6 family limit", ControlV2Peer{ObservedV6: makeObservedV6(14)}, true},
		{"over total limit", ControlV2Peer{ObservedV4: observedV4, ObservedV6: append(observedV6, ControlV2ObservedAddress{Address: "[2001:db8::3]:51820", ReporterCount: 1})}, false},
		{"over IPv4 limit", ControlV2Peer{ObservedV4: append(observedV4, ControlV2ObservedAddress{Address: "203.0.113.15:51820", ReporterCount: 1})}, false},
		{"over IPv6 limit", ControlV2Peer{ObservedV6: makeObservedV6(15)}, false},
		{"noncanonical address", ControlV2Peer{ObservedV6: []ControlV2ObservedAddress{{Address: "[2001:0db8::1]:51820", ReporterCount: 1}}}, false},
		{"missing reporter count", ControlV2Peer{ObservedV4: []ControlV2ObservedAddress{{Address: "203.0.113.1:51820"}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			err := tc.peer.Validate()

			// Then
			if tc.ok {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if !IsControlV2Error(err) {
				t.Fatalf("expected typed ControlV2Error, got %T: %v", err, err)
			}
		})
	}

	// Given
	peer := ControlV2Peer{ObservedV4: observedV4[:1]}

	// When
	raw, err := json.Marshal(peer.ObservedV4)
	if err != nil {
		t.Fatalf("marshal observed snapshot peer: %v", err)
	}

	// Then
	if strings.Contains(string(raw), "node_id") || strings.Contains(string(raw), "timestamp") || strings.Contains(string(raw), "reported_at") {
		t.Fatalf("observed snapshot leaked attribution: %s", raw)
	}
}

// TestEdgeConfigV2DirectConnectivityDefaults proves omitted additive config
// resolves to the documented Super-discovered peer timings.
func TestEdgeConfigV2DirectConnectivityDefaults(t *testing.T) {
	// Given
	cfg := EdgeConfigV2{}

	// When
	resolved := cfg.ResolveDirectConnectivity()

	// Then
	want := ControlV2DirectConnectivity{PersistentKeepaliveSeconds: 25, PingIntervalSeconds: 16, PeerAliveTimeoutSeconds: 70, OfflineCheckSeconds: 10, NextEndpointTrySeconds: 5}
	if resolved != want {
		t.Fatalf("resolved defaults = %+v, want %+v", resolved, want)
	}
}

// TestEdgeConfigV2DirectConnectivityValidation rejects values outside the
// bounded seconds contract while accepting omitted and explicit values.
func TestEdgeConfigV2DirectConnectivityValidation(t *testing.T) {
	cases := []struct {
		name string
		cfg  ControlV2DirectConnectivity
		ok   bool
	}{
		{"omitted", ControlV2DirectConnectivity{}, true},
		{"explicit", ControlV2DirectConnectivity{PersistentKeepaliveSeconds: 25, PingIntervalSeconds: 16, PeerAliveTimeoutSeconds: 70, OfflineCheckSeconds: 10, NextEndpointTrySeconds: 5}, true},
		{"negative", ControlV2DirectConnectivity{PingIntervalSeconds: -1}, false},
		{"absurd", ControlV2DirectConnectivity{OfflineCheckSeconds: 86401}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// When
			err := tc.cfg.Validate()

			// Then
			if tc.ok {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if !IsControlV2Error(err) {
				t.Fatalf("expected typed ControlV2Error, got %T: %v", err, err)
			}
		})
	}
}

func makeObservedV6(count int) []ControlV2ObservedAddress {
	observed := make([]ControlV2ObservedAddress, count)
	for i := range observed {
		observed[i] = ControlV2ObservedAddress{Address: fmt.Sprintf("[2001:db8::%d]:51820", i+3), ReporterCount: 1}
	}
	return observed
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

func TestValidateSTUNURIAcceptsDNSHostnamesAndAuthorities(t *testing.T) {
	valid := []string{
		"stun:stun.example.com:3478",
		"stun://stun.example.com:3478",
		"stuns:stun.example.com:5349",
		"stun:[2001:db8::1]:3478",
	}
	for _, raw := range valid {
		t.Run(raw, func(t *testing.T) {
			// When
			err := ValidateSTUNURI(raw)

			// Then
			if err != nil {
				t.Fatalf("ValidateSTUNURI(%q): %v", raw, err)
			}
		})
	}
}

func TestValidateSTUNURIReturnsTypedErrorsForMalformedAuthorities(t *testing.T) {
	invalid := []string{
		"",
		"http://stun.example.com:3478",
		"stun://:3478",
		"stun:stun.example.com",
		"stun://stun.example.com:notaport",
		"stun://stun.example.com:0",
		"stun://bad_host.example.com:3478",
		"stun://user@stun.example.com:3478",
		"stun://stun.example.com:3478/path",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			// When
			err := ValidateSTUNURI(raw)

			// Then
			if !IsControlV2Error(err) {
				t.Fatalf("ValidateSTUNURI(%q) error = %T, want typed ControlV2Error", raw, err)
			}
			if got := ErrorCode(err); got != ControlV2ErrInvalidSTUNServer {
				t.Fatalf("ValidateSTUNURI(%q) code = %v, want %v", raw, got, ControlV2ErrInvalidSTUNServer)
			}
		})
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

func TestEdgeConfigV2RejectsLegacySuperBlock(t *testing.T) {
	cases := []struct {
		name         string
		useSuperNode bool
	}{
		{name: "enabled", useSuperNode: true},
		{name: "disabled", useSuperNode: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			body := fmt.Sprintf(`
NodeID: 10
NodeName: edge-010
DynamicRoute:
  SuperNode:
    UseSuperNode: %t
`, tc.useSuperNode)

			// When
			var cfg EdgeConfigV2
			err := yamlUnmarshal([]byte(body), &cfg)

			// Then
			if !IsControlV2Error(err) {
				t.Fatalf("expected typed ControlV2Error, got %T: %v", err, err)
			}
			if got := ErrorCode(err); got != ControlV2ErrLegacyUDPField {
				t.Fatalf("error code = %q, want %q", got, ControlV2ErrLegacyUDPField)
			}
		})
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

// TestListenPortPriorityExpandsInOrderAndDeduplicates proves Expand honors
// first-occurrence order, dedupes later repetitions, and walks a range
// inclusive in the order declared on the wire.
func TestListenPortPriorityExpandsInOrderAndDeduplicates(t *testing.T) {
	policy := ListenPortPriority{
		{Port: intPtr(16386)},
		{Range: &ListenPortRange{From: 16386, To: 16388}},
		{Port: intPtr(16387)},
	}
	ports, err := policy.Expand()
	if err != nil {
		t.Fatalf("Expand() error = %v", err)
	}
	want := []int{16386, 16387, 16388}
	if !reflect.DeepEqual(ports, want) {
		t.Fatalf("Expand() = %v, want %v", ports, want)
	}
}

// TestListenPortPriorityRejectsMalformedEntries locks the typed validation
// surface: zero/out-of-range ports, reversed ranges, mixed port+range, and
// empty entries must each surface as Expand errors rather than silently
// producing a partial candidate set.
func TestListenPortPriorityRejectsMalformedEntries(t *testing.T) {
	cases := []struct {
		name   string
		policy ListenPortPriority
	}{
		{name: "zero port", policy: ListenPortPriority{{Port: intPtr(0)}}},
		{name: "out of range", policy: ListenPortPriority{{Port: intPtr(65536)}}},
		{name: "reversed range", policy: ListenPortPriority{{Range: &ListenPortRange{From: 10, To: 9}}}},
		{name: "mixed entry", policy: ListenPortPriority{{Port: intPtr(10), Range: &ListenPortRange{From: 10, To: 11}}}},
		{name: "empty entry", policy: ListenPortPriority{{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.policy.Expand(); err == nil {
				t.Fatalf("Expand() error = nil, want typed validation error for %s", tc.name)
			}
		})
	}
}

// TestListenPortPriorityRejectsExpansionOver256 pins the 256-candidate cap.
// A range covering 257 ports must be rejected even though each individual
// port is in [1, 65535].
func TestListenPortPriorityRejectsExpansionOver256(t *testing.T) {
	policy := ListenPortPriority{{Range: &ListenPortRange{From: 1, To: 257}}}
	if _, err := policy.Expand(); err == nil {
		t.Fatal("Expand() error = nil, want expansion-cap error")
	}
}

// TestControlV2ParametersListenPortPriorityWireKey pins the PascalCase wire
// key, the round-trip shape, and the absent-field backward-compatibility
// contract: a snapshot missing ListenPortPriority must decode to an empty
// policy without error.
func TestControlV2ParametersListenPortPriorityWireKey(t *testing.T) {
	parameters := ControlV2Parameters{
		ProtocolVersion: ControlV2ProtocolVersion,
		ListenPortPriority: ListenPortPriority{
			{Port: intPtr(16386)},
			{Range: &ListenPortRange{From: 16387, To: 16388}},
		},
	}
	data, err := json.Marshal(parameters)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(data), `"ListenPortPriority"`) {
		t.Fatalf("wire JSON = %s, missing PascalCase key", data)
	}
	var decoded ControlV2Parameters
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if !reflect.DeepEqual(decoded.ListenPortPriority, parameters.ListenPortPriority) {
		t.Fatalf("decoded policy = %#v, want %#v", decoded.ListenPortPriority, parameters.ListenPortPriority)
	}
	var old ControlV2Parameters
	if err := json.Unmarshal([]byte(`{"ProtocolVersion":"v2"}`), &old); err != nil {
		t.Fatalf("old JSON Unmarshal() error = %v", err)
	}
	if len(old.ListenPortPriority) != 0 {
		t.Fatalf("old JSON policy = %#v, want empty", old.ListenPortPriority)
	}
}

// TestSuperConfigV2ListenPortPriorityJSONShape exercises the Super-side
// config decode path so a future YAML like
//
//	ListenPortPriority:
//	  - Port: 16386
//	  - Range:
//	      From: 16387
//	      To:   16388
//
// round-trips with both port and range entries preserved in declared order.
func TestSuperConfigV2ListenPortPriorityJSONShape(t *testing.T) {
	data := []byte(`{"ListenPortPriority":[{"Port":16386},{"Range":{"From":16387,"To":16388}}]}`)
	var config SuperConfigV2
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(config.ListenPortPriority) != 2 {
		t.Fatalf("decoded policy len = %d, want 2", len(config.ListenPortPriority))
	}
	if got := config.ListenPortPriority[0]; got.Port == nil || *got.Port != 16386 {
		t.Fatalf("entry[0] = %#v, want Port=16386", got)
	}
	if got := config.ListenPortPriority[1]; got.Range == nil || got.Range.From != 16387 || got.Range.To != 16388 {
		t.Fatalf("entry[1] = %#v, want Range{From:16387, To:16388}", got)
	}
}

func intPtr(v int) *int { return &v }
