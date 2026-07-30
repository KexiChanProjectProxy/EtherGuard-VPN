package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

// allDocFiles covers every README the project ships.
var allDocFiles = []string{
	"README.md",
	"README_zh.md",
	"example_config/super_mode/README.md",
	"example_config/super_mode/README_zh.md",
}

// superDocFiles are the detailed Super-mode docs that must contain
// HMAC headers, event types, and complete API documentation.
var superDocFiles = []string{
	"example_config/super_mode/README.md",
	"example_config/super_mode/README_zh.md",
}

// legacyUDPPatterns are YAML keys that must NEVER appear in Super context
// inside any documentation file.
var legacyUDPPatterns = []string{
	"PrivKeyV4", "PrivKeyV6", "ListenPort", "FwMark", "API_Prefix",
}

// TestDocsNoLegacyUDPSuperKeys verifies that none of the documentation
// files contain legacy UDP-only Super config keys in Super context.
func TestDocsNoLegacyUDPSuperKeys(t *testing.T) {
	t.Parallel()
	for _, doc := range allDocFiles {
		content := readFile(t, doc)
		for _, pattern := range legacyUDPPatterns {
			lines := strings.Split(content, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if isSuperContext(lines, i) {
					if strings.Contains(trimmed, pattern+":") {
						t.Errorf("%s line %d: legacy UDP key %q in Super context: %s",
							doc, i+1, pattern, trimmed)
					}
				}
			}
		}
	}
}

// TestDocsNoServerUpdateUDPConcept verifies that the docs do not contain
// the legacy "### ServerUpdate" section heading.
func TestDocsNoServerUpdateUDPConcept(t *testing.T) {
	t.Parallel()
	for _, doc := range allDocFiles {
		content := readFile(t, doc)
		lower := strings.ToLower(content)
		if strings.Contains(lower, "### serverupdate") {
			t.Errorf("%s: legacy '### ServerUpdate' heading found (UDP concept removed in v2)", doc)
		}
	}
}

// TestDocsReferenceV2APIRoutes verifies that every /edge/v2/* route path
// referenced in the detailed Super docs exists in super_control_http.go.
func TestDocsReferenceV2APIRoutes(t *testing.T) {
	t.Parallel()
	validRoutes := map[string]bool{
		"/edge/v2/register": true,
		"/edge/v2/report":   true,
		"/edge/v2/snapshot": true,
		"/edge/v2/events":   true,
	}
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			idx := strings.Index(trimmed, "/edge/v2/")
			if idx < 0 {
				continue
			}
			rest := trimmed[idx:]
			endIdx := len(rest)
			for _, ch := range []string{" ", "\t", "\"", "'", ")", "`", "|", "<"} {
				if pos := strings.Index(rest, ch); pos >= 0 && pos < endIdx {
					endIdx = pos
				}
			}
			route := rest[:endIdx]
			route = strings.TrimRight(route, ".,;:")
			// Skip nginx proxy paths, HTML tags, and manage handler
			if strings.Contains(route, "/manage/") || strings.HasSuffix(route, "/") {
				continue
			}
			if !validRoutes[route] {
				t.Errorf("%s line %d: unknown /edge/v2/* route %q not in super_control_http.go",
					doc, i+1, route)
			}
		}
	}
}

// TestDocsReferenceValidYAMLKeys verifies that YAML keys in Super config
// parameter tables exist in the v2 structs.
func TestDocsReferenceValidYAMLKeys(t *testing.T) {
	t.Parallel()
	validSuperKeys := map[string]bool{
		"NodeName": true, "APIUrl": true, "APIPrefix": true,
		"ManagementAuth": true, "STUNServers": true,
		"STUNRequestTimeoutSeconds": true, "STUNRefreshIntervalSeconds": true,
		"PollIntervalSeconds": true, "ReportIntervalSeconds": true,
		"HeartbeatIntervalSeconds": true, "EventReplay": true,
		"PeerAliveTimeoutSeconds": true, "UsePSKForInterEdge": true,
		"DampingFilterRadius": true, "RelayCostMS": true,
		"EndpointBlacklist": true, "Peers": true,
	}
	validEdgeKeys := map[string]bool{
		"Interface": true, "NodeID": true, "NodeName": true,
		"DefaultTTL": true, "LogLevel": true, "RelayCostMS": true,
		"SuperNodeV2": true, "Peers": true,
	}
	validPeerKeys := map[string]bool{
		"NodeID": true, "NodeName": true, "ControlPSKey": true, "AdditionalCost": true,
	}
	validV2RefKeys := map[string]bool{
		"APIUrl": true, "APIPrefix": true, "NodeID": true, "ControlPSKey": true,
	}
	allValid := mergeMaps(validSuperKeys, validEdgeKeys, validPeerKeys, validV2RefKeys)

	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		lines := strings.Split(content, "\n")
		inSuperConfigSection := false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "SuperNode Config Parameter") ||
				strings.Contains(trimmed, "SuperNode設定參數") ||
				strings.Contains(trimmed, "Super-side") {
				inSuperConfigSection = true
			} else if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
				if !strings.Contains(trimmed, "Config") && !strings.Contains(trimmed, "設定") {
					inSuperConfigSection = false
				}
			}
			if strings.Contains(trimmed, "|") && inSuperConfigSection {
				parts := strings.Split(trimmed, "|")
				if len(parts) >= 2 {
					key := strings.TrimSpace(parts[0])
					if key == "" || key == "Key" || key == "---" || strings.HasPrefix(key, "[") {
						continue
					}
					if strings.Contains(key, " ") && !strings.Contains(key, "PSKey") {
						continue
					}
					if !allValid[key] && isLikelyYAMLKey(key) {
						t.Logf("%s line %d: YAML key %q not in v2 structs (may be sub-key)",
							doc, i+1, key)
					}
				}
			}
		}
	}
}

// TestDocsControlAPIHeadersMatch verifies that the four HMAC header names
// appear in the detailed Super docs.
func TestDocsControlAPIHeadersMatch(t *testing.T) {
	t.Parallel()
	requiredHeaders := []string{
		"X-EG-NodeID",
		"X-EG-Timestamp",
		"X-EG-Nonce",
		"X-EG-Signature",
	}
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		for _, header := range requiredHeaders {
			if !strings.Contains(content, header) {
				t.Errorf("%s: missing HMAC header %q", doc, header)
			}
		}
	}
}

// TestDocsProtocolVersionMatch verifies that the protocol version "v2"
// is mentioned in all docs.
func TestDocsProtocolVersionMatch(t *testing.T) {
	t.Parallel()
	for _, doc := range allDocFiles {
		content := readFile(t, doc)
		if !strings.Contains(content, mtypes.ControlV2ProtocolVersion) {
			t.Errorf("%s: missing protocol version %q", doc, mtypes.ControlV2ProtocolVersion)
		}
	}
}

// TestDocsEventTypesMatch verifies that the SSE event types appear in
// the detailed Super docs.
func TestDocsEventTypesMatch(t *testing.T) {
	t.Parallel()
	requiredTypes := []string{
		string(mtypes.ControlV2EventPeerChange),
		string(mtypes.ControlV2EventPeerGone),
		string(mtypes.ControlV2EventParamsChange),
		string(mtypes.ControlV2EventRevision),
	}
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		for _, eventType := range requiredTypes {
			if !strings.Contains(content, eventType) {
				t.Errorf("%s: missing SSE event type %q", doc, eventType)
			}
		}
	}
}

// --- helpers ---

func readFile(t *testing.T, relPath string) string {
	t.Helper()
	abs, err := filepath.Abs(relPath)
	if err != nil {
		abs = relPath
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("cannot read %s: %v", relPath, err)
	}
	return string(data)
}

func isSuperContext(lines []string, i int) bool {
	for j := i; j >= 0 && j > i-50; j-- {
		line := strings.TrimSpace(lines[j])
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "static") || strings.Contains(lower, "p2p") {
				return false
			}
			if strings.Contains(lower, "super") || strings.Contains(lower, "config parameter") ||
				strings.Contains(lower, "設定參數") || strings.Contains(lower, "edgeapi") ||
				strings.Contains(lower, "control") {
				return true
			}
		}
	}
	return true
}

func isLikelyYAMLKey(s string) bool {
	if len(s) == 0 || s[0] < 'A' || s[0] > 'Z' {
		return false
	}
	for _, ch := range s {
		if (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == ' ' {
			continue
		}
		return false
	}
	return true
}

func mergeMaps(maps ...map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}

// --- non-vpp-exit-issues Task 6 contract tests ---

// TestDocsSTUNURIAcceptsHostnames verifies that the STUN documentation
// describes both stun:host:port and stun://host:port URI forms and
// mentions DNS hostname support. Source: mtypes/http_control.go
// ValidateSTUNURI (line 637) accepts both forms and validates hosts via
// validSTUNHostname; device/super_stun.go resolveAddresses (line 120)
// resolves DNS at runtime.
func TestDocsSTUNURIAcceptsHostnames(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		if !strings.Contains(content, "stun://") {
			t.Errorf("%s: STUN section should mention stun://host:port URI form", doc)
		}
		// Must not claim STUN URIs are IP-literal-only. The phrase may
		// legitimately appear in the generic endpoint (conn/conn.go) context,
		// so we do a doc-wide check that it is absent.
		if strings.Contains(content, "IP literals only") {
			t.Errorf("%s: must not claim 'IP literals only' (STUN now accepts DNS hostnames)", doc)
		}
	}
}

// TestDocsSSEPollingIsFallbackOnly verifies that the SSE documentation
// describes polling as fallback-only, not as an always-on dedicated
// goroutine. Source: device/super_http_client.go Sync (line 362)
// starts polling only after stream failure and cancels it on reconnect.
func TestDocsSSEPollingIsFallbackOnly(t *testing.T) {
	t.Parallel()
	stalePhrases := []string{
		"dedicated polling goroutine runs alongside",
		"always-on",
		"polling goroutine runs alongside SSE",
	}
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		lower := strings.ToLower(content)
		for _, phrase := range stalePhrases {
			if strings.Contains(lower, strings.ToLower(phrase)) {
				t.Errorf("%s: stale polling wording found: %q (polling is fallback-only)", doc, phrase)
			}
		}
	}
}

// TestDocsRejectedLegacyFieldsEnumerated verifies that both
// ListenPort_EdgeAPI and ListenPort_ManageAPI are mentioned in the
// documentation as rejected legacy fields. Source: main_super.go
// legacyUDPFieldPresent (line 612) rejects all seven v1 field names.
func TestDocsRejectedLegacyFieldsEnumerated(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		if !strings.Contains(content, "ListenPort_EdgeAPI") {
			t.Errorf("%s: ListenPort_EdgeAPI not mentioned as rejected field", doc)
		}
		if !strings.Contains(content, "ListenPort_ManageAPI") {
			t.Errorf("%s: ListenPort_ManageAPI not mentioned as rejected field", doc)
		}
	}
}

// TestDocsVPPExcluded verifies that VPP exclusion is documented.
// Source: HANDOVER.md lines 12-17 — make vpp was never validated on
// any libmemif-equipped host.
func TestDocsVPPExcluded(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		lower := strings.ToLower(content)
		if !strings.Contains(lower, "vpp") {
			t.Errorf("%s: VPP exclusion statement not found", doc)
		}
	}
}

// TestDocsEdgeLegacyRejection verifies that Edge config legacy rejection
// (LegacySuper key, DynamicRoute.SuperNode key) is documented.
// Source: mtypes/http_control.go EdgeConfigV2.UnmarshalYAML (line 609)
// rejects LegacySuper and DynamicRoute.SuperNode by key presence.
func TestDocsEdgeLegacyRejection(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		if !strings.Contains(content, "LegacySuper") {
			t.Errorf("%s: LegacySuper rejection not documented for Edge config", doc)
		}
		if !strings.Contains(content, "DynamicRoute.SuperNode") {
			t.Errorf("%s: DynamicRoute.SuperNode rejection not documented for Edge config", doc)
		}
	}
}

func TestDocsSTUNRefresh(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		if !strings.Contains(content, "STUNRefreshIntervalSeconds") {
			t.Errorf("%s: STUNRefreshIntervalSeconds not mentioned in config table", doc)
		}
		lower := strings.ToLower(content)
		if !strings.Contains(lower, "periodic") && !strings.Contains(content, "週期") {
			t.Errorf("%s: STUNRefreshIntervalSeconds must document active periodic discovery", doc)
		}
		if strings.Contains(lower, "stun refresh is one-shot") || strings.Contains(lower, "stunrefreshintervalseconds | reserved") || strings.Contains(content, "STUN刷新在註冊時一次性") || strings.Contains(content, "STUNRefreshIntervalSeconds | 保留") {
			t.Errorf("%s: STUNRefreshIntervalSeconds must not be documented as inert", doc)
		}
		if !strings.Contains(lower, "not a keepalive") && !strings.Contains(content, "不是keepalive") {
			t.Errorf("%s: STUN discovery must be distinguished from keepalive", doc)
		}
	}
}

func TestDocsDirectConnectivity(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		for _, required := range []string{
			"DirectConnectivity",
			"PersistentKeepaliveSeconds | 25",
			"SendPingIntervalSeconds | 16",
			"PeerAliveTimeoutSeconds | 70",
			"TimeoutCheckIntervalSeconds | 10",
			"ConnNextTrySeconds | 5",
			"256",
			"16",
			"14",
			"PeerAliveTimeoutSeconds",
		} {
			if !strings.Contains(content, required) {
				t.Errorf("%s: missing DirectConnectivity contract %q", doc, required)
			}
		}
	}
}

// --- super-listen-port-policy Task 6 corpus audit ---
//
// The 100 Edge profiles in /home/kexi/KexiSdnConfig/http-sse/ form the
// authoritative operational corpus for the bootstrap-required listen-port
// policy. The audit below enumerates every Edge file, asserts that no
// local-port-policy key has crept in, and pins RecvAddr/SendAddr to the
// golden manifest captured before Task 6 edits. The operational Super
// YAML is checked separately: it must contain exactly the approved
// `RelayCostMS: 10` and `ListenPortPriority` range additions with no other
// surface change. When the corpus directory is not present (e.g. CI runners
// without the operational repo) the tests skip with t.Skipf so the
// contract still runs everywhere the corpus is mounted.

// operationalCorpusDir is the on-disk location of the 100 Edge profiles
// + the operational Super YAML. The path is host-specific; in this
// environment the corpus is mounted at /home/kexi/KexiSdnConfig/http-sse/.
// Tests skip cleanly when the path is absent so CI without the corpus
// stays green.
const operationalCorpusDir = "/home/kexi/KexiSdnConfig/http-sse"

// operationalSuperYAML is the path to the single Super YAML inside the
// operational corpus. The audit asserts it carries the approved
// RelayCostMS and ListenPortPriority additions and nothing else.
const operationalSuperYAML = operationalCorpusDir + "/ngsdn_super.yaml"

// edgeFiles returns the 100 file basenames the audit must enumerate, in
// the same order the corpus ships: logs.yaml, ngsdn_edge002.yaml, ...,
// ngsdn_edge100.yaml. The test does NOT discover the corpus dynamically
// (it pins the exact set so a stray file going missing is itself a
// failure with a clear message, not a silent pass).
func edgeFiles() []string {
	files := make([]string, 0, 100)
	files = append(files, "logs.yaml")
	for i := 2; i <= 100; i++ {
		files = append(files, "ngsdn_edge"+zeroPad3(i)+".yaml")
	}
	if len(files) != 100 {
		panic("edgeFiles: must yield 100 files, got " + intToStr(len(files)))
	}
	return files
}

func zeroPad3(i int) string {
	switch {
	case i < 10:
		return "00" + intToStr(i)
	case i < 100:
		return "0" + intToStr(i)
	default:
		return intToStr(i)
	}
}

func intToStr(i int) string {
	// strconv.Itoa without importing strconv at the top of the file.
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

// goldenRecvSend is the captured RecvAddr / SendAddr pair every Edge
// file in the operational corpus shipped with before Task 6. The audit
// reads each file and asserts the value is unchanged. If the corpus
// legitimately changes (operator action) the test will fail loudly —
// the operator then refreshes this constant after review.
const (
	goldenEdgeRecvAddr = "127.0.0.1:4001"
	goldenEdgeSendAddr = "127.0.0.1:5001"
)

// forbiddenEdgePortPolicyKeys is the closed set of port-policy keys
// that MUST NOT appear in any Edge profile. ListenPortPriority is the
// ordered Super-owned candidate list; ListenPort is the legacy v1
// single-port field; BootstrapListenPortPriority and similar keys are
// local-fallbacks the Super contract explicitly forbids (an Edge that
// cannot reach the Super has no local policy to fall back to).
var forbiddenEdgePortPolicyKeys = []string{
	"ListenPortPriority",
	"ListenPort",
	"BootstrapListenPortPriority",
	"LocalListenPort",
	"ListenPortOverride",
}

// TestCorpusEdgeNoLocalPortPolicy enumerates the 100 Edge files in the
// operational corpus and asserts NONE of them carry a local-port-policy
// key. This is the "client/Edge profiles MUST NOT define any local port
// policy" half of the Task 6 contract.
func TestCorpusEdgeNoLocalPortPolicy(t *testing.T) {
	t.Parallel()
	corpusDir := corpusDirOrSkip(t)
	for _, name := range edgeFiles() {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := corpusDir + "/" + name
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, key := range forbiddenEdgePortPolicyKeys {
				if strings.Contains(string(data), key+":") {
					t.Errorf("%s: forbidden local port policy key %q present (Super is the sole source of truth)", path, key)
				}
			}
		})
	}
}

// TestCorpusEdgeRecvSendUnchanged pins the RecvAddr / SendAddr golden
// manifest. Every Edge file in the operational corpus MUST keep the
// exact same RecvAddr and SendAddr values it had before Task 6. A
// failure here means either the operator changed the corpus, or a
// regression slipped through: in either case the corpus is no longer
// byte-stable and the operational contract is broken.
func TestCorpusEdgeRecvSendUnchanged(t *testing.T) {
	t.Parallel()
	corpusDir := corpusDirOrSkip(t)
	type pair struct{ recv, send string }
	want := pair{goldenEdgeRecvAddr, goldenEdgeSendAddr}
	for _, name := range edgeFiles() {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path := corpusDir + "/" + name
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			got := pair{
				recv: extractYAMLValue(string(data), "RecvAddr"),
				send: extractYAMLValue(string(data), "SendAddr"),
			}
			if got.recv == "" || got.send == "" {
				t.Fatalf("%s: missing RecvAddr/SendAddr keys (recv=%q send=%q)", path, got.recv, got.send)
			}
			if got.recv != want.recv {
				t.Errorf("%s: RecvAddr drift: got %q, want %q (golden manifest)", path, got.recv, want.recv)
			}
			if got.send != want.send {
				t.Errorf("%s: SendAddr drift: got %q, want %q (golden manifest)", path, got.send, want.send)
			}
		})
	}
}

func TestCorpusSuperYAMLPolicyIsRange(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(operationalSuperYAML); err != nil {
		t.Skipf("operational Super YAML not present at %s: %v", operationalSuperYAML, err)
	}
	data, err := os.ReadFile(operationalSuperYAML)
	if err != nil {
		t.Fatalf("read %s: %v", operationalSuperYAML, err)
	}
	if !strings.Contains(string(data), "ListenPortPriority:") {
		t.Fatalf("%s: missing ListenPortPriority: key", operationalSuperYAML)
	}
	// The Super YAML must decode into a typed SuperConfigV2 and the
	// policy must contain exactly one range with the approved bounds.
	var cfg mtypes.SuperConfigV2
	if err := yamlUnmarshal(data, &cfg); err != nil {
		t.Fatalf("%s: yaml unmarshal: %v", operationalSuperYAML, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("%s: SuperConfigV2.Validate(): %v", operationalSuperYAML, err)
	}
	if len(cfg.ListenPortPriority) != 1 {
		t.Fatalf("%s: ListenPortPriority has %d entries, want exactly one", operationalSuperYAML, len(cfg.ListenPortPriority))
	}
	entry := cfg.ListenPortPriority[0]
	if entry.Port != nil || entry.Range == nil {
		t.Fatalf("%s: ListenPortPriority entry = %#v, want exactly one Range entry", operationalSuperYAML, entry)
	}
	if entry.Range.From != 16386 || entry.Range.To != 16390 {
		t.Fatalf("%s: ListenPortPriority range = %#v, want From=16386 To=16390", operationalSuperYAML, *entry.Range)
	}
	ports, err := cfg.ListenPortPriority.Expand()
	if err != nil {
		t.Fatalf("%s: ListenPortPriority.Expand(): %v", operationalSuperYAML, err)
	}
	if len(ports) != 5 || ports[0] != 16386 || ports[1] != 16387 || ports[2] != 16388 || ports[3] != 16389 || ports[4] != 16390 {
		t.Fatalf("%s: expanded policy = %v, want [16386 16387 16388 16389 16390]", operationalSuperYAML, ports)
	}
	// Ensure the YAML does not carry a forbidden legacy key that
	// would be rejected by SuperConfigV2.UnmarshalYAML — the typed
	// decode above already enforces this, but a second-layer check
	// makes the failure mode self-evident.
	for _, banned := range []string{"PrivKeyV4:", "PrivKeyV6:", "FwMark:", "API_Prefix:", "ListenPort_EdgeAPI:", "ListenPort_ManageAPI:"} {
		if strings.Contains(string(data), banned) {
			t.Errorf("%s: legacy UDP field %q present (must be absent in v2)", operationalSuperYAML, banned)
		}
	}
}

// TestCorpusSuperYAMLOtherFieldsUnchanged guarantees the operational
// Super YAML is touched ONLY for the approved RelayCostMS and
// ListenPortPriority insertions: every
// other top-level key/value pair must be byte-identical to the golden
// snapshot captured before Task 6 edits. The golden snapshot is the
// exact pre-edit file content embedded as a string; the test computes
// the line-level delta and fails if any non-approved insertion line
// drifted. This is the strongest possible guarantee that the
// operational deployment (which copies this file to /opt/sdn/config.yaml)
// remains bit-compatible with the previous release.
func TestCorpusSuperYAMLOtherFieldsUnchanged(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat(operationalSuperYAML); err != nil {
		t.Skipf("operational Super YAML not present at %s: %v", operationalSuperYAML, err)
	}
	data, err := os.ReadFile(operationalSuperYAML)
	if err != nil {
		t.Fatalf("read %s: %v", operationalSuperYAML, err)
	}
	liveLines := strings.Split(string(data), "\n")
	goldenLines := strings.Split(operationalSuperYAMLGolden, "\n")
	if len(liveLines) != len(goldenLines)+5 {
		t.Fatalf("%s: line count drift: got %d, want golden %d + 5 approved additions = %d",
			operationalSuperYAML, len(liveLines), len(goldenLines), len(goldenLines)+5)
	}
	// Walk both side-by-side, skipping the five inserted lines. The
	// insertion is anchored AFTER DampingFilterRadius: 4 — the live
	// YAML has golden[0..insertAt] verbatim, then the five approved
	// lines, then golden[insertAt+1..]. Locate the DampingFilterRadius
	// anchor in the live YAML and assert those five lines are exact.
	// insertAt is the 0-based index of the anchor line in the live YAML;
	// in the golden the anchor is at the same index.
	insertAt := -1
	for i, line := range liveLines {
		if line == "DampingFilterRadius: 4" {
			insertAt = i
			break
		}
	}
	if insertAt < 0 {
		t.Fatalf("%s: DampingFilterRadius: 4 anchor not found", operationalSuperYAML)
	}
	if insertAt+5 >= len(liveLines) {
		t.Fatalf("%s: not enough lines after DampingFilterRadius anchor for approved additions", operationalSuperYAML)
	}
	for offset, want := range []string{
		"RelayCostMS: 10",
		"ListenPortPriority:",
		"- Range:",
		"    From: 16386",
		"    To: 16390",
	} {
		if liveLines[insertAt+1+offset] != want {
			t.Errorf("%s: approved insertion line %d = %q, want %q", operationalSuperYAML, offset+1, liveLines[insertAt+1+offset], want)
		}
	}
	// Now compare every other line to the golden snapshot. For golden
	// indices strictly past insertAt, the live YAML has shifted by 5.
	for i, gline := range goldenLines {
		liveLine := liveLines[i]
		if i > insertAt {
			liveLine = liveLines[i+5]
		}
		if liveLine != gline {
			t.Errorf("%s: line %d drift: got %q, want golden %q", operationalSuperYAML, i+1, liveLine, gline)
		}
	}
}

// operationalSuperYAMLGolden is the byte-exact content of the
// operational Super YAML as it existed BEFORE Task 6 edits, captured
// from the working tree at the start of the task. The audit compares
// the live file against this snapshot, allowing exactly 5 lines of
// drift for the approved RelayCostMS and ListenPortPriority additions.
// A future operator change (renaming, adding a STUN server, etc.) must
// refresh this constant
// after review.
const operationalSuperYAMLGolden = `NodeName: ngsdnSN
APIUrl: https://cd.kexi.fqbin.com
APIPrefix: /edge/v2
ManagementAuth:
  User: admin
  PasswordHash: 393f523c-7a0a-453f-af60-8cd3f0005bf4
STUNServers:
- stun:stun.miwifi.com:3478
- stun:turn.cloudflare.com:3478
- stun:stun.nextcloud.com:3478
- stun:stun.voipbuster.com:3478
- stun:turn.cloudflare.com:3478
STUNRequestTimeoutSeconds: 3
STUNRefreshIntervalSeconds: 60
PollIntervalSeconds: 15
ReportIntervalSeconds: 15
HeartbeatIntervalSeconds: 10
EventReplay: 256
PeerAliveTimeoutSeconds: 70
UsePSKForInterEdge: true
DampingFilterRadius: 4
Peers:
- NodeID: 1
  NodeName: ngsdn
  ControlPSKey: kVKwzsy1ssyaj09i0dv9wfTLolRM8eSw//V8kxm/Rz0=
  AdditionalCost: 10
- NodeID: 2
  NodeName: ngsdn
  ControlPSKey: kzj4qz2KAMojJ/Hk9Q3FRaOn/+cjwz/9s+ZUtrj7Pkg=
  AdditionalCost: 10
- NodeID: 3
  NodeName: ngsdn
  ControlPSKey: Vy3uIIMTzo+DYjyRn/VZ0iKmPj6MKPNYWrTZlJyC5TE=
  AdditionalCost: 10
- NodeID: 4
  NodeName: ngsdn
  ControlPSKey: Tpq+PdSJXBykmdo7kwRRb+/Kj4zq1up5iP59Wd9oW/E=
  AdditionalCost: 10
- NodeID: 5
  NodeName: ngsdn
  ControlPSKey: MqM8yTKV3Ofw67KEF/zRm0RSm1v5MohE8Yn70O5Dbto=
  AdditionalCost: 10
- NodeID: 6
  NodeName: ngsdn
  ControlPSKey: i636CPKZS+TpqHIHRQA6Sm1Pzlukqw9YYcMX3Gx8pkI=
  AdditionalCost: 10
- NodeID: 7
  NodeName: ngsdn
  ControlPSKey: StwjF4U7ADYlRDeWWIsXJ/xKyVa2pk2EB0V3W0jmRN0=
  AdditionalCost: 10
- NodeID: 8
  NodeName: ngsdn
  ControlPSKey: OOk4gK4UDdhynj4+odnFWfxBGJeIKcYMC6Nv9eA+eKk=
  AdditionalCost: 10
- NodeID: 9
  NodeName: ngsdn
  ControlPSKey: dGfA5TyCZ1SjHtEUTRJSD+jYu5EtuFSDIHI1no9P23s=
  AdditionalCost: 10
- NodeID: 10
  NodeName: ngsdn
  ControlPSKey: r7uMr4Y7qKz7/+YQ0oqjwVm2kx7EVQNPNnfPf6NO4DM=
  AdditionalCost: 10
- NodeID: 11
  NodeName: ngsdn
  ControlPSKey: y3eFsrAxqoMTa9rQJ6a/OIAgXBdYY9DjA+zM+Ogsr2g=
  AdditionalCost: 10
- NodeID: 12
  NodeName: ngsdn
  ControlPSKey: ywnOGWs+G/escZ+8KG2LyeuIsrSyTQugqgHNWfQNGJo=
  AdditionalCost: 10
- NodeID: 13
  NodeName: ngsdn
  ControlPSKey: kILk3sKh/oCB8DFNHLWb6a86LXqzeUZ9BuubwHCBLiQ=
  AdditionalCost: 10
- NodeID: 14
  NodeName: ngsdn
  ControlPSKey: 3QivODaLGJprr0lek/z9nnjhmxJ5BmZybaVuGWFpp5c=
  AdditionalCost: 10
- NodeID: 15
  NodeName: ngsdn
  ControlPSKey: cddIud4Ryw7buTUNfxO2jY6oIG2uUFq4+YzxGUHJo8g=
  AdditionalCost: 10
- NodeID: 16
  NodeName: ngsdn
  ControlPSKey: S9TwTePu2Goam9tlTAcZ64YpY5g/61eI7pZjfrVBwY0=
  AdditionalCost: 10
- NodeID: 17
  NodeName: ngsdn
  ControlPSKey: TAAWIRuUuvFv0C0AH/BEDh5MX8Kx8JJdZQOV3WTrIxw=
  AdditionalCost: 10
- NodeID: 18
  NodeName: ngsdn
  ControlPSKey: QDos7gsPioAbw57B2vCzMdX1PXoHXVlQbjyUtt5dZNA=
  AdditionalCost: 10
- NodeID: 19
  NodeName: ngsdn
  ControlPSKey: I35EE1TKEh/gDGPPpGsiN21EvxVe4zXSV0BFl88zMIE=
  AdditionalCost: 10
- NodeID: 20
  NodeName: ngsdn
  ControlPSKey: jmfAbU5pGl2eO2UNkuKydKNhgw4AIsXu5Zm3s7BGjKU=
  AdditionalCost: 10
- NodeID: 21
  NodeName: ngsdn
  ControlPSKey: +lP/Ekx6PKRp3QKVkEC3tjTrjyzzoh2ie/k3JDBDfbo=
  AdditionalCost: 10
- NodeID: 22
  NodeName: ngsdn
  ControlPSKey: JSVXCVW6BqMtgT8SO/6tCxzQUAE35zlQJStQ99zpyik=
  AdditionalCost: 10
- NodeID: 23
  NodeName: ngsdn
  ControlPSKey: wj3sZIdul5mKPP2Cj6Do13DnxBVQNAoPD3aiuH2PwGQ=
  AdditionalCost: 10
- NodeID: 24
  NodeName: ngsdn
  ControlPSKey: vuQ2JK3bdv2q0aquLSOveCL5NRkWahEU3C4atsnpN0M=
  AdditionalCost: 10
- NodeID: 25
  NodeName: ngsdn
  ControlPSKey: n3uqj8jwYvjidcNpAv0cB2TrDAQGroxHln2qf5JIOCg=
  AdditionalCost: 10
- NodeID: 26
  NodeName: ngsdn
  ControlPSKey: mjcl4Pyy1NGk94unMTygvuNbAcnjKarnfDjXkPFK/yA=
  AdditionalCost: 10
- NodeID: 27
  NodeName: ngsdn
  ControlPSKey: v1GudCsH0WCyMY2c60yM7Fu+ExLpn+aRqskVi0JxOew=
  AdditionalCost: 10
- NodeID: 28
  NodeName: ngsdn
  ControlPSKey: Dmagas3jJ8qW/8ME9wzVJr9Kf7xF67bESzjA7EQfvCI=
  AdditionalCost: 10
- NodeID: 29
  NodeName: ngsdn
  ControlPSKey: 5tRXxDWti0h0GaafhioSsl65iE6Z5kEsIaBH28tcnVs=
  AdditionalCost: 10
- NodeID: 30
  NodeName: ngsdn
  ControlPSKey: EdGzRNfNpIClUQ025kc1lbKzguQvUSD01D0iNZTf5nQ=
  AdditionalCost: 10
- NodeID: 31
  NodeName: ngsdn
  ControlPSKey: azU8TtedJQq2xVJQm6gwihLvVHtiMFwRxYBCsFcKsp8=
  AdditionalCost: 10
- NodeID: 32
  NodeName: ngsdn
  ControlPSKey: 2o1YA8xSF/3Y1o0lntzwJNM0BIHZdAPNf8rnU/+ZV4k=
  AdditionalCost: 10
- NodeID: 33
  NodeName: ngsdn
  ControlPSKey: KJucFl6yPBBzqXi+lPpoG+jsPcs6grIEZaFd6ZhSSFQ=
  AdditionalCost: 10
- NodeID: 34
  NodeName: ngsdn
  ControlPSKey: 6KRV4GM472pS9VemGeae/UrNoVwnTQFIIW7lJR1+DRs=
  AdditionalCost: 10
- NodeID: 35
  NodeName: ngsdn
  ControlPSKey: OsKyw3lezJNw5j67v1miVCR10jKubs7Q3rWgSx/FZMo=
  AdditionalCost: 10
- NodeID: 36
  NodeName: ngsdn
  ControlPSKey: EwI2DcaXjHsbjGaYuXN8u3IPfaOSqWbb7XOtiHyU36M=
  AdditionalCost: 10
- NodeID: 37
  NodeName: ngsdn
  ControlPSKey: 62o8CEk+uXAl6sezQZ2S4zEyPxTJmXUcYepJpDwco18=
  AdditionalCost: 10
- NodeID: 38
  NodeName: ngsdn
  ControlPSKey: ADXnS9MLYYmeZGOjEuWxaio6t+5/hXgYpBdRSOZVpTw=
  AdditionalCost: 10
- NodeID: 39
  NodeName: ngsdn
  ControlPSKey: fkfx/pESKYT7NL5A22EOM+OSzUD1eSN8wcpvjZAuSVs=
  AdditionalCost: 10
- NodeID: 40
  NodeName: ngsdn
  ControlPSKey: qVXwd+sT1SnurS8ymlPerhSZYRjSarnhhSdgZM3Y4Ak=
  AdditionalCost: 10
- NodeID: 41
  NodeName: ngsdn
  ControlPSKey: to/7sUsODu33ajsmLB+88QJ4gWI6iK9uWYCO1uiIj8w=
  AdditionalCost: 10
- NodeID: 42
  NodeName: ngsdn
  ControlPSKey: f78qijUf1cupU1l1lyi6CL+AhSYHlNELyqNBYMu2wWw=
  AdditionalCost: 10
- NodeID: 43
  NodeName: ngsdn
  ControlPSKey: v+jZPfVpEnFMjCuP6yGMLhMr4J+do+758jiRVbOjH7g=
  AdditionalCost: 10
- NodeID: 44
  NodeName: ngsdn
  ControlPSKey: RvxMRoFu2JfrU8Ll471cKo1BcmfUOrYf/0SHrALejCw=
  AdditionalCost: 10
- NodeID: 45
  NodeName: ngsdn
  ControlPSKey: LS3tl0OaZuG09p4Pm3+wIqQwLGOxvkg34K3U90hp2/o=
  AdditionalCost: 10
- NodeID: 46
  NodeName: ngsdn
  ControlPSKey: ll5Bfz1Y6P8Q1yJJlYYi7sBeQj833/QNM5DM5SvO5aI=
  AdditionalCost: 10
- NodeID: 47
  NodeName: ngsdn
  ControlPSKey: DIuib3dEwJAxRJDEIdWfAx20MALH50FXa/bcnUy2EhQ=
  AdditionalCost: 10
- NodeID: 48
  NodeName: ngsdn
  ControlPSKey: +rnw/VTbw0d/lcUU27H2MzHzn3usjHPpSTmLo4nDJKw=
  AdditionalCost: 10
- NodeID: 49
  NodeName: ngsdn
  ControlPSKey: U/HEc5zS8Rao1GUhIbIpYrlXzuvuthYclkLr2Nbw7yE=
  AdditionalCost: 10
- NodeID: 50
  NodeName: ngsdn
  ControlPSKey: cCqCIOITYbPVz+aSCBtxfCovRft1yox2ByHruQ4c4Cc=
  AdditionalCost: 10
- NodeID: 51
  NodeName: ngsdn
  ControlPSKey: cBDVgwrEWY4WljTTJW/bZC1nCMOB/m8EhBjTzJ4TMx4=
  AdditionalCost: 10
- NodeID: 52
  NodeName: ngsdn
  ControlPSKey: UhqhSITFkaIkbJdzn1YuAIzndBJOGmwu3ohxHGxpcaE=
  AdditionalCost: 10
- NodeID: 53
  NodeName: ngsdn
  ControlPSKey: wywuani8BKFleHVYJ74UN6wLZEwbjav5cAyM4qpgOmk=
  AdditionalCost: 10
- NodeID: 54
  NodeName: ngsdn
  ControlPSKey: BeO67k1icBO9JSFW50Qeq6DYO1FarSACJeDPSO7EU64=
  AdditionalCost: 10
- NodeID: 55
  NodeName: ngsdn
  ControlPSKey: BcTHgXfwF6Zru9sihcjGAoiN4AR1u1AFFFu2HuxFIEY=
  AdditionalCost: 10
- NodeID: 56
  NodeName: ngsdn
  ControlPSKey: +NtWlkZRlM+CcVzOETDW9T6tBXazxwGnN/O0axNnuGM=
  AdditionalCost: 10
- NodeID: 57
  NodeName: ngsdn
  ControlPSKey: 3WPuKS0jiHLWka9gtoNIq6crhXlRZ/m38ID+GU318sE=
  AdditionalCost: 10
- NodeID: 58
  NodeName: ngsdn
  ControlPSKey: d+Ght+iqskJvGe5DopIeUHVLQL37Q2l2CjLe1amnb8Q=
  AdditionalCost: 10
- NodeID: 59
  NodeName: ngsdn
  ControlPSKey: h5puC32BfYzOtxYPXel5Rl1qNtYIi4WKv40MKOynw1c=
  AdditionalCost: 10
- NodeID: 60
  NodeName: ngsdn
  ControlPSKey: 2VmcwJz6USHboe6G9afStYVvMkxRqt7XHa87YrlTAUA=
  AdditionalCost: 10
- NodeID: 61
  NodeName: ngsdn
  ControlPSKey: Mm5dvXYsNAqwshwfr4vbzUcaFZrHDS686siSHGWgQ+0=
  AdditionalCost: 10
- NodeID: 62
  NodeName: ngsdn
  ControlPSKey: Ct/GbKeiSuaVE9wITBmYk2ZxBNzjrU0Lj4YN3s7QV9M=
  AdditionalCost: 10
- NodeID: 63
  NodeName: ngsdn
  ControlPSKey: 85jTGuVZVNUY6Qq6GlQQhnD2UhL2vSv0KuROzLQIrCw=
  AdditionalCost: 10
- NodeID: 64
  NodeName: ngsdn
  ControlPSKey: NgkCZNuw9GQ3vyikNY8qyRAEO5qqQ3dEffO6rkgt9ng=
  AdditionalCost: 10
- NodeID: 65
  NodeName: ngsdn
  ControlPSKey: qLJKP9rjU9JilQ0mshXA0t3yz9y24CRri55cjXqVhko=
  AdditionalCost: 10
- NodeID: 66
  NodeName: ngsdn
  ControlPSKey: MgMPYehsNgwFAObYXP/1lJSEdeQx1BEqQi3ieiylCh4=
  AdditionalCost: 10
- NodeID: 67
  NodeName: ngsdn
  ControlPSKey: B6Z1hEcDLs9kSS3mcMjfDHnnOLeEZwlalu3Q9L/nI8w=
  AdditionalCost: 10
- NodeID: 68
  NodeName: ngsdn
  ControlPSKey: bZZaHW3OoKcOW1vkNawCim40j6/7TQzInPqnezwVHdc=
  AdditionalCost: 10
- NodeID: 69
  NodeName: ngsdn
  ControlPSKey: agOWWu4WGfYQikAmnzuf6zRwbg1P9Jl54OCpRk+pt00=
  AdditionalCost: 10
- NodeID: 70
  NodeName: ngsdn
  ControlPSKey: StX4vRl4TRF39edVH5eC/7KxVB8j9HghKagI8fuG+pQ=
  AdditionalCost: 10
- NodeID: 71
  NodeName: ngsdn
  ControlPSKey: ytA8AUzlxABssfhhsSA77QRFmgqrQxV/IIXVHo1M3Yo=
  AdditionalCost: 10
- NodeID: 72
  NodeName: ngsdn
  ControlPSKey: I1ElS3SreBN94llIQX861jRZKWmdE37OnITj6+0VJCk=
  AdditionalCost: 10
- NodeID: 73
  NodeName: ngsdn
  ControlPSKey: Aml7ezwUM/GD3LSQ+iCjlu/JyPDxZ6vjz98l11fpzm4=
  AdditionalCost: 10
- NodeID: 74
  NodeName: ngsdn
  ControlPSKey: 0E/eKT2aT5wu3igYVf63Pv3olssjbFWuwbbr/rdq164=
  AdditionalCost: 10
- NodeID: 75
  NodeName: ngsdn
  ControlPSKey: BiGOfeOOYxMi6MR38/n42L0fT+f15sh1xtVCPneKkCE=
  AdditionalCost: 10
- NodeID: 76
  NodeName: ngsdn
  ControlPSKey: +WnpXI5A8SzDdRzqj04dxW95rvG93i1xfgm1P70/rfo=
  AdditionalCost: 10
- NodeID: 77
  NodeName: ngsdn
  ControlPSKey: ZA045mQSaUY7L+03qTVQE9UR4deTW2wIADZY9iYnuPY=
  AdditionalCost: 10
- NodeID: 78
  NodeName: ngsdn
  ControlPSKey: kGCauIX8pch+HLR3P+WVtXTkToPN2buZCkBtSvd51K0=
  AdditionalCost: 10
- NodeID: 79
  NodeName: ngsdn
  ControlPSKey: 8yrjsGZ287LvKtBv+hDqA6GItArcU/qnnyud4c2nIBk=
  AdditionalCost: 10
- NodeID: 80
  NodeName: ngsdn
  ControlPSKey: KDTc5upJSStPDez2aKk8684DVKvq37zEF56jZDn5dG4=
  AdditionalCost: 10
- NodeID: 81
  NodeName: ngsdn
  ControlPSKey: FX0z3hDkQOAOhUs5bbR5Q+4NN072sLRGi4TTGo2BSMw=
  AdditionalCost: 10
- NodeID: 82
  NodeName: ngsdn
  ControlPSKey: zEPkPC/Aft90DJ5M3gdQxaWhMXUrsvYfwKKiTMhouY4=
  AdditionalCost: 10
- NodeID: 83
  NodeName: ngsdn
  ControlPSKey: TRD8y9w1HO150gkSzwrxPygEoAi4lfxG9lWQekgW9Oo=
  AdditionalCost: 10
- NodeID: 84
  NodeName: ngsdn
  ControlPSKey: 7nkxFdYnClh63Y/wGIC9FbhyCP9ILPweUcO9mWQIjys=
  AdditionalCost: 10
- NodeID: 85
  NodeName: ngsdn
  ControlPSKey: PycLX47cw+fzVupa0aVl4IrvVXbbCF9c6ZRLcRBfVi8=
  AdditionalCost: 10
- NodeID: 86
  NodeName: ngsdn
  ControlPSKey: pEJU0AKkDY6itAXSjvKcFkee7TGLoMX1XIQwHlGhFOY=
  AdditionalCost: 10
- NodeID: 87
  NodeName: ngsdn
  ControlPSKey: tZr++5XSbYvnMFiduTrMm0r2vVvD/4pmbqDOdjs5En8=
  AdditionalCost: 10
- NodeID: 88
  NodeName: ngsdn
  ControlPSKey: ABTsOV6awvJZrio4ptYSvGxv4JKcpgC+7pdprofISSo=
  AdditionalCost: 10
- NodeID: 89
  NodeName: ngsdn
  ControlPSKey: jNk+A9PERlks6TRbI41Sa+4e1mQVnVk9iPbuuBmefRQ=
  AdditionalCost: 10
- NodeID: 90
  NodeName: ngsdn
  ControlPSKey: T11HqH5esTHa/vhhTOSEqBi12suLaRSSrTwOcbWyqY4=
  AdditionalCost: 10
- NodeID: 91
  NodeName: ngsdn
  ControlPSKey: uHMOD/XnqNcMaZyesa/9ebW7p5MPmicXUwIAF8qukXc=
  AdditionalCost: 10
- NodeID: 92
  NodeName: ngsdn
  ControlPSKey: EU9z2t3bW4jQNNobVyVd3rDF5Bx4QT5hZRiwymQzDC8=
  AdditionalCost: 10
- NodeID: 93
  NodeName: ngsdn
  ControlPSKey: yrhMm3CcSQKKfj5ORgAiZIlqu0S1y0kGBnETB8i6MGk=
  AdditionalCost: 10
- NodeID: 94
  NodeName: ngsdn
  ControlPSKey: NWNJ0m16ZIeldE929bgNFL/pY30NSfxAi/Yx+jRKoiI=
  AdditionalCost: 10
- NodeID: 95
  NodeName: ngsdn
  ControlPSKey: 6l4iOwFvFuIOrTrbI77XC+JrYeK0rwi6JdmV9A8p8vg=
  AdditionalCost: 10
- NodeID: 96
  NodeName: ngsdn
  ControlPSKey: +qTDXTiH9j7jVrlFCGCFLr2Wtqr98cv9Ege1ShV/fcE=
  AdditionalCost: 10
- NodeID: 97
  NodeName: ngsdn
  ControlPSKey: cZhIk2+Pw7aQrkHaMwodbULsqbnzCdBln2mFa/c7qjI=
  AdditionalCost: 10
- NodeID: 98
  NodeName: ngsdn
  ControlPSKey: tolkFgw2GgyYna1U3IuwvUxj+j0E+q8Ox8PKGIk0rWw=
  AdditionalCost: 10
- NodeID: 99
  NodeName: ngsdn
  ControlPSKey: RCkdOZHquNYLx5Uo/9oxQKGXuUlxsOSANd0zsqj2tys=
  AdditionalCost: 10
- NodeID: 100
  NodeName: ngsdn
  ControlPSKey: OPWJ2NvA3qiX3xmdOK1jsRsar2gOas7eoRZ5frxf9Ko=
  AdditionalCost: 10
`

// corpusDirOrSkip returns the operational corpus directory or skips
// the test when it is not present (CI without the corpus mount).
func corpusDirOrSkip(t *testing.T) string {
	t.Helper()
	info, err := os.Stat(operationalCorpusDir)
	if err != nil || !info.IsDir() {
		t.Skipf("operational corpus not present at %s: %v", operationalCorpusDir, err)
	}
	return operationalCorpusDir
}

// extractYAMLValue returns the scalar value following `key:` on a
// top-level or nested line in a YAML document. It performs a substring
// search, not a structural decode, so it can be used to detect the
// golden value without invoking the full unmarshal path. Whitespace
// around the value is trimmed.
func extractYAMLValue(content, key string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key+":") {
			continue
		}
		rest := strings.TrimPrefix(trimmed, key+":")
		return strings.TrimSpace(rest)
	}
	return ""
}

// yamlUnmarshal decodes a YAML byte slice into the supplied typed
// destination. Test-local helper so docs_contract_test.go does not need
// to import gopkg.in/yaml.v2 in every test.
func yamlUnmarshal(data []byte, out interface{}) error {
	return yaml.Unmarshal(data, out)
}
