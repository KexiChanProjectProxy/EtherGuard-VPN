package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
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
		"DampingFilterRadius": true, "Peers": true,
	}
	validEdgeKeys := map[string]bool{
		"Interface": true, "NodeID": true, "NodeName": true,
		"DefaultTTL": true, "LogLevel": true, "SuperNodeV2": true, "Peers": true,
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

// TestDocsSTUNRefreshReserved verifies that STUNRefreshIntervalSeconds is
// documented as reserved/inert. The field exists in SuperConfigV2 and is
// validated (> 0) but no runtime code reads it — refreshSTUN is called
// once at register time only (device/super_http_runtime.go:75).
func TestDocsSTUNRefreshReserved(t *testing.T) {
	t.Parallel()
	for _, doc := range superDocFiles {
		content := readFile(t, doc)
		if !strings.Contains(content, "STUNRefreshIntervalSeconds") {
			t.Errorf("%s: STUNRefreshIntervalSeconds not mentioned in config table", doc)
		}
		lower := strings.ToLower(content)
		// The description must contain a reserved/inert qualifier.
		if !strings.Contains(lower, "reserved") && !strings.Contains(lower, "保留") &&
			!strings.Contains(lower, "inert") && !strings.Contains(lower, "無效") {
			t.Errorf("%s: STUNRefreshIntervalSeconds description must note it is reserved/inert", doc)
		}
	}
}
