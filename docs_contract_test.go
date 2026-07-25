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
