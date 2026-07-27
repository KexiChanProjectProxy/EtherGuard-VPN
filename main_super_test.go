// SPDX-License-Identifier: MIT
//
// Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
//
// Tests for the Super legacy-field prescan. The prescan must:
//
//   - accept a v2 Super YAML carrying only `ListenPortPriority:` and no
//     bare `ListenPort:` (the new wire key MUST NOT be flagged);
//   - reject a v1 Super YAML carrying the bare legacy `ListenPort:` key;
//   - reject a Super YAML that carries BOTH the new priority key AND the
//     legacy bare key (operator likely migrated incompletely);
//   - preserve existing rejection semantics for `ListenPort_EdgeAPI` /
//     `ListenPort_ManageAPI` and every other v1 UDP field.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLegacyUDPFieldPresentListenPortPriority pins the bytes-prescan
// contract for the new v2 `ListenPortPriority:` wire key.
func TestLegacyUDPFieldPresentListenPortPriority(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantPresent bool
		wantName    string
	}{
		{
			name:        "priority only",
			body:        "NodeName: super-1\nListenPortPriority:\n  - Port: 16386\n",
			wantPresent: false,
			wantName:    "",
		},
		{
			name:        "bare legacy ListenPort",
			body:        "NodeName: super-1\nListenPort: 51820\n",
			wantPresent: true,
			wantName:    "ListenPort",
		},
		{
			name:        "both new and legacy",
			body:        "NodeName: super-1\nListenPort: 51820\nListenPortPriority:\n  - Port: 16386\n",
			wantPresent: true,
			wantName:    "ListenPort",
		},
		{
			name:        "ListenPort_EdgeAPI preserved",
			body:        "NodeName: super-1\nListenPort_EdgeAPI: 9090\n",
			wantPresent: true,
			wantName:    "ListenPort_EdgeAPI",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write temp yaml: %v", err)
			}
			gotPresent, gotName := legacyUDPFieldPresent(path)
			if gotPresent != tc.wantPresent || gotName != tc.wantName {
				t.Fatalf("legacyUDPFieldPresent(%s) = (%v, %q), want (%v, %q)",
					tc.name, gotPresent, gotName, tc.wantPresent, tc.wantName)
			}
		})
	}
}
