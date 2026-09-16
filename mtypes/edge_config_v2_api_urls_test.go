package mtypes

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func TestEdgeConfigLegacySingleURLStillValid(t *testing.T) {
	assertLegacyExampleYAMLStillValid(t)
}

func TestEdgeConfigV2LegacySingleURLStillValid(t *testing.T) {
	assertLegacyExampleYAMLStillValid(t)
}

func assertLegacyExampleYAMLStillValid(t *testing.T) {
	t.Helper()
	// Given — production example YAML with only SuperNodeV2.APIUrl (no APIUrls)
	path := filepath.Join("..", "example_config", "super_mode", "EgNet_edge001.yaml")
	var config EdgeConfigV2
	if err := ReadYaml(path, &config); err != nil {
		t.Fatalf("load example edge yaml: %v", err)
	}

	// When
	err := config.Validate()
	urls := config.SuperNodeV2.ResolveAPIUrls()

	// Then
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("ResolveAPIUrls() = %v, want exactly 1 URL", urls)
	}
	if urls[0] != "http://127.0.0.1:3456" {
		t.Fatalf("ResolveAPIUrls()[0] = %q, want http://127.0.0.1:3456", urls[0])
	}
}

func TestEdgeConfigV2APIUrlsOnlyStillValid(t *testing.T) {
	// Given
	config := EdgeConfigV2{
		NodeID:   7,
		NodeName: "edge-007",
		SuperNodeV2: SuperNodeV2Ref{
			APIUrls:      []string{"https://a.example/", "https://b.example"},
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "control-key",
		},
	}

	// When
	err := config.Validate()
	urls := config.SuperNodeV2.ResolveAPIUrls()

	// Then
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	want := []string{"https://a.example", "https://b.example"}
	if !reflect.DeepEqual(urls, want) {
		t.Fatalf("ResolveAPIUrls() = %v, want %v", urls, want)
	}
}

func TestEdgeConfigV2RejectsMissingAPIUrls(t *testing.T) {
	// Given
	config := EdgeConfigV2{
		NodeID:   7,
		NodeName: "edge-007",
		SuperNodeV2: SuperNodeV2Ref{
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "control-key",
		},
	}

	// When
	err := config.Validate()

	// Then
	var controlErr *ControlV2Error
	if !errors.As(err, &controlErr) {
		t.Fatalf("Validate() error = %T %v, want *ControlV2Error", err, err)
	}
	if controlErr.Code != ControlV2ErrMissingField {
		t.Fatalf("error code = %q, want %q", controlErr.Code, ControlV2ErrMissingField)
	}
}
