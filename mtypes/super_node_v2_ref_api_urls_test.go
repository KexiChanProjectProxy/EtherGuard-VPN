package mtypes

import (
	"errors"
	"reflect"
	"testing"
)

func TestSuperNodeV2RefAPIUrlsResolveOrder(t *testing.T) {
	// Given
	reference := SuperNodeV2Ref{
		APIUrl:  "https://a/",
		APIUrls: []string{"https://b", "https://a"},
	}

	// When
	got := reference.ResolveAPIUrls()

	// Then
	want := []string{"https://a", "https://b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveAPIUrls() = %v, want %v", got, want)
	}
}

func TestSuperNodeV2RefAPIUrlsValidateListOnly(t *testing.T) {
	// Given
	reference := validSuperNodeV2Ref()
	reference.APIUrl = ""
	reference.APIUrls = []string{"https://a/", "http://b"}

	// When
	err := reference.Validate()

	// Then
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	want := []string{"https://a", "http://b"}
	if got := reference.ResolveAPIUrls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveAPIUrls() = %v, want %v", got, want)
	}
}

func TestSuperNodeV2RefAPIUrlsLegacySingleURLValid(t *testing.T) {
	// Given
	reference := validSuperNodeV2Ref()

	// When
	err := reference.Validate()

	// Then
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	want := []string{"https://legacy.example.com"}
	if got := reference.ResolveAPIUrls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolveAPIUrls() = %v, want %v", got, want)
	}
}

func TestSuperNodeV2RefAPIUrlsRejectsInvalid(t *testing.T) {
	tests := []struct {
		name     string
		apiURL   string
		apiURLs  []string
		wantCode string
	}{
		{name: "missing all URLs", wantCode: ControlV2ErrMissingField},
		{name: "unsupported scheme", apiURLs: []string{"ftp://x"}, wantCode: ControlV2ErrInvalidURI},
		{name: "missing host", apiURLs: []string{"https:///path"}, wantCode: ControlV2ErrInvalidURI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			reference := validSuperNodeV2Ref()
			reference.APIUrl = tt.apiURL
			reference.APIUrls = tt.apiURLs

			// When
			err := reference.Validate()

			// Then
			var controlErr *ControlV2Error
			if !errors.As(err, &controlErr) {
				t.Fatalf("Validate() error = %T %v, want *ControlV2Error", err, err)
			}
			if controlErr.Code != tt.wantCode {
				t.Fatalf("error code = %q, want %q", controlErr.Code, tt.wantCode)
			}
		})
	}
}

func validSuperNodeV2Ref() SuperNodeV2Ref {
	return SuperNodeV2Ref{
		APIUrl:       "https://legacy.example.com/",
		APIPrefix:    "/edge/v2",
		NodeID:       1,
		ControlPSKey: "control-key",
	}
}
