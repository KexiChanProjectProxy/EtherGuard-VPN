package device

import (
	"reflect"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestEdgeConfigV2APIUrlsOnlyRuntimeSelector(t *testing.T) {
	// Given
	config := mtypes.EdgeConfigV2{
		NodeID: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      []string{"https://a.example/", "https://b.example/"},
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "control-key",
		},
	}

	// When
	runtime := NewSuperHTTPRuntime(nil, config)

	// Then
	want := []string{"https://a.example", "https://b.example"}
	if !reflect.DeepEqual(runtime.selector.urls, want) {
		t.Fatalf("selector urls = %v, want %v", runtime.selector.urls, want)
	}
	if runtime.selector.idx != 0 {
		t.Fatalf("selector idx = %d, want 0", runtime.selector.idx)
	}
	if runtime.client.BaseURL != "https://a.example" {
		t.Fatalf("client base = %q, want https://a.example", runtime.client.BaseURL)
	}
}

func TestEdgeConfigV2EnableSuperHTTPStartsAtIndex(t *testing.T) {
	// Given
	config := mtypes.EdgeConfigV2{
		NodeID: 7,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      []string{"https://a.example/", "https://b.example/"},
			APIPrefix:    "/edge/v2",
			NodeID:       1,
			ControlPSKey: "control-key",
		},
	}
	device := &Device{}

	// When
	device.EnableSuperHTTP(config, 1)
	t.Cleanup(func() {
		if device.controlCancel != nil {
			device.controlCancel()
		}
		if device.superHTTP != nil {
			<-device.superHTTP.Done()
		}
	})

	// Then
	runtime := device.superHTTP
	if runtime == nil {
		t.Fatal("EnableSuperHTTP did not install a runtime")
	}
	want := []string{"https://a.example", "https://b.example"}
	if !reflect.DeepEqual(runtime.selector.urls, want) {
		t.Fatalf("selector urls = %v, want %v", runtime.selector.urls, want)
	}
	if runtime.selector.idx != 1 {
		t.Fatalf("selector idx = %d, want 1", runtime.selector.idx)
	}
	if runtime.client.BaseURL != "https://b.example" {
		t.Fatalf("client base = %q, want https://b.example", runtime.client.BaseURL)
	}
}

func TestEdgeConfigV2EnableSuperHTTPLegacySingleURL(t *testing.T) {
	// Given
	config := mtypes.EdgeConfigV2{
		NodeID: 1,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrl:       "http://127.0.0.1:3456",
			APIPrefix:    "/edge/v2",
			NodeID:       10,
			ControlPSKey: "control-key",
		},
	}
	device := &Device{}

	// When
	device.EnableSuperHTTP(config, 0)
	t.Cleanup(func() {
		if device.controlCancel != nil {
			device.controlCancel()
		}
		if device.superHTTP != nil {
			<-device.superHTTP.Done()
		}
	})

	// Then
	runtime := device.superHTTP
	if runtime == nil {
		t.Fatal("EnableSuperHTTP did not install a runtime")
	}
	want := []string{"http://127.0.0.1:3456"}
	if !reflect.DeepEqual(runtime.selector.urls, want) {
		t.Fatalf("selector urls = %v, want %v", runtime.selector.urls, want)
	}
	if runtime.client.BaseURL != "http://127.0.0.1:3456" {
		t.Fatalf("client base = %q, want http://127.0.0.1:3456", runtime.client.BaseURL)
	}
}
