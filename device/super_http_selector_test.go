package device

import (
	"errors"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestSuperSelectorThresholds(t *testing.T) {
	// Given
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		selector   superSelector
		interval   time.Duration
		wantRotate bool
	}{
		{
			name: "single URL never rotates",
			selector: superSelector{
				urls:                      []string{"https://a.example"},
				consecutiveReportFailures: 3,
				lastSuccess:               now.Add(-time.Hour),
				now:                       func() time.Time { return now },
			},
			interval:   time.Second,
			wantRotate: false,
		},
		{
			name: "three report failures rotate",
			selector: superSelector{
				urls:                      []string{"https://a.example", "https://b.example"},
				consecutiveReportFailures: 3,
				lastSuccess:               now,
				now:                       func() time.Time { return now },
			},
			interval:   time.Second,
			wantRotate: true,
		},
		{
			name: "no-success window uses three report intervals",
			selector: superSelector{
				urls:        []string{"https://a.example", "https://b.example"},
				lastSuccess: now.Add(-30 * time.Second),
				now:         func() time.Time { return now },
			},
			interval:   10 * time.Second,
			wantRotate: true,
		},
		{
			name: "below both thresholds stays",
			selector: superSelector{
				urls:                      []string{"https://a.example", "https://b.example"},
				consecutiveReportFailures: 2,
				lastSuccess:               now.Add(-14 * time.Second),
				now:                       func() time.Time { return now },
			},
			interval:   time.Second,
			wantRotate: false,
		},
	}

	// When / Then
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.selector.shouldRotate(test.interval); got != test.wantRotate {
				t.Fatalf("shouldRotate() = %v, want %v", got, test.wantRotate)
			}
		})
	}

	selector := superSelector{urls: []string{"https://a.example", "https://b.example"}, now: func() time.Time { return now }}
	selector.recordReportFailure(ErrControlUnknownPeer)
	if selector.consecutiveReportFailures != 0 {
		t.Fatalf("unknown-peer failures = %d, want 0", selector.consecutiveReportFailures)
	}
	selector.recordReportFailure(errors.New("transport failed"))
	selector.recordSuccess()
	if selector.consecutiveReportFailures != 0 || !selector.lastSuccess.Equal(now) {
		t.Fatalf("recordSuccess state = failures %d, last %v", selector.consecutiveReportFailures, selector.lastSuccess)
	}
	if got := selector.rotate(); got != "https://b.example" || selector.idx != 1 {
		t.Fatalf("rotate() = %q at index %d, want https://b.example at 1", got, selector.idx)
	}

	runtime := NewSuperHTTPRuntime(nil, mtypes.EdgeConfigV2{
		SuperNodeV2: mtypes.SuperNodeV2Ref{APIUrls: []string{"https://a.example/", "https://b.example/"}},
	}, WithStartIndex(1))
	runtime.SetClockForTest(func() time.Time { return now })
	if runtime.client.BaseURL != "https://b.example" || runtime.selector.idx != 1 || !runtime.selector.lastSuccess.Equal(now) {
		t.Fatalf("start selection = base %q, index %d, last success %v", runtime.client.BaseURL, runtime.selector.idx, runtime.selector.lastSuccess)
	}
}
