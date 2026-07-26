package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestHTTPMux_returnsGoneForLegacyRoutes_whenManageIsNil(t *testing.T) {
	// Given
	mux := newHTTPMux("", http.NotFoundHandler(), nil)
	legacyPaths := []string{
		"/manage/peer/add",
		"/manage/peer/del",
		"/manage/peer/update",
		"/manage/super/state",
		"/manage/super/update",
	}

	for _, path := range legacyPaths {
		t.Run(path, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))

			// Then
			if response.Code != http.StatusGone {
				t.Fatalf("status=%d, want %d", response.Code, http.StatusGone)
			}
		})
	}
}

func TestManageAuthOK_acceptsConfiguredPassword_andRejectsLegacyFailures(t *testing.T) {
	// Given
	httpobj.Lock()
	previousPasswords := httpobj.http_passwords
	httpobj.http_passwords = mtypes.Passwords{AddPeer: "correct-password"}
	httpobj.Unlock()
	t.Cleanup(func() {
		httpobj.Lock()
		httpobj.http_passwords = previousPasswords
		httpobj.Unlock()
	})

	tests := []struct {
		name       string
		requestURL string
		wantOK     bool
		wantStatus int
	}{
		{name: "missing password", requestURL: "/manage/peer/add", wantOK: false, wantStatus: http.StatusUnauthorized},
		{name: "wrong password", requestURL: "/manage/peer/add?Password=wrong-password", wantOK: false, wantStatus: http.StatusUnauthorized},
		{name: "configured password", requestURL: "/manage/peer/add?Password=correct-password", wantOK: true, wantStatus: http.StatusOK},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			ok := manageAuthOK(response, httptest.NewRequest(http.MethodPost, test.requestURL, nil))

			// Then
			if ok != test.wantOK {
				t.Fatalf("manageAuthOK()=%t, want %t", ok, test.wantOK)
			}
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d, want %d", response.Code, test.wantStatus)
			}
		})
	}
}
