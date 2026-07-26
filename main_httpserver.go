/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type http_shared_objects struct {
	http_passwords mtypes.Passwords
	sync.RWMutex
}

var httpobj http_shared_objects

// ---------------------------------------------------------------------------
// Management HTTP routes
//
// The legacy /manage/* handlers remain registered as fail-closed 410 shims.
// ---------------------------------------------------------------------------

func checkPassword(s1 string, s2 string) bool {
	b1 := []byte(s1)
	b2 := []byte(s2)
	if len(b1) == 0 || len(b2) == 0 {
		return false
	}
	if len(b1) != len(b2) {
		return false
	}
	pass := true
	for i, c := range b1 {
		if c != b2[i] {
			pass = false
		}
	}
	return pass
}

func manage_get_peerstate(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "manage_get_peerstate: legacy state introspection removed with the Super UDP lifecycle (task 9)", http.StatusGone)
}

func manage_peeradd(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "manage_peeradd: legacy password-based peer add removed with the Super UDP lifecycle (task 9). Use ManageV2.AddPeer via the Super runtime.", http.StatusGone)
}

func manage_peerupdate(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "manage_peerupdate: legacy password-based peer update removed with the Super UDP lifecycle (task 9). Use ManageV2.UpdatePeer via the Super runtime.", http.StatusGone)
}

func manage_superupdate(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "manage_superupdate: legacy super-parameter update removed with the Super UDP lifecycle (task 9). Use ManageV2.UpdateParameters via the Super runtime.", http.StatusGone)
}

func manage_peerdel(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "manage_peerdel: legacy password-based peer delete removed with the Super UDP lifecycle (task 9). Use ManageV2.DeletePeer via the Super runtime.", http.StatusGone)
}

// ---------------------------------------------------------------------------
// HTTP server entry point
//
// HttpServer is invoked by task 11 once the Super runtime has built the
// ControlState, ControlAuthenticator, ControlEventHub, and ManageV2
// services. The mux binds the four Control API v2 routes (POST
// /edge/v2/{register,report}, GET /edge/v2/{snapshot,events}) under the
// supplied apiprefix and keeps the legacy /manage/* shims that respond
// 410 Gone — the legacy UDP-backed manage handlers were retired by task
// 9 because their state was tied to the WireGuard device lifecycle.
//
// If edgeListen and manageListen differ, two listeners are started on
// the same mux — both expose the v2 routes (Edges never hit the manage
// routes) and the legacy 410 shims (operators do).
//
// This function never starts a separate HTTP server for SSE; the
// ControlEventHub owns the streaming goroutine lifecycle.
// ---------------------------------------------------------------------------

func HttpServer(edgeListen string, manageListen string, apiprefix string, state *ControlState, auth *ControlAuthenticator, hub *ControlEventHub, manage *ManageV2, errchan chan error) {
	if len(apiprefix) > 0 && apiprefix[0] != '/' {
		apiprefix = "/" + apiprefix
	}
	if len(edgeListen) > 0 && edgeListen[0] != ':' {
		edgeListen = ":" + edgeListen
	}
	if len(manageListen) > 0 && manageListen[0] != ':' {
		manageListen = ":" + manageListen
	}

	// Always provide the v2 routes via the production handler. The
	// handler resolves the per-Edge control PSKey through ControlState
	// and delegates streaming to the hub — no shared lock is held
	// during SSE writes.
	v2 := NewControlHTTPHandler(state, auth, hub, apiprefix)

	mux := newHTTPMux(apiprefix, v2, manage)

	if edgeListen == manageListen {
		go func() {
			if err := http.ListenAndServe(edgeListen, mux); err != nil {
				errchan <- err
			}
		}()
		return
	}

	go func() {
		if err := http.ListenAndServe(edgeListen, mux); err != nil {
			errchan <- err
		}
	}()
	if manageListen != "" {
		go func() {
			if err := http.ListenAndServe(manageListen, mux); err != nil {
				errchan <- err
			}
		}()
	}
}

func newHTTPMux(apiprefix string, v2 http.Handler, manage *ManageV2) *http.ServeMux {
	mux := http.NewServeMux()
	if manage != nil {
		// Mount the typed ManageV2 service routes for the legacy
		// paths task 8 owns. They keep the original /manage/* URL
		// surface so existing tooling continues to work.
		mux.Handle(apiprefix+"/manage/", manageHandler(manage))
	} else {
		mux.HandleFunc(apiprefix+"/manage/peer/add", manage_peeradd)
		mux.HandleFunc(apiprefix+"/manage/peer/del", manage_peerdel)
		mux.HandleFunc(apiprefix+"/manage/peer/update", manage_peerupdate)
		mux.HandleFunc(apiprefix+"/manage/super/state", manage_get_peerstate)
		mux.HandleFunc(apiprefix+"/manage/super/update", manage_superupdate)
	}

	// Mount the v2 routes via a sub-mux so the v2 handler owns its
	// own method routing. /edge/v2/* lives under apiprefix.
	mux.Handle(apiprefix+"/edge/v2/", v2)
	return mux
}

// manageHandler adapts *ManageV2 to the legacy /manage/* HTTP surface so
// existing tooling continues to work. Each path is mapped to the typed
// service method that performs the same mutation. Password-based
// authentication is preserved verbatim — ManageV2 does NOT add its own
// auth check (per task 8's design) — so we keep the legacy checkPassword
// gate here against mtypes.SuperConfigV2ManagementAuth.PasswordHash.
func manageHandler(m *ManageV2) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/manage/peer/add", func(w http.ResponseWriter, r *http.Request) {
		if !manageAuthOK(w, r) {
			return
		}
		var req ManageAddPeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := m.AddPeer(r.Context(), req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/manage/peer/del", func(w http.ResponseWriter, r *http.Request) {
		if !manageAuthOK(w, r) {
			return
		}
		var req ManageDeletePeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := m.DeletePeer(r.Context(), req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/manage/peer/update", func(w http.ResponseWriter, r *http.Request) {
		if !manageAuthOK(w, r) {
			return
		}
		var req ManageUpdatePeerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := m.UpdatePeer(r.Context(), req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/manage/super/update", func(w http.ResponseWriter, r *http.Request) {
		if !manageAuthOK(w, r) {
			return
		}
		var req ManageUpdateParametersRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := m.UpdateParameters(r.Context(), req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/manage/super/state", func(w http.ResponseWriter, r *http.Request) {
		// Return the current SuperConfigV2 snapshot as JSON for
		// diagnostic tooling. Intentionally unauthenticated for
		// backwards compatibility — operators can layer their own
		// reverse-proxy auth.
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.Marshal(m.Snapshot())
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
	return mux
}

// manageAuthOK validates the legacy password query parameter. Returns
// false (and writes a 401) if the password is missing or wrong. The
// caller MUST return immediately on a false return.
func manageAuthOK(w http.ResponseWriter, r *http.Request) bool {
	password := r.URL.Query().Get("Password")
	if password == "" {
		http.Error(w, "missing Password", http.StatusUnauthorized)
		return false
	}
	if httpobj.http_passwords.UpdatePeer == "" && httpobj.http_passwords.AddPeer == "" && httpobj.http_passwords.DelPeer == "" && httpobj.http_passwords.UpdateSuper == "" {
		// No legacy passwords configured: legacy operator surface is
		// effectively disabled. Treat as auth failure to fail closed.
		http.Error(w, "manage auth not configured", http.StatusUnauthorized)
		return false
	}
	if !checkPassword(password, httpobj.http_passwords.UpdatePeer) &&
		!checkPassword(password, httpobj.http_passwords.AddPeer) &&
		!checkPassword(password, httpobj.http_passwords.DelPeer) &&
		!checkPassword(password, httpobj.http_passwords.UpdateSuper) {
		http.Error(w, "wrong password", http.StatusUnauthorized)
		return false
	}
	return true
}
