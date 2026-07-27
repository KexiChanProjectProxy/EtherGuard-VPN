/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

// Package main — authenticated Control API v2 HTTP handler.
//
// This file wires the four production endpoints (POST /edge/v2/register,
// POST /edge/v2/report, GET /edge/v2/snapshot, GET /edge/v2/events) under
// a configurable API prefix. The handler is mounted by main_super.go (task
// 11) on the existing EdgeAPI listener; it does NOT start a separate HTTP
// server and it does NOT bind the Super's UDP listener.
//
// Authentication: every request is verified by *ControlAuthenticator which
// resolves the per-Edge control PSKey exclusively through the
// *ControlState. The Super-control PSKey is never exposed in any response
// body, error message, log line, URL query string, or SSE event.
//
// Streaming: /edge/v2/events delegates to *ControlEventHub.ServeSSE; the
// hub owns the subscriber lifecycle. The HTTP handler sets the SSE headers
// and flushes the initial framing, but it does NOT hold the ControlState
// lock while writing events. Cancellation flows through r.Context() —
// closing the request context terminates the renderer goroutine.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// ControlHTTPHandler is the constructor for the Control API v2 HTTP handler.
//
// Mounting: task 11 calls NewControlHTTPHandler(...) and wires the returned
// http.Handler onto the existing EdgeAPI listener under prefix
// (typically mtypes.ControlV2APIPrefix, i.e. "/edge/v2"). The handler is
// safe to mount on any net/http mux.
//
// Dependencies: state owns the authoritative peer records; auth verifies
// the per-Edge HMAC signature; hub fans out state-change events to SSE
// subscribers. The constructor does NOT start a goroutine, does NOT bind
// any port, and does NOT modify the ControlState.
//
// Publish wiring: the caller must install hub.Publish into ControlState
// (state.SetPublishForTest or the production-time publish hook). The
// handler does not touch this — it is the responsibility of the Super
// startup so the state and hub share the same single publish hook.
type ControlHTTPHandler struct {
	state  *ControlState
	auth   *ControlAuthenticator
	hub    *ControlEventHub
	prefix string
}

// NewControlHTTPHandler constructs the v2 HTTP handler. prefix is
// normalised to start with "/"; an empty prefix becomes "/". The returned
// handler is safe for concurrent use.
func NewControlHTTPHandler(state *ControlState, auth *ControlAuthenticator, hub *ControlEventHub, prefix string) *ControlHTTPHandler {
	if prefix == "" {
		prefix = mtypes.ControlV2APIPrefix
	}
	if prefix[0] != '/' {
		prefix = "/" + prefix
	}
	return &ControlHTTPHandler{state: state, auth: auth, hub: hub, prefix: prefix}
}

// ServeHTTP routes an inbound request to the matching handler. The
// registered path set is:
//
//	POST prefix/register   -> handleRegister
//	POST prefix/report     -> handleReport
//	GET  prefix/snapshot   -> handleSnapshot
//	GET  prefix/events     -> handleEvents
//	GET  prefix/bootstrap  -> handleBootstrap
//
// Unknown methods or paths return 405 / 404 respectively. Every route
// requires the four HMAC headers; missing headers → 401 via Verify.
func (h *ControlHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case h.prefix + "/register":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleRegister(w, r)
	case h.prefix + "/report":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleReport(w, r)
	case h.prefix + "/snapshot":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleSnapshot(w, r)
	case h.prefix + "/events":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleEvents(w, r)
	case h.prefix + "/bootstrap":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.handleBootstrap(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleRegister authenticates the request, decodes the v2 register body,
// and asks ControlState to register the Edge. The returned snapshot is
// the body of the 200 response. ETag is set from snap.ETag() so a
// subsequent /snapshot call can short-circuit with 304.
func (h *ControlHTTPHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	nodeID, body, err := h.auth.Verify(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req mtypes.ControlV2RegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid register body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.NodeID != nodeID {
		http.Error(w, "node id mismatch", http.StatusBadRequest)
		return
	}
	pskey, ok := h.state.ControlKeyFor(nodeID)
	if !ok || pskey == "" {
		http.Error(w, "no control key registered", http.StatusBadRequest)
		return
	}
	snap, err := h.state.Register(r.Context(), req, pskey)
	if err != nil {
		http.Error(w, "register: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("ETag", snap.ETag())
	writeJSON(w, http.StatusOK, snap)
}

// handleReport authenticates the request, decodes the v2 report body,
// and asks ControlState to apply the heartbeat / candidates / pongs.
// Returns 204 on success; the publish hook installed by the Super
// startup fires the corresponding peer_change event (outside the lock).
func (h *ControlHTTPHandler) handleReport(w http.ResponseWriter, r *http.Request) {
	nodeID, body, err := h.auth.Verify(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	var req mtypes.ControlV2ReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid report body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.NodeID != nodeID {
		http.Error(w, "node id mismatch", http.StatusBadRequest)
		return
	}
	if err := h.state.Report(r.Context(), req); err != nil {
		http.Error(w, "report: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSnapshot authenticates the request, returns the per-request
// peer-safe view from ControlState.SnapshotFor, and short-circuits with
// 304 when the client supplied a matching If-None-Match ETag.
//
// The ETag is `"rev-<n>"` so it changes monotonically with revision;
// clients that have already observed the latest snapshot MUST NOT
// re-fetch (no body).
func (h *ControlHTTPHandler) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	nodeID, _, err := h.auth.Verify(r)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	snap := h.state.SnapshotFor(nodeID)
	etag := snap.ETag()
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

// handleEvents authenticates the request and delegates the SSE stream to
// ControlEventHub.ServeSSE. The handler sets the text/event-stream
// headers and writes a 200 status so the hub's initial framing
// (: comment + retry:) is the first bytes the client sees.
//
// Last-Event-ID is forwarded verbatim to the hub; the hub's
// replayFromLocked decides whether the buffer can replay or whether the
// client must re-fetch a full snapshot (ResyncRequired signal). The
// caller drains the request context: cancellation terminates the
// renderer goroutine.
func (h *ControlHTTPHandler) handleEvents(w http.ResponseWriter, r *http.Request) {
	if _, _, err := h.auth.Verify(r); err != nil {
		writeAuthError(w, err)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	last := r.Header.Get("Last-Event-ID")
	writer := sseResponseWriter{w: w, f: flusher}
	renderer, err := h.hub.ServeSSE(r.Context(), writer, last, SSEOptions{})
	if err != nil {
		// Initial framing already on the wire; we cannot recover the
		// status code. Just return so the connection closes.
		return
	}
	defer renderer.Close()
	select {
	case <-r.Context().Done():
	case <-renderer.Subscriber().Done():
	}
}

// handleBootstrap authenticates the request and returns the published
// ListenPortPriority as a typed ControlV2Parameters payload. The endpoint
// exists so a freshly-provisioned Edge can fetch its bind policy BEFORE it
// has ever contacted the Super (or after its active peer record has been
// swept). Authentication resolves via ControlKeyFor, which prefers the
// active peer map and falls back to the pre-authorized registry (Task 2):
// bootstrap MUST NOT require an active peer record and MUST NOT create one.
//
// The response body is EXACTLY mtypes.ControlV2Parameters — no PSKey,
// Peers, candidates, observed hints, or management state. An empty
// ListenPortPriority is a bootstrap error (503): the endpoint exists to
// deliver the policy, and a Super with no policy is misconfigured for
// bootstrap purposes. Empty policy remains valid elsewhere (snapshot,
// SSE) because other endpoints already serve parameters alongside other
// state.
func (h *ControlHTTPHandler) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	if _, _, err := h.auth.Verify(r); err != nil {
		writeAuthError(w, err)
		return
	}
	params := h.state.ParametersForBootstrap()
	if len(params.ListenPortPriority) == 0 {
		// Bootstrap is policy-only; a Super with no policy is not ready
		// to onboard Edges. The body intentionally avoids leaking the
		// configuration state so an attacker cannot infer the Super's
		// YAML content from the error.
		http.Error(w, "bootstrap policy not configured", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, params)
}

// writeAuthError translates a *ControlAuthError into the uniform HTTP
// response the production handler emits. The body never reveals which
// sub-check failed and never contains key material.
func writeAuthError(w http.ResponseWriter, err error) {
	status := ControlAuthHTTPStatus(err)
	// Uniform body; do not include err.Error() (always "control auth
	// failed" but using the constant here documents intent).
	http.Error(w, "control auth failed", status)
}

// writeJSON serialises v as JSON. Errors here are 500.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encode: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

// sseResponseWriter adapts http.ResponseWriter to the (io.Writer +
// Flush()) interface the hub's SSE renderer requires.
type sseResponseWriter struct {
	w io.Writer
	f http.Flusher
}

func (s sseResponseWriter) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s sseResponseWriter) Flush()                      { s.f.Flush() }

// Compile-time guard against accidental signature drift.
var _ http.Handler = (*ControlHTTPHandler)(nil)
var _ = errors.New
var _ = context.Background
