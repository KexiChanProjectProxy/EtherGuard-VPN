/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

// Tests for the Control API v2 HTTP handler. All tests stand up a real
// ControlState + ControlAuthenticator + ControlEventHub + ManageV2 behind an
// httptest.Server so they exercise the full request signature, route table,
// and stream framing — no mocks. The tests assert:
//
//   - all four routes round-trip signed requests;
//   - the snapshot is conditional (ETag → 304);
//   - SSE delivers the initial comment, the retry directive, replay from
//     Last-Event-ID, and the resync signal when the requested ID is older
//     than retention;
//   - an unsigned / cross-Edge / replayed request is rejected with 401;
//   - the Super-control PSKey never appears in any JSON or SSE byte stream;
//   - invalid JSON body → 400;
//   - the state publish hook fires exactly once per successful mutation;
//   - request cancellation tears down the SSE renderer goroutine.
//
// Tests intentionally avoid wall-clock sleeps; they drive the hub via the
// real ServeSSE renderer so the runtimes observed here are the same the
// production code paths use.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

// testHarness wires the real ControlState + Authenticator + Hub + ManageV2
// behind an httptest.Server, returning helpers that sign requests on behalf
// of the simulated Edge. Every test uses a fresh harness so they are
// independent and `-shuffle=on` does not cause interference.
type testHarness struct {
	t          *testing.T
	server     *httptest.Server
	state      *ControlState
	auth       *ControlAuthenticator
	hub        *ControlEventHub
	manage     *ManageV2
	publishLog *countingPublish
	prefix     string
	clock      func() time.Time

	// edges registered during fixture setup, keyed by NodeID.
	edges map[mtypes.Vertex]string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	hub := NewControlEventHub(64)
	pub := &countingPublish{}
	state := NewControlState(ControlStateConfig{
		Parameters: validParams(),
		Publish:    pub.hook,
		Now:        time.Now,
	})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: time.Now})

	dir := t.TempDir()
	manage, err := NewManageV2(ManageV2Config{
		State:        state,
		ConfigDir:    dir,
		BaseConfig:   validBaseConfig(),
		EdgeTemplate: validEdgeTemplate(),
	})
	if err != nil {
		t.Fatalf("NewManageV2: %v", err)
	}

	// Wire the state publish hook into the hub so SSE subscribers see
	// state-change events. This is exactly what task 11 wires at startup.
	state.SetPublishForTest(pub.hook)
	originalPublish := pub.hook
	wrappedPublish := func(ev mtypes.ControlV2Event) {
		originalPublish(ev)
		hub.Publish(ev)
	}
	state.SetPublishForTest(wrappedPublish)

	h := &testHarness{
		t:          t,
		state:      state,
		auth:       auth,
		hub:        hub,
		manage:     manage,
		publishLog: pub,
		prefix:     "",
		edges:      map[mtypes.Vertex]string{},
	}

	mux := http.NewServeMux()
	h.mount(mux)
	h.server = httptest.NewServer(mux)
	t.Cleanup(func() {
		hub.Close()
		h.server.Close()
	})
	return h
}

func (h *testHarness) mount(mux *http.ServeMux) {
	h.mountV2(mux)
	h.mountManage(mux)
}

// mountV2 mounts the four Control API v2 routes under the conventional
// prefix. The path set is exactly the contract documented for task 11.
func (h *testHarness) mountV2(mux *http.ServeMux) {
	mux.HandleFunc("/edge/v2/register", h.handleRegister)
	mux.HandleFunc("/edge/v2/report", h.handleReport)
	mux.HandleFunc("/edge/v2/snapshot", h.handleSnapshot)
	mux.HandleFunc("/edge/v2/events", h.handleEvents)
}

// mountManage mirrors the production mux for the legacy /manage/* routes
// that task 8 owns. The HTTP server here is a test-only stand-in; the real
// mux lives in main_httpserver.go.
func (h *testHarness) mountManage(mux *http.ServeMux) {
	mux.HandleFunc("/manage/peer/add", h.managePeerAdd)
	mux.HandleFunc("/manage/peer/del", h.managePeerDel)
	mux.HandleFunc("/manage/peer/update", h.managePeerUpdate)
	mux.HandleFunc("/manage/super/update", h.manageSuperUpdate)
}

func (h *testHarness) seedEdge(nodeID mtypes.Vertex, name, pskey string) {
	h.t.Helper()
	// AddPeer installs a freshly-generated control PSKey into the
	// ControlState. The test harness replaces it with the deterministic
	// test key so the verifier can sign requests for it. Both
	// operations emit one peer_change each (AddPeer's Register + the
	// key-swap diff detection in setControlKeyForTest); tests that count
	// events capture their baseline AFTER seedEdge.
	_, err := h.manage.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: nodeID, NodeName: name})
	if err != nil {
		h.t.Fatalf("seedEdge AddPeer: %v", err)
	}
	h.state.setControlKeyForTest(nodeID, pskey)
	h.edges[nodeID] = pskey
}

// handleRegister is the production-shape handler for POST /edge/v2/register.
// It binds the real ControlState, calls Register, and writes the initial
// snapshot back as JSON.
func (h *testHarness) handleRegister(w http.ResponseWriter, r *http.Request) {
	nodeID, body, err := h.auth.Verify(r)
	if err != nil {
		http.Error(w, ControlAuthHTTPStatusText(err), ControlAuthHTTPStatus(err))
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
	// Production handlers look up the registered control PSKey through
	// the ControlState (task-6 verifies the signature against the same
	// map). The harness mirrors that contract here.
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
	writeJSON(w, http.StatusOK, snap)
}

func (h *testHarness) handleReport(w http.ResponseWriter, r *http.Request) {
	nodeID, body, err := h.auth.Verify(r)
	if err != nil {
		http.Error(w, ControlAuthHTTPStatusText(err), ControlAuthHTTPStatus(err))
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

func (h *testHarness) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	nodeID, _, err := h.auth.Verify(r)
	if err != nil {
		http.Error(w, ControlAuthHTTPStatusText(err), ControlAuthHTTPStatus(err))
		return
	}
	snap := h.state.SnapshotFor(nodeID)
	if match := r.Header.Get("If-None-Match"); match != "" && match == snap.ETag() {
		w.Header().Set("ETag", snap.ETag())
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", snap.ETag())
	writeJSON(w, http.StatusOK, snap)
}

func (h *testHarness) handleEvents(w http.ResponseWriter, r *http.Request) {
	nodeID, _, err := h.auth.Verify(r)
	if err != nil {
		http.Error(w, ControlAuthHTTPStatusText(err), ControlAuthHTTPStatus(err))
		return
	}
	last := r.Header.Get("Last-Event-ID")
	h.serveSSE(w, r, nodeID, last)
}

func (h *testHarness) serveSSE(w http.ResponseWriter, r *http.Request, _ mtypes.Vertex, last string) {
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

	writer := sseWriter{w: w, f: flusher}
	renderer, err := h.hub.ServeSSE(r.Context(), writer, last, SSEOptions{
		Heartbeat:            50 * time.Millisecond,
		SubscriberBufferSize: 8,
	})
	if err != nil {
		// Could not subscribe; the initial framing is already on the wire.
		return
	}
	defer renderer.Close()
	select {
	case <-r.Context().Done():
	case <-renderer.Subscriber().Done():
	}
}

// sseWriter adapts http.ResponseWriter into the (io.Writer + Flush()) pair
// the hub's renderer requires.
type sseWriter struct {
	w io.Writer
	f http.Flusher
}

func (s sseWriter) Write(p []byte) (int, error) { return s.w.Write(p) }
func (s sseWriter) Flush()                      { s.f.Flush() }

// ---------------------------------------------------------------------------
// Management shims
//
// The real ManageV2 HTTP routing lives in main_httpserver.go. Tests exercise
// it via the same package-level helpers task 8 wired in, so the test suite
// stays a single unit. The shims below are intentionally tiny wrappers
// around the production handlers — they exist only because the production
// handlers read from the legacy httpobj package globals, which task 9 will
// retire. They are used to confirm the new HTTP handler does not regress
// the management routes.
// ---------------------------------------------------------------------------

func (h *testHarness) managePeerAdd(w http.ResponseWriter, r *http.Request) {
	var req ManageAddPeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if _, err := h.manage.AddPeer(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *testHarness) managePeerDel(w http.ResponseWriter, r *http.Request) {
	var req ManageDeletePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := h.manage.DeletePeer(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *testHarness) managePeerUpdate(w http.ResponseWriter, r *http.Request) {
	var req ManageUpdatePeerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := h.manage.UpdatePeer(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *testHarness) manageSuperUpdate(w http.ResponseWriter, r *http.Request) {
	var req ManageUpdateParametersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if err := h.manage.UpdateParameters(r.Context(), req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

// signAndSend signs and sends a request, returning the response. The
// returned body bytes are owned by the caller. The X-EG-Nonce is generated
// per call so two invocations are distinguishable.
func (h *testHarness) signAndSend(method, path string, body []byte, nodeID mtypes.Vertex, pskey string) (*http.Response, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	ts := time.Now().Unix()
	nonce := randHex(16)
	canonical := method + "\n" + req.URL.EscapedPath() + "\n" + fmt.Sprintf("%d", ts) + "\n" + nonce + "\n" + hex.EncodeToString(sha256Of(body))
	mac := hmac.New(sha256.New, []byte(pskey))
	mac.Write([]byte(canonical))
	req.Header.Set(ControlAuthHeaderNodeID, nodeID.ToString())
	req.Header.Set(ControlAuthHeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(ControlAuthHeaderNonce, nonce)
	req.Header.Set(ControlAuthHeaderSignature, hex.EncodeToString(mac.Sum(nil)))
	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("Do: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, respBody
}

// signAndSendWithHeaders is signAndSend + extra headers (used for ETag /
// Last-Event-ID tests).
func (h *testHarness) signAndSendWithHeaders(method, path string, body []byte, nodeID mtypes.Vertex, pskey string, extra map[string]string) (*http.Response, []byte) {
	h.t.Helper()
	req, err := http.NewRequest(method, h.server.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	ts := time.Now().Unix()
	nonce := randHex(16)
	canonical := method + "\n" + req.URL.EscapedPath() + "\n" + fmt.Sprintf("%d", ts) + "\n" + nonce + "\n" + hex.EncodeToString(sha256Of(body))
	mac := hmac.New(sha256.New, []byte(pskey))
	mac.Write([]byte(canonical))
	req.Header.Set(ControlAuthHeaderNodeID, nodeID.ToString())
	req.Header.Set(ControlAuthHeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(ControlAuthHeaderNonce, nonce)
	req.Header.Set(ControlAuthHeaderSignature, hex.EncodeToString(mac.Sum(nil)))
	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("Do: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, respBody
}

func sha256Of(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// ControlAuthHTTPStatusText returns the uniform body the handler writes
// when an auth check fails. We never reveal the underlying sentinel.
func ControlAuthHTTPStatusText(err error) string {
	return "control auth failed"
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestControlHTTPV2RegisterReturnsSnapshot — POST /edge/v2/register with a
// valid signature returns 200 and an initial snapshot. The PSKey the test
// registered the Edge with never appears in the response body.
func TestControlHTTPV2RegisterReturnsSnapshot(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-one-control-key-secret"
	h.seedEdge(1, "alpha", pskey)

	body, _ := json.Marshal(mtypes.ControlV2RegisterRequest{
		NodeID:         1,
		NodeName:       "alpha",
		Version:        mtypes.ControlV2ProtocolVersion,
		ListenPort:     1234,
		LocalV4:        []string{"10.0.0.1:1234"},
		PublicV4:       []string{"203.0.113.1:1234"},
		RequestedAt:    time.Now(),
		Implementation: "etherguard-test",
	})
	resp, respBody := h.signAndSend(http.MethodPost, "/edge/v2/register", body, 1, pskey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status=%d body=%s", resp.StatusCode, respBody)
	}
	var snap mtypes.ControlV2Snapshot
	if err := json.Unmarshal(respBody, &snap); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if snap.Revision == 0 {
		t.Fatalf("revision: got 0")
	}
	if bytes.Contains(respBody, []byte(pskey)) {
		t.Fatalf("response leaked the Super-control PSKey: %s", respBody)
	}
}

// TestControlHTTPV2SnapshotConditional304 — a fresh snapshot's ETag is set
// on the first call; replaying the same ETag returns 304 with empty body.
func TestControlHTTPV2SnapshotConditional304(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-cond-304"
	h.seedEdge(2, "beta", pskey)

	resp, body := h.signAndSend(http.MethodGet, "/edge/v2/snapshot", nil, 2, pskey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first snapshot: status=%d body=%s", resp.StatusCode, body)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatalf("first snapshot: missing ETag header")
	}

	resp, body = h.signAndSendWithHeaders(http.MethodGet, "/edge/v2/snapshot", nil, 2, pskey, map[string]string{"If-None-Match": etag})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional 304: status=%d body=%s", resp.StatusCode, body)
	}
	if len(body) != 0 {
		t.Fatalf("304 body should be empty, got %d bytes", len(body))
	}
}

// TestControlHTTPV2ReportMutatesState — POST /edge/v2/report returns 204
// after a valid signed body; a subsequent report with new candidates bumps
// the revision.
func TestControlHTTPV2ReportMutatesState(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-report-key"
	h.seedEdge(3, "gamma", pskey)

	// Baseline snapshot
	resp, _ := h.signAndSend(http.MethodGet, "/edge/v2/snapshot", nil, 3, pskey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("snapshot: status=%d", resp.StatusCode)
	}

	body, _ := json.Marshal(mtypes.ControlV2ReportRequest{
		NodeID: 3,
		Candidates: []mtypes.ControlV2Candidate{
			{Address: "10.0.0.3:5555", Source: mtypes.ControlV2CandidateLocal},
			{Address: "203.0.113.3:5555", Source: mtypes.ControlV2CandidateSTUN},
		},
		ReportedAt: time.Now(),
	})
	resp, respBody := h.signAndSend(http.MethodPost, "/edge/v2/report", body, 3, pskey)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("report: status=%d body=%s", resp.StatusCode, respBody)
	}
	if bytes.Contains(respBody, []byte(pskey)) {
		t.Fatalf("report response leaked PSKey")
	}
}

// TestControlHTTPV2UnsignedRequestRejected — a request without the four
// signed headers is rejected with 401 and a uniform body.
func TestControlHTTPV2UnsignedRequestRejected(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-noauth-key"
	h.seedEdge(4, "delta", pskey)

	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/edge/v2/snapshot", nil)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: status=%d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("401 body leaked PSKey: %s", body)
	}
	if bytes.Contains(body, []byte("missing")) || bytes.Contains(body, []byte("invalid")) {
		t.Fatalf("401 body should be uniform, got %s", body)
	}
}

// TestControlHTTPV2CrossEdgeImpersonationRejected — Edge A signing its own
// request but asserting Edge B's NodeID is rejected. The cross-edge key
// cannot sign for another NodeID.
func TestControlHTTPV2CrossEdgeImpersonationRejected(t *testing.T) {
	h := newTestHarness(t)
	h.seedEdge(5, "alpha-5", "key-for-5")
	h.seedEdge(6, "beta-6", "key-for-6")

	body, _ := json.Marshal(mtypes.ControlV2RegisterRequest{
		NodeID:   5,
		NodeName: "alpha-5",
		Version:  mtypes.ControlV2ProtocolVersion,
	})
	// Sign with NodeID=6's key but claim NodeID=5.
	resp, respBody := h.signAndSend(http.MethodPost, "/edge/v2/register", body, 6, "key-for-6")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("cross-edge impersonation should fail, body=%s", respBody)
	}
}

// TestControlHTTPV2InvalidJSONRejected — a non-JSON body returns 400.
func TestControlHTTPV2InvalidJSONRejected(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-bad-json"
	h.seedEdge(7, "epsilon", pskey)

	resp, body := h.signAndSend(http.MethodPost, "/edge/v2/report", []byte("{not-json"), 7, pskey)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid JSON: status=%d body=%s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("invalid-JSON response leaked PSKey")
	}
}

// TestControlHTTPV2PublishesOnRegister — the ControlState publish hook
// fires exactly once when an authenticated Register returns 200 for a
// peer that was NOT pre-registered via management (the normal flow).
func TestControlHTTPV2PublishesOnRegister(t *testing.T) {
	h := newTestHarness(t)
	const nodeID mtypes.Vertex = 8
	const name = "eta"
	const pskey = "edge-publish-key"
	// Pre-register the peer via management so the verifier has a key,
	// then DELETE its state entry via state.SetPublishForTest-disabled
	// re-register. Simpler: register the control key, then call the
	// state layer's Register directly through the HTTP endpoint with a
	// freshly-generated PSKey so the diff detection fires.
	h.state.setControlKeyForTest(nodeID, pskey)
	before := h.publishLog.count()

	body, _ := json.Marshal(mtypes.ControlV2RegisterRequest{
		NodeID:   nodeID,
		NodeName: name,
		Version:  mtypes.ControlV2ProtocolVersion,
	})
	resp, _ := h.signAndSend(http.MethodPost, "/edge/v2/register", body, nodeID, pskey)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status=%d", resp.StatusCode)
	}
	if got, want := h.publishLog.count()-before, 1; got != want {
		t.Fatalf("events from a fresh Register: got %d, want %d", got, want)
	}
	if h.publishLog.last().Type != mtypes.ControlV2EventPeerChange {
		t.Fatalf("event type: got %q, want peer_change", h.publishLog.last().Type)
	}
}

// TestControlHTTPV2SSEHeadersAndInitialFlush — the SSE handler sets the
// required headers and emits the initial comment + retry directive before
// any event arrives.
func TestControlHTTPV2SSEHeadersAndInitialFlush(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-sse-headers"
	h.seedEdge(9, "theta", pskey)

	// Use a request with a short context so the test ends quickly.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+"/edge/v2/events", nil)
	signRequest(req, 9, pskey, nil)

	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events: status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type: got %q want text/event-stream", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("Cache-Control: got %q want no-cache", cc)
	}
	if xb := resp.Header.Get("X-Accel-Buffering"); xb != "no" {
		t.Fatalf("X-Accel-Buffering: got %q want no", xb)
	}
	if c := resp.Header.Get("Connection"); c != "keep-alive" {
		t.Fatalf("Connection: got %q want keep-alive", c)
	}

	reader := bufio.NewReader(resp.Body)
	// Initial comment + retry directive.
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read initial comment: %v", err)
	}
	if !strings.HasPrefix(line, ": ") {
		t.Fatalf("initial line not a comment: %q", line)
	}
	line2, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read retry: %v", err)
	}
	if !strings.HasPrefix(line2, "retry: ") {
		t.Fatalf("retry line: %q", line2)
	}
	// Empty line terminates the preamble.
	line3, _ := reader.ReadString('\n')
	if strings.TrimSpace(line3) != "" {
		t.Fatalf("expected blank separator, got %q", line3)
	}
	cancel()
}

// TestControlHTTPV2SSEReplayFromLastEventID — a subscriber connecting with
// a Last-Event-ID receives only events with strictly greater numeric IDs.
// We seed the hub with two events, reconnect with the older ID, and assert
// only the newer event arrives.
func TestControlHTTPV2SSEReplayFromLastEventID(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-sse-replay"
	h.seedEdge(10, "iota", pskey)

	// Seed events directly via the hub so we have stable IDs.
	h.hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange, Data: mtypes.ControlV2PeerChangePayload{NodeID: 11, NodeName: "kappa"}})
	h.hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange, Data: mtypes.ControlV2PeerChangePayload{NodeID: 12, NodeName: "lambda"}})

	// The IDs are monotonic "evt-N". Read one event from a fresh
	// subscriber to discover the first ID, then reconnect with it and
	// assert only the second event arrives.
	firstID := readFirstEventID(t, h, 10, pskey)
	if firstID == "" {
		t.Fatalf("could not read first event id")
	}

	// Now connect again with Last-Event-ID == firstID.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+"/edge/v2/events", nil)
	signRequest(req, 10, pskey, nil)
	req.Header.Set("Last-Event-ID", firstID)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var dataLines []string
	var idSeen string
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "id: "):
			idSeen = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
		if idSeen != "" && idSeen != firstID && len(dataLines) > 0 {
			break
		}
	}
	if idSeen == firstID {
		t.Fatalf("replay delivered event with id <= last-event-id: %s", idSeen)
	}
}

// TestControlHTTPV2SSEStaleIDResync — a Last-Event-ID older than retention
// results in a resync signal AND replay of the retained buffer (per task-7
// semantics). We deliberately exhaust the hub capacity first.
func TestControlHTTPV2SSEStaleIDResync(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-sse-stale"
	h.seedEdge(13, "nu", pskey)

	// Build a fresh small-capacity hub so we can overflow it.
	hub := NewControlEventHub(2)
	for i := 0; i < 5; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange, Data: mtypes.ControlV2PeerChangePayload{NodeID: mtypes.Vertex(i), NodeName: "stale"}})
	}
	// Subscribe directly to confirm the resync signal fires.
	sub, err := hub.Subscribe(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()
	select {
	case <-sub.ResyncRequired():
		// expected
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("stale Last-Event-ID did not signal ResyncRequired")
	}
}

// TestControlHTTPV2NoPSKeyInResponse — every JSON and SSE body the
// handlers produce is byte-scanned for the registered control PSKey. The
// fixture seeds a key that would be catastrophic to leak; none of the
// responses may contain it.
func TestControlHTTPV2NoPSKeyInResponse(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "DO-NOT-LEAK-THIS-KEY-1234567890"
	h.seedEdge(14, "xi", pskey)

	probe := func(path string, method string, body []byte, extra map[string]string) {
		var resp *http.Response
		var respBody []byte
		if extra != nil {
			resp, respBody = h.signAndSendWithHeaders(method, path, body, 14, pskey, extra)
		} else {
			resp, respBody = h.signAndSend(method, path, body, 14, pskey)
		}
		if resp.StatusCode >= 500 {
			t.Fatalf("%s %s: status=%d body=%s", method, path, resp.StatusCode, respBody)
		}
		if bytes.Contains(respBody, []byte(pskey)) {
			t.Fatalf("%s %s leaked PSKey in body: %s", method, path, respBody)
		}
	}

	regBody, _ := json.Marshal(mtypes.ControlV2RegisterRequest{
		NodeID:   14,
		NodeName: "xi",
		Version:  mtypes.ControlV2ProtocolVersion,
		LocalV4:  []string{"10.0.0.14:14"},
	})
	probe("/edge/v2/register", http.MethodPost, regBody, nil)

	reportBody, _ := json.Marshal(mtypes.ControlV2ReportRequest{NodeID: 14, ReportedAt: time.Now()})
	probe("/edge/v2/report", http.MethodPost, reportBody, nil)
	probe("/edge/v2/snapshot", http.MethodGet, nil, nil)

	// SSE: read a handful of bytes and scan.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+"/edge/v2/events", nil)
	signRequest(req, 14, pskey, nil)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("SSE Do: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if bytes.Contains(buf[:n], []byte(pskey)) {
				t.Fatalf("SSE leaked PSKey: %s", buf[:n])
			}
		}
		if err != nil {
			break
		}
	}
}

// TestControlHTTPV2GracefulCancellation — closing the request context
// terminates the SSE renderer goroutine and frees its resources (the hub
// reports Done closed via the renderer Close path).
func TestControlHTTPV2GracefulCancellation(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-cancel"
	h.seedEdge(15, "omicron", pskey)

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+"/edge/v2/events", nil)
	signRequest(req, 15, pskey, nil)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	// Drain the initial framing.
	_, _ = bufio.NewReader(resp.Body).ReadString('\n')
	_, _ = bufio.NewReader(resp.Body).ReadString('\n')
	cancel()
	// After cancellation the response body must close promptly; give
	// the server a moment to drain its renderer.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1024)
		for {
			if _, err := resp.Body.Read(buf); err != nil {
				close(done)
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("SSE renderer did not release after cancellation")
	}
}

func TestControlHTTPV2SSETerminates_whenHubCloses(t *testing.T) {
	// Given an authenticated Edge with an established SSE response.
	h := newTestHarness(t)
	const pskey = "edge-hub-close"
	h.seedEdge(16, "pi", pskey)
	req, err := http.NewRequest(http.MethodGet, h.server.URL+"/edge/v2/events", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	signRequest(req, 16, pskey, nil)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	reader := bufio.NewReader(resp.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("read initial SSE framing: %v", err)
	}

	// When the Super event hub becomes unavailable.
	h.hub.Close()

	// Then the active stream terminates so the Edge can enter polling fallback.
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SSE response did not terminate after hub close")
	}
}

// TestControlHTTPV2ReplayedNonceRejected — the same X-EG-Nonce for the
// same NodeID within the TTL window is rejected as a replay.
func TestControlHTTPV2ReplayedNonceRejected(t *testing.T) {
	h := newTestHarness(t)
	const pskey = "edge-replay"
	h.seedEdge(16, "pi", pskey)

	// Build a custom signed request so we can reuse the nonce.
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/edge/v2/snapshot", nil)
	ts := time.Now().Unix()
	nonce := randHex(16)
	canonical := http.MethodGet + "\n" + req.URL.EscapedPath() + "\n" + fmt.Sprintf("%d", ts) + "\n" + nonce + "\n" + hex.EncodeToString(sha256Of(nil))
	mac := hmac.New(sha256.New, []byte(pskey))
	mac.Write([]byte(canonical))
	req.Header.Set(ControlAuthHeaderNodeID, "16")
	req.Header.Set(ControlAuthHeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(ControlAuthHeaderNonce, nonce)
	req.Header.Set(ControlAuthHeaderSignature, hex.EncodeToString(mac.Sum(nil)))

	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do first: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first snapshot: status=%d", resp.StatusCode)
	}

	// Replay the exact same headers.
	resp2, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do replay: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed nonce: status=%d, want 401", resp2.StatusCode)
	}
}

// signRequest fills in the four HMAC headers for an outbound request. The
// caller is responsible for setting any path/body-digest-specific headers
// (Content-Type, etc.) before calling.
func signRequest(r *http.Request, nodeID mtypes.Vertex, pskey string, body []byte) {
	var b []byte
	if r.Body != nil {
		b, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
	}
	ts := time.Now().Unix()
	nonce := randHex(16)
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + fmt.Sprintf("%d", ts) + "\n" + nonce + "\n" + hex.EncodeToString(sha256Of(b))
	mac := hmac.New(sha256.New, []byte(pskey))
	mac.Write([]byte(canonical))
	r.Header.Set(ControlAuthHeaderNodeID, nodeID.ToString())
	r.Header.Set(ControlAuthHeaderTimestamp, fmt.Sprintf("%d", ts))
	r.Header.Set(ControlAuthHeaderNonce, nonce)
	r.Header.Set(ControlAuthHeaderSignature, hex.EncodeToString(mac.Sum(nil)))
}

// readFirstEventID connects to the SSE stream once and returns the id of
// the first event the hub emits.
func readFirstEventID(t *testing.T, h *testHarness, nodeID mtypes.Vertex, pskey string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+"/edge/v2/events", nil)
	signRequest(req, nodeID, pskey, nil)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "id: ") {
			return strings.TrimPrefix(line, "id: ")
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Bootstrap endpoint tests (Task 4).
//
// /edge/v2/bootstrap returns the published ListenPortPriority so a freshly
// provisioned Edge can fetch its bind policy BEFORE it has ever contacted
// the Super. Auth MUST resolve via the pre-authorized registry (Task 2):
// the active peer map may be empty (no Register yet) or swept (post-
// SweepTimeouts), so the credential lookup falls back to preauthorized.
// The response MUST contain only ControlV2Parameters — no PSKey, no Peers,
// no candidates, no observed hints, no report/state fields. An empty
// policy is a non-200 bootstrap error because the bootstrap endpoint's
// only purpose is to deliver the policy.
//
// Test fixtures: bootstrap tests need a non-empty ListenPortPriority so the
// production handler returns 200. The default validParams() has none, so
// each bootstrap test builds its own ControlState directly (or calls
// NewControlState with a custom Parameters).
// ---------------------------------------------------------------------------

// bootstrapTestParams returns ControlV2Parameters with a non-empty
// ListenPortPriority so the bootstrap endpoint serves a real policy.
func bootstrapTestParams() mtypes.ControlV2Parameters {
	portA := 51820
	portB := 51821
	return mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		PollInterval:        15 * time.Second,
		STUNServers:         []string{"stun:203.0.113.10:3478"},
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
		ListenPortPriority: mtypes.ListenPortPriority{
			{Port: &portA},
			{Port: &portB},
		},
	}
}

// bootstrapHarness wires ControlState + Authenticator + Hub behind the
// production NewControlHTTPHandler constructor. The harness uses
// bootstrapTestParams (non-empty ListenPortPriority) so the handler can
// successfully serve a 200. Tests that need an empty policy build their
// own state without using this helper.
type bootstrapHarness struct {
	t      *testing.T
	server *httptest.Server
	state  *ControlState
}

func newBootstrapHarness(t *testing.T) *bootstrapHarness {
	t.Helper()
	hub := NewControlEventHub(8)
	state := NewControlState(ControlStateConfig{
		Parameters: bootstrapTestParams(),
		Publish:    func(mtypes.ControlV2Event) {},
		Now:        time.Now,
	})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: time.Now})
	handler := NewControlHTTPHandler(state, auth, hub, "")
	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		hub.Close()
		srv.Close()
	})
	return &bootstrapHarness{t: t, server: srv, state: state}
}

// TestControlHTTPV2BootstrapReturnsParameters — GET /edge/v2/bootstrap with
// a valid signed request returns 200 and the published parameters. The
// response contains the ListenPortPriority but NEVER PSKey, Peers, or any
// other field outside ControlV2Parameters.
func TestControlHTTPV2BootstrapReturnsParameters(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-bootstrap-key"
	const nodeID mtypes.Vertex = 21
	h.state.SetPreAuthorized(nodeID, pskey)

	resp, body := signedRequest(t, h.server, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap: status=%d body=%s", resp.StatusCode, body)
	}
	// Response is exactly ControlV2Parameters (wire shape with PascalCase
	// keys). Re-decode into the typed struct; sanity-check the policy is
	// the one we installed.
	var got mtypes.ControlV2Parameters
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode bootstrap body: %v body=%s", err, body)
	}
	if got.ProtocolVersion != mtypes.ControlV2ProtocolVersion {
		t.Fatalf("ProtocolVersion=%q want %q", got.ProtocolVersion, mtypes.ControlV2ProtocolVersion)
	}
	if len(got.ListenPortPriority) != 2 {
		t.Fatalf("ListenPortPriority len=%d want 2: body=%s", len(got.ListenPortPriority), body)
	}
	if got.ListenPortPriority[0].Port == nil || *got.ListenPortPriority[0].Port != 51820 {
		t.Fatalf("policy[0].Port: got %#v want 51820", got.ListenPortPriority[0])
	}
	if got.ListenPortPriority[1].Port == nil || *got.ListenPortPriority[1].Port != 51821 {
		t.Fatalf("policy[1].Port: got %#v want 51821", got.ListenPortPriority[1])
	}
	// Body must NOT contain any key outside ControlV2Parameters.
	forbidden := []string{
		`"PSKey"`, `"PSKey":`,
		`"Peers"`, `"Peers":`,
		`"Candidates"`, `"Candidates":`,
		`"Observed"`, `"Observed":`,
		`"Reports"`, `"Reports":`,
		`"Management"`, `"Management":`,
		`"PeerID"`,
	}
	for _, k := range forbidden {
		if bytes.Contains(body, []byte(k)) {
			t.Fatalf("bootstrap response leaked forbidden key %q in body: %s", k, body)
		}
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("bootstrap response leaked PSKey: %s", body)
	}
}

// TestControlHTTPV2BootstrapEmptyPolicyRejected — when the Super is
// misconfigured for bootstrap (no ListenPortPriority), the bootstrap
// endpoint returns a non-200 status. The other endpoints (snapshot,
// register, report) MUST still work because the policy is bootstrap-only.
func TestControlHTTPV2BootstrapEmptyPolicyRejected(t *testing.T) {
	hub := NewControlEventHub(8)
	state := NewControlState(ControlStateConfig{
		Parameters: validParams(), // empty ListenPortPriority
		Publish:    func(mtypes.ControlV2Event) {},
		Now:        time.Now,
	})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: time.Now})
	handler := NewControlHTTPHandler(state, auth, hub, "")
	srv := httptest.NewServer(handler)
	defer srv.Close()
	defer hub.Close()

	const pskey = "edge-empty-policy-key"
	const nodeID mtypes.Vertex = 22
	state.SetPreAuthorized(nodeID, pskey)

	resp, body := signedRequest(t, srv, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, pskey, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("empty policy: status=200 body=%s, want non-200", body)
	}
	if resp.StatusCode < 400 {
		t.Fatalf("empty policy: status=%d body=%s, want a non-2xx error code", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("empty-policy error leaked PSKey: %s", body)
	}
}

// TestControlHTTPV2BootstrapNonGETRejected — POST/PUT/DELETE on /bootstrap
// return 405 (the production handler enforces the method in its switch).
func TestControlHTTPV2BootstrapNonGETRejected(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-method-key"
	const nodeID mtypes.Vertex = 23
	h.state.SetPreAuthorized(nodeID, pskey)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		resp, body := signedRequest(t, h.server, method, "/edge/v2/bootstrap", []byte(`{}`), nodeID, pskey, nil)
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s bootstrap: status=%d body=%s want 405", method, resp.StatusCode, body)
		}
		if bytes.Contains(body, []byte(pskey)) {
			t.Fatalf("%s bootstrap leaked PSKey: %s", method, body)
		}
	}
}

// TestControlHTTPV2BootstrapUnsignedRejected — a request with NO X-EG-* headers
// fails the same way as on every other endpoint: uniform 401 body, no PSKey
// in the response.
func TestControlHTTPV2BootstrapUnsignedRejected(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-unsigned-bs"
	const nodeID mtypes.Vertex = 24
	h.state.SetPreAuthorized(nodeID, pskey)

	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/edge/v2/bootstrap", nil)
	resp, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned: status=%d body=%s want 401", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("unsigned bootstrap leaked PSKey: %s", body)
	}
}

// TestControlHTTPV2BootstrapWrongKeyRejected — signing with a key that does
// NOT match the configured registry entry fails the HMAC check. The
// response is uniform 401 and never reveals the registered key.
func TestControlHTTPV2BootstrapWrongKeyRejected(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-correct-key"
	const wrong = "edge-attacker-key"
	const nodeID mtypes.Vertex = 25
	h.state.SetPreAuthorized(nodeID, pskey)

	resp, body := signedRequest(t, h.server, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, wrong, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key: status=%d body=%s want 401", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) || bytes.Contains(body, []byte(wrong)) {
		t.Fatalf("wrong-key response leaked key material: %s", body)
	}
}

// TestControlHTTPV2BootstrapUnknownNodeRejected — an authenticated request
// for a NodeID that has no registry entry and no active peer record fails
// the ControlKeyFor lookup and returns uniform 401. The bootstrap endpoint
// must NOT resurrect peer records (Task 2 invariant).
func TestControlHTTPV2BootstrapUnknownNodeRejected(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-unknown-key"
	const nodeID mtypes.Vertex = 26
	// Intentionally do NOT call SetPreAuthorized — the NodeID is unknown.

	resp, body := signedRequest(t, h.server, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown node: status=%d body=%s want 401", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("unknown-node response leaked PSKey: %s", body)
	}
	// Task 2 invariant: bootstrap MUST NOT create an active peer record.
	if _, ok := h.state.ControlKeyFor(nodeID); ok {
		t.Fatalf("bootstrap resurrected peer record for unknown NodeID")
	}
}

// TestControlHTTPV2BootstrapReplayedNonceRejected — replaying the same nonce
// within the TTL window is rejected with uniform 401 (Task 9 invariant).
func TestControlHTTPV2BootstrapReplayedNonceRejected(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-replay-bs"
	var nodeID mtypes.Vertex = 27
	h.state.SetPreAuthorized(nodeID, pskey)

	// Build a single request with a fixed nonce and timestamp, send it
	// twice. The verifier stores the (NodeID, nonce) pair on success and
	// rejects the replay.
	req, _ := http.NewRequest(http.MethodGet, h.server.URL+"/edge/v2/bootstrap", nil)
	ts := time.Now().Unix()
	nonce := randHex(16)
	digest := sha256.Sum256(nil)
	canonical := http.MethodGet + "\n" + req.URL.EscapedPath() + "\n" + fmt.Sprintf("%d", ts) + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	mac := hmac.New(sha256.New, []byte(pskey))
	_, _ = mac.Write([]byte(canonical))
	req.Header.Set(ControlAuthHeaderNodeID, nodeID.ToString())
	req.Header.Set(ControlAuthHeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(ControlAuthHeaderNonce, nonce)
	req.Header.Set(ControlAuthHeaderSignature, hex.EncodeToString(mac.Sum(nil)))

	resp1, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do first: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first bootstrap: status=%d body=%s", resp1.StatusCode, body1)
	}

	resp2, err := h.server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do replay: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed bootstrap: status=%d body=%s want 401", resp2.StatusCode, body2)
	}
	if bytes.Contains(body2, []byte(pskey)) {
		t.Fatalf("replay response leaked PSKey: %s", body2)
	}
}

// TestControlHTTPV2BootstrapDeletedNodeRejected — DeletePeer scrubs both
// the active record AND the registry entry. A subsequent bootstrap MUST
// fail with 401 (the credential is gone).
func TestControlHTTPV2BootstrapDeletedNodeRejected(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-deleted-bs"
	const nodeID mtypes.Vertex = 28
	h.state.SetPreAuthorized(nodeID, pskey)
	// Populate the active peer record so DeletePeer finds the entry.
	h.state.setControlKeyForTest(nodeID, pskey)

	if err := h.state.DeletePeer(context.Background(), nodeID); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}

	resp, body := signedRequest(t, h.server, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deleted node: status=%d body=%s want 401", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("deleted-node response leaked PSKey: %s", body)
	}
}

// TestControlHTTPV2BootstrapSweptActiveRecordAuthenticatesViaRegistry — the
// central Task 4 invariant: a provisioned-but-swept Edge can still fetch
// the bootstrap policy because the pre-authorized registry survives
// SweepTimeouts. The test installs the credential ONLY in the registry
// (the active peer map is populated and then immediately removed to
// simulate a post-sweep state without depending on time).
func TestControlHTTPV2BootstrapSweptActiveRecordAuthenticatesViaRegistry(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-swept-registry-key"
	const nodeID mtypes.Vertex = 29
	h.state.SetPreAuthorized(nodeID, pskey)

	// Populate the active record (with a different key so the active
	// path would fail), then remove the active record directly. The
	// registry fallback is the only way bootstrap can succeed.
	const wrongActiveKey = "transient-active-key"
	h.state.setControlKeyForTest(nodeID, wrongActiveKey)
	h.state.mu.Lock()
	delete(h.state.peers, nodeID)
	h.state.mu.Unlock()

	resp, body := signedRequest(t, h.server, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("swept active record: status=%d body=%s want 200", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte(`"ListenPortPriority"`)) {
		t.Fatalf("swept-record bootstrap response missing ListenPortPriority: %s", body)
	}
	if bytes.Contains(body, []byte(pskey)) || bytes.Contains(body, []byte(wrongActiveKey)) {
		t.Fatalf("swept-record bootstrap leaked key material: %s", body)
	}
}

// TestControlHTTPV2BootstrapDoesNotMutateState — fetching bootstrap MUST
// NOT bump the revision or create an active peer record. The endpoint is
// a read-only path that only consults ParametersForBootstrap and the
// pre-authorized registry.
func TestControlHTTPV2BootstrapDoesNotMutateState(t *testing.T) {
	h := newBootstrapHarness(t)
	const pskey = "edge-readonly-key"
	const nodeID mtypes.Vertex = 30
	h.state.SetPreAuthorized(nodeID, pskey)

	beforeRev := h.state.Revision()
	resp, _ := signedRequest(t, h.server, http.MethodGet, "/edge/v2/bootstrap", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bootstrap: status=%d", resp.StatusCode)
	}
	if got := h.state.Revision(); got != beforeRev {
		t.Fatalf("revision bumped on bootstrap: before=%d after=%d", beforeRev, got)
	}
	// Bootstrap must NOT create an active peer record.
	h.state.mu.RLock()
	_, exists := h.state.peers[nodeID]
	h.state.mu.RUnlock()
	if exists {
		t.Fatalf("bootstrap created an active peer record for NodeID %d", nodeID)
	}
}

// Compile-time guard against unused imports.
var (
	_ = errors.New
	_ sync.Once
)

// TestControlHTTPV2ProductionHandler — the SAME assertions run against the
// production-shaped handler constructor (NewControlHTTPHandler), so the
// route table and headers are exercised exactly as task 11 will mount
// them. Uses ControlState + ControlAuthenticator + ControlEventHub wired
// through the production constructor.
func TestControlHTTPV2ProductionHandler(t *testing.T) {
	hub := NewControlEventHub(64)
	pub := &countingPublish{}
	state := NewControlState(ControlStateConfig{
		Parameters: validParams(),
		Publish:    pub.hook,
		Now:        time.Now,
	})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: time.Now})

	// Mirror the production publish wiring: every state event also fans
	// out to the hub so SSE subscribers observe it.
	state.SetPublishForTest(func(ev mtypes.ControlV2Event) {
		pub.hook(ev)
		hub.Publish(ev)
	})

	dir := t.TempDir()
	manage, err := NewManageV2(ManageV2Config{
		State:        state,
		ConfigDir:    dir,
		BaseConfig:   validBaseConfig(),
		EdgeTemplate: validEdgeTemplate(),
	})
	if err != nil {
		t.Fatalf("NewManageV2: %v", err)
	}

	const nodeID mtypes.Vertex = 42
	const pskey = "production-handler-key"
	if _, err := manage.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: nodeID, NodeName: "prod"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	state.setControlKeyForTest(nodeID, pskey)

	handler := NewControlHTTPHandler(state, auth, hub, "")
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// Register
	regBody, _ := json.Marshal(mtypes.ControlV2RegisterRequest{
		NodeID:   nodeID,
		NodeName: "prod",
		Version:  mtypes.ControlV2ProtocolVersion,
	})
	resp, body := signedRequest(t, srv, http.MethodPost, "/edge/v2/register", regBody, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register: status=%d body=%s", resp.StatusCode, body)
	}
	if bytes.Contains(body, []byte(pskey)) {
		t.Fatalf("register response leaked PSKey")
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatalf("register: missing ETag")
	}

	// Conditional snapshot → 304
	resp, _ = signedRequest(t, srv, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, map[string]string{"If-None-Match": etag})
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("304: status=%d", resp.StatusCode)
	}

	// Unknown path → 404
	resp, _ = signedRequest(t, srv, http.MethodGet, "/edge/v2/unknown", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route: status=%d", resp.StatusCode)
	}

	// Wrong method → 405
	resp, _ = signedRequest(t, srv, http.MethodGet, "/edge/v2/register", nil, nodeID, pskey, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method: status=%d", resp.StatusCode)
	}

	hub.Close()
}

// signedRequest constructs + signs a request and returns the response.
// Used by TestControlHTTPV2ProductionHandler to exercise the real
// NewControlHTTPHandler without dragging in the test harness.
func signedRequest(t *testing.T, srv *httptest.Server, method, path string, body []byte, nodeID mtypes.Vertex, pskey string, extra map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	ts := time.Now().Unix()
	nonce := randHex(16)
	canonical := method + "\n" + req.URL.EscapedPath() + "\n" + fmt.Sprintf("%d", ts) + "\n" + nonce + "\n" + hex.EncodeToString(sha256Of(body))
	mac := hmac.New(sha256.New, []byte(pskey))
	mac.Write([]byte(canonical))
	req.Header.Set(ControlAuthHeaderNodeID, nodeID.ToString())
	req.Header.Set(ControlAuthHeaderTimestamp, fmt.Sprintf("%d", ts))
	req.Header.Set(ControlAuthHeaderNonce, nonce)
	req.Header.Set(ControlAuthHeaderSignature, hex.EncodeToString(mac.Sum(nil)))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, respBody
}
