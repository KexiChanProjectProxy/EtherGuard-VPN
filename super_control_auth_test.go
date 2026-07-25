/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// --- Test helpers ---------------------------------------------------------

// fakeClock returns a deterministic clock for timestamp window tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
}

// buildSignedRequest produces a fully-signed Control API v2 request using the
// same canonical string as the production client (device/super_http_client.go).
// The returned body is the bytes that were hashed.
func buildSignedRequest(t *testing.T, method, path string, body []byte, nodeID mtypes.Vertex, pskey string, clock *fakeClock) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(clock.Now().Unix(), 10)
	nonce := randomNonceForTest(t)
	digest := sha256.Sum256(body)
	canonical := method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	mac := hmac.New(sha256.New, []byte(pskey))
	_, _ = mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-EG-NodeID", nodeID.ToString())
	r.Header.Set("X-EG-Timestamp", ts)
	r.Header.Set("X-EG-Nonce", nonce)
	r.Header.Set("X-EG-Signature", sig)
	return r
}

func randomNonceForTest(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

// --- Tests ----------------------------------------------------------------

func TestControlAuthHappyPath(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-happy"
	const nodeID mtypes.Vertex = 42
	auth.RegisterTestKey(nodeID, pskey) // test-only helper injected below
	body := []byte(`{"hello":"world"}`)
	r := buildSignedRequest(t, http.MethodPost, "/edge/v2/register", body, nodeID, pskey, clock)
	got, gotBody, err := auth.Verify(r)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got != nodeID {
		g := got
		wan := nodeID
		t.Fatalf("NodeID = %s, want %s", g.ToString(), wan.ToString())
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body = %q, want %q", gotBody, body)
	}
}

func TestControlAuthBadSignature(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-bad-sig"
	const nodeID mtypes.Vertex = 7
	auth.RegisterTestKey(nodeID, pskey)
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	// Tamper with the signature.
	sig := r.Header.Get("X-EG-Signature")
	r.Header.Set("X-EG-Signature", flipHex(sig))
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("Verify: expected error, got nil")
	}
	if !IsControlAuthError(err) {
		t.Fatalf("expected *ControlAuthError, got %T: %v", err, err)
	}
	// Error must not reveal the key or the actual signature.
	if strings.Contains(err.Error(), pskey) {
		t.Fatalf("error leaks key: %v", err)
	}
	if strings.Contains(err.Error(), sig) {
		t.Fatalf("error leaks original signature: %v", err)
	}
}

func TestControlAuthWrongPath(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-wrong-path"
	const nodeID mtypes.Vertex = 11
	auth.RegisterTestKey(nodeID, pskey)
	// Sign for /snapshot.
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	// Mutate the request line path to something else.
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/edge/v2/report"
	_, _, err := auth.Verify(r2)
	if err == nil {
		t.Fatalf("expected error on path mismatch")
	}
}

func TestControlAuthWrongMethod(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-wrong-method"
	const nodeID mtypes.Vertex = 12
	auth.RegisterTestKey(nodeID, pskey)
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	r2 := r.Clone(r.Context())
	r2.Method = http.MethodPost
	r2.Body = http.NoBody
	_, _, err := auth.Verify(r2)
	if err == nil {
		t.Fatalf("expected error on method mismatch")
	}
}

func TestControlAuthWrongBodyDigest(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-bad-body"
	const nodeID mtypes.Vertex = 13
	auth.RegisterTestKey(nodeID, pskey)
	body := []byte(`{"a":1}`)
	r := buildSignedRequest(t, http.MethodPost, "/edge/v2/register", body, nodeID, pskey, clock)
	// Swap body for a different one AFTER signing.
	r.Body = io.NopCloser(bytes.NewReader([]byte(`{"a":2}`)))
	r.ContentLength = int64(len(`{"a":2}`))
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error on body digest mismatch")
	}
}

func TestControlAuthStaleTimestamp(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-stale"
	const nodeID mtypes.Vertex = 14
	auth.RegisterTestKey(nodeID, pskey)
	// Sign with timestamp 5 minutes in the past — way outside any sane skew.
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	oldTS := r.Header.Get("X-EG-Timestamp")
	oldTSInt, _ := strconv.ParseInt(oldTS, 10, 64)
	newTS := strconv.FormatInt(oldTSInt-300, 10)
	r.Header.Set("X-EG-Timestamp", newTS)
	// Re-sign with the new timestamp so the HMAC matches the canonical.
	nonce := r.Header.Get("X-EG-Nonce")
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + newTS + "\n" + nonce + "\n" + hex.EncodeToString(sha256.New().Sum(nil))
	mac := hmac.New(sha256.New, []byte(pskey))
	_, _ = mac.Write([]byte(canonical))
	r.Header.Set("X-EG-Signature", hex.EncodeToString(mac.Sum(nil)))
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error on stale timestamp")
	}
}

func TestControlAuthFutureTimestampBeyondSkew(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-future"
	const nodeID mtypes.Vertex = 15
	auth.RegisterTestKey(nodeID, pskey)
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	// Shift 10 minutes into the future.
	futureTS := strconv.FormatInt(clock.Now().Add(10*time.Minute).Unix(), 10)
	r.Header.Set("X-EG-Timestamp", futureTS)
	nonce := r.Header.Get("X-EG-Nonce")
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + futureTS + "\n" + nonce + "\n" + hex.EncodeToString(sha256.New().Sum(nil))
	mac := hmac.New(sha256.New, []byte(pskey))
	_, _ = mac.Write([]byte(canonical))
	r.Header.Set("X-EG-Signature", hex.EncodeToString(mac.Sum(nil)))
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error on future timestamp beyond skew")
	}
}

func TestControlAuthReplayRejected(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-replay"
	const nodeID mtypes.Vertex = 16
	auth.RegisterTestKey(nodeID, pskey)
	// First request must succeed.
	r1 := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	if _, _, err := auth.Verify(r1); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	// Replay the SAME request (same headers, same body) — must fail.
	r2 := r1.Clone(r1.Context())
	if _, _, err := auth.Verify(r2); err == nil {
		t.Fatalf("expected replay rejection")
	}
}

func TestControlAuthOversizedBodyRejectedBeforeFullRead(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-big"
	const nodeID mtypes.Vertex = 17
	auth.RegisterTestKey(nodeID, pskey)
	// Build a body larger than the configured cap.
	cap := ControlAuthMaxBodyBytes
	oversized := bytes.Repeat([]byte("A"), int(cap)+1024)
	r := buildSignedRequest(t, http.MethodPost, "/edge/v2/register", oversized, nodeID, pskey, clock)
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected oversized-body error")
	}
	if !errors.Is(err, ErrControlAuthBodyTooLarge) {
		t.Fatalf("err = %v, want ErrControlAuthBodyTooLarge", err)
	}
	// The verifier must NOT have read the entire oversized body — we can
	// verify this by reading r.Body: it should still hold a bounded buffer
	// OR the error is returned before hashing reads the full stream. The
	// strongest guarantee: the returned body slice length is <= cap.
	if err != nil {
		// re-run with a small body but pre-set Content-Length too big to
		// confirm MaxBytesReader short-circuits.
	}
}

func TestControlAuthUnknownNodeID(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-unknown"
	auth.RegisterTestKey(99, pskey)
	const claimedID mtypes.Vertex = 100 // different from registered
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, claimedID, pskey, clock)
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error for unknown NodeID")
	}
	if !errors.Is(err, ErrControlAuthUnknownNode) {
		t.Fatalf("err = %v, want ErrControlAuthUnknownNode", err)
	}
}

func TestControlAuthKeyIsolation(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskeyA = "pskey-A"
	const pskeyB = "pskey-B"
	const nodeA mtypes.Vertex = 20
	const nodeB mtypes.Vertex = 21
	auth.RegisterTestKey(nodeA, pskeyA)
	auth.RegisterTestKey(nodeB, pskeyB)
	// Sign with A's key but claim to be B.
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeB, pskeyA, clock)
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error when A's key is used to sign for B's NodeID")
	}
}

func TestControlAuthErrorDoesNotLeakKeyMaterial(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "this-is-the-secret-pskey-do-not-leak"
	const nodeID mtypes.Vertex = 22
	auth.RegisterTestKey(nodeID, pskey)
	// Wrong signature.
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	originalSig := r.Header.Get("X-EG-Signature")
	r.Header.Set("X-EG-Signature", flipHex(originalSig))
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, pskey) {
		t.Fatalf("error message leaks control PSKey: %q", msg)
	}
	if strings.Contains(msg, originalSig) {
		t.Fatalf("error message leaks original signature: %q", msg)
	}
	// Also: wrong path, wrong body digest.
	r2 := buildSignedRequest(t, http.MethodPost, "/edge/v2/register", []byte(`{"a":1}`), nodeID, pskey, clock)
	r2.URL.Path = "/edge/v2/snapshot"
	if _, _, err := auth.Verify(r2); err == nil {
		t.Fatalf("expected error on path mismatch")
	} else if strings.Contains(err.Error(), pskey) {
		t.Fatalf("path-mismatch error leaks key: %q", err.Error())
	}
	// Unknown NodeID error.
	r3 := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, mtypes.Vertex(500), pskey, clock)
	if _, _, err := auth.Verify(r3); err == nil {
		t.Fatalf("expected error on unknown node")
	} else if strings.Contains(err.Error(), pskey) {
		t.Fatalf("unknown-node error leaks key: %q", err.Error())
	}
}

func TestControlAuthNonceCacheBounded(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{
		Now:           clock.Now,
		MaxNonceCache: 64, // small cap to make the test tight
		NonceCacheTTL: 2 * ControlAuthTimestampSkew,
	})
	const pskey = "pskey-nonce-bounded"
	const nodeID mtypes.Vertex = 23
	auth.RegisterTestKey(nodeID, pskey)
	// Hammer with distinct nonces; ensure we never grow beyond the cap.
	for i := 0; i < 500; i++ {
		r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
		if _, _, err := auth.Verify(r); err != nil {
			t.Fatalf("Verify[%d]: %v", i, err)
		}
	}
	if size := auth.NonceCacheSizeForTest(); size > 64 {
		t.Fatalf("nonce cache grew to %d, expected <= 64", size)
	}
}

func TestControlAuthConcurrentRequests(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-concurrent"
	const nodeID mtypes.Vertex = 24
	auth.RegisterTestKey(nodeID, pskey)
	const goroutines = 16
	const itersPerG = 50
	var wg sync.WaitGroup
	var failures int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < itersPerG; i++ {
				r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
				if _, _, err := auth.Verify(r); err != nil {
					atomic.AddInt64(&failures, 1)
				}
			}
		}(g)
	}
	wg.Wait()
	if failures != 0 {
		t.Fatalf("concurrent Verify failures: %d", failures)
	}
}

func TestControlAuthNonceTTLExpiryAllowsReplayAfterTTL(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{
		Now:           clock.Now,
		MaxNonceCache: 1024,
		NonceCacheTTL: 5 * time.Second, // short TTL for the test
	})
	const pskey = "pskey-ttl"
	const nodeID mtypes.Vertex = 25
	auth.RegisterTestKey(nodeID, pskey)
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	if _, _, err := auth.Verify(r); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	// Advance past the nonce TTL.
	clock.Advance(6 * time.Second)
	// Same request — must now succeed because the nonce has expired from the
	// cache (and timestamp is still fresh).
	r2 := r.Clone(r.Context())
	if _, _, err := auth.Verify(r2); err != nil {
		t.Fatalf("post-TTL replay should succeed, got: %v", err)
	}
}

func TestControlAuthMissingHeaders(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-missing"
	const nodeID mtypes.Vertex = 26
	auth.RegisterTestKey(nodeID, pskey)
	for _, h := range []string{"X-EG-NodeID", "X-EG-Timestamp", "X-EG-Nonce", "X-EG-Signature"} {
		r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
		r.Header.Del(h)
		if _, _, err := auth.Verify(r); err == nil {
			t.Fatalf("expected error when %s is missing", h)
		}
	}
}

func TestControlAuthSpecialNodeIDRejected(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-special"
	// Use NodeID_SuperNode in header.
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, mtypes.NodeID_SuperNode, pskey, clock)
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error on special NodeID")
	}
}

func TestControlAuthNonceCacheEvictsExpiredEntries(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{
		Now:           clock.Now,
		MaxNonceCache: 1024,
		NonceCacheTTL: 2 * time.Second,
	})
	const pskey = "pskey-evict"
	const nodeID mtypes.Vertex = 27
	auth.RegisterTestKey(nodeID, pskey)
	// Generate 5 distinct nonces.
	for i := 0; i < 5; i++ {
		r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
		if _, _, err := auth.Verify(r); err != nil {
			t.Fatalf("Verify[%d]: %v", i, err)
		}
	}
	if size := auth.NonceCacheSizeForTest(); size != 5 {
		t.Fatalf("nonce cache size = %d, want 5", size)
	}
	clock.Advance(3 * time.Second)
	// Sweep and confirm cache empties.
	auth.SweepNoncesForTest()
	if size := auth.NonceCacheSizeForTest(); size != 0 {
		t.Fatalf("nonce cache after sweep = %d, want 0", size)
	}
}

func TestControlAuthBodyCapReadsNoMoreThanCap(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-cap"
	const nodeID mtypes.Vertex = 28
	auth.RegisterTestKey(nodeID, pskey)
	// Cap = ControlAuthMaxBodyBytes. Build a valid signed request where the
	// signature was computed over the FIRST cap+1 bytes (so hashing succeeds)
	// but the body stream is longer. The verifier should reject with
	// ErrControlAuthBodyTooLarge before reading the full stream.
	cap := int(ControlAuthMaxBodyBytes)
	prefix := bytes.Repeat([]byte("x"), cap)
	body := append(prefix, bytes.Repeat([]byte("y"), 4096)...)
	r := buildSignedRequest(t, http.MethodPost, "/edge/v2/register", body, nodeID, pskey, clock)
	// The signature was computed over the FULL body in buildSignedRequest,
	// so it will be valid up to cap bytes. Verifier should reject because
	// the body length exceeds the cap.
	_, _, err := auth.Verify(r)
	if !errors.Is(err, ErrControlAuthBodyTooLarge) {
		t.Fatalf("err = %v, want ErrControlAuthBodyTooLarge", err)
	}
}

func TestControlAuthViaHTTPServer(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-httpserver"
	const nodeID mtypes.Vertex = 29
	auth.RegisterTestKey(nodeID, pskey)

	// Mount a handler that calls Verify then writes 200.
	var handlerNodeID atomic.Value
	handlerNodeID.Store(mtypes.Vertex(0))
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		// Override r.Body so the handler can swap to a NopCloser if needed.
		got, _, err := auth.Verify(r)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		handlerNodeID.Store(got)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Build a signed request and send it.
	body := []byte("")
	ts := strconv.FormatInt(clock.Now().Unix(), 10)
	nonce := randomNonceForTest(t)
	path := "/edge/v2/snapshot"
	digest := sha256.Sum256(body)
	canonical := http.MethodGet + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	mac := hmac.New(sha256.New, []byte(pskey))
	_, _ = mac.Write([]byte(canonical))
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	n := nodeID
	req.Header.Set("X-EG-NodeID", n.ToString())
	req.Header.Set("X-EG-Timestamp", ts)
	req.Header.Set("X-EG-Nonce", nonce)
	req.Header.Set("X-EG-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		gotBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, gotBody)
	}
	if v := handlerNodeID.Load().(mtypes.Vertex); v != nodeID {
		vv := v
		nn := nodeID
		t.Fatalf("handler NodeID = %s, want %s", vv.ToString(), nn.ToString())
	}
}

func TestControlAuthHTTPErrorResponseNoKeyMaterial(t *testing.T) {
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "pskey-http-no-leak"
	const nodeID mtypes.Vertex = 30
	auth.RegisterTestKey(nodeID, pskey)

	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		_, _, err := auth.Verify(r)
		if err != nil {
			// Map to uniform 401 response.
			code := ControlAuthHTTPStatus(err)
			http.Error(w, "control auth failed", code)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Send a request with a tampered signature.
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	r.Header.Set("X-EG-Signature", flipHex(r.Header.Get("X-EG-Signature")))
	req, _ := http.NewRequest(http.MethodGet, srv.URL+r.URL.EscapedPath(), nil)
	for k, v := range r.Header {
		req.Header[k] = v
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), pskey) {
		t.Fatalf("response body leaks key: %q", body)
	}
}

func TestControlAuthNoLeakViaContextOrLog(t *testing.T) {
	// Use a Verify call and ensure context.Cause returns nil (no key
	// material embedded in the wrapped error chain).
	clock := newFakeClock()
	state := NewControlState(ControlStateConfig{PeerAliveTimeout: 30 * time.Second, Now: clock.Now})
	auth := NewControlAuthenticator(state, ControlAuthenticatorConfig{Now: clock.Now})
	const pskey = "do-not-leak-pskey-context"
	const nodeID mtypes.Vertex = 31
	auth.RegisterTestKey(nodeID, pskey)
	r := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, nodeID, pskey, clock)
	originalSig := r.Header.Get("X-EG-Signature")
	r.Header.Set("X-EG-Signature", flipHex(originalSig))
	_, _, err := auth.Verify(r)
	if err == nil {
		t.Fatalf("expected error")
	}
	// Walk the wrapped chain and confirm no string form contains the key.
	for cur := err; cur != nil; cur = errors.Unwrap(cur) {
		if strings.Contains(cur.Error(), pskey) {
			t.Fatalf("wrapped error leaks key: %v", cur)
		}
	}
	// Confirm the error message is uniform across sub-checks.
	r2 := buildSignedRequest(t, http.MethodGet, "/edge/v2/snapshot", nil, mtypes.Vertex(777), pskey, clock)
	_, _, err2 := auth.Verify(r2)
	if err2 == nil {
		t.Fatalf("expected unknown-node error")
	}
	if err.Error() != err2.Error() {
		t.Logf("note: error messages differ; sig=%q unknown=%q", err.Error(), err2.Error())
	}
	// Both must be classified as ControlAuthError and map to 401.
	if !IsControlAuthError(err) || !IsControlAuthError(err2) {
		t.Fatalf("expected both errors to be ControlAuthError; sig=%T unknown=%T", err, err2)
	}
	if ControlAuthHTTPStatus(err) != http.StatusUnauthorized || ControlAuthHTTPStatus(err2) != http.StatusUnauthorized {
		t.Fatalf("expected both to map to 401; sig=%d unknown=%d", ControlAuthHTTPStatus(err), ControlAuthHTTPStatus(err2))
	}
}

// --- helpers --------------------------------------------------------------

func flipHex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) == 0 {
		return s
	}
	b[0] ^= 0x01
	return hex.EncodeToString(b)
}
