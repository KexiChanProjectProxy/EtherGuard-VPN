/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

// Package main — replay-safe per-Edge HMAC authentication for the Super
// Control API v2 boundary.
//
// # Threat model
//
// Every Control API v2 request from an Edge carries:
//
//	X-EG-NodeID    decimal NodeID  (mtypes.Vertex.ToString())
//	X-EG-Timestamp unix seconds
//	X-EG-Nonce     unique server-validated token per request
//	X-EG-Signature hex(HMAC-SHA256(key=controlPSKey,
//	                               msg="METHOD\nescaped-path\nunix-ts\nnonce\nhex(SHA-256(body))"))
//
// The verifier enforces:
//
//  1. Bounded body size BEFORE hashing (constant cap; enforced by
//     http.MaxBytesReader so the request stream is short-circuited and the
//     server never reads beyond the cap).
//  2. Strict timestamp skew window (default ±60 s).
//  3. Bounded per-Edge nonce cache with TTL ≥ 2× the timestamp window so a
//     replay within the window is rejected and the cache never grows without
//     bound.
//  4. HMAC comparison via hmac.Equal (constant time).
//  5. Uniform error responses — the single *ControlAuthError type is mapped
//     to HTTP 401/403/413 by ControlAuthHTTPStatus; the message is constant
//     and never reveals which sub-check failed or any key material.
//
// The control PSKey is resolved exclusively through
// ControlState.ControlKeyFor — the verifier never reads the underlying
// controlPeerRecord map directly and never holds the ControlState lock
// while hashing. ControlKeyFor returns a defensive copy of the key string,
// after which the lock has been released.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// ---------------------------------------------------------------------------
// Public constants (consume these names exactly — task 9 wires them in).
// ---------------------------------------------------------------------------

const (
	// ControlAuthHeaderNodeID is the header carrying the decimal NodeID.
	ControlAuthHeaderNodeID = "X-EG-NodeID"
	// ControlAuthHeaderTimestamp is the header carrying the request unix
	// timestamp in seconds.
	ControlAuthHeaderTimestamp = "X-EG-Timestamp"
	// ControlAuthHeaderNonce is the header carrying a per-request nonce
	// (random hex by default; any unique string is accepted).
	ControlAuthHeaderNonce = "X-EG-Nonce"
	// ControlAuthHeaderSignature is the header carrying the hex-encoded
	// HMAC-SHA256 of the canonical string.
	ControlAuthHeaderSignature = "X-EG-Signature"

	// ControlAuthTimestampSkew is the maximum allowed clock drift between
	// the Edge and the Super. Requests outside this window are rejected.
	ControlAuthTimestampSkew = 60 * time.Second

	// ControlAuthMaxBodyBytes is the hard cap on the request body size.
	// Bodies larger than this are rejected with ErrControlAuthBodyTooLarge
	// before any signature computation. 1 MiB matches the worst-case JSON
	// payload (ControlV2ReportRequest candidates + pongs) with headroom.
	ControlAuthMaxBodyBytes int64 = 1 << 20

	// defaultControlAuthMaxNonceCache is the default upper bound on the
	// total number of (NodeID, nonce) entries retained across all peers.
	defaultControlAuthMaxNonceCache = 16 << 10 // 16384

	// defaultControlAuthNonceTTL is the default retention period for
	// observed nonces. It is >= 2× ControlAuthTimestampSkew so a replay
	// within the timestamp window is always rejected, and a request with
	// a timestamp slightly past the window is still caught.
	defaultControlAuthNonceTTL = 2 * ControlAuthTimestampSkew
)

// Public error sentinels (used by errors.Is and by task 9 wiring).
var (
	// ErrControlAuthMissingHeader is returned when any of the four signed
	// headers is absent.
	ErrControlAuthMissingHeader = errors.New("control auth: missing header")
	// ErrControlAuthInvalidNodeID is returned when the X-EG-NodeID header
	// is not a valid decimal Vertex, or refers to a reserved (special)
	// NodeID that cannot be assigned to an Edge.
	ErrControlAuthInvalidNodeID = errors.New("control auth: invalid node id")
	// ErrControlAuthUnknownNode is returned when the NodeID is well-formed
	// but has no registered control PSKey in ControlState.
	ErrControlAuthUnknownNode = errors.New("control auth: unknown node")
	// ErrControlAuthInvalidTimestamp is returned when the timestamp is
	// non-numeric or outside ±ControlAuthTimestampSkew.
	ErrControlAuthInvalidTimestamp = errors.New("control auth: invalid timestamp")
	// ErrControlAuthBodyTooLarge is returned when the body exceeds
	// ControlAuthMaxBodyBytes. The body is NOT fully read in this case.
	ErrControlAuthBodyTooLarge = errors.New("control auth: body too large")
	// ErrControlAuthInvalidSignature is returned when the HMAC signature
	// fails to verify (or is malformed).
	ErrControlAuthInvalidSignature = errors.New("control auth: invalid signature")
	// ErrControlAuthReplay is returned when the same (NodeID, nonce) has
	// already been observed within the nonce cache TTL.
	ErrControlAuthReplay = errors.New("control auth: replay detected")
)

// uniformControlAuthMessage is the single client-visible message returned
// by ControlAuthError.Error(). All sub-checks produce the same string so an
// attacker cannot infer which check failed.
const uniformControlAuthMessage = "control auth failed"

// ControlAuthError is the single error type returned by Verify. Its Error()
// method always returns the constant uniformControlAuthMessage; details are
// kept on the typed Code field for server-side logging only.
type ControlAuthError struct {
	// Code is one of the ErrControlAuth* sentinels above. It is NEVER
	// serialised into an HTTP response — the HTTP handler must call
	// ControlAuthHTTPStatus to map it to a status code and write a
	// generic body.
	Code error
}

func (e *ControlAuthError) Error() string { return uniformControlAuthMessage }

// Unwrap exposes the underlying sentinel so callers can errors.Is the
// specific check (for server-side metrics / logging only).
func (e *ControlAuthError) Unwrap() error { return e.Code }

// IsControlAuthError reports whether err (or anything it wraps) is a
// *ControlAuthError. The HTTP handler uses this to emit uniform responses.
func IsControlAuthError(err error) bool {
	var v *ControlAuthError
	return errors.As(err, &v)
}

// ControlAuthHTTPStatus maps a ControlAuthError to its HTTP status code.
// Body-too-large is the only "client can fix it" case (413); everything
// else is an auth failure (401). The mapping is uniform — no sub-check is
// distinguishable from the outside.
func ControlAuthHTTPStatus(err error) int {
	if !IsControlAuthError(err) {
		return http.StatusUnauthorized
	}
	if errors.Is(err, ErrControlAuthBodyTooLarge) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusUnauthorized
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

// ControlAuthenticator verifies HMAC-signed Control API v2 requests. It is
// safe for concurrent use by multiple goroutines.
type ControlAuthenticator struct {
	state *ControlState

	now func() time.Time

	// Nonce cache configuration.
	nonceTTL        time.Duration
	maxNonceEntries int

	// nonceMu guards nonceSeen. Nonce lookups + inserts are O(1) average
	// against the inner map. Eviction is amortised through a per-entry
	// expiresAt timestamp; a periodic sweep is provided via
	// SweepNoncesForTest (also called from a runtime goroutine in
	// production — wired by task 11).
	nonceMu   sync.Mutex
	nonceSeen map[nonceKey]nonceEntry
}

type nonceKey struct {
	nodeID mtypes.Vertex
	nonce  string
}

type nonceEntry struct {
	expiresAt time.Time
}

// ControlAuthenticatorConfig configures a ControlAuthenticator. All fields
// are optional; sensible defaults match the production behaviour.
type ControlAuthenticatorConfig struct {
	// Now is the clock function. Defaults to time.Now when nil.
	Now func() time.Time
	// NonceCacheTTL is the retention period for nonces. Defaults to
	// defaultControlAuthNonceTTL (2× ControlAuthTimestampSkew) when ≤ 0.
	NonceCacheTTL time.Duration
	// MaxNonceCache caps the total number of (NodeID, nonce) entries
	// across all peers. Defaults to defaultControlAuthMaxNonceCache when
	// ≤ 0. When the cap is reached the oldest entries are evicted.
	MaxNonceCache int
}

// NewControlAuthenticator constructs a verifier bound to the given
// ControlState. The state is required — the verifier resolves the per-Edge
// control PSKey exclusively through ControlState.ControlKeyFor.
func NewControlAuthenticator(state *ControlState, cfg ControlAuthenticatorConfig) *ControlAuthenticator {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	ttl := cfg.NonceCacheTTL
	if ttl <= 0 {
		ttl = defaultControlAuthNonceTTL
	}
	max := cfg.MaxNonceCache
	if max <= 0 {
		max = defaultControlAuthMaxNonceCache
	}
	return &ControlAuthenticator{
		state:           state,
		now:             now,
		nonceTTL:        ttl,
		maxNonceEntries: max,
		nonceSeen:       make(map[nonceKey]nonceEntry),
	}
}

// Verify parses the four signed headers, validates the timestamp window,
// limits the body size, recomputes the HMAC, and on success returns the
// authenticated NodeID and the buffered body. On any failure it returns a
// *ControlAuthError — the HTTP handler MUST translate via
// ControlAuthHTTPStatus and write a generic body.
//
// The body buffer is consumed via http.MaxBytesReader so the underlying
// reader short-circuits at ControlAuthMaxBodyBytes+1 bytes; the caller is
// responsible for closing r.Body after the request completes.
//
// Verify never holds the ControlState lock while hashing. ControlKeyFor
// returns a defensive copy of the key string and releases the lock before
// this function is called.
func (a *ControlAuthenticator) Verify(r *http.Request) (mtypes.Vertex, []byte, error) {
	// 1. Extract the four signed headers — every failure here is a
	//    MISSING_HEADER error.
	nodeIDHeader := r.Header.Get(ControlAuthHeaderNodeID)
	if nodeIDHeader == "" {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthMissingHeader}
	}
	tsHeader := r.Header.Get(ControlAuthHeaderTimestamp)
	if tsHeader == "" {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthMissingHeader}
	}
	nonce := r.Header.Get(ControlAuthHeaderNonce)
	if nonce == "" {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthMissingHeader}
	}
	sigHeader := r.Header.Get(ControlAuthHeaderSignature)
	if sigHeader == "" {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthMissingHeader}
	}

	// 2. Parse NodeID. Special NodeIDs are rejected to mirror the v2
	//    schema's "no reserved IDs in live requests" rule.
	nodeID, err := mtypes.String2NodeID(nodeIDHeader)
	if err != nil || nodeID.IsSpecial() {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthInvalidNodeID}
	}

	// 3. Parse timestamp; enforce the skew window BEFORE any further work.
	tsInt, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthInvalidTimestamp}
	}
	now := a.now()
	delta := now.Sub(time.Unix(tsInt, 0))
	if delta < -ControlAuthTimestampSkew || delta > ControlAuthTimestampSkew {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthInvalidTimestamp}
	}

	// 4. Resolve the per-Edge control PSKey via the authoritative state
	//    service. The lock is released before we use the returned copy.
	key, ok := a.state.ControlKeyFor(nodeID)
	if !ok || key == "" {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthUnknownNode}
	}

	// 5. Bound the body BEFORE hashing. MaxBytesReader caps the reader
	//    stream at cap+1 bytes; if the next Read returns ErrBodyTooLarge
	//    we translate to ErrControlAuthBodyTooLarge. We do NOT call
	//    io.ReadAll(r.Body) directly — that would bypass the cap.
	capped := http.MaxBytesReader(nil, r.Body, ControlAuthMaxBodyBytes)
	body, err := io.ReadAll(capped)
	if err != nil {
		// MaxBytesReader returns a *http.MaxBytesError; we never let
		// that surface to the caller because it carries the cap value.
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return 0, nil, &ControlAuthError{Code: ErrControlAuthBodyTooLarge}
		}
		return 0, nil, &ControlAuthError{Code: ErrControlAuthInvalidSignature}
	}

	// 6. Recompute the canonical string and the expected HMAC. The
	//    canonical string must match the client (device/super_http_client.go
	//    sign()) byte-for-byte.
	digest := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + tsHeader + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	expected := mtypes.HMACSHA256([]byte(key), []byte(canonical))

	// 7. Decode the supplied signature and compare in constant time.
	supplied, err := hex.DecodeString(sigHeader)
	if err != nil || len(supplied) != len(expected) {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthInvalidSignature}
	}
	if !hmac.Equal(supplied, expected) {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthInvalidSignature}
	}

	// 8. Replay check — record the (NodeID, nonce) pair. We do this AFTER
	//    HMAC verification so the cache only retains entries that passed
	//    authentication. If the entry already exists and has not yet
	//    expired, reject.
	if dup := a.observeNonce(nodeID, nonce); dup {
		return 0, nil, &ControlAuthError{Code: ErrControlAuthReplay}
	}

	return nodeID, body, nil
}

// observeNonce records (nodeID, nonce) with an expiry of now+nonceTTL and
// returns true if the pair was already present (and still within TTL).
func (a *ControlAuthenticator) observeNonce(nodeID mtypes.Vertex, nonce string) bool {
	now := a.now()
	key := nonceKey{nodeID: nodeID, nonce: nonce}
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	entry, exists := a.nonceSeen[key]
	if exists && entry.expiresAt.After(now) {
		return true
	}
	// Evict oldest entries if at cap. We evict at most one entry per call;
	// the periodic sweep keeps the cache tight in steady state.
	if len(a.nonceSeen) >= a.maxNonceEntries {
		a.evictOldestLocked(now)
	}
	a.nonceSeen[key] = nonceEntry{expiresAt: now.Add(a.nonceTTL)}
	return false
}

// evictOldestLocked removes the entry with the earliest expiresAt. Caller
// must hold nonceMu.
func (a *ControlAuthenticator) evictOldestLocked(now time.Time) {
	var (
		oldestKey nonceKey
		oldestAt  time.Time
		found     bool
	)
	for k, v := range a.nonceSeen {
		if !found || v.expiresAt.Before(oldestAt) {
			oldestKey = k
			oldestAt = v.expiresAt
			found = true
		}
	}
	if found {
		delete(a.nonceSeen, oldestKey)
	}
}

// SweepNonces drops every expired entry. The runtime should call this on a
// slow timer (task 11 wires it). The implementation is O(n) over the cache.
func (a *ControlAuthenticator) SweepNonces() int {
	now := a.now()
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	before := len(a.nonceSeen)
	for k, v := range a.nonceSeen {
		if !v.expiresAt.After(now) {
			delete(a.nonceSeen, k)
		}
	}
	return before - len(a.nonceSeen)
}

// ---------------------------------------------------------------------------
// Test-only helpers
// ---------------------------------------------------------------------------

// RegisterTestKey directly installs a control PSKey for the given NodeID in
// the bound ControlState, bypassing the Register flow. Tests use this to
// exercise the verifier without a full Register/Report round-trip. The
// method is prefixed "Register" rather than "Set" to make accidental
// production use obvious at the call site.
//
// NOTE: This method reaches into the ControlState's internal map. It is
// safe because the verifier and the production Register path both serialise
// through the same mutex; tests do not need to be racing against Register
// when calling it.
func (a *ControlAuthenticator) RegisterTestKey(nodeID mtypes.Vertex, pskey string) {
	if a.state == nil || pskey == "" {
		return
	}
	a.state.setControlKeyForTest(nodeID, pskey)
}

// NonceCacheSizeForTest reports the current number of cached (NodeID,
// nonce) pairs. Test-only.
func (a *ControlAuthenticator) NonceCacheSizeForTest() int {
	a.nonceMu.Lock()
	defer a.nonceMu.Unlock()
	return len(a.nonceSeen)
}

// SweepNoncesForTest wraps SweepNonces for the test surface.
func (a *ControlAuthenticator) SweepNoncesForTest() int { return a.SweepNonces() }

// ---------------------------------------------------------------------------
// Internal helper on ControlState (test wiring)
// ---------------------------------------------------------------------------

// setControlKeyForTest directly installs a control PSKey in the ControlState
// for tests. It mirrors Register's write path: takes the write lock, clones
// the key, and emits a peer_change event outside the lock.
func (s *ControlState) setControlKeyForTest(nodeID mtypes.Vertex, pskey string) {
	if s == nil || nodeID.IsSpecial() || pskey == "" {
		return
	}
	s.mu.Lock()
	rec, exists := s.peers[nodeID]
	now := s.now()
	if exists {
		rec.controlKey = pskey
		rec.view.LastSeen = now
	} else {
		s.peers[nodeID] = &controlPeerRecord{
			view:       mtypes.ControlV2Peer{NodeID: nodeID, NodeName: fmt.Sprintf("test-%d", nodeID), LatencyMS: map[mtypes.Vertex]float64{}, LastSeen: now},
			controlKey: pskey,
		}
	}
	rev := s.revision
	s.mu.Unlock()
	if !exists {
		s.emit(mtypes.ControlV2EventPeerChange, nodeID, fmt.Sprintf("test-%d", nodeID), rev)
	}
}
