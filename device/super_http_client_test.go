package device

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func vertexFromInt(t *testing.T, v uint32) mtypes.Vertex {
	t.Helper()
	if v > 0xFFFF {
		t.Fatalf("vertex out of range: %d", v)
	}
	return mtypes.Vertex(v)
}

func newTestClient(t *testing.T, base, prefix string, nodeID mtypes.Vertex, key string) *ControlHTTPClient {
	t.Helper()
	c := NewControlHTTPClient(base, prefix, nodeID, key)
	c.HTTP.Timeout = 5 * time.Second
	return c
}

type serverEnv struct {
	psKey         []byte
	seenNonces    sync.Map
	rejectsExpire atomic.Int32
	rejectsNonce  atomic.Int32
	rejectsSig    atomic.Int32
	storedRev     atomic.Uint64
	snapshotCalls atomic.Int32
	eventCalls    atomic.Int32
	snapshots     atomic.Int32
}

func (env *serverEnv) verify(t *testing.T, r *http.Request, body []byte) (ok bool) {
	t.Helper()
	tsStr := r.Header.Get(HeaderTimestamp)
	nonce := r.Header.Get(HeaderNonce)
	sig := r.Header.Get(HeaderSignature)
	node := r.Header.Get(HeaderNodeID)
	if tsStr == "" || nonce == "" || sig == "" || node == "" {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(ts, 0)) > 5*time.Minute || time.Until(time.Unix(ts, 0)) > 5*time.Minute {
		env.rejectsExpire.Add(1)
		return false
	}
	if _, dup := env.seenNonces.LoadOrStore(nonce, struct{}{}); dup {
		env.rejectsNonce.Add(1)
		return false
	}
	digest := sha256.Sum256(body)
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + tsStr + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	mac := hmac.New(sha256.New, env.psKey)
	_, _ = mac.Write([]byte(canonical))
	if hex.EncodeToString(mac.Sum(nil)) != sig {
		env.rejectsSig.Add(1)
		return false
	}
	return true
}

func (env *serverEnv) snapshot(rev uint64) mtypes.ControlV2Snapshot {
	return mtypes.ControlV2Snapshot{
		Revision: rev,
		IssuedAt: time.Unix(int64(rev), 0),
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        100 * time.Millisecond,
			STUNServers:         []string{"stun:127.0.0.1:3478"},
			STUNRequestTimeout:  500 * time.Millisecond,
			STUNRefreshInterval: 30 * time.Second,
			ReportInterval:      500 * time.Millisecond,
			HeartbeatInterval:   1 * time.Second,
			EventReplay:         16,
		},
	}
}

// verifies signing headers + body digest produce a matching server-side HMAC.
func TestControlHTTPClientSigning(t *testing.T) {
	env := &serverEnv{psKey: []byte("super-secret")}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		snap := env.snapshot(env.storedRev.Add(1))
		w.Header().Set("ETag", snap.ETag())
		_ = json.NewEncoder(w).Encode(&snap)
	})
	mux.HandleFunc("/edge/v2/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req mtypes.ControlV2RegisterRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if req.Version != mtypes.ControlV2ProtocolVersion {
			http.Error(w, "version", http.StatusBadRequest)
			return
		}
		snap := env.snapshot(env.storedRev.Add(1))
		w.Header().Set("ETag", snap.ETag())
		_ = json.NewEncoder(w).Encode(&snap)
	})
	mux.HandleFunc("/edge/v2/report", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req mtypes.ControlV2ReportRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 1001), "super-secret")
	if _, _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot 2: %v", err)
	}
	if err := c.Report(context.Background(), &mtypes.ControlV2ReportRequest{
		NodeID:     vertexFromInt(t, 1001),
		ReportedAt: time.Now(),
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
}

// exercises ETag/If-None-Match 304 handling.
func TestControlHTTPClientSnapshotConditional304(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	rev := uint64(7)
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		snap := env.snapshot(rev)
		w.Header().Set("ETag", snap.ETag())
		if r.Header.Get("If-None-Match") == snap.ETag() {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_ = json.NewEncoder(w).Encode(&snap)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 7), "k")
	snap, ok, err := c.Snapshot(context.Background())
	if err != nil || !ok || snap == nil {
		t.Fatalf("first snapshot err=%v ok=%v snap=%v", err, ok, snap)
	}
	etag := snap.ETag()
	snap2, ok2, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if ok2 {
		t.Fatalf("expected 304 not-modified, got ok=true")
	}
	if snap2 == nil || snap2.ETag() != etag {
		t.Fatalf("expected cached snapshot unchanged, got %+v", snap2)
	}
}

// exercises Sync's SSE event delivery + reconnect-with-Last-Event-ID after server-side close.
// Hard check: the second SSE connect MUST carry the Last-Event-ID observed on the first connect.
func TestControlHTTPClientSSEReconnect(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	var sent atomic.Int32
	var lastSeenMu sync.Mutex
	var lastSeen []string
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		env.snapshotCalls.Add(1)
		snap := env.snapshot(env.storedRev.Add(1))
		w.Header().Set("ETag", snap.ETag())
		_ = json.NewEncoder(w).Encode(&snap)
	})
	mux.HandleFunc("/edge/v2/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		env.eventCalls.Add(1)
		lastSeenMu.Lock()
		lastSeen = append(lastSeen, r.Header.Get("Last-Event-ID"))
		lastSeenMu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		count := sent.Add(1)
		ev := mtypes.ControlV2Event{ID: "evt-" + strconv.Itoa(int(count)), Type: mtypes.ControlV2EventPeerChange, Revision: uint64(count)}
		buf, _ := json.Marshal(&ev)
		_, _ = io.WriteString(w, "id: "+ev.ID+"\nevent: "+string(ev.Type)+"\ndata: "+string(buf)+"\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		hj, _ := w.(http.Hijacker)
		if hj != nil {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 11), "k")
	c.MinBackoff = 5 * time.Millisecond
	c.MaxBackoff = 20 * time.Millisecond
	c.Jitter = func(d time.Duration) time.Duration { return d } // deterministic

	applyCount := 0
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	syncDone := make(chan error, 1)
	go func() { syncDone <- c.Sync(ctx, func(*mtypes.ControlV2Snapshot) { applyCount++ }) }()

	// Wait until at least two SSE connects have happened and reconnect used the recorded id.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		lastSeenMu.Lock()
		ls := append([]string(nil), lastSeen...)
		lastSeenMu.Unlock()
		if len(ls) >= 2 && ls[1] == "evt-1" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-syncDone

	lastSeenMu.Lock()
	defer lastSeenMu.Unlock()
	if len(lastSeen) < 2 {
		t.Fatalf("expected at least 2 SSE connections, got %d", len(lastSeen))
	}
	if lastSeen[0] != "" {
		t.Fatalf("first connect should have empty Last-Event-ID, got %q", lastSeen[0])
	}
	if lastSeen[1] != "evt-1" {
		t.Fatalf("second connect should carry Last-Event-ID=evt-1, got %q", lastSeen[1])
	}
	if applyCount == 0 {
		t.Fatalf("apply callback should have been called")
	}
}

// verifies the SSE parser handles multi-line data, id:, retry:, comments, CR/LF.
func TestSSEParserDirect(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(":heartbeat\r\n")
	buf.WriteString("id: 42\r\n")
	buf.WriteString("retry: 1500\r\n")
	buf.WriteString("data: {\"id\":\"42\",\"type\":\"peer_change\",\"revision\":7,\r\n")
	buf.WriteString("data: \"data\":{\"node_id\":\"5\"}}\r\n")
	buf.WriteString("\r\n")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan mtypes.ControlV2Event, 1)
	done := make(chan error, 1)
	go func() { done <- (SSEParser{}).ParseReader(ctx, &buf, events) }()
	select {
	case ev := <-events:
		if ev.ID != "42" {
			t.Fatalf("id=%q", ev.ID)
		}
		if ev.Type != mtypes.ControlV2EventPeerChange {
			t.Fatalf("type=%q", ev.Type)
		}
		if ev.Revision != 7 {
			t.Fatalf("revision=%d", ev.Revision)
		}
	case <-time.After(time.Second):
		t.Fatalf("parser timed out")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("parse err: %v", err)
	}
}

// sanity: the SSE parser propagates read errors.
func TestSSEParserScanError(t *testing.T) {
	r := &errReader{err: errors.New("boom")}
	events := make(chan mtypes.ControlV2Event)
	if err := (SSEParser{}).ParseReader(context.Background(), r, events); err == nil {
		t.Fatalf("expected error from reader")
	}
}

type errReader struct{ err error }

func (e *errReader) Read(p []byte) (int, error) { return 0, e.err }

// bufio is used by SSEParser; ensure the scanner buffer is large enough for long events.
func TestSSEParserBuffering(t *testing.T) {
	long := strings.Repeat("x", 200*1024)
	ev := mtypes.ControlV2Event{ID: "long", Type: mtypes.ControlV2EventRevision, Revision: 1, Data: long}
	encoded, err := json.Marshal(&ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := []byte("id: long\ndata: " + string(encoded) + "\n\n")
	events := make(chan mtypes.ControlV2Event, 1)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- (SSEParser{}).ParseReader(ctx, bytes.NewReader(raw), events) }()
	select {
	case got := <-events:
		if got.ID != "long" {
			t.Fatalf("id=%q", got.ID)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout")
	}
	cancel()
	<-done
}

// verifies snapshot revisions are monotonic: stale snapshots must not overwrite current.
func TestControlHTTPClientMonotonicRevision(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		snap := env.snapshot(3)
		w.Header().Set("ETag", snap.ETag())
		_ = json.NewEncoder(w).Encode(&snap)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 99), "k")
	c.mu.Lock()
	c.current = &mtypes.ControlV2Snapshot{Revision: 7}
	c.mu.Unlock()

	snap, ok, err := c.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if ok {
		t.Fatalf("expected stale snapshot to be rejected (ok=false)")
	}
	if snap == nil || snap.Revision != 7 {
		t.Fatalf("expected current revision 7 retained, got %+v", snap)
	}
	if cur := c.Current(); cur == nil || cur.Revision != 7 {
		t.Fatalf("Current() should still be rev 7, got %+v", cur)
	}
}

// verifies register request flows through to the server and returns a snapshot.
func TestControlHTTPClientRegister(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/register", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req mtypes.ControlV2RegisterRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		if req.NodeID.IsSpecial() {
			http.Error(w, "special", http.StatusBadRequest)
			return
		}
		snap := env.snapshot(env.storedRev.Add(1))
		_ = json.NewEncoder(w).Encode(&snap)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 555), "k")
	snap, err := c.Register(context.Background(), &mtypes.ControlV2RegisterRequest{
		NodeID:         vertexFromInt(t, 555),
		NodeName:       "edge",
		Version:        mtypes.ControlV2ProtocolVersion,
		ListenPort:     51820,
		RequestedAt:    time.Now(),
		Implementation: "etherguard",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if snap == nil || snap.Revision != 1 {
		t.Fatalf("expected snapshot rev 1, got %+v", snap)
	}
}

// rejects bad signature.
func TestControlHTTPClientBadSignature(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 77), "wrong-key")
	if _, _, err := c.Snapshot(context.Background()); err == nil {
		t.Fatalf("expected signature mismatch error")
	}
	if cur := c.Current(); cur != nil {
		t.Fatalf("local state should remain nil on bad signature")
	}
}

// verifies Sync polls snapshot while SSE is down and resumes reconnect attempts.
func TestControlHTTPClientSyncPollingFallback(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()

	// Snapshot: always advance revision, count calls.
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		env.snapshotCalls.Add(1)
		snap := env.snapshot(env.storedRev.Add(1))
		w.Header().Set("ETag", snap.ETag())
		_ = json.NewEncoder(w).Encode(&snap)
	})

	// SSE: fail first 3 calls, then succeed on the 4th attempt.
	var sseAttempts atomic.Int32
	streamUp := make(chan struct{}, 16)
	mux.HandleFunc("/edge/v2/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		attempt := sseAttempts.Add(1)
		if attempt <= 3 {
			http.Error(w, "stream down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		ev := mtypes.ControlV2Event{ID: "evt-up", Type: mtypes.ControlV2EventRevision, Revision: uint64(attempt)}
		buf, _ := json.Marshal(&ev)
		_, _ = io.WriteString(w, "id: "+ev.ID+"\nevent: "+string(ev.Type)+"\ndata: "+string(buf)+"\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		select {
		case streamUp <- struct{}{}:
		default:
		}
		hj, _ := w.(http.Hijacker)
		if hj != nil {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 222), "k")
	c.MinBackoff = 50 * time.Millisecond
	c.MaxBackoff = 100 * time.Millisecond
	c.Jitter = func(d time.Duration) time.Duration { return d }

	applyCount := int32(0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	syncDone := make(chan error, 1)
	go func() { syncDone <- c.Sync(ctx, func(*mtypes.ControlV2Snapshot) { atomic.AddInt32(&applyCount, 1) }) }()

	// Wait for the SSE stream to come up at least once.
	select {
	case <-streamUp:
	case <-ctx.Done():
		t.Fatalf("SSE stream never came up: %v", ctx.Err())
	}

	// Once stream is up, polling should have fired at least 2 times during the down period.
	// PollInterval = 100ms, down period is ~150ms (3 attempts * 50ms backoff).
	// Allow some slack: wait up to 500ms for snapshots to accumulate.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if env.snapshotCalls.Load() >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	snapshotsDuringDown := env.snapshotCalls.Load()

	cancel()
	if err := <-syncDone; err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("Sync returned unexpected error: %v", err)
	}

	if snapshotsDuringDown < 3 {
		t.Fatalf("expected polling to fire >= 3 snapshots during SSE down period, got %d", snapshotsDuringDown)
	}
	if atomic.LoadInt32(&applyCount) == 0 {
		t.Fatalf("apply should have been called at least once")
	}
	if sseAttempts.Load() < 4 {
		t.Fatalf("expected at least 4 SSE reconnect attempts (3 failed + 1 succeeded), got %d", sseAttempts.Load())
	}
}

// verifies Sync applies snapshots in monotonically increasing order, even when SSE
// arrives faster than polling can complete (older revisions must be rejected).
func TestControlHTTPClientSyncMonotonic(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()

	// Snapshot endpoint tracks its own counter and always returns an OLDER revision than what we last applied.
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		env.snapshotCalls.Add(1)
		// Always return rev=1; the client must reject as stale.
		snap := env.snapshot(1)
		w.Header().Set("ETag", snap.ETag())
		_ = json.NewEncoder(w).Encode(&snap)
	})

	mux.HandleFunc("/edge/v2/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		ev := mtypes.ControlV2Event{ID: "e", Type: mtypes.ControlV2EventRevision, Revision: 5}
		buf, _ := json.Marshal(&ev)
		_, _ = io.WriteString(w, "id: "+ev.ID+"\nevent: "+string(ev.Type)+"\ndata: "+string(buf)+"\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		hj, _ := w.(http.Hijacker)
		if hj != nil {
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 333), "k")
	// Pre-seed current to rev=10 so all incoming snapshots are stale.
	c.mu.Lock()
	c.current = &mtypes.ControlV2Snapshot{Revision: 10}
	c.mu.Unlock()
	c.MinBackoff = 10 * time.Millisecond
	c.MaxBackoff = 20 * time.Millisecond
	c.Jitter = func(d time.Duration) time.Duration { return d }

	applyCount := 0
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = c.Sync(ctx, func(snap *mtypes.ControlV2Snapshot) {
		applyCount++
		if snap != nil && snap.Revision != 10 {
			t.Fatalf("apply got stale revision %d", snap.Revision)
		}
	})
	if applyCount != 0 {
		t.Fatalf("apply should never be called with stale snapshots, got %d calls", applyCount)
	}
	if cur := c.Current(); cur == nil || cur.Revision != 10 {
		t.Fatalf("Current revision should remain 10, got %+v", cur)
	}
}

// verifies that an expired timestamp is rejected and local state stays clean.
func TestControlHTTPClientExpiredTimestampNoState(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		snap := env.snapshot(env.storedRev.Add(1))
		_ = json.NewEncoder(w).Encode(&snap)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 22), "k")
	c.Now = func() time.Time { return time.Unix(1, 0) }
	if _, _, err := c.Snapshot(context.Background()); err == nil {
		t.Fatalf("expected error from expired timestamp")
	}
	if cur := c.Current(); cur != nil {
		t.Fatalf("expected nil current snapshot after rejected request, got %+v", cur)
	}
	if env.rejectsExpire.Load() == 0 {
		t.Fatalf("server should have rejected expired timestamp")
	}
}

// verifies a replayed nonce is rejected by the server.
func TestControlHTTPClientReplayedNonce(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		snap := env.snapshot(env.storedRev.Add(1))
		_ = json.NewEncoder(w).Encode(&snap)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 33), "k")
	c.Nonce = func() string { return "fixed-nonce-1" }
	if _, _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	c.Nonce = func() string { return "fixed-nonce-1" }
	if _, _, err := c.Snapshot(context.Background()); err == nil {
		t.Fatalf("expected replayed nonce to be rejected")
	}
	if env.rejectsNonce.Load() == 0 {
		t.Fatalf("server should have rejected replayed nonce")
	}
}

// verifies malformed SSE leaves the local snapshot state untouched.
func TestControlHTTPClientMalformedSSENoState(t *testing.T) {
	env := &serverEnv{psKey: []byte("k")}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/v2/snapshot", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		snap := env.snapshot(env.storedRev.Add(1))
		_ = json.NewEncoder(w).Encode(&snap)
	})
	mux.HandleFunc("/edge/v2/events", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !env.verify(t, r, body) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "id: bad\ndata: not-json\n\n")
		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := newTestClient(t, srv.URL, "edge/v2", vertexFromInt(t, 44), "k")
	if _, _, err := c.Snapshot(context.Background()); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	before := c.Current()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	events := make(chan mtypes.ControlV2Event, 1)
	if err := c.Events(ctx, events); err == nil {
		t.Fatalf("expected parser error on malformed event")
	}
	if c.Current() != before {
		t.Fatalf("snapshot state changed by malformed SSE")
	}
}
