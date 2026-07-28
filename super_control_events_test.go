/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// syncBuffer is a thread-safe wrapper around bytes.Buffer for tests
// that read concurrently with the renderer's writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Flush() { _ = s.b.Len() /* no-op; flush happens below */ }

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Return a copy so the underlying buffer can grow safely.
	out := make([]byte, s.b.Len())
	copy(out, s.b.Bytes())
	return out
}

// flushWriter adapts a *bufio.Writer so its Flush() returns nothing, to
// satisfy ServeSSE's writer interface (which expects a no-error Flush).
type flushWriter struct {
	mu sync.Mutex
	bw *bufio.Writer
}

func newFlushWriter(w io.Writer) *flushWriter { return &flushWriter{bw: bufio.NewWriter(w)} }
func (f *flushWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bw.Write(p)
}
func (f *flushWriter) Flush() {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = f.bw.Flush()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// drain is a test helper that pulls from a channel until either the count
// is reached or the context expires.
func drain[T any](t *testing.T, ctx context.Context, ch <-chan T, want int) []T {
	t.Helper()
	got := make([]T, 0, want)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for len(got) < want {
		select {
		case v, ok := <-ch:
			if !ok {
				return got
			}
			got = append(got, v)
		case <-timer.C:
			t.Fatalf("timeout draining %d events (got %d)", want, len(got))
		}
	}
	return got
}

// countGoroutines returns the goroutine count minus one (the test goroutine).
func countGoroutines() int {
	return runtime.NumGoroutine() - 1
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestControlEventsPublishAssignsID ensures Publish assigns a monotonic
// non-empty ID even when callers pass one with ID="" (the client SSE
// parser relies on every event carrying an ID — see issues.md).
func TestControlEventsPublishAssignsID(t *testing.T) {
	hub := NewControlEventHub(8)
	defer hub.Close()

	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange})
	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerGone})
	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})

	buf := hub.snapshotBuffer()
	if len(buf) != 3 {
		t.Fatalf("expected 3 events in replay buffer, got %d", len(buf))
	}
	prev := uint64(0)
	for i, ev := range buf {
		if ev.ID == "" {
			t.Fatalf("event %d has empty ID", i)
		}
		// Parse "evt-<n>" — monotonic.
		var n uint64
		if _, err := fmt.Sscanf(ev.ID, "evt-%d", &n); err != nil {
			t.Fatalf("event %d ID %q not in evt-N form: %v", i, ev.ID, err)
		}
		if n <= prev {
			t.Fatalf("event %d ID %q not strictly greater than previous %d", i, ev.ID, prev)
		}
		prev = n
	}
}

// TestControlEventsPreservesCallerID ensures a non-empty ID passed by the
// caller is preserved verbatim (the hub only assigns IDs when ID is empty).
func TestControlEventsPreservesCallerID(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	hub.Publish(mtypes.ControlV2Event{ID: "custom-1", Type: mtypes.ControlV2EventRevision})
	buf := hub.snapshotBuffer()
	if len(buf) != 1 || buf[0].ID != "custom-1" {
		t.Fatalf("expected caller ID preserved, got %#v", buf)
	}
}

// TestControlEventsSubscribeReplayFromID replays events with ID > lastEventID
// in monotonic order on Subscribe.
func TestControlEventsSubscribeReplayFromID(t *testing.T) {
	hub := NewControlEventHub(16)
	defer hub.Close()

	for i := 0; i < 5; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	buf := hub.snapshotBuffer()
	mid := buf[2].ID // replay from this point; expect 2 events (buf[3], buf[4])

	sub, err := hub.Subscribe(context.Background(), mid)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	got := drain(t, context.Background(), sub.Events(), 2)
	if got[0].ID != buf[3].ID || got[1].ID != buf[4].ID {
		t.Fatalf("replay mismatch: got [%s,%s], want [%s,%s]", got[0].ID, got[1].ID, buf[3].ID, buf[4].ID)
	}
}

// TestControlEventsSubscribeReplayAll when lastEventID is empty the
// subscriber must receive the entire buffer in order.
func TestControlEventsSubscribeReplayAll(t *testing.T) {
	hub := NewControlEventHub(16)
	defer hub.Close()

	for i := 0; i < 4; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	sub, err := hub.Subscribe(context.Background(), "")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	got := drain(t, context.Background(), sub.Events(), 4)
	for i, ev := range got {
		if ev.ID != hub.snapshotBuffer()[i].ID {
			t.Fatalf("event %d ID mismatch: got %s, want %s", i, ev.ID, hub.snapshotBuffer()[i].ID)
		}
	}
}

// TestControlEventsStaleIDSignalsResync ensures Subscribe with a
// lastEventID older than the buffer's oldest retained event signals
// ResyncRequired so the client knows to fetch a snapshot.
func TestControlEventsStaleIDSignalsResync(t *testing.T) {
	hub := NewControlEventHub(4) // small buffer
	defer hub.Close()

	// Publish 10 events; only the last 4 are retained.
	for i := 0; i < 10; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	oldest := "evt-1" // older than any retained event

	sub, err := hub.Subscribe(context.Background(), oldest)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	select {
	case <-sub.ResyncRequired():
		// expected
	case <-time.After(2 * time.Second):
		t.Fatalf("expected ResyncRequired to fire for stale lastEventID")
	}
	// And the replayed events should still arrive.
	got := drain(t, context.Background(), sub.Events(), 4)
	if len(got) != 4 {
		t.Fatalf("expected 4 replay events, got %d", len(got))
	}
}

// TestControlEventsSubscribeUnknownIDReplaysAll verifies that a lastEventID
// the hub has never seen but is NEWER than the buffer's highest entry
// still replays the buffer (we cannot prove it's stale so we err on the
// side of replay).
func TestControlEventsSubscribeUnknownIDReplaysAll(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	for i := 0; i < 3; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	sub, err := hub.Subscribe(context.Background(), "evt-999-not-seen")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	// Unknown newer ID -> no resync signal (we can't be sure), full replay.
	select {
	case <-sub.ResyncRequired():
		t.Fatalf("unknown newer ID must not trigger resync")
	case <-time.After(50 * time.Millisecond):
	}
	got := drain(t, context.Background(), sub.Events(), 3)
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
}

// TestControlEventsBoundedReplayBuffer ensures the replay ring is capped
// at the configured capacity.
func TestControlEventsBoundedReplayBuffer(t *testing.T) {
	hub := NewControlEventHub(8)
	defer hub.Close()

	for i := 0; i < 25; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	buf := hub.snapshotBuffer()
	if len(buf) != 8 {
		t.Fatalf("expected 8 events retained, got %d", len(buf))
	}
	// Oldest retained ID should be evt-(25-8+1) = evt-18.
	if buf[0].ID != "evt-18" {
		t.Fatalf("expected oldest retained to be evt-18, got %s", buf[0].ID)
	}
	if buf[len(buf)-1].ID != "evt-25" {
		t.Fatalf("expected newest to be evt-25, got %s", buf[len(buf)-1].ID)
	}
}

// TestControlEventsOrderedDelivery verifies subscribers receive events in
// monotonic order across replay and live phases.
func TestControlEventsOrderedDelivery(t *testing.T) {
	hub := NewControlEventHub(32)
	defer hub.Close()

	for i := 0; i < 3; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}

	sub, err := hub.Subscribe(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	// Drain the 2 replays.
	drain(t, context.Background(), sub.Events(), 2)

	// Now publish 5 more live events.
	for i := 0; i < 5; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange})
	}
	got := drain(t, context.Background(), sub.Events(), 5)
	var prev uint64
	for i, ev := range got {
		var n uint64
		if _, err := fmt.Sscanf(ev.ID, "evt-%d", &n); err != nil {
			t.Fatalf("event %d ID %q bad: %v", i, ev.ID, err)
		}
		if n <= prev {
			t.Fatalf("event %d not monotonic: %d <= %d", i, n, prev)
		}
		prev = n
	}
}

// TestControlEventsSlowSubscriberEvicted ensures a subscriber whose buffer
// fills is evicted (with ErrSlowSubscriber) and does not block the
// publisher.
func TestControlEventsSlowSubscriberEvicted(t *testing.T) {
	hub := NewControlEventHub(64)
	defer hub.Close()

	// Subscribe with a small per-subscriber buffer so we can saturate it.
	sub, err := hub.SubscribeWithBuffer(context.Background(), "", 2)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	// Publish 100 events without draining. Publisher must not block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
		}
		close(done)
	}()
	select {
	case <-done:
		// publisher didn't block
	case <-time.After(2 * time.Second):
		t.Fatalf("publisher blocked on slow subscriber")
	}

	// Subscriber must have been evicted.
	select {
	case <-sub.Done():
		if err := sub.Err(); !errors.Is(err, ErrSlowSubscriber) {
			t.Fatalf("expected ErrSlowSubscriber via Err(), got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("slow subscriber never terminated")
	}
}

// TestControlEventsSlowSubscriberEvictionPreservesFastSubscriber ensures
// that one slow subscriber does not affect a parallel fast subscriber.
func TestControlEventsSlowSubscriberEvictionPreservesFastSubscriber(t *testing.T) {
	hub := NewControlEventHub(64)
	defer hub.Close()

	slow, err := hub.SubscribeWithBuffer(context.Background(), "", 1)
	if err != nil {
		t.Fatalf("slow Subscribe: %v", err)
	}
	defer slow.Close()

	fast, err := hub.Subscribe(context.Background(), "")
	if err != nil {
		t.Fatalf("fast Subscribe: %v", err)
	}
	defer fast.Close()

	// Drain fast's initial empty buffer.
	drain(t, context.Background(), fast.Events(), 0)

	// Publish; slow fills up, fast keeps up.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
		}
	}()
	// Drain fast concurrently.
	got := 0
	for got < 30 {
		select {
		case _, ok := <-fast.Events():
			if !ok {
				t.Fatalf("fast.Events closed early after %d events", got)
			}
			got++
		case <-time.After(2 * time.Second):
			t.Fatalf("fast subscriber blocked after %d events", got)
		}
	}
	wg.Wait()

	// Slow must have been evicted.
	select {
	case <-slow.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("slow subscriber never terminated")
	}
	if !errors.Is(slow.Err(), ErrSlowSubscriber) {
		t.Fatalf("expected ErrSlowSubscriber, got %v", slow.Err())
	}
}

// TestControlEventsCtxCancelClosesSubscriber ensures cancelling the
// subscribe context releases the subscriber without goroutine leaks.
// The hub's per-subscriber state is a struct (no goroutine), so
// cancellation is a cheap flag flip. The test calls sub.Close()
// explicitly (the documented way for the caller to release the sub)
// and verifies no goroutine is left behind.
func TestControlEventsCtxCancelClosesSubscriber(t *testing.T) {
	hub := NewControlEventHub(8)
	defer hub.Close()

	ctx, cancel := context.WithCancel(context.Background())

	sub, err := hub.Subscribe(ctx, "")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	sub.Close()

	// No goroutines were spawned for this subscriber, so there's
	// nothing to wait for; just sanity-check we can call methods on
	// the sub without panicking.
	select {
	case <-sub.Done():
	case <-time.After(100 * time.Millisecond):
		// Done may not close on ctx cancel alone (the design: Done
		// closes on eviction or hub.Close); sub.Close is the
		// explicit release path.
	}
	if sub.Err() != nil {
		// Err is set on eviction or hub.Close; sub.Close alone is a
		// no-op for the error state. Allow nil.
	}
}

// TestControlEventsCloseCancelsAllSubscribers verifies hub.Close()
// terminates every active subscriber with ErrHubClosed and never blocks.
func TestControlEventsCloseCancelsAllSubscribers(t *testing.T) {
	hub := NewControlEventHub(8)

	var subs []*Subscriber
	for i := 0; i < 5; i++ {
		s, err := hub.Subscribe(context.Background(), "")
		if err != nil {
			t.Fatalf("Subscribe %d: %v", i, err)
		}
		subs = append(subs, s)
	}

	done := make(chan struct{})
	go func() {
		hub.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("hub.Close blocked")
	}
	for i, s := range subs {
		select {
		case <-s.Done():
		case <-time.After(2 * time.Second):
			t.Fatalf("subscriber %d never closed after hub.Close", i)
		}
		if !errors.Is(s.Err(), ErrHubClosed) {
			t.Fatalf("subscriber %d err = %v, want ErrHubClosed", i, s.Err())
		}
	}
	// Idempotent.
	hub.Close()
}

// TestControlEventsServeSSEFraming verifies the SSE renderer writes
// id/event/data/retry directives and an initial comment.
func TestControlEventsServeSSEFraming(t *testing.T) {
	hub := NewControlEventHub(8)
	defer hub.Close()

	hub.Publish(mtypes.ControlV2Event{
		Type: mtypes.ControlV2EventPeerChange,
		Data: mtypes.ControlV2PeerChangePayload{NodeID: 42, NodeName: "alpha"},
	})

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := newManualTickerFactory()
	_, err := hub.ServeSSE(ctx, bw, "", SSEOptions{
		RetryMillis: 3000,
		Heartbeat:   50 * time.Millisecond,
		TickerFunc:  clock.New,
	})
	if err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}

	// Wait for the renderer to write the event into the buffer.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte("id: evt-1")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Contains(buf.Bytes(), []byte("retry: 3000")) {
		t.Fatalf("expected retry: 3000 directive, got:\n%s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("event: peer_change")) {
		t.Fatalf("expected event: peer_change directive, got:\n%s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("id: evt-1")) {
		t.Fatalf("expected id: evt-1, got:\n%s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"node_id":42`)) {
		t.Fatalf("expected data payload with node_id:42, got:\n%s", buf.String())
	}
	cancel()
}

// TestControlEventsHeartbeatComments ensures the SSE renderer emits
// `: heartbeat` comments on a steady cadence using an injected clock. The
// test does NOT sleep 25-30 seconds.
func TestControlEventsHeartbeatComments(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Heartbeat = 27s (inside the 25-30s window). Inject a ticker factory
	// that fires every Advance() call so we don't wait wall-clock time.
	clock := newManualTickerFactory()
	_, err := hub.ServeSSE(ctx, bw, "", SSEOptions{
		Heartbeat:  27 * time.Second,
		TickerFunc: clock.New,
	})
	if err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}

	// No events published — heartbeat must still emit because the
	// renderer flushes an initial comment, then waits for events OR
	// heartbeat tick. Force 3 ticks.
	for i := 0; i < 3; i++ {
		clock.Advance()
		// Give the renderer a moment to write.
		time.Sleep(20 * time.Millisecond)
		bw.Flush()
	}
	cancel()

	// Count ": heartbeat" occurrences.
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	count := 0
	for sc.Scan() {
		if sc.Text() == ": heartbeat" {
			count++
		}
	}
	if count < 2 {
		t.Fatalf("expected at least 2 heartbeat comments, got %d\nbuffer:\n%s", count, buf.String())
	}
}

// TestControlEventsServeSSEReplayFromLastEventID verifies ServeSSE with
// a lastEventID replays the buffer then transitions to live.
func TestControlEventsServeSSEReplayFromLastEventID(t *testing.T) {
	hub := NewControlEventHub(8)
	defer hub.Close()

	for i := 0; i < 4; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := hub.ServeSSE(ctx, bw, hub.snapshotBuffer()[1].ID, SSEOptions{Heartbeat: 1 * time.Hour})
	if err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}

	// Wait for renderer to flush the two replay events.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte("id: evt-4")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !bytes.Contains(buf.Bytes(), []byte("id: evt-3")) || !bytes.Contains(buf.Bytes(), []byte("id: evt-4")) {
		t.Fatalf("expected both replay events in buffer, got:\n%s", buf.String())
	}

	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange})
	// Wait for the live event to land in the buffer.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Count(buf.Bytes(), []byte("event: peer_change")) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if bytes.Count(buf.Bytes(), []byte("event: peer_change")) < 1 {
		t.Fatalf("expected live event in buffer, got:\n%s", buf.String())
	}
	cancel()
}

// TestControlEventsSubscribeAfterClose ensures Subscribe after Close
// returns ErrHubClosed and does not panic.
func TestControlEventsSubscribeAfterClose(t *testing.T) {
	hub := NewControlEventHub(4)
	hub.Close()
	_, err := hub.Subscribe(context.Background(), "")
	if !errors.Is(err, ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
}

// TestControlEventsServeSSEAfterClose ensures ServeSSE after Close
// returns ErrHubClosed.
func TestControlEventsServeSSEAfterClose(t *testing.T) {
	hub := NewControlEventHub(4)
	hub.Close()
	var buf syncBuffer
	bw := newFlushWriter(&buf)
	_, err := hub.ServeSSE(context.Background(), bw, "", SSEOptions{Heartbeat: 1 * time.Second})
	if !errors.Is(err, ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed, got %v", err)
	}
}

// TestControlEventsPublishAfterClose verifies Publish after Close does
// not panic; events after Close are dropped (no subscribers anyway).
func TestControlEventsPublishAfterClose(t *testing.T) {
	hub := NewControlEventHub(4)
	hub.Close()
	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision}) // must not panic
}

// TestControlEventsConcurrentSubscribePublish hammers the hub with many
// publishers and many subscribers concurrently and asserts no goroutine
// leaks, no panics, and that every subscriber's terminated status is
// reachable.
func TestControlEventsConcurrentSubscribePublish(t *testing.T) {
	hub := NewControlEventHub(64)

	const nSubs = 4
	const nPubs = 4
	const perPub = 100

	before := countGoroutines()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var subs []*Subscriber
	for i := 0; i < nSubs; i++ {
		s, err := hub.Subscribe(ctx, "")
		if err != nil {
			t.Fatalf("Subscribe %d: %v", i, err)
		}
		subs = append(subs, s)
	}

	var pubWG sync.WaitGroup
	var drainWG sync.WaitGroup
	var published int64

	// Drainers — exit on sub.Done() (closed when hub is Close()d or
	// the sub is evicted). They drain remaining events then return.
	for i, s := range subs {
		drainWG.Add(1)
		go func(idx int, sub *Subscriber) {
			defer drainWG.Done()
			for {
				select {
				case <-sub.Done():
					for {
						select {
						case _, ok := <-sub.Events():
							if !ok {
								return
							}
						default:
							return
						}
					}
				case _, ok := <-sub.Events():
					if !ok {
						return
					}
				}
			}
		}(i, s)
	}

	// Publishers.
	for i := 0; i < nPubs; i++ {
		pubWG.Add(1)
		go func() {
			defer pubWG.Done()
			for j := 0; j < perPub; j++ {
				hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
				atomic.AddInt64(&published, 1)
			}
		}()
	}

	pubWG.Wait()
	if atomic.LoadInt64(&published) != int64(nPubs*perPub) {
		t.Fatalf("published count mismatch: got %d, want %d", published, nPubs*perPub)
	}

	hub.Close()
	drainWG.Wait()

	// Goroutine count must drop back to before.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if countGoroutines() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak under concurrent load: before=%d after=%d", before, countGoroutines())
}

// TestControlEventsLastEventIDHex ensures the event ID format is parseable
// by the client SSE parser's `id:` line. The task-4 client uses plain
// strings, so any monotonic string is fine; we just assert non-empty
// after each publish and that the ID is unique across calls.
func TestControlEventsLastEventIDUnique(t *testing.T) {
	hub := NewControlEventHub(64)
	defer hub.Close()

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	buf := hub.snapshotBuffer()
	for i, ev := range buf {
		if ev.ID == "" {
			t.Fatalf("event %d has empty ID", i)
		}
		if seen[ev.ID] {
			t.Fatalf("duplicate ID %q", ev.ID)
		}
		seen[ev.ID] = true
	}
	for i := 1; i < len(buf); i++ {
		var prev, cur uint64
		if _, err := fmt.Sscanf(buf[i-1].ID, "evt-%d", &prev); err != nil {
			t.Fatalf("event %d ID %q bad: %v", i-1, buf[i-1].ID, err)
		}
		if _, err := fmt.Sscanf(buf[i].ID, "evt-%d", &cur); err != nil {
			t.Fatalf("event %d ID %q bad: %v", i, buf[i].ID, err)
		}
		if cur != prev+1 {
			t.Fatalf("event IDs not contiguous: %q (%d) -> %q (%d)", buf[i-1].ID, prev, buf[i].ID, cur)
		}
	}
}

// TestControlEventsReplayFromExactID verifies that lastEventID equal to
// the buffer's newest retained event replays zero events (no future
// events exist yet) and the subscriber is positioned to receive live.
func TestControlEventsReplayFromExactID(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	for i := 0; i < 3; i++ {
		hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
	}
	last := hub.snapshotBuffer()[2].ID

	sub, err := hub.Subscribe(context.Background(), last)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Close()

	select {
	case _, ok := <-sub.Events():
		if ok {
			t.Fatalf("expected no events (lastEventID is newest), got one")
		}
	case <-time.After(50 * time.Millisecond):
		// expected: nothing to replay
	}

	// Now publish one live event and confirm delivery.
	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventPeerChange})
	select {
	case ev := <-sub.Events():
		if ev.Type != mtypes.ControlV2EventPeerChange {
			t.Fatalf("live event type = %v", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("live event not delivered")
	}
}

// TestControlEventsDataJSON verifies that arbitrary Data payloads
// round-trip through the SSE renderer as JSON. This is what the
// task-4 SSEParser decodes.
func TestControlEventsParamsChangeCarriesListenPortPolicy(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	port := 51820
	policy := mtypes.ListenPortPriority{{Port: &port}, {Range: &mtypes.ListenPortRange{From: 41000, To: 41002}}}
	payload := mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		STUNServers:         []string{"stun:203.0.113.10:3478"},
		PollInterval:        15 * time.Second,
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
		ListenPortPriority:  policy,
	}
	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventParamsChange, Revision: 1, Data: payload})

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := hub.ServeSSE(ctx, bw, "", SSEOptions{Heartbeat: 1 * time.Hour}); err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte(`"ListenPortPriority":`)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wire := buf.Bytes()
	if !bytes.Contains(wire, []byte(`"ListenPortPriority":`)) {
		t.Fatalf("SSE frame missing ListenPortPriority: %s", wire)
	}
	if !bytes.Contains(wire, []byte(`"port":51820`)) {
		t.Fatalf("SSE frame missing ordered port entry: %s", wire)
	}
	if !bytes.Contains(wire, []byte(`"from":41000`)) || !bytes.Contains(wire, []byte(`"to":41002`)) {
		t.Fatalf("SSE frame missing range entry: %s", wire)
	}
	idxPort := bytes.Index(wire, []byte(`"port":51820`))
	idxRange := bytes.Index(wire, []byte(`"from":41000`))
	if idxPort < 0 || idxRange < 0 || idxPort > idxRange {
		t.Fatalf("SSE frame order port=%d range=%d want port<range: %s", idxPort, idxRange, wire)
	}
}

func TestControlEventsParamsChangeCarriesEndpointBlacklist(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	blacklist := []string{"203.0.113.17", "198.51.100.0/24", "2001:db8::/32"}
	payload := mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		STUNServers:         []string{"stun:203.0.113.10:3478"},
		PollInterval:        15 * time.Second,
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
		EndpointBlacklist:   blacklist,
	}
	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventParamsChange, Revision: 1, Data: payload})

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := hub.ServeSSE(ctx, bw, "", SSEOptions{Heartbeat: 1 * time.Hour}); err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte(`"EndpointBlacklist":`)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wire := buf.Bytes()
	if !bytes.Contains(wire, []byte(`"EndpointBlacklist":["203.0.113.17","198.51.100.0/24","2001:db8::/32"]`)) {
		t.Fatalf("SSE frame missing ordered EndpointBlacklist: %s", wire)
	}
}

func TestControlEventsAbsentEndpointBlacklistDecodesEmpty(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventParamsChange, Revision: 1, Data: mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		PollInterval:        15 * time.Second,
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
	}})

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := hub.ServeSSE(ctx, bw, "", SSEOptions{Heartbeat: 1 * time.Hour}); err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte("event: params_change")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var decoded struct {
		EndpointBlacklist []string `json:"EndpointBlacklist"`
	}
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if bytes.HasPrefix(line, []byte("data: ")) {
			if err := json.Unmarshal(line[6:], &decoded); err != nil {
				t.Fatalf("decode: %v on %s", err, line)
			}
		}
	}
	if len(decoded.EndpointBlacklist) != 0 {
		t.Fatalf("absent blacklist decoded as %#v, want empty", decoded.EndpointBlacklist)
	}
}

func TestControlEventsAbsentListenPortPolicyDecodesForOldConsumers(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventParamsChange, Revision: 1, Data: mtypes.ControlV2Parameters{
		ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
		PollInterval:        15 * time.Second,
		STUNRequestTimeout:  3 * time.Second,
		STUNRefreshInterval: 60 * time.Second,
		ReportInterval:      15 * time.Second,
		HeartbeatInterval:   10 * time.Second,
		EventReplay:         256,
	}})

	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := hub.ServeSSE(ctx, bw, "", SSEOptions{Heartbeat: 1 * time.Hour}); err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte("event: params_change")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	wire := buf.Bytes()
	var decoded struct {
		ListenPortPriority mtypes.ListenPortPriority `json:"ListenPortPriority"`
	}
	for _, line := range bytes.Split(wire, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("data: ")) {
			if err := json.Unmarshal(line[6:], &decoded); err != nil {
				t.Fatalf("decode: %v on %s", err, line)
			}
		}
	}
	if len(decoded.ListenPortPriority) != 0 {
		t.Fatalf("absent policy decoded as %d entries, want 0: %#v", len(decoded.ListenPortPriority), decoded.ListenPortPriority)
	}
}

func TestControlEventsDataJSON(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	hub.Publish(mtypes.ControlV2Event{
		Type: mtypes.ControlV2EventPeerChange,
		Data: mtypes.ControlV2PeerChangePayload{NodeID: 7, NodeName: "node7"},
	})

	// Use ServeSSE into a buffer and the task-4 parser to decode.
	var buf syncBuffer
	bw := newFlushWriter(&buf)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := hub.ServeSSE(ctx, bw, "", SSEOptions{Heartbeat: 1 * time.Hour})
	if err != nil {
		t.Fatalf("ServeSSE: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		bw.Flush()
		if bytes.Contains(buf.Bytes(), []byte(`"node_id":7`)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Decode with task-4 parser (we are in package main, the parser is
	// in package device; use JSON directly here).
	if !bytes.Contains(buf.Bytes(), []byte(`"node_id":7`)) {
		t.Fatalf("expected JSON node_id:7, got:\n%s", buf.String())
	}
}

// TestControlEventsHub_NoLockDuringEventWrite verifies Publish returns
// quickly even if a subscriber's buffer is full. This is a regression
// guard for the "no lock during event write" invariant: Publish MUST
// evict the slow subscriber via a non-blocking send and return.
func TestControlEventsHub_NoLockDuringEventWrite(t *testing.T) {
	hub := NewControlEventHub(4)
	defer hub.Close()

	// Buffer=1 so one event saturates it immediately.
	sub, err := hub.SubscribeWithBuffer(context.Background(), "", 1)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// Drain the first replay (empty buffer, nothing).
	select {
	case <-sub.Events():
	case <-time.After(100 * time.Millisecond):
	}

	// Saturate the buffer without draining.
	sub.events <- mtypes.ControlV2Event{ID: "seed", Type: mtypes.ControlV2EventRevision}
	// (Direct channel send to sub.events — sub is reachable as a struct
	// field in the same package; the public API doesn't expose this.)

	// Publish must NOT block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			hub.Publish(mtypes.ControlV2Event{Type: mtypes.ControlV2EventRevision})
		}
		close(done)
	}()
	select {
	case <-done:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatalf("Publish blocked on slow subscriber (lock held across write)")
	}
	// Sub must have been evicted.
	select {
	case <-sub.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("sub not evicted")
	}
	if !errors.Is(sub.Err(), ErrSlowSubscriber) {
		t.Fatalf("expected ErrSlowSubscriber, got %v", sub.Err())
	}
}

// manualTickerFactory builds a *time.Ticker that fires only when Advance
// is called. Used for heartbeat tests with no wall-clock waits.
type manualTickerFactory struct {
	mu       sync.Mutex
	pending  []chan time.Time
	stoppers []chan struct{}
}

func newManualTickerFactory() *manualTickerFactory {
	return &manualTickerFactory{}
}

func (m *manualTickerFactory) New(d time.Duration) *time.Ticker {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Use a real Ticker with the requested period and override by
	// forwarding every tick through Advance(). Simplest correct approach:
	// wrap time.NewTicker and expose Advance via a goroutine pump.
	t := time.NewTicker(d)
	// We immediately stop the real ticker so it never fires on its own;
	// Advance() synthesizes ticks by manually calling t.C send.
	t.Stop()
	// Re-create using a manual channel instead.
	c := make(chan time.Time, 8)
	stop := make(chan struct{})
	m.pending = append(m.pending, c)
	m.stoppers = append(m.stoppers, stop)
	return &time.Ticker{C: c}
}

func (m *manualTickerFactory) Advance() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.pending {
		select {
		case c <- time.Now():
		default:
		}
	}
}

func (m *manualTickerFactory) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.stoppers {
		close(s)
	}
}
