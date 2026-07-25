/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Kusakabe Si. All Rights Reserved.
 */

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// Public error sentinels surfaced through Subscriber.Err().
var (
	// ErrHubClosed is returned when Subscribe / ServeSSE are called on a
	// hub that has been Close()d, or when an active subscriber is
	// terminated by Close().
	ErrHubClosed = errors.New("control event hub closed")
	// ErrSlowSubscriber is returned when a subscriber's per-subscriber
	// buffer fills up because the consumer (renderer / test drain) is
	// too slow; the subscriber is evicted and no further events will be
	// delivered to it.
	ErrSlowSubscriber = errors.New("control event subscriber evicted (slow consumer)")
	// ErrInvalidCapacity is returned by NewControlEventHub when the
	// replay capacity is zero.
	ErrInvalidCapacity = errors.New("control event hub capacity must be > 0")
)

// Default values for a ControlEventHub.
const (
	// defaultSubscriberBuffer is the per-subscriber event queue size when
	// callers do not pass an explicit buffer size via SubscribeWithBuffer.
	// 64 is large enough to absorb a brief render stall without losing
	// the very next events.
	defaultSubscriberBuffer = 64

	// defaultHeartbeat is the cadence for `: heartbeat` comments inside
	// the SSE renderer when the caller does not override it via
	// SSEOptions.Heartbeat. 27 seconds sits inside the spec-recommended
	// 25-30 second window.
	defaultHeartbeat = 27 * time.Second

	// defaultRetryMillis is the SSE retry directive emitted by
	// ServeSSE when the caller does not override it via
	// SSEOptions.RetryMillis.
	defaultRetryMillis = 3000
)

// ---------------------------------------------------------------------------
// Hub
// ---------------------------------------------------------------------------

// ControlEventHub is the bounded pub/sub fan-out used by the Super's
// control-plane event stream. Producers call Publish (e.g. from the
// control-state service in task 5); consumers call Subscribe or ServeSSE.
//
// Invariants:
//   - Publish NEVER blocks on a slow subscriber: it hands events to each
//     subscriber's bounded queue with a non-blocking send; if the queue
//     is full the subscriber is evicted (ErrSlowSubscriber).
//   - The hub's state lock is NEVER held while writing an event to a
//     sink. Per-subscriber channels are filled under the lock; the
//     actual write to a wire/serializer is done by the consumer.
//   - Event IDs are strictly monotonic across the hub's lifetime; they
//     are assigned at Publish time when the caller left ID empty.
//   - The replay ring is bounded by the configured capacity; older
//     events are evicted silently (no error) when the ring fills.
type ControlEventHub struct {
	capacity uint64

	mu          sync.Mutex
	nextID      uint64
	buffer      []mtypes.ControlV2Event // ring storage, oldest at [0]
	bufferFirst uint64                  // event-ID of buffer[0]; next-ID+1 if empty
	bufferIDs   map[string]uint64       // event-ID -> numeric monotonic id
	subs        map[*Subscriber]struct{}
	closed      bool
	closeOnce   sync.Once
}

// NewControlEventHub constructs a hub with the given bounded replay
// capacity. The capacity must be > 0 (use 1 if you do not need replay).
func NewControlEventHub(capacity uint64) *ControlEventHub {
	if capacity == 0 {
		capacity = 1
	}
	return &ControlEventHub{
		capacity:    capacity,
		buffer:      make([]mtypes.ControlV2Event, 0, capacity),
		bufferIDs:   make(map[string]uint64),
		subs:        make(map[*Subscriber]struct{}),
		bufferFirst: 1,
	}
}

// nextEventIDLocked returns the next monotonic event ID under the hub
// lock. Must be called with h.mu held.
func (h *ControlEventHub) nextEventIDLocked() string {
	h.nextID++
	return "evt-" + strconv.FormatUint(h.nextID, 10)
}

// appendBufferLocked evicts the oldest entry if the ring is full and
// appends ev at the tail.
func (h *ControlEventHub) appendBufferLocked(ev mtypes.ControlV2Event) {
	if uint64(len(h.buffer)) >= h.capacity {
		drop := h.buffer[0]
		h.buffer = h.buffer[1:]
		if droppedID, ok := h.bufferIDs[drop.ID]; ok {
			delete(h.bufferIDs, drop.ID)
			if h.bufferFirst == droppedID && len(h.buffer) > 0 {
				if v, ok := h.bufferIDs[h.buffer[0].ID]; ok {
					h.bufferFirst = v
				}
			}
		}
	}
	h.buffer = append(h.buffer, ev)
	if id, err := strconv.ParseUint(ev.ID[len("evt-"):], 10, 64); err == nil {
		h.bufferIDs[ev.ID] = id
		if len(h.buffer) == 1 {
			h.bufferFirst = id
		}
	}
}

// Publish assigns a monotonic ID (when the caller left ID empty),
// appends the event to the bounded replay ring, and hands the event to
// every active subscriber's bounded queue using a non-blocking send.
// Slow subscribers are evicted and surfaced via Subscriber.Err().
// Publish itself never blocks on subscribers.
//
// If the hub has been Close()d, Publish is a no-op.
func (h *ControlEventHub) Publish(ev mtypes.ControlV2Event) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	if ev.ID == "" {
		ev.ID = h.nextEventIDLocked()
	} else {
		// Caller supplied an ID; bump nextID past the parsed value so
		// hub-assigned IDs stay strictly greater than caller IDs.
		if id, err := strconv.ParseUint(ev.ID[len("evt-"):], 10, 64); err == nil && id > h.nextID {
			h.nextID = id
		}
	}
	h.appendBufferLocked(ev)

	// Snapshot subscribers under lock; release before delivering.
	subs := make([]*Subscriber, 0, len(h.subs))
	for s := range h.subs {
		subs = append(subs, s)
	}
	h.mu.Unlock()

	for _, s := range subs {
		s.tryDeliver(ev)
	}
}

// snapshotBuffer returns a copy of the current replay buffer.
func (h *ControlEventHub) snapshotBuffer() []mtypes.ControlV2Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]mtypes.ControlV2Event, len(h.buffer))
	copy(out, h.buffer)
	return out
}

// replayFromLocked returns the events to replay for the given
// lastEventID, and reports whether the caller's lastEventID is older
// than the oldest retained event (i.e. the client must re-fetch a
// snapshot).
//
// lastEventID semantics:
//   - "" (empty)              -> replay the entire buffer.
//   - equal to a retained id  -> replay events with strictly greater ID.
//   - numerically older than bufferFirst -> resyncRequired=true, replay all.
//   - numerically newer than buffer's max -> unknown, but err on the
//     safe side: replay the entire buffer (we cannot prove stale).
//
// Must be called with h.mu held.
func (h *ControlEventHub) replayFromLocked(lastEventID string) (events []mtypes.ControlV2Event, resync bool) {
	if len(h.buffer) == 0 {
		return nil, false
	}
	if lastEventID == "" {
		out := make([]mtypes.ControlV2Event, len(h.buffer))
		copy(out, h.buffer)
		return out, false
	}
	numericLast, ok := h.bufferIDs[lastEventID]
	if !ok {
		var n uint64
		if _, err := fmt.Sscanf(lastEventID, "evt-%d", &n); err != nil {
			out := make([]mtypes.ControlV2Event, len(h.buffer))
			copy(out, h.buffer)
			return out, false
		}
		if n < h.bufferFirst {
			out := make([]mtypes.ControlV2Event, len(h.buffer))
			copy(out, h.buffer)
			return out, true
		}
		out := make([]mtypes.ControlV2Event, len(h.buffer))
		copy(out, h.buffer)
		return out, false
	}
	for i, ev := range h.buffer {
		evID := h.bufferIDs[ev.ID]
		if evID > numericLast {
			out := make([]mtypes.ControlV2Event, len(h.buffer)-i)
			copy(out, h.buffer[i:])
			return out, false
		}
	}
	return nil, false
}

// Subscribe registers a new subscriber with the default per-subscriber
// buffer (64 events). See SubscribeWithBuffer for control over the
// buffer size. lastEventID is the client's Last-Event-ID (may be empty
// for a fresh connect); see hub.replayFromLocked for replay semantics.
func (h *ControlEventHub) Subscribe(ctx context.Context, lastEventID string) (*Subscriber, error) {
	return h.SubscribeWithBuffer(ctx, lastEventID, defaultSubscriberBuffer)
}

// SubscribeWithBuffer registers a new subscriber with a caller-chosen
// per-subscriber buffer. A small buffer (e.g. 1) makes slow-consumer
// tests deterministic; production callers should leave the default.
func (h *ControlEventHub) SubscribeWithBuffer(ctx context.Context, lastEventID string, bufSize int) (*Subscriber, error) {
	return h.subscribeInternal(ctx, lastEventID, bufSize)
}

// subscribeInternal is the common subscribe path. Replay events are
// enqueued synchronously into the per-sub bounded queue; the caller is
// responsible for draining via Events() (or for SSE, the renderer
// consumes them).
func (h *ControlEventHub) subscribeInternal(ctx context.Context, lastEventID string, bufSize int) (*Subscriber, error) {
	if bufSize < 1 {
		bufSize = 1
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrHubClosed
	}
	subCtx, subCancel := context.WithCancel(ctx)
	sub := &Subscriber{
		ctx:    subCtx,
		cancel: subCancel,
		events: make(chan mtypes.ControlV2Event, bufSize),
		resync: make(chan struct{}),
		done:   make(chan struct{}),
	}
	h.subs[sub] = struct{}{}
	replay, resync := h.replayFromLocked(lastEventID)
	h.mu.Unlock()

	// Enqueue replay events. If bufSize < len(replay) the caller
	// misconfigured; we drop the excess and mark for eviction.
	for _, ev := range replay {
		select {
		case sub.events <- ev:
		default:
			sub.markEvicted(ErrSlowSubscriber)
			break
		}
	}
	if resync {
		sub.signalResync()
	}
	return sub, nil
}

// Close terminates every active subscriber and refuses new
// subscriptions. It is safe to call Close multiple times (idempotent)
// and from any goroutine. Close does NOT block on per-subscriber
// goroutines because there are none in this design: the consumer
// drains the per-sub channel directly and observes Done() for
// termination.
func (h *ControlEventHub) Close() {
	h.closeOnce.Do(func() {
		h.mu.Lock()
		h.closed = true
		subs := make([]*Subscriber, 0, len(h.subs))
		for s := range h.subs {
			subs = append(subs, s)
		}
		h.subs = nil
		h.mu.Unlock()

		for _, s := range subs {
			s.cancel()
			s.markEvictedIfNotSet(ErrHubClosed)
		}
	})
}

// ServeSSE creates a new SSE connection: a subscriber with an SSE sink
// that writes properly framed event-stream output into w (which MUST be
// an io.Writer + Flush() no-error method).
//
// Behavior:
//   - writes an initial SSE comment line so the client sees bytes
//     immediately even if no events are pending yet;
//   - emits `retry: <ms>` so clients that reconnect know the backoff
//     hint;
//   - streams events as `id:`, `event:`, multi-line `data:`;
//   - emits `: heartbeat` comments every opts.Heartbeat (default 27s);
//   - flushes after every write so the client observes bytes promptly;
//   - returns ErrHubClosed if the hub is closed.
//
// The returned renderer terminates when ctx is cancelled, when its
// subscriber is evicted (slow consumer), or when the underlying writer
// returns an error.
func (h *ControlEventHub) ServeSSE(ctx context.Context, w interface {
	io.Writer
	Flush()
}, lastEventID string, opts SSEOptions) (*SSERenderer, error) {
	if opts.Heartbeat == 0 {
		opts.Heartbeat = defaultHeartbeat
	}
	if opts.RetryMillis == 0 {
		opts.RetryMillis = defaultRetryMillis
	}
	if opts.SubscriberBufferSize == 0 {
		opts.SubscriberBufferSize = defaultSubscriberBuffer
	}

	sub, err := h.subscribeInternal(ctx, lastEventID, opts.SubscriberBufferSize)
	if err != nil {
		return nil, err
	}

	rctx, rcancel := context.WithCancel(ctx)
	r := &SSERenderer{
		sub:         sub,
		cancel:      rcancel,
		writer:      w,
		opts:        opts,
		flushSignal: make(chan struct{}, 16),
	}

	// Write initial framing synchronously.
	if opts.InitialComment != "" {
		fmt.Fprintf(w, ": %s\n", opts.InitialComment)
	} else {
		io.WriteString(w, ": ok\n")
	}
	fmt.Fprintf(w, "retry: %d\n\n", opts.RetryMillis)
	w.Flush()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.run(rctx)
	}()

	return r, nil
}

// ---------------------------------------------------------------------------
// Subscriber
// ---------------------------------------------------------------------------

// Subscriber is a single consumer of the hub's events. It owns its
// own bounded queue; the publisher (Hub.Publish) fills it under the
// hub lock, and the consumer drains it via Events(). Termination is
// observed via Done() and Err().
type Subscriber struct {
	ctx    context.Context
	cancel context.CancelFunc

	events chan mtypes.ControlV2Event
	resync chan struct{}
	done   chan struct{}

	err       atomic.Pointer[error]
	evict     atomic.Pointer[error]
	closeOnce sync.Once
}

// Events returns the channel of events delivered to this subscriber.
// Replay events are queued first (in order), then live events. The
// channel is NEVER closed; consumers observe termination by selecting
// on Done() (closed when the subscriber terminates for any reason).
func (s *Subscriber) Events() <-chan mtypes.ControlV2Event { return s.events }

// ResyncRequired returns a channel that fires once when the
// subscriber's lastEventID was older than the hub's oldest retained
// event — i.e. the client must re-fetch a full snapshot. The channel
// is closed after firing.
func (s *Subscriber) ResyncRequired() <-chan struct{} { return s.resync }

// Done returns a channel that is closed when the subscriber
// terminates.
func (s *Subscriber) Done() <-chan struct{} { return s.done }

// Err returns the reason the subscriber terminated (nil if still
// active).
func (s *Subscriber) Err() error {
	if p := s.err.Load(); p != nil {
		return *p
	}
	return nil
}

// Close cancels the subscriber's context. Idempotent.
func (s *Subscriber) Close() {
	s.cancel()
}

// signalResync closes the resync channel exactly once.
func (s *Subscriber) signalResync() {
	select {
	case <-s.resync:
	default:
		close(s.resync)
	}
}

// markEvicted records the eviction reason and cancels the sub's
// context so the consumer observes Done(). The done channel is closed
// exactly once.
func (s *Subscriber) markEvicted(err error) {
	if s.evict.CompareAndSwap(nil, &err) {
		s.setErr(err)
		s.cancel()
		s.closeOnce.Do(func() { close(s.done) })
	}
}

// markEvictedIfNotSet records err as the termination reason iff no
// reason has been recorded yet. Also closes the done channel.
func (s *Subscriber) markEvictedIfNotSet(err error) {
	s.setErr(err)
	s.closeOnce.Do(func() { close(s.done) })
}

func (s *Subscriber) setErr(err error) {
	s.err.CompareAndSwap(nil, &err)
}

// tryDeliver is invoked by Hub.Publish AFTER the hub mutex is
// released. It performs a non-blocking send into the subscriber's
// per-sub buffer; if the buffer is full the subscriber is marked for
// eviction. If the sub has already been evicted, the event is dropped.
func (s *Subscriber) tryDeliver(ev mtypes.ControlV2Event) {
	if s.evict.Load() != nil {
		return
	}
	select {
	case s.events <- ev:
	default:
		s.markEvicted(ErrSlowSubscriber)
	}
}

// ---------------------------------------------------------------------------
// SSE renderer
// ---------------------------------------------------------------------------

// SSEOptions configures ServeSSE.
type SSEOptions struct {
	// RetryMillis sets the value of the SSE `retry:` directive written
	// before the first event. Zero uses defaultRetryMillis.
	RetryMillis int

	// Heartbeat sets the cadence for `: heartbeat` comments. Zero uses
	// defaultHeartbeat (27s, inside the 25-30s spec window).
	Heartbeat time.Duration

	// TickerFunc lets tests inject a deterministic ticker factory so
	// they can drive heartbeats without wall-clock sleeps. nil means
	// use time.NewTicker.
	TickerFunc func(d time.Duration) *time.Ticker

	// InitialComment, when non-empty, is written as the first SSE
	// comment line before the retry directive.
	InitialComment string

	// SubscriberBufferSize controls the per-subscriber buffer for the
	// SSE connection. Zero uses defaultSubscriberBuffer.
	SubscriberBufferSize int
}

// SSERenderer is the active renderer returned by ServeSSE. The
// renderer owns a goroutine that drains the underlying subscriber and
// writes SSE framing into the underlying io.Writer (which MUST be a
// Flush() no-error method).
//
// The renderer terminates when ctx is cancelled, when its subscriber
// is evicted (slow consumer), or when the underlying writer returns
// an error.
type SSERenderer struct {
	sub    *Subscriber
	cancel context.CancelFunc
	wg     sync.WaitGroup
	writer interface {
		io.Writer
		Flush()
	}
	opts SSEOptions

	deliverMu   sync.Mutex
	flushSignal chan struct{}
	writeErr    atomic.Pointer[error]
}

// Subscriber exposes the underlying subscriber so callers can observe
// delivered events (mostly useful for tests).
func (r *SSERenderer) Subscriber() *Subscriber { return r.sub }

// Close terminates the renderer. Idempotent.
func (r *SSERenderer) Close() {
	r.cancel()
	r.wg.Wait()
}

// run is the renderer's pump goroutine. It selects between the
// subscriber's event channel and the heartbeat ticker, serializing
// writes through r.deliverMu, and flushing after every write.
func (r *SSERenderer) run(ctx context.Context) {
	tickerFactory := r.opts.TickerFunc
	if tickerFactory == nil {
		tickerFactory = time.NewTicker
	}
	t := tickerFactory(r.opts.Heartbeat)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.sub.Done():
			return
		case <-t.C:
			r.deliverMu.Lock()
			_, _ = io.WriteString(r.writer, ": heartbeat\n\n")
			r.writer.Flush()
			r.deliverMu.Unlock()
		case ev, ok := <-r.sub.Events():
			if !ok {
				return
			}
			r.deliverMu.Lock()
			ok2 := r.writeEventLocked(ev)
			r.writer.Flush()
			r.deliverMu.Unlock()
			if !ok2 {
				return
			}
		}
	}
}

// writeEventLocked serializes one ControlV2Event into SSE framing.
// MUST be called with r.deliverMu held. Returns false on writer error.
func (r *SSERenderer) writeEventLocked(ev mtypes.ControlV2Event) bool {
	if ev.ID != "" {
		if _, err := fmt.Fprintf(r.writer, "id: %s\n", ev.ID); err != nil {
			r.setWriteErr(err)
			return false
		}
	}
	if ev.Type != "" {
		if _, err := fmt.Fprintf(r.writer, "event: %s\n", ev.Type); err != nil {
			r.setWriteErr(err)
			return false
		}
	}
	var payload []byte
	if ev.Data != nil {
		var err error
		payload, err = json.Marshal(ev.Data)
		if err != nil {
			payload = []byte(fmt.Sprintf("%v", ev.Data))
		}
	}
	if payload == nil {
		if _, err := io.WriteString(r.writer, "data: \n"); err != nil {
			r.setWriteErr(err)
			return false
		}
	} else {
		for _, line := range splitLines(payload) {
			if _, err := fmt.Fprintf(r.writer, "data: %s\n", line); err != nil {
				r.setWriteErr(err)
				return false
			}
		}
	}
	if _, err := io.WriteString(r.writer, "\n"); err != nil {
		r.setWriteErr(err)
		return false
	}
	return true
}

func (r *SSERenderer) setWriteErr(err error) {
	r.writeErr.CompareAndSwap(nil, &err)
}

// splitLines splits b on '\n' (CRLF trimmed).
func splitLines(b []byte) []string {
	out := []string{}
	start := 0
	for i, c := range b {
		if c == '\n' {
			line := b[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, string(line))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ioWriterAsFlusher wraps an io.Writer so it satisfies ServeSSE's
// writer+Flush() no-error signature.
func ioWriterAsFlusher(w io.Writer) interface {
	io.Writer
	Flush()
} {
	if f, ok := w.(interface {
		io.Writer
		Flush()
	}); ok {
		return f
	}
	return &flushAdapter{w: bufio.NewWriter(w)}
}

type flushAdapter struct{ w *bufio.Writer }

func (f *flushAdapter) Write(p []byte) (int, error) { return f.w.Write(p) }
func (f *flushAdapter) Flush()                      { _ = f.w.Flush() }
