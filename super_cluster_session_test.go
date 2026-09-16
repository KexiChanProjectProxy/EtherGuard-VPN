package main

import (
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestClusterSessionPipeRoundTrip(t *testing.T) {
	baseline := runtime.NumGoroutine()
	receivedA := make(chan clusterEnvelope, 1)
	receivedB := make(chan clusterEnvelope, 1)
	a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{mode: "zstd", heartbeat: time.Hour, deadAfter: 2 * time.Hour, inboxA: receivedA, inboxB: receivedB})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	runA := runClusterSession(ctx, a)
	runB := runClusterSession(ctx, b)

	for i := 1; i <= 1000; i++ {
		envelopeA := clusterEnvelope{T: clusterMessagePeerDelete, Delete: &clusterDelete{NodeID: mtypes.Vertex(i), Version: ClusterVersion{HLC: uint64(i), Origin: 1}}, HLC: uint64(i)}
		envelopeB := clusterEnvelope{T: clusterMessagePeerDelete, Delete: &clusterDelete{NodeID: mtypes.Vertex(i + 1000), Version: ClusterVersion{HLC: uint64(i), Origin: 2}}, HLC: uint64(i)}
		if err := a.Send(envelopeA); err != nil {
			t.Fatalf("send A envelope %d: %v", i, err)
		}
		if err := b.Send(envelopeB); err != nil {
			t.Fatalf("send B envelope %d: %v", i, err)
		}
		if got := waitClusterEnvelope(t, receivedB, time.Second); got.HLC != uint64(i) {
			t.Fatalf("B envelope HLC = %d, want %d", got.HLC, i)
		}
		if got := waitClusterEnvelope(t, receivedA, time.Second); got.HLC != uint64(i) {
			t.Fatalf("A envelope HLC = %d, want %d", got.HLC, i)
		}
	}

	if got := a.Stats().TX.Messages; got != 1001 {
		t.Fatalf("A TX messages = %d, want 1001 (hello + 1000 payloads)", got)
	}
	if got := b.Stats().TX.Messages; got != 1001 {
		t.Fatalf("B TX messages = %d, want 1001 (hello + 1000 payloads)", got)
	}
	closeClusterSessionPair(t, a, b, runA, runB)
	assertClusterSessionGoroutines(t, baseline)
}

func TestClusterSessionPingPongKeepsAlive(t *testing.T) {
	baseline := runtime.NumGoroutine()
	var pingsA atomic.Uint64
	var pingsB atomic.Uint64
	a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{
		mode: "none", heartbeat: 20 * time.Millisecond, deadAfter: 100 * time.Millisecond,
		onPingA: func(uint64) { pingsA.Add(1) }, onPingB: func(uint64) { pingsB.Add(1) },
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runA := runClusterSession(ctx, a)
	runB := runClusterSession(ctx, b)

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-runA:
		t.Fatalf("A closed while heartbeat traffic was active: %v", err)
	case err := <-runB:
		t.Fatalf("B closed while heartbeat traffic was active: %v", err)
	case <-timer.C:
	}
	if got := pingsA.Load() + pingsB.Load(); got < 10 {
		t.Fatalf("received pings = %d, want at least 10", got)
	}

	closeClusterSessionPair(t, a, b, runA, runB)
	assertClusterSessionGoroutines(t, baseline)
}

func TestClusterSessionStaleLogicalClockKeepsSocketDeadlineAlive(t *testing.T) {
	// Given: both peers use a deliberately stale logical clock while real time advances.
	stale := time.Now().Add(-time.Hour)
	a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{
		mode: "none", heartbeat: 20 * time.Millisecond, deadAfter: 100 * time.Millisecond,
		now: func() time.Time { return stale },
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	runA := runClusterSession(ctx, a)
	runB := runClusterSession(ctx, b)

	// When: heartbeat traffic refreshes each socket's read deadline.
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-runA:
		t.Fatalf("A closed because stale logical time produced an expired socket deadline: %v", err)
	case err := <-runB:
		t.Fatalf("B closed because stale logical time produced an expired socket deadline: %v", err)
	case <-timer.C:
	}

	// Then: the session remains healthy until explicitly closed.
	closeClusterSessionPair(t, a, b, runA, runB)
}

func TestClusterSessionCountersMonotonic(t *testing.T) {
	for _, mode := range []string{"zstd", "none"} {
		t.Run(mode, func(t *testing.T) {
			received := make(chan clusterEnvelope, 1)
			a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{mode: mode, heartbeat: time.Hour, deadAfter: 2 * time.Hour, inboxB: received})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			runA := runClusterSession(ctx, a)
			runB := runClusterSession(ctx, b)
			payload := strings.Repeat("compressible-cluster-payload-", 256)

			for i := 0; i < 64; i++ {
				envelope := clusterEnvelope{T: clusterMessagePeerUpsert, Peer: &clusterPeerRecord{NodeID: 101, NodeName: payload, PubKey: payload, Version: ClusterVersion{HLC: uint64(i + 1), Origin: 1}}, HLC: uint64(i + 1)}
				if err := a.Send(envelope); err != nil {
					t.Fatalf("send repetitive envelope %d: %v", i, err)
				}
				_ = waitClusterEnvelope(t, received, time.Second)
			}

			stats := a.Stats().TX
			if stats.WireBytes < stats.CompressedBytes+20*stats.Messages {
				t.Fatalf("wire bytes = %d, compressed = %d, messages = %d", stats.WireBytes, stats.CompressedBytes, stats.Messages)
			}
			if mode == "zstd" && stats.InnerBytes < stats.CompressedBytes {
				t.Fatalf("zstd inner bytes = %d, compressed bytes = %d", stats.InnerBytes, stats.CompressedBytes)
			}
			if mode == "none" && stats.InnerBytes != stats.CompressedBytes {
				t.Fatalf("none inner bytes = %d, compressed bytes = %d", stats.InnerBytes, stats.CompressedBytes)
			}
			closeClusterSessionPair(t, a, b, runA, runB)
		})
	}
}

func TestClusterSessionDeadPeerCloses(t *testing.T) {
	baseline := runtime.NumGoroutine()
	local, peer := newClusterSessionTestEndpoint(t, clusterSessionTestEndpointConfig{mode: "none", heartbeat: 20 * time.Millisecond, deadAfter: 100 * time.Millisecond})
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	run := runClusterSession(ctx, local)

	err := waitClusterSessionRun(t, run, 500*time.Millisecond)
	if !errors.Is(err, ErrClusterLinkDead) {
		t.Fatalf("Run error = %v, want ErrClusterLinkDead", err)
	}
	assertClusterSessionGoroutines(t, baseline)
}

func TestClusterSessionTamperCloses(t *testing.T) {
	baseline := runtime.NumGoroutine()
	a, b := newTamperedClusterSessionTestPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runA := runClusterSession(ctx, a)
	runB := runClusterSession(ctx, b)

	if err := a.Send(clusterEnvelope{T: clusterMessagePing, HLC: 1}); err != nil {
		t.Fatalf("send tampered envelope: %v", err)
	}
	errA := waitClusterSessionRun(t, runA, time.Second)
	errB := waitClusterSessionRun(t, runB, time.Second)
	if errA == nil || errB == nil {
		t.Fatalf("tampered session errors = (%v, %v), want both non-nil", errA, errB)
	}
	if !errors.Is(errA, ErrClusterAuthFailed) && !errors.Is(errB, ErrClusterAuthFailed) {
		t.Fatalf("tampered session errors = (%v, %v), want one ErrClusterAuthFailed", errA, errB)
	}
	assertClusterSessionGoroutines(t, baseline)
}

func TestClusterSessionRejectsNonHelloFirstMessage(t *testing.T) {
	t.Run("non_hello_first_closes", func(t *testing.T) {
		// Given: a live session pair that has not exchanged hello.
		received := make(chan clusterEnvelope, 1)
		a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{
			mode: "none", heartbeat: time.Hour, deadAfter: 2 * time.Hour, inboxB: received, skipHello: true,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		runA := runClusterSession(ctx, a)
		runB := runClusterSession(ctx, b)

		// When: the first inbound envelope is a ping rather than hello.
		if err := a.Send(clusterEnvelope{T: clusterMessagePing, HLC: 1}); err != nil {
			t.Fatalf("send non-hello first message: %v", err)
		}

		// Then: the receiver closes with ErrClusterFirstMessageNotHello and does not inbox the ping.
		errB := waitClusterSessionRun(t, runB, time.Second)
		if !errors.Is(errB, ErrClusterFirstMessageNotHello) {
			t.Fatalf("B Run error = %v, want ErrClusterFirstMessageNotHello", errB)
		}
		select {
		case envelope := <-received:
			t.Fatalf("inbox received %q after non-hello first message", envelope.T)
		default:
		}
		_ = a.Close()
		_ = waitClusterSessionRun(t, runA, time.Second)
	})

	t.Run("hello_first_then_payload_continues", func(t *testing.T) {
		// Given: both sides queue hello as the first inner message.
		received := make(chan clusterEnvelope, 1)
		a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{
			mode: "none", heartbeat: time.Hour, deadAfter: 2 * time.Hour, inboxB: received,
		})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		runA := runClusterSession(ctx, a)
		runB := runClusterSession(ctx, b)

		// When: a non-hello payload follows the hello exchange.
		payload := clusterEnvelope{
			T:      clusterMessagePeerDelete,
			Delete: &clusterDelete{NodeID: 7, Version: ClusterVersion{HLC: 2, Origin: 1}},
			HLC:    2,
		}
		if err := a.Send(payload); err != nil {
			t.Fatalf("send payload after hello: %v", err)
		}

		// Then: the session stays up and delivers the payload.
		got := waitClusterEnvelope(t, received, time.Second)
		if got.T != clusterMessagePeerDelete || got.HLC != 2 {
			t.Fatalf("payload = %+v, want peer_delete HLC 2", got)
		}
		closeClusterSessionPair(t, a, b, runA, runB)
	})
}

func TestClusterSessionSendQueueFull(t *testing.T) {
	session, peer := newClusterSessionTestEndpoint(t, clusterSessionTestEndpointConfig{mode: "none", heartbeat: time.Hour, deadAfter: 2 * time.Hour})
	defer peer.Close()
	defer session.Close()

	for i := 0; i < 256; i++ {
		if err := session.Send(clusterEnvelope{T: clusterMessagePing, HLC: uint64(i + 1)}); err != nil {
			t.Fatalf("Send %d returned %v", i+1, err)
		}
	}
	if err := session.Send(clusterEnvelope{T: clusterMessagePing, HLC: 257}); !errors.Is(err, ErrClusterSendQueueFull) {
		t.Fatalf("257th Send error = %v, want ErrClusterSendQueueFull", err)
	}
}

func TestClusterSessionDrainsQueuedHelloBeforeHeartbeatTicker(t *testing.T) {
	// Given: hello and a follow-up envelope are already queued, and the heartbeat
	// channel is fireable from the first select (buffered tick waiting).
	session, peer := newClusterSessionTestEndpoint(t, clusterSessionTestEndpointConfig{mode: "none", heartbeat: time.Hour, deadAfter: 2 * time.Hour})
	defer peer.Close()
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	queueClusterSessionHello(t, session, 2)
	if err := session.Send(clusterEnvelope{
		T:      clusterMessagePeerDelete,
		Delete: &clusterDelete{NodeID: 7, Version: ClusterVersion{HLC: 2, Origin: 1}},
		HLC:    2,
	}); err != nil {
		t.Fatalf("queue follow-up envelope: %v", err)
	}
	if queued := len(session.sendCh); queued != 2 {
		t.Fatalf("queued envelopes = %d, want 2", queued)
	}
	readyTick := make(chan time.Time, 1)
	readyTick <- time.Time{}
	tickerCreated := make(chan int, 1)
	session.newHeartbeatTicker = func(time.Duration) (<-chan time.Time, func()) {
		tickerCreated <- len(session.sendCh)
		return readyTick, func() {}
	}

	// When: Run starts the writer, which must drain sendCh before creating the ticker.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	run := runClusterSession(ctx, session)

	// Then: the ticker factory observes an empty sendCh, so hello cannot lose a select to ping.
	select {
	case queued := <-tickerCreated:
		if queued != 0 {
			t.Fatalf("heartbeat ticker created with %d envelopes still queued; drainSendQueue must empty sendCh first", queued)
		}
	case err := <-run:
		t.Fatalf("session exited before heartbeat ticker was created: %v", err)
	}
	_ = session.Close()
	_ = waitClusterSessionRun(t, run, time.Second)
}

func TestClusterSessionFreezeReaderStopsBlockedReadWithoutClosing(t *testing.T) {
	// Given: a live pair with no heartbeats, so B's reader stays blocked in ReadMessage
	// after hello. Freeze must not wait for the next envelope or the dead-after timeout.
	baseline := runtime.NumGoroutine()
	a, b := newClusterSessionTestPair(t, clusterSessionTestPairConfig{
		mode: "none", heartbeat: time.Hour, deadAfter: 2 * time.Hour,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runA := runClusterSession(ctx, a)
	runB := runClusterSession(ctx, b)
	waitClusterSessionRX(t, a, 1, time.Second)
	waitClusterSessionRX(t, b, 1, time.Second)

	// When: freeze is requested while B is blocked on the next record.
	b.FreezeReaderForTest()

	// Then: the reader parks without closing the underlying session.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for !b.readerFrozen.Load() {
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("reader did not freeze while blocked on ReadMessage")
		case err := <-runB:
			t.Fatalf("B closed instead of freezing: %v", err)
		}
	}
	if b.closed() {
		t.Fatal("freezing the blocked reader closed the session")
	}

	closeClusterSessionPair(t, a, b, runA, runB)
	assertClusterSessionGoroutines(t, baseline)
}
