package main

import (
	"context"
	"errors"
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

	if got := a.Stats().TX.Messages; got != 1000 {
		t.Fatalf("A TX messages = %d, want 1000", got)
	}
	if got := b.Stats().TX.Messages; got != 1000 {
		t.Fatalf("B TX messages = %d, want 1000", got)
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
