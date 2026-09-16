package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clusterSessionTestKeys struct {
	aSend [32]byte
	aRecv [32]byte
	bSend [32]byte
	bRecv [32]byte
}

type clusterSessionTestPairConfig struct {
	mode      string
	heartbeat time.Duration
	deadAfter time.Duration
	inboxA    chan<- clusterEnvelope
	inboxB    chan<- clusterEnvelope
	onPingA   func(uint64)
	onPingB   func(uint64)
}

type clusterSessionTestEndpointConfig struct {
	mode      string
	heartbeat time.Duration
	deadAfter time.Duration
	inbox     chan<- clusterEnvelope
	onPing    func(uint64)
}

func newClusterSessionTestKeys(t *testing.T) clusterSessionTestKeys {
	t.Helper()
	a := mustClusterEphemeral(t)
	b := mustClusterEphemeral(t)
	secret := []byte("cluster session test shared secret")
	aSend, aRecv, err := deriveClusterKeys(secret, a.priv, b.pub, a.pub, b.pub, "session-test-nonce", true)
	if err != nil {
		t.Fatalf("derive A keys: %v", err)
	}
	bSend, bRecv, err := deriveClusterKeys(secret, b.priv, a.pub, a.pub, b.pub, "session-test-nonce", false)
	if err != nil {
		t.Fatalf("derive B keys: %v", err)
	}
	return clusterSessionTestKeys{aSend: aSend, aRecv: aRecv, bSend: bSend, bRecv: bRecv}
}

func newClusterSessionTestPair(
	t *testing.T,
	cfg clusterSessionTestPairConfig,
) (*clusterSession, *clusterSession) {
	t.Helper()
	connA, connB := net.Pipe()
	keys := newClusterSessionTestKeys(t)
	var hlcA atomic.Uint64
	var hlcB atomic.Uint64
	a := newClusterSession(clusterSessionConfig{
		PeerID: 2, Dialer: true, Conn: connA, Reader: bufio.NewReader(connA), SendKey: keys.aSend, RecvKey: keys.aRecv,
		Compression: cfg.mode, Heartbeat: cfg.heartbeat, DeadAfter: cfg.deadAfter, Now: time.Now, HLC: func() uint64 { return hlcA.Add(1) },
		Inbox: clusterSessionTestInbox(cfg.inboxA), OnPing: cfg.onPingA,
	})
	b := newClusterSession(clusterSessionConfig{
		PeerID: 1, Dialer: false, Conn: connB, Reader: bufio.NewReader(connB), SendKey: keys.bSend, RecvKey: keys.bRecv,
		Compression: cfg.mode, Heartbeat: cfg.heartbeat, DeadAfter: cfg.deadAfter, Now: time.Now, HLC: func() uint64 { return hlcB.Add(1) },
		Inbox: clusterSessionTestInbox(cfg.inboxB), OnPing: cfg.onPingB,
	})
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func newClusterSessionTestEndpoint(t *testing.T, cfg clusterSessionTestEndpointConfig) (*clusterSession, io.ReadWriteCloser) {
	t.Helper()
	conn, peer := net.Pipe()
	keys := newClusterSessionTestKeys(t)
	var hlc atomic.Uint64
	session := newClusterSession(clusterSessionConfig{
		PeerID: 2, Dialer: true, Conn: conn, Reader: bufio.NewReader(conn), SendKey: keys.aSend, RecvKey: keys.aRecv,
		Compression: cfg.mode, Heartbeat: cfg.heartbeat, DeadAfter: cfg.deadAfter, Now: time.Now, HLC: func() uint64 { return hlc.Add(1) },
		Inbox: clusterSessionTestInbox(cfg.inbox), OnPing: cfg.onPing,
	})
	t.Cleanup(func() { _ = session.Close() })
	return session, peer
}

func newTamperedClusterSessionTestPair(t *testing.T) (*clusterSession, *clusterSession) {
	t.Helper()
	connA, connB := net.Pipe()
	keys := newClusterSessionTestKeys(t)
	flipped := &clusterFlipWriteConn{ReadWriteCloser: connA}
	a := newClusterSession(clusterSessionConfig{PeerID: 2, Dialer: true, Conn: flipped, Reader: bufio.NewReader(flipped), SendKey: keys.aSend, RecvKey: keys.aRecv, Compression: "none", Heartbeat: time.Hour, DeadAfter: 2 * time.Hour, Now: time.Now})
	b := newClusterSession(clusterSessionConfig{PeerID: 1, Conn: connB, Reader: bufio.NewReader(connB), SendKey: keys.bSend, RecvKey: keys.bRecv, Compression: "none", Heartbeat: time.Hour, DeadAfter: 2 * time.Hour, Now: time.Now})
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
	})
	return a, b
}

func clusterSessionTestInbox(ch chan<- clusterEnvelope) func(clusterEnvelope) error {
	if ch == nil {
		return nil
	}
	return func(envelope clusterEnvelope) error {
		ch <- envelope
		return nil
	}
}

func runClusterSession(ctx context.Context, session *clusterSession) <-chan error {
	result := make(chan error, 1)
	go func() { result <- session.Run(ctx) }()
	return result
}

func waitClusterEnvelope(t *testing.T, ch <-chan clusterEnvelope, timeout time.Duration) clusterEnvelope {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case envelope := <-ch:
		return envelope
	case <-timer.C:
		t.Fatal("timed out waiting for cluster envelope")
		return clusterEnvelope{}
	}
}

func waitClusterSessionRun(t *testing.T, result <-chan error, timeout time.Duration) error {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		t.Fatal("timed out waiting for cluster session Run")
		return nil
	}
}

func closeClusterSessionPair(t *testing.T, a, b *clusterSession, runA, runB <-chan error) {
	t.Helper()
	if err := a.Close(); err != nil {
		t.Fatalf("close A: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("close B: %v", err)
	}
	if err := waitClusterSessionRun(t, runA, time.Second); err != nil {
		t.Fatalf("A Run after clean close: %v", err)
	}
	if err := waitClusterSessionRun(t, runB, time.Second); err != nil {
		t.Fatalf("B Run after clean close: %v", err)
	}
}

func assertClusterSessionGoroutines(t *testing.T, baseline int) {
	t.Helper()
	if got := runtime.NumGoroutine(); got > baseline+2 {
		t.Fatalf("goroutine count = %d, baseline = %d", got, baseline)
	}
}

type clusterFlipWriteConn struct {
	io.ReadWriteCloser
	mu      sync.Mutex
	writes  int
	flipped bool
}

func (c *clusterFlipWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	if !c.flipped && c.writes == 2 && len(p) > 0 {
		p = append([]byte(nil), p...)
		p[0] ^= 0x80
		c.flipped = true
	}
	c.mu.Unlock()
	return c.ReadWriteCloser.Write(p)
}
