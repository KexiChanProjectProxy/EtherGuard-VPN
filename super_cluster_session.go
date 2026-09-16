package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrClusterLinkDead      = errors.New("cluster session: link dead")
	ErrClusterSendQueueFull = errors.New("cluster session: send queue full")
	ErrClusterSessionClosed = errors.New("cluster session: closed")
)

type clusterDirectionStats struct {
	Messages        uint64 `json:"messages"`
	InnerBytes      uint64 `json:"inner_bytes"`
	CompressedBytes uint64 `json:"compressed_bytes"`
	WireBytes       uint64 `json:"wire_bytes"`
}

type clusterLinkStats struct {
	TX             clusterDirectionStats `json:"tx"`
	RX             clusterDirectionStats `json:"rx"`
	ConnectedSince time.Time             `json:"connected_since"`
	LastRXAt       time.Time             `json:"last_rx_at"`
	Dialer         bool                  `json:"dialer"`
	Compression    string                `json:"compression"`
}

type clusterSessionConfig struct {
	PeerID      mtypes.Vertex
	Dialer      bool
	Conn        io.ReadWriteCloser
	Reader      *bufio.Reader
	SendKey     [32]byte
	RecvKey     [32]byte
	Compression string
	Inbox       func(clusterEnvelope) error
	HLC         func() uint64
	ObserveHLC  func(uint64)
	OnPing      func(uint64)
	Heartbeat   time.Duration
	DeadAfter   time.Duration
	Now         func() time.Time
}

type clusterSession struct {
	peerID mtypes.Vertex
	dialer bool
	conn   io.ReadWriteCloser
	br     *bufio.Reader
	rw     *clusterRecordWriter
	rr     *clusterRecordReader
	enc    *clusterStreamEncoder
	dec    *clusterStreamDecoder

	sendCh     chan clusterEnvelope
	inbox      func(clusterEnvelope) error
	hlc        func() uint64
	observeHLC func(uint64)
	onPing     func(uint64)

	compression    string
	heartbeat      time.Duration
	deadAfter      time.Duration
	now            func() time.Time
	connectedSince atomic.Int64
	lastRX         atomic.Int64
	txWire         atomic.Uint64
	rxWire         atomic.Uint64

	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	initErr   error
}

func newClusterSession(cfg clusterSessionConfig) *clusterSession {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Inbox == nil {
		cfg.Inbox = func(clusterEnvelope) error { return nil }
	}
	if cfg.HLC == nil {
		cfg.HLC = func() uint64 { return 0 }
	}
	if cfg.Reader == nil && cfg.Conn != nil {
		cfg.Reader = bufio.NewReader(cfg.Conn)
	}
	s := &clusterSession{
		peerID: cfg.PeerID, dialer: cfg.Dialer, conn: cfg.Conn, br: cfg.Reader,
		sendCh: make(chan clusterEnvelope, 256), inbox: cfg.Inbox, hlc: cfg.HLC,
		observeHLC: cfg.ObserveHLC, onPing: cfg.OnPing, compression: cfg.Compression,
		heartbeat: cfg.Heartbeat, deadAfter: cfg.DeadAfter, now: cfg.Now, done: make(chan struct{}),
	}
	if cfg.Conn == nil || cfg.Reader == nil {
		s.initErr = errors.New("cluster session: connection and reader are required")
		return s
	}
	if cfg.Heartbeat <= 0 || cfg.DeadAfter <= 0 {
		s.initErr = errors.New("cluster session: heartbeat and dead-after must be positive")
		return s
	}
	sendAEAD, err := chacha20poly1305.New(cfg.SendKey[:])
	if err != nil {
		s.initErr = fmt.Errorf("cluster session: create send AEAD: %w", err)
		return s
	}
	recvAEAD, err := chacha20poly1305.New(cfg.RecvKey[:])
	if err != nil {
		s.initErr = fmt.Errorf("cluster session: create receive AEAD: %w", err)
		return s
	}
	s.rw = &clusterRecordWriter{w: cfg.Conn, aead: sendAEAD}
	s.rr = &clusterRecordReader{r: cfg.Reader, aead: recvAEAD}
	s.enc, err = NewClusterStreamEncoder(cfg.Compression, s.writeRecord)
	if err != nil {
		s.initErr = err
		return s
	}
	s.dec, err = NewClusterStreamDecoder(cfg.Compression, s.readRecord)
	if err != nil {
		s.initErr = err
	}
	return s
}

func (s *clusterSession) Run(ctx context.Context) error {
	if s.initErr != nil {
		_ = s.Close()
		return s.initErr
	}
	if s.closed() {
		return nil
	}
	if tcpConn, ok := s.conn.(*net.TCPConn); ok {
		if err := tcpConn.SetKeepAliveConfig(net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 10 * time.Second, Count: 3}); err != nil {
			_ = s.Close()
			return fmt.Errorf("cluster session: configure TCP keepalive: %w", err)
		}
	}
	now := s.now()
	s.connectedSince.Store(now.UnixNano())
	s.lastRX.Store(now.UnixNano())
	results := make(chan error, 2)
	go func() { results <- s.writerLoop(ctx) }()
	go func() { results <- s.readerLoop() }()
	checkEvery := s.heartbeat / 2
	if checkEvery <= 0 {
		checkEvery = s.heartbeat
	}
	deadTicker := time.NewTicker(checkEvery)
	defer deadTicker.Stop()

	remaining := 2
	var terminal error
	ctxDone := ctx.Done()
	deadCheck := deadTicker.C
	for remaining > 0 {
		select {
		case err := <-results:
			remaining--
			if err != nil && terminal == nil && !s.closed() {
				terminal = err
				_ = s.Close()
				deadCheck = nil
			}
		case <-ctxDone:
			if terminal == nil {
				terminal = ctx.Err()
			}
			_ = s.Close()
			ctxDone = nil
			deadCheck = nil
		case <-deadCheck:
			if terminal == nil && !s.closed() && s.now().Sub(loadClusterSessionTime(&s.lastRX)) > s.deadAfter {
				terminal = ErrClusterLinkDead
				_ = s.Close()
				deadCheck = nil
			}
		}
	}
	return terminal
}

func (s *clusterSession) Send(envelope clusterEnvelope) error {
	if s.closed() {
		return ErrClusterSessionClosed
	}
	select {
	case s.sendCh <- envelope:
		return nil
	default:
		return ErrClusterSendQueueFull
	}
}

func (s *clusterSession) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		if s.conn != nil {
			s.closeErr = s.conn.Close()
		}
	})
	return s.closeErr
}

func (s *clusterSession) Stats() clusterLinkStats {
	return clusterLinkStats{
		TX:             clusterDirectionStats{Messages: s.enc.Messages(), InnerBytes: s.enc.InnerBytes(), CompressedBytes: s.enc.CompressedBytes(), WireBytes: s.txWire.Load()},
		RX:             clusterDirectionStats{Messages: s.dec.Messages(), InnerBytes: s.dec.InnerBytes(), CompressedBytes: s.dec.CompressedBytes(), WireBytes: s.rxWire.Load()},
		ConnectedSince: loadClusterSessionTime(&s.connectedSince), LastRXAt: loadClusterSessionTime(&s.lastRX),
		Dialer: s.dialer, Compression: s.compression,
	}
}

func (s *clusterSession) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func loadClusterSessionTime(value *atomic.Int64) time.Time {
	if unixNano := value.Load(); unixNano != 0 {
		return time.Unix(0, unixNano).UTC()
	}
	return time.Time{}
}
