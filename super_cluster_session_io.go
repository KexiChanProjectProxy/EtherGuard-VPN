package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func (s *clusterSession) writerLoop(ctx context.Context) error {
	if err := s.drainSendQueue(); err != nil {
		return err
	}
	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case envelope := <-s.sendCh:
			if err := s.writeEnvelope(envelope); err != nil {
				return err
			}
		case <-ticker.C:
			if err := s.writeEnvelope(clusterEnvelope{T: clusterMessagePing, HLC: s.hlc()}); err != nil {
				return err
			}
		}
	}
}

func (s *clusterSession) drainSendQueue() error {
	for {
		select {
		case envelope := <-s.sendCh:
			if err := s.writeEnvelope(envelope); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (s *clusterSession) readerLoop() error {
	for {
		if s.freezeReader.Load() {
			s.readerFrozen.Store(true)
			<-s.done
			return nil
		}
		message, err := s.dec.ReadMessage()
		if err != nil {
			if s.closed() {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return ErrClusterLinkDead
			}
			return fmt.Errorf("cluster session: read message: %w", err)
		}
		envelope, err := decodeClusterEnvelope(message)
		if err != nil {
			return err
		}
		if !s.helloReceived {
			s.firstInbound.Store(envelope.T)
			if envelope.T != clusterMessageHello {
				return fmt.Errorf("cluster session: first message %q: %w", envelope.T, ErrClusterFirstMessageNotHello)
			}
			s.helloReceived = true
		}
		if s.observeHLC != nil {
			s.observeHLC(envelope.HLC)
		}
		switch envelope.T {
		case clusterMessagePing:
			if s.onPing != nil {
				s.onPing(envelope.HLC)
			}
			if err := s.Send(clusterEnvelope{T: clusterMessagePong, HLC: s.hlc()}); err != nil {
				return err
			}
		case clusterMessagePong:
			continue
		default:
			// Inbox handlers must apply state quickly and return; the reader calls them synchronously.
			if err := s.inbox(envelope); err != nil {
				return fmt.Errorf("cluster session: inbox: %w", err)
			}
		}
	}
}

func (s *clusterSession) writeEnvelope(envelope clusterEnvelope) error {
	encoded, err := encodeClusterEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := s.enc.WriteMessage(encoded); err != nil {
		return fmt.Errorf("cluster session: write message: %w", err)
	}
	return nil
}

func (s *clusterSession) writeRecord(plain []byte) error {
	before := s.rw.wire
	err := s.rw.WriteRecord(plain)
	s.txWire.Add(s.rw.wire - before)
	return err
}

func (s *clusterSession) readRecord() ([]byte, error) {
	before := s.rr.wire
	plain, err := s.rr.ReadRecord()
	s.rxWire.Add(s.rr.wire - before)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.lastRX.Store(now.UnixNano())
	if netConn, ok := s.conn.(net.Conn); ok {
		if err := netConn.SetReadDeadline(s.wallNow().Add(s.deadAfter)); err != nil {
			return nil, fmt.Errorf("cluster session: set read deadline: %w", err)
		}
	}
	return plain, nil
}
