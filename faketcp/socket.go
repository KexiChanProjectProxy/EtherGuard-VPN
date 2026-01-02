// SPDX-License-Identifier: MIT
package faketcp

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ConnTimeout       = 3 * time.Second
	RetryCount        = 6
	MaxUnackedLen     = 128 * 1024 * 1024 // 128MB
	IncomingQueueSize = 512
)

// ConnState represents the TCP connection state
type ConnState int

const (
	StateIdle ConnState = iota
	StateSynSent
	StateSynReceived
	StateEstablished
	StateClosed
)

func (s ConnState) String() string {
	switch s {
	case StateIdle:
		return "Idle"
	case StateSynSent:
		return "SynSent"
	case StateSynReceived:
		return "SynReceived"
	case StateEstablished:
		return "Established"
	case StateClosed:
		return "Closed"
	default:
		return "Unknown"
	}
}

// Socket represents a TCP connection in the fake TCP stack
type Socket struct {
	stack       *Stack
	tun         *Tun
	incoming    chan []byte
	localAddr   *net.UDPAddr
	remoteAddr  *net.UDPAddr
	seq         atomic.Uint32
	ack         atomic.Uint32
	lastAck     atomic.Uint32
	state       ConnState
	stateMu     sync.RWMutex
	closed      atomic.Bool
	closeChan   chan struct{}
}

// newSocket creates a new socket
func newSocket(stack *Stack, tun *Tun, localAddr, remoteAddr *net.UDPAddr, initialAck uint32, state ConnState) *Socket {
	s := &Socket{
		stack:      stack,
		tun:        tun,
		incoming:   make(chan []byte, IncomingQueueSize),
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		state:      state,
		closeChan:  make(chan struct{}),
	}

	// Initialize sequence number with random value
	s.seq.Store(rand.Uint32())
	s.ack.Store(initialAck)
	s.lastAck.Store(initialAck)

	return s
}

// Connect initiates a TCP connection (client side - active open)
func (s *Socket) Connect() error {
	s.stateMu.Lock()
	if s.state != StateIdle {
		s.stateMu.Unlock()
		return fmt.Errorf("socket not in idle state")
	}
	s.state = StateSynSent
	s.stateMu.Unlock()

	// Try connecting with retries
	for i := 0; i < RetryCount; i++ {
		// Send SYN
		if err := s.sendPacket(SYN, nil); err != nil {
			log.Printf("Failed to send SYN: %v", err)
			time.Sleep(ConnTimeout)
			continue
		}

		// Wait for SYN-ACK
		select {
		case data := <-s.incoming:
			pkt := ParseTCPPacket(data)
			if pkt == nil {
				continue
			}

			if pkt.Flags == (SYN | ACK) {
				// Received SYN-ACK
				s.seq.Add(1)
				s.ack.Store(pkt.Seq + 1)
				s.lastAck.Store(pkt.Seq + 1)

				// Send ACK
				if err := s.sendPacket(ACK, nil); err != nil {
					log.Printf("Failed to send ACK: %v", err)
					continue
				}

				s.stateMu.Lock()
				s.state = StateEstablished
				s.stateMu.Unlock()

				log.Printf("FakeTCP connection established: %s -> %s", s.localAddr, s.remoteAddr)
				return nil
			}
		case <-time.After(ConnTimeout):
			// Timeout, retry
			continue
		case <-s.closeChan:
			return fmt.Errorf("socket closed during connect")
		}
	}

	s.stateMu.Lock()
	s.state = StateClosed
	s.stateMu.Unlock()
	return fmt.Errorf("connection timeout after %d retries", RetryCount)
}

// Accept completes the server-side TCP handshake (passive open)
func (s *Socket) Accept(synPacket *TCPPacket) error {
	s.stateMu.Lock()
	if s.state != StateIdle {
		s.stateMu.Unlock()
		return fmt.Errorf("socket not in idle state")
	}
	s.state = StateSynReceived
	s.stateMu.Unlock()

	// Store initial ACK (client's SEQ + 1)
	s.ack.Store(synPacket.Seq + 1)
	s.lastAck.Store(synPacket.Seq + 1)

	// Send SYN-ACK
	if err := s.sendPacket(SYN|ACK, nil); err != nil {
		s.stateMu.Lock()
		s.state = StateClosed
		s.stateMu.Unlock()
		return fmt.Errorf("failed to send SYN-ACK: %w", err)
	}

	// Wait for ACK
	for i := 0; i < RetryCount; i++ {
		select {
		case data := <-s.incoming:
			pkt := ParseTCPPacket(data)
			if pkt == nil {
				continue
			}

			if (pkt.Flags & ACK) != 0 {
				// Received ACK, connection established
				s.seq.Add(1)

				s.stateMu.Lock()
				s.state = StateEstablished
				s.stateMu.Unlock()

				log.Printf("FakeTCP connection accepted: %s <- %s", s.localAddr, s.remoteAddr)
				return nil
			}
		case <-time.After(ConnTimeout):
			// Resend SYN-ACK
			if err := s.sendPacket(SYN|ACK, nil); err != nil {
				log.Printf("Failed to resend SYN-ACK: %v", err)
			}
		case <-s.closeChan:
			return fmt.Errorf("socket closed during accept")
		}
	}

	s.stateMu.Lock()
	s.state = StateClosed
	s.stateMu.Unlock()
	return fmt.Errorf("accept timeout after %d retries", RetryCount)
}

// Send sends data through the fake TCP connection
func (s *Socket) Send(data []byte) error {
	s.stateMu.RLock()
	state := s.state
	s.stateMu.RUnlock()

	if state != StateEstablished {
		return fmt.Errorf("socket not established (state: %v)", state)
	}

	if s.closed.Load() {
		return fmt.Errorf("socket closed")
	}

	// Send data with ACK flag
	if err := s.sendPacket(ACK, data); err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}

	// Update sequence number
	s.seq.Add(uint32(len(data)))

	return nil
}

// Recv receives data from the fake TCP connection
func (s *Socket) Recv(buf []byte) (int, error) {
	s.stateMu.RLock()
	state := s.state
	s.stateMu.RUnlock()

	if state != StateEstablished {
		return 0, fmt.Errorf("socket not established (state: %v)", state)
	}

	select {
	case data := <-s.incoming:
		pkt := ParseTCPPacket(data)
		if pkt == nil {
			return 0, fmt.Errorf("failed to parse incoming packet")
		}

		payload := pkt.Payload
		if len(payload) == 0 {
			// Empty packet, likely just an ACK
			return s.Recv(buf)
		}

		// Update ACK
		newAck := pkt.Seq + uint32(len(payload))
		s.ack.Store(newAck)

		// Send ACK if too much unacked data
		lastAck := s.lastAck.Load()
		if newAck-lastAck > MaxUnackedLen {
			s.lastAck.Store(newAck)
			if err := s.sendPacket(ACK, nil); err != nil {
				log.Printf("Failed to send ACK: %v", err)
			}
		}

		// Copy payload to buffer
		n := copy(buf, payload)
		return n, nil

	case <-s.closeChan:
		return 0, fmt.Errorf("socket closed")
	}
}

// sendPacket sends a TCP packet through the TUN device
func (s *Socket) sendPacket(flags uint8, payload []byte) error {
	seq := s.seq.Load()
	ack := s.ack.Load()

	packet := BuildTCPPacket(s.localAddr, s.remoteAddr, seq, ack, flags, payload)

	_, err := s.tun.Write(packet)
	return err
}

// handleIncoming handles an incoming packet for this socket
func (s *Socket) handleIncoming(data []byte) {
	if s.closed.Load() {
		return
	}

	// Make a copy of the data since it might be reused
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	select {
	case s.incoming <- dataCopy:
	default:
		log.Printf("Warning: incoming queue full for socket %s -> %s", s.localAddr, s.remoteAddr)
	}
}

// Close closes the socket
func (s *Socket) Close() error {
	if s.closed.Swap(true) {
		return nil // Already closed
	}

	s.stateMu.Lock()
	s.state = StateClosed
	s.stateMu.Unlock()

	close(s.closeChan)

	// Unregister from stack
	if s.stack != nil {
		s.stack.unregisterSocket(s.localAddr, s.remoteAddr)
	}

	log.Printf("FakeTCP socket closed: %s <-> %s", s.localAddr, s.remoteAddr)
	return nil
}

// LocalAddr returns the local address
func (s *Socket) LocalAddr() *net.UDPAddr {
	return s.localAddr
}

// RemoteAddr returns the remote address
func (s *Socket) RemoteAddr() *net.UDPAddr {
	return s.remoteAddr
}

// State returns the current connection state
func (s *Socket) State() ConnState {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.state
}

// String returns a string representation of the socket
func (s *Socket) String() string {
	return fmt.Sprintf("%s <-> %s (state: %v)", s.localAddr, s.remoteAddr, s.State())
}
