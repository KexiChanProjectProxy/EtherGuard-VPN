// SPDX-License-Identifier: MIT
package faketcp

import (
	"fmt"
	"log"
	"net"
	"sync"
)

// addrTuple represents a unique socket identifier
type addrTuple struct {
	localAddr  string
	remoteAddr string
}

func newAddrTuple(local, remote *net.UDPAddr) addrTuple {
	return addrTuple{
		localAddr:  local.String(),
		remoteAddr: remote.String(),
	}
}

// Stack represents the fake TCP stack
type Stack struct {
	tuns         []*Tun
	localIPv4    net.IP
	localIPv6    net.IP
	listening    map[uint16]bool
	sockets      map[addrTuple]*Socket
	acceptQueue  chan *Socket
	stopChan     chan struct{}
	mu           sync.RWMutex
	wg           sync.WaitGroup
}

// NewStack creates a new fake TCP stack
func NewStack(tuns []*Tun, localIPv4 net.IP, localIPv6 net.IP) *Stack {
	s := &Stack{
		tuns:        tuns,
		localIPv4:   localIPv4,
		localIPv6:   localIPv6,
		listening:   make(map[uint16]bool),
		sockets:     make(map[addrTuple]*Socket),
		acceptQueue: make(chan *Socket, 128),
		stopChan:    make(chan struct{}),
	}

	// Start packet readers for each TUN device
	for _, tun := range tuns {
		s.wg.Add(1)
		go s.packetReader(tun)
	}

	return s
}

// Listen starts listening on a specific port
func (s *Stack) Listen(port uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.listening[port] {
		return fmt.Errorf("already listening on port %d", port)
	}

	s.listening[port] = true
	log.Printf("FakeTCP stack listening on port %d", port)
	return nil
}

// Accept waits for and returns the next incoming connection
func (s *Stack) Accept() (*Socket, error) {
	select {
	case sock := <-s.acceptQueue:
		return sock, nil
	case <-s.stopChan:
		return nil, fmt.Errorf("stack closed")
	}
}

// Connect creates a new outgoing connection
func (s *Stack) Connect(localPort uint16, remoteAddr *net.UDPAddr) (*Socket, error) {
	// Determine local IP based on remote address
	var localIP net.IP
	if remoteAddr.IP.To4() != nil {
		localIP = s.localIPv4
	} else {
		if s.localIPv6 == nil {
			return nil, fmt.Errorf("IPv6 not configured")
		}
		localIP = s.localIPv6
	}

	localAddr := &net.UDPAddr{
		IP:   localIP,
		Port: int(localPort),
	}

	// Select TUN device (round-robin or first one)
	tun := s.tuns[0]

	// Create socket
	sock := newSocket(s, tun, localAddr, remoteAddr, 0, StateIdle)

	// Register socket
	tuple := newAddrTuple(localAddr, remoteAddr)
	s.mu.Lock()
	s.sockets[tuple] = sock
	s.mu.Unlock()

	// Initiate connection
	if err := sock.Connect(); err != nil {
		s.unregisterSocket(localAddr, remoteAddr)
		return nil, err
	}

	return sock, nil
}

// packetReader reads packets from a TUN device and dispatches them
func (s *Stack) packetReader(tun *Tun) {
	defer s.wg.Done()

	buf := make([]byte, MaxPacketLen)

	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		n, err := tun.Read(buf)
		if err != nil {
			select {
			case <-s.stopChan:
				return
			default:
				log.Printf("Error reading from TUN device: %v", err)
				continue
			}
		}

		if n == 0 {
			continue
		}

		// Parse packet
		packet := ParseTCPPacket(buf[:n])
		if packet == nil {
			continue
		}

		// Handle the packet
		s.handlePacket(tun, packet, buf[:n])
	}
}

// handlePacket processes an incoming TCP packet
func (s *Stack) handlePacket(tun *Tun, pkt *TCPPacket, rawData []byte) {
	// Create address tuples for lookup
	localAddr := &net.UDPAddr{
		IP:   pkt.DstIP,
		Port: int(pkt.DstPort),
	}
	remoteAddr := &net.UDPAddr{
		IP:   pkt.SrcIP,
		Port: int(pkt.SrcPort),
	}

	tuple := newAddrTuple(localAddr, remoteAddr)

	s.mu.RLock()
	sock, exists := s.sockets[tuple]
	s.mu.RUnlock()

	if exists {
		// Existing connection - dispatch to socket
		sock.handleIncoming(rawData)
		return
	}

	// Check if this is a new connection (SYN packet)
	if pkt.Flags == SYN {
		s.mu.RLock()
		listening := s.listening[pkt.DstPort]
		s.mu.RUnlock()

		if !listening {
			// Not listening on this port, ignore
			return
		}

		// Create new socket for incoming connection
		sock := newSocket(s, tun, localAddr, remoteAddr, 0, StateIdle)

		// Register socket
		s.mu.Lock()
		s.sockets[tuple] = sock
		s.mu.Unlock()

		// Handle accept in background
		go func() {
			if err := sock.Accept(pkt); err != nil {
				log.Printf("Failed to accept connection: %v", err)
				sock.Close()
				return
			}

			// Add to accept queue
			select {
			case s.acceptQueue <- sock:
			case <-s.stopChan:
			}
		}()
	}
	// Ignore packets for non-existent connections
}

// unregisterSocket removes a socket from the stack
func (s *Stack) unregisterSocket(localAddr, remoteAddr *net.UDPAddr) {
	tuple := newAddrTuple(localAddr, remoteAddr)

	s.mu.Lock()
	delete(s.sockets, tuple)
	s.mu.Unlock()
}

// Close closes the stack and all associated resources
func (s *Stack) Close() error {
	close(s.stopChan)

	// Close all TUN devices
	for _, tun := range s.tuns {
		tun.Close()
	}

	// Wait for packet readers to finish
	s.wg.Wait()

	// Close all sockets
	s.mu.Lock()
	for _, sock := range s.sockets {
		sock.Close()
	}
	s.sockets = make(map[addrTuple]*Socket)
	s.mu.Unlock()

	log.Println("FakeTCP stack closed")
	return nil
}

// GetLocalIPv4 returns the configured local IPv4 address
func (s *Stack) GetLocalIPv4() net.IP {
	return s.localIPv4
}

// GetLocalIPv6 returns the configured local IPv6 address
func (s *Stack) GetLocalIPv6() net.IP {
	return s.localIPv6
}

// Stats returns statistics about the stack
func (s *Stack) Stats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return map[string]interface{}{
		"sockets":         len(s.sockets),
		"listening_ports": len(s.listening),
		"tun_devices":     len(s.tuns),
	}
}
