// SPDX-License-Identifier: MIT
package conn

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"

	"github.com/KusakabeSi/EtherGuard-VPN/faketcp"
)

// recvPacket represents a received packet with its source endpoint
type recvPacket struct {
	data []byte
	from Endpoint
}

// FakeTCPBind implements the Bind interface using FakeTCP
type FakeTCPBind struct {
	mu          sync.RWMutex
	stack       *faketcp.Stack
	tuns        []*faketcp.Tun
	port        uint16
	use4        bool
	use6        bool
	localIPv4   net.IP
	localIPv6   net.IP
	tunConfig   faketcp.TunConfig
	sockets     map[string]*faketcp.Socket // keyed by remote address
	recvQueue   chan recvPacket            // multiplexed receive queue
	closed      bool
	stopChan    chan struct{}
	acceptWg    sync.WaitGroup // tracks accept goroutine
}

// FakeTCPEndpoint implements the Endpoint interface for FakeTCP
type FakeTCPEndpoint struct {
	addr *net.UDPAddr
}

var _ Bind = (*FakeTCPBind)(nil)
var _ Endpoint = (*FakeTCPEndpoint)(nil)

// NewFakeTCPBind creates a new FakeTCP bind
func NewFakeTCPBind(use4, use6 bool, tunConfig faketcp.TunConfig) Bind {
	return &FakeTCPBind{
		use4:      use4,
		use6:      use6,
		tunConfig: tunConfig,
		sockets:   make(map[string]*faketcp.Socket),
		recvQueue: make(chan recvPacket, 1024),
		stopChan:  make(chan struct{}),
	}
}

// Open implements Bind.Open
func (b *FakeTCPBind) Open(port uint16) (fns []ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.stack != nil {
		return nil, 0, ErrBindAlreadyOpen
	}

	b.port = port

	// Parse local IPs from config
	if b.use4 && b.tunConfig.IPv4Address != "" {
		ip, _, err := net.ParseCIDR(b.tunConfig.IPv4Address)
		if err != nil {
			// Try parsing as plain IP
			ip = net.ParseIP(b.tunConfig.IPv4Address)
			if ip == nil {
				return nil, 0, fmt.Errorf("invalid IPv4 address: %s", b.tunConfig.IPv4Address)
			}
		}
		b.localIPv4 = ip.To4()
	}

	if b.use6 && b.tunConfig.IPv6Address != "" {
		ip, _, err := net.ParseCIDR(b.tunConfig.IPv6Address)
		if err != nil {
			// Try parsing as plain IP
			ip = net.ParseIP(b.tunConfig.IPv6Address)
			if ip == nil {
				return nil, 0, fmt.Errorf("invalid IPv6 address: %s", b.tunConfig.IPv6Address)
			}
		}
		b.localIPv6 = ip.To16()
	}

	// Determine number of queues (use number of CPUs for performance)
	numCPUs := runtime.NumCPU()
	if b.tunConfig.Queues == 0 {
		b.tunConfig.Queues = numCPUs
	}

	// Create TUN devices
	tuns, err := faketcp.NewTun(b.tunConfig)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create TUN device: %w", err)
	}
	b.tuns = tuns

	// Create FakeTCP stack
	b.stack = faketcp.NewStack(tuns, b.localIPv4, b.localIPv6)

	// Start listening on the port
	if err := b.stack.Listen(port); err != nil {
		b.stack.Close()
		return nil, 0, fmt.Errorf("failed to listen: %w", err)
	}

	// Start accept goroutine
	b.acceptWg.Add(1)
	go b.acceptLoop()

	// Create receive functions (one per TUN queue for parallelism)
	numRecvFuncs := len(tuns)
	if numRecvFuncs > 4 {
		numRecvFuncs = 4 // Limit to 4 receive goroutines
	}
	fns = make([]ReceiveFunc, numRecvFuncs)
	for i := range fns {
		fns[i] = b.makeReceiveFunc()
	}

	log.Printf("FakeTCP bind opened on port %d with %d queues", port, len(tuns))
	return fns, port, nil
}

// acceptLoop continuously accepts incoming connections
func (b *FakeTCPBind) acceptLoop() {
	defer b.acceptWg.Done()

	for {
		sock, err := b.stack.Accept()
		if err != nil {
			select {
			case <-b.stopChan:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		// Store the socket
		remoteAddr := sock.RemoteAddr().String()
		b.mu.Lock()
		b.sockets[remoteAddr] = sock
		b.mu.Unlock()

		log.Printf("Accepted FakeTCP connection from %s", remoteAddr)

		// Start goroutine to receive from this socket
		go b.handleSocket(sock)
	}
}

// handleSocket continuously receives data from a socket and forwards to recvQueue
func (b *FakeTCPBind) handleSocket(sock *faketcp.Socket) {
	buf := make([]byte, 2048)
	endpoint := &FakeTCPEndpoint{addr: sock.RemoteAddr()}

	for {
		n, err := sock.Recv(buf)
		if err != nil {
			log.Printf("Socket recv error from %s: %v", sock.RemoteAddr(), err)
			sock.Close()

			// Remove from sockets map
			b.mu.Lock()
			delete(b.sockets, sock.RemoteAddr().String())
			b.mu.Unlock()
			return
		}

		// Make a copy of the data
		data := make([]byte, n)
		copy(data, buf[:n])

		// Send to receive queue
		select {
		case b.recvQueue <- recvPacket{data: data, from: endpoint}:
		case <-b.stopChan:
			return
		}
	}
}

// makeReceiveFunc creates a ReceiveFunc that reads from the multiplexed receive queue
func (b *FakeTCPBind) makeReceiveFunc() ReceiveFunc {
	return func(buf []byte) (int, Endpoint, error) {
		select {
		case pkt := <-b.recvQueue:
			n := copy(buf, pkt.data)
			return n, pkt.from, nil
		case <-b.stopChan:
			return 0, nil, net.ErrClosed
		}
	}
}

// Close implements Bind.Close
func (b *FakeTCPBind) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()

	close(b.stopChan)

	// Wait for accept goroutine to finish
	b.acceptWg.Wait()

	b.mu.Lock()
	defer b.mu.Unlock()

	// Close all sockets
	for _, sock := range b.sockets {
		sock.Close()
	}
	b.sockets = make(map[string]*faketcp.Socket)

	// Close stack
	if b.stack != nil {
		b.stack.Close()
		b.stack = nil
	}

	log.Println("FakeTCP bind closed")
	return nil
}

// SetMark implements Bind.SetMark (not applicable for FakeTCP)
func (b *FakeTCPBind) SetMark(mark uint32) error {
	// FakeTCP uses TUN device, so fwmark is not directly applicable
	// This is a no-op for now
	return nil
}

// Send implements Bind.Send
func (b *FakeTCPBind) Send(buf []byte, ep Endpoint) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return net.ErrClosed
	}

	ftcpEp, ok := ep.(*FakeTCPEndpoint)
	if !ok {
		return ErrWrongEndpointType
	}

	remoteAddr := ftcpEp.addr.String()

	// Check if we have an existing socket for this remote
	sock, exists := b.sockets[remoteAddr]
	if !exists {
		// Create new outgoing connection
		var err error
		sock, err = b.stack.Connect(b.port, ftcpEp.addr)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %w", remoteAddr, err)
		}

		b.mu.RUnlock()
		b.mu.Lock()
		b.sockets[remoteAddr] = sock
		b.mu.Unlock()
		b.mu.RLock()
	}

	// Send data through the socket
	return sock.Send(buf)
}

// ParseEndpoint implements Bind.ParseEndpoint
func (b *FakeTCPBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := parseEndpoint(s)
	if err != nil {
		return nil, err
	}
	return &FakeTCPEndpoint{addr: addr}, nil
}

// EnabledAf implements Bind.EnabledAf
func (b *FakeTCPBind) EnabledAf() EnabledAf {
	return EnabledAf{
		IPv4: b.use4,
		IPv6: b.use6,
	}
}

// FakeTCPEndpoint methods

func (e *FakeTCPEndpoint) ClearSrc() {}

func (e *FakeTCPEndpoint) DstIP() net.IP {
	return e.addr.IP
}

func (e *FakeTCPEndpoint) SrcIP() net.IP {
	return nil // not supported
}

func (e *FakeTCPEndpoint) DstToBytes() []byte {
	out := e.addr.IP.To4()
	if out == nil {
		out = e.addr.IP
	}
	out = append(out, byte(e.addr.Port&0xff))
	out = append(out, byte((e.addr.Port>>8)&0xff))
	return out
}

func (e *FakeTCPEndpoint) DstToString() string {
	return e.addr.String()
}

func (e *FakeTCPEndpoint) SrcToString() string {
	return ""
}
