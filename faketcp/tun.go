// SPDX-License-Identifier: MIT
package faketcp

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cloneDevicePath = "/dev/net/tun"
	ifReqSize       = unix.IFNAMSIZ + 64
)

// Tun represents a TUN device for FakeTCP
type Tun struct {
	file  *os.File
	name  string
	mtu   int
	mu    sync.RWMutex
	closed bool
}

// TunConfig holds configuration for creating a TUN device
type TunConfig struct {
	Name        string // Device name (e.g., "etherguard-tcp0")
	MTU         int    // MTU size (default: 1500)
	Queues      int    // Number of queues for multi-queue support
	IPv4Address string // Local IPv4 address (e.g., "192.168.200.1")
	IPv4Peer    string // Peer IPv4 address (e.g., "192.168.200.2")
	IPv6Address string // Local IPv6 address (optional)
	IPv6Peer    string // Peer IPv6 address (optional)
}

// NewTun creates a new TUN device
func NewTun(config TunConfig) ([]*Tun, error) {
	if config.MTU == 0 {
		config.MTU = 1500
	}
	if config.Queues == 0 {
		config.Queues = 1
	}

	tuns := make([]*Tun, config.Queues)

	// Create multiple TUN devices for multi-queue support
	for i := 0; i < config.Queues; i++ {
		nfd, err := unix.Open(cloneDevicePath, os.O_RDWR, 0)
		if err != nil {
			// Clean up previously created devices
			for j := 0; j < i; j++ {
				tuns[j].Close()
			}
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("NewTun(%q) failed; %s does not exist", config.Name, cloneDevicePath)
			}
			return nil, err
		}

		var ifr [ifReqSize]byte
		var flags uint16 = unix.IFF_TUN | unix.IFF_NO_PI

		// Enable multi-queue if needed
		if config.Queues > 1 {
			flags |= unix.IFF_MULTI_QUEUE
		}

		nameBytes := []byte(config.Name)
		copy(ifr[:], nameBytes)
		*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags

		_, _, errno := unix.Syscall(
			unix.SYS_IOCTL,
			uintptr(nfd),
			uintptr(unix.TUNSETIFF),
			uintptr(unsafe.Pointer(&ifr[0])),
		)

		if errno != 0 {
			unix.Close(nfd)
			// Clean up previously created devices
			for j := 0; j < i; j++ {
				tuns[j].Close()
			}
			return nil, fmt.Errorf("failed to create TUN device: %v", errno)
		}

		file := os.NewFile(uintptr(nfd), cloneDevicePath)
		if file == nil {
			unix.Close(nfd)
			// Clean up previously created devices
			for j := 0; j < i; j++ {
				tuns[j].Close()
			}
			return nil, fmt.Errorf("failed to create file from fd")
		}

		deviceName := string(ifr[:unix.IFNAMSIZ])
		deviceName = deviceName[:len(deviceName)-1] // Remove null terminator

		tuns[i] = &Tun{
			file: file,
			name: deviceName,
			mtu:  config.MTU,
		}
	}

	// Configure the first device (they share the same interface)
	if err := tuns[0].setUp(); err != nil {
		for i := range tuns {
			tuns[i].Close()
		}
		return nil, fmt.Errorf("failed to bring up TUN device: %w", err)
	}

	if err := tuns[0].setMTU(config.MTU); err != nil {
		for i := range tuns {
			tuns[i].Close()
		}
		return nil, fmt.Errorf("failed to set MTU: %w", err)
	}

	if config.IPv4Address != "" && config.IPv4Peer != "" {
		if err := tuns[0].setIPv4Addresses(config.IPv4Address, config.IPv4Peer); err != nil {
			for i := range tuns {
				tuns[i].Close()
			}
			return nil, fmt.Errorf("failed to set IPv4 addresses: %w", err)
		}
	}

	if config.IPv6Address != "" && config.IPv6Peer != "" {
		if err := tuns[0].setIPv6Addresses(config.IPv6Address, config.IPv6Peer); err != nil {
			for i := range tuns {
				tuns[i].Close()
			}
			return nil, fmt.Errorf("failed to set IPv6 addresses: %w", err)
		}
	}

	return tuns, nil
}

// Name returns the TUN device name
func (t *Tun) Name() string {
	return t.name
}

// MTU returns the MTU of the TUN device
func (t *Tun) MTU() int {
	return t.mtu
}

// Read reads a packet from the TUN device
func (t *Tun) Read(buf []byte) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return 0, os.ErrClosed
	}

	return t.file.Read(buf)
}

// Write writes a packet to the TUN device
func (t *Tun) Write(buf []byte) (int, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return 0, os.ErrClosed
	}

	return t.file.Write(buf)
}

// Close closes the TUN device
func (t *Tun) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	return t.file.Close()
}

// setUp brings up the TUN interface
func (t *Tun) setUp() error {
	return execCmd("ip", "link", "set", "dev", t.name, "up")
}

// setMTU sets the MTU of the TUN interface
func (t *Tun) setMTU(mtu int) error {
	return execCmd("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", mtu))
}

// setIPv4Addresses sets the IPv4 addresses for the TUN interface
func (t *Tun) setIPv4Addresses(local, peer string) error {
	return execCmd("ip", "addr", "add", local, "peer", peer, "dev", t.name)
}

// setIPv6Addresses sets the IPv6 addresses for the TUN interface
func (t *Tun) setIPv6Addresses(local, peer string) error {
	return execCmd("ip", "-6", "addr", "add", local, "peer", peer, "dev", t.name)
}

// execCmd is a helper function to execute shell commands
func execCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %s %v failed: %w, output: %s", name, args, err, string(output))
	}
	return nil
}
