package conn

import (
	"net"
	"testing"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// IPv4 Private ranges
		{"Private 10.x", "10.0.0.1", true},
		{"Private 172.16.x", "172.16.0.1", true},
		{"Private 172.31.x", "172.31.255.255", true},
		{"Private 192.168.x", "192.168.1.1", true},
		{"Loopback 127.x", "127.0.0.1", true},
		{"Link-local 169.254.x", "169.254.1.1", true},
		{"Carrier-grade NAT 100.64.x", "100.64.0.1", true},
		{"Multicast 224.x", "224.0.0.1", true},
		{"Reserved 240.x", "240.0.0.1", true},
		{"Broadcast", "255.255.255.255", true},
		{"Current network", "0.0.0.0", true},
		{"Documentation TEST-NET-1", "192.0.2.1", true},
		{"Documentation TEST-NET-2", "198.51.100.1", true},
		{"Documentation TEST-NET-3", "203.0.113.1", true},
		{"Benchmarking", "198.18.0.1", true},

		// IPv4 Public ranges
		{"Public 8.8.8.8", "8.8.8.8", false},
		{"Public 1.1.1.1", "1.1.1.1", false},
		{"Public 172.15.x", "172.15.0.1", false},
		{"Public 172.32.x", "172.32.0.1", false},
		{"Public 192.167.x", "192.167.1.1", false},
		{"Public 192.169.x", "192.169.1.1", false},

		// IPv6 Private/Special ranges
		{"IPv6 Loopback", "::1", true},
		{"IPv6 Link-local", "fe80::1", true},
		{"IPv6 ULA", "fc00::1", true},
		{"IPv6 ULA fd", "fd00::1", true},
		{"IPv6 Multicast", "ff02::1", true},
		{"IPv6 Unspecified", "::", true},
		{"IPv6 Documentation", "2001:db8::1", true},

		// IPv6 Public ranges
		{"IPv6 Public", "2001:4860:4860::8888", false},
		{"IPv6 Public Cloudflare", "2606:4700:4700::1111", false},

		// Edge cases
		{"Nil IP", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
				if ip == nil && tt.ip != "" {
					t.Fatalf("Failed to parse IP: %s", tt.ip)
				}
			}
			result := IsPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("IsPrivateIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Public 8.8.8.8", "8.8.8.8", true},
		{"Private 10.0.0.1", "10.0.0.1", false},
		{"Public 1.1.1.1", "1.1.1.1", true},
		{"Private 192.168.1.1", "192.168.1.1", false},
		{"Public IPv6", "2001:4860:4860::8888", true},
		{"Private IPv6 Link-local", "fe80::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("Failed to parse IP: %s", tt.ip)
			}
			result := IsPublicIP(ip)
			if result != tt.expected {
				t.Errorf("IsPublicIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}
