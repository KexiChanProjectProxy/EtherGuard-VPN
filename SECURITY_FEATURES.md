# Security Features: Private IP Blocking and Relay Prevention

## Overview

This document describes the security enhancements added to EtherGuard-VPN to protect against unintended connections to private IP addresses and prevent the node from acting as a relay for traffic between other peers.

## Features

### 1. Private IP Address Blocking

By default, EtherGuard-VPN now blocks connections to private/non-routable IP addresses for security reasons. This prevents:

- Accidental exposure of internal network services
- Potential attacks via private IP ranges
- Connection to non-routable special-use addresses

#### Blocked IP Ranges

**IPv4:**
- `10.0.0.0/8` - Private network (RFC 1918)
- `172.16.0.0/12` - Private network (RFC 1918)
- `192.168.0.0/16` - Private network (RFC 1918)
- `127.0.0.0/8` - Loopback
- `169.254.0.0/16` - Link-local
- `100.64.0.0/10` - Carrier-grade NAT (RFC 6598)
- `224.0.0.0/4` - Multicast
- `240.0.0.0/4` - Reserved
- `0.0.0.0/8` - Current network
- `192.0.0.0/24` - IETF Protocol Assignments
- `192.0.2.0/24` - Documentation (TEST-NET-1)
- `198.51.100.0/24` - Documentation (TEST-NET-2)
- `203.0.113.0/24` - Documentation (TEST-NET-3)
- `198.18.0.0/15` - Benchmarking
- `255.255.255.255/32` - Broadcast

**IPv6:**
- `::1/128` - Loopback
- `fe80::/10` - Link-local unicast
- `fc00::/7` - Unique local address (ULA)
- `ff00::/8` - Multicast
- `::/128` - Unspecified
- `2001:db8::/32` - Documentation
- `::ffff:0:0/96` - IPv4-mapped IPv6 (checks embedded IPv4)

#### Configuration

Add the following to your configuration file (EdgeConfig or SuperConfig):

```yaml
AllowPrivateIP: false  # Default: false (recommended)
```

Set to `true` only if you specifically need to connect to peers on private networks (e.g., LAN deployments).

#### Behavior

When `AllowPrivateIP: false` (default):
- **Outgoing connections**: Rejected when setting endpoint via `SetEndpointFromConnURL()`
- **Incoming packets**: Endpoint updates from private IPs are rejected in `SetEndpointFromPacket()`
- **Error messages**: Clear error messages indicate why the connection was rejected
- **Logging**: Control log shows rejected endpoints with instructions to enable if needed

Example error message:
```
connection to private/non-routable IP 192.168.1.100:3001 rejected (set AllowPrivateIP: true to allow)
```

Example log message:
```
Control: Rejected endpoint update from private IP 10.0.0.5:3001 for peer 2 (set AllowPrivateIP: true to allow)
```

### 2. Relay/Forwarding Prevention

EtherGuard-VPN includes mesh routing capabilities where nodes can forward packets for other peers. The new `DisableRelay` option allows you to disable this behavior, ensuring that a node only processes its own traffic and never forwards packets between other peers.

#### Use Cases for Disabling Relay

- **End-user nodes**: Devices that should only handle their own traffic
- **Security policy**: Prevent the node from becoming a transit point
- **Bandwidth conservation**: Avoid using bandwidth for other peers' traffic
- **Compliance**: Meet network policies that prohibit packet forwarding

#### Configuration

Add the following to your configuration file (EdgeConfig or SuperConfig):

```yaml
DisableRelay: false  # Default: false (relaying enabled)
```

Set to `true` to prevent this node from forwarding packets between other peers.

#### Behavior

When `DisableRelay: true`:
- **Direct traffic**: Packets destined for this node are processed normally
- **Broadcast/Spread**: Broadcast and spread packets are NOT forwarded to other peers
- **Transit traffic**: Packets destined for other nodes are dropped, not forwarded
- **Logging**: Transit log shows dropped packets with reason

Example log message:
```
Transit: Relay disabled - dropped packet S:5 D:3 From:2 (set DisableRelay: false to enable relaying)
```

When `DisableRelay: false` (default):
- **Normal routing**: The node participates in mesh routing as designed
- **Broadcasts**: Broadcasts are forwarded to all peers
- **Transit**: Packets are forwarded to next-hop peers based on routing table

## Implementation Details

### Code Changes

1. **IP Validation Functions** (`conn/conn.go`)
   - `IsPrivateIP(ip net.IP) bool` - Checks if IP is in private/non-routable range
   - `IsPublicIP(ip net.IP) bool` - Checks if IP is publicly routable
   - Comprehensive coverage of all RFC-defined private ranges

2. **Configuration Fields** (`mtypes/config.go`)
   - Added `AllowPrivateIP bool` to `EdgeConfig` and `SuperConfig`
   - Added `DisableRelay bool` to `EdgeConfig` and `SuperConfig`

3. **Endpoint Validation** (`device/peer.go`)
   - `SetEndpointFromConnURL()`: Validates configured endpoint IPs
   - `SetEndpointFromPacket()`: Validates source IPs from received packets

4. **Relay Control** (`device/receive.go`)
   - Modified `should_transfer` logic to check `DisableRelay` setting
   - Added logging for dropped transit packets

### Testing

Comprehensive test suite in `conn/ipvalidation_test.go`:
- Tests all private IPv4 ranges
- Tests all private IPv6 ranges
- Tests public IPv4 and IPv6 addresses
- Tests edge cases (nil, boundary addresses)

Run tests:
```bash
go test ./conn -v -run TestIsPrivateIP
go test ./conn -v -run TestIsPublicIP
```

## Security Considerations

### Recommended Settings for Maximum Security

```yaml
AllowPrivateIP: false  # Block private IPs
DisableRelay: true     # Prevent relaying
```

### Recommended Settings for LAN Deployments

```yaml
AllowPrivateIP: true   # Allow private IPs for LAN peers
DisableRelay: false    # Allow routing within LAN mesh
```

### Recommended Settings for Public Internet Mesh

```yaml
AllowPrivateIP: false  # Block private IPs (default)
DisableRelay: false    # Allow mesh routing (default)
```

## Migration Guide

### Existing Deployments

If you have existing configurations, the new fields default to:
- `AllowPrivateIP: false` - Private IPs are blocked by default
- `DisableRelay: false` - Relaying remains enabled by default

**Action Required:**
1. If you have peers on private IP addresses, add `AllowPrivateIP: true` to your config
2. If you want to disable packet forwarding, add `DisableRelay: true` to your config
3. Update example configs with the new fields for documentation

### New Deployments

For new deployments, explicitly set these values in your configuration file based on your security requirements.

## Troubleshooting

### Connection Failed to Private IP

**Error:**
```
connection to private/non-routable IP 192.168.1.100:3001 rejected
```

**Solution:**
Add `AllowPrivateIP: true` to your configuration if you need to connect to private IPs.

### Packets Not Being Relayed

**Log:**
```
Transit: Relay disabled - dropped packet S:5 D:3 From:2
```

**Solution:**
If you need this node to forward packets, set `DisableRelay: false` in your configuration.

### Endpoint Updates Rejected

**Log:**
```
Control: Rejected endpoint update from private IP 10.0.0.5:3001 for peer 2
```

**Solution:**
Add `AllowPrivateIP: true` to allow endpoint updates from private IPs.

## API Reference

### IsPrivateIP(ip net.IP) bool

Checks if the provided IP address is in a private/non-routable range.

**Parameters:**
- `ip` - The IP address to check (can be IPv4 or IPv6)

**Returns:**
- `true` if the IP is private/non-routable
- `false` if the IP is publicly routable

**Example:**
```go
import "github.com/KusakabeSi/EtherGuard-VPN/conn"

ip := net.ParseIP("192.168.1.1")
if conn.IsPrivateIP(ip) {
    fmt.Println("This is a private IP")
}
```

### IsPublicIP(ip net.IP) bool

Checks if the provided IP address is publicly routable.

**Parameters:**
- `ip` - The IP address to check (can be IPv4 or IPv6)

**Returns:**
- `true` if the IP is publicly routable
- `false` if the IP is private/non-routable

**Example:**
```go
import "github.com/KusakabeSi/EtherGuard-VPN/conn"

ip := net.ParseIP("8.8.8.8")
if conn.IsPublicIP(ip) {
    fmt.Println("This is a public IP")
}
```

## References

- RFC 1918 - Private Address Space
- RFC 6598 - Carrier-Grade NAT
- RFC 4193 - Unique Local IPv6 Unicast Addresses
- RFC 3927 - Dynamic Configuration of IPv4 Link-Local Addresses
- RFC 5735 - Special Use IPv4 Addresses
- RFC 5156 - Special-Use IPv6 Addresses
