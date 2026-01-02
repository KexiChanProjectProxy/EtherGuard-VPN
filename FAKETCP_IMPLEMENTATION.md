# FakeTCP Dual-Stack Implementation for EtherGuard-VPN

## Overview

This implementation adds FakeTCP support to EtherGuard-VPN, allowing the VPN to operate over both UDP and FakeTCP simultaneously with automatic failover. The system prefers UDP for performance but seamlessly falls back to FakeTCP when UDP is blocked or unreachable.

## Architecture

### Components

1. **FakeTCP Library** (`/faketcp/`)
   - `tun.go`: TUN device management for Layer 3 packet handling
   - `packet.go`: TCP/IP packet building and parsing
   - `socket.go`: TCP socket with state machine (SYN/ACK handshake)
   - `stack.go`: TCP stack with connection multiplexing

2. **Integration Layer** (`/conn/bind_faketcp.go`)
   - Implements `conn.Bind` interface for seamless integration
   - Manages FakeTCP connections and packet multiplexing
   - Handles accept loop and connection lifecycle

3. **Device Updates** (`/device/`)
   - Dual-bind support: UDP + FakeTCP running simultaneously
   - Smart send logic with automatic failover
   - Per-peer endpoint management for both transports

4. **Configuration** (`/mtypes/config.go`)
   - New `FakeTCPConfig` structure
   - Added to both `EdgeConfig` and `SuperConfig`

## How It Works

### Dual-Stack Operation

1. **Startup**: Both UDP and FakeTCP binds are initialized if FakeTCP is enabled
2. **Listening**: System listens on both UDP socket and FakeTCP (TUN-based)
3. **Receiving**: Packets from both transports flow into the same processing pipeline
4. **Sending**: Smart failover logic:
   - Try UDP first (preferred for performance)
   - If UDP fails, automatically switch to FakeTCP
   - Track UDP health and recover when available

### Automatic Failover

```
Send Packet
    ↓
Is UDP available && not failed?
    ↓ Yes                    ↓ No
Try UDP send          Try FakeTCP send
    ↓ Success              ↓ Success
Update UDP health      Log FakeTCP used
Mark as sent          Mark as sent
    ↓ Failure
Mark UDP as failed
Try FakeTCP send
```

## Configuration

### Edge Node Example

```yaml
FakeTCP:
  Enabled: true                      # Enable FakeTCP support
  TunName: "etherguard-tcp0"         # TUN device name
  TunIPv4: "192.168.200.1/24"        # Local IPv4 for TUN
  TunPeerIPv4: "192.168.200.2"       # Peer IPv4 for TUN
  TunIPv6: "fcc9::1/64"              # Local IPv6 for TUN (optional)
  TunPeerIPv6: "fcc9::2"             # Peer IPv6 for TUN (optional)
  TunMTU: 1500                       # MTU (default: 1500)
```

### Super Node Example

```yaml
FakeTCP:
  Enabled: true
  TunName: "etherguard-tcp-super"
  TunIPv4: "192.168.201.1/24"
  TunPeerIPv4: "192.168.201.2"
  TunMTU: 1500
```

### Defaults

If FakeTCP is enabled but some fields are not specified:
- `TunName`: "etherguard-tcp0" (edge) or "etherguard-tcp-super" (super)
- `TunIPv4`: "192.168.200.1/24" (edge) or "192.168.201.1/24" (super)
- `TunPeerIPv4`: "192.168.200.2" (edge) or "192.168.201.2" (super)
- `TunMTU`: 1500

## Config Generator & API Server

### ✅ Verified Components

**Config Generator (`gencfg/example_conf.go`):**
- ✅ Example Edge config includes FakeTCP settings (disabled by default)
- ✅ Example Super config includes FakeTCP settings (disabled by default)
- ✅ All FakeTCP fields properly initialized with sensible defaults

**API Server (HTTP/YAML handling):**
- ✅ YAML marshaling/unmarshaling works correctly
- ✅ FakeTCP configuration automatically handled via mtypes structures
- ✅ No additional API changes needed - works out of the box

**Generated Example Configs Include:**
```yaml
FakeTCP:
  Enabled: false              # Set to true to enable
  TunName: "etherguard-tcp0"  # Edge nodes
  # or "etherguard-tcp-super" for Super nodes
  TunIPv4: "192.168.200.1/24" # Edge: .200.x, Super: .201.x
  TunPeerIPv4: "192.168.200.2"
  TunIPv6: ""
  TunPeerIPv6: ""
  TunMTU: 1500
```

## Testing

### Build

```bash
cd /home/kexi/EtherGuard-VPN
go build -o etherguard-edge ./cmd/etherguard-edge
go build -o etherguard-super ./cmd/etherguard-super
```

### Test Scenario 1: Normal Operation (UDP)

1. Configure both nodes with FakeTCP enabled
2. Start nodes - both should establish UDP connection
3. Verify traffic flows over UDP
4. Check logs for "UDP bind has been updated" and "FakeTCP bind opened"

### Test Scenario 2: UDP Blocked (FakeTCP Fallback)

1. Start nodes with FakeTCP enabled
2. Block UDP traffic using iptables:
   ```bash
   sudo iptables -A OUTPUT -p udp --dport <listen_port> -j DROP
   ```
3. Observe automatic fallback to FakeTCP in logs:
   - "UDP send failed for peer X, trying FakeTCP"
   - "Sent packet via FakeTCP for peer X"
4. Verify traffic continues over FakeTCP
5. Unblock UDP and verify recovery:
   ```bash
   sudo iptables -D OUTPUT -p udp --dport <listen_port> -j DROP
   ```
6. Check logs for "UDP communication recovered"

### Test Scenario 3: Firewall Traversal

FakeTCP appears as regular TCP traffic (port 443 recommended) and should pass through:
- DPI firewalls that block UDP-based VPNs
- Networks that only allow TCP (e.g., corporate WiFi)
- NAT devices that have UDP timeout issues

## Implementation Details

### FakeTCP Protocol

- **Handshake**: Full TCP 3-way handshake (SYN, SYN-ACK, ACK)
- **State Machine**: Idle → SynSent/SynReceived → Established
- **Sequence Numbers**: Random initial sequence, incremented per payload byte
- **ACK Management**: Periodic ACKs, up to 128MB unacked data
- **No Flow Control**: Preserves UDP's datagram semantics
- **Out-of-Order**: Packets delivered in receive order (no reordering)

### TUN Device

- **Layer**: Layer 3 (IP packets)
- **Multi-Queue**: Supports multiple queues for SMP performance
- **Separate Device**: Independent from VPN TAP device
- **IP Range**: Uses separate IP subnet (192.168.200.0/24)

### Performance Considerations

- **Overhead**: FakeTCP adds ~40 bytes per packet (20B IP + 20B TCP)
- **MTU Reduction**: Recommend MTU 1460 for FakeTCP to avoid fragmentation
- **CPU Usage**: TCP packet building/parsing adds minimal overhead
- **Latency**: Similar to UDP in most cases, slight increase due to handshake

## File Modifications Summary

### New Files
- `/faketcp/tun.go` (227 lines)
- `/faketcp/packet.go` (278 lines)
- `/faketcp/socket.go` (332 lines)
- `/faketcp/stack.go` (207 lines)
- `/conn/bind_faketcp.go` (303 lines)

### Modified Files
- `/mtypes/config.go`: Added `FakeTCPConfig` structure
- `/device/device.go`: Added `faketcpBind` field, dual-bind support in `BindUpdate()`
- `/device/peer.go`: Added `faketcpEndpoint`, dual-endpoint support, smart failover in `SendBuffer()`
- `/main_edge.go`: FakeTCP initialization for edge nodes
- `/main_super.go`: FakeTCP initialization for super nodes

## Troubleshooting

### TUN Device Creation Fails
```
Error: Failed to create TUN device: /dev/net/tun does not exist
```
**Solution**: Ensure TUN kernel module is loaded:
```bash
sudo modprobe tun
```

### Permission Denied
```
Error: Failed to create TUN device: permission denied
```
**Solution**: Run with sudo or set CAP_NET_ADMIN capability:
```bash
sudo setcap cap_net_admin=eip ./etherguard-edge
```

### FakeTCP Connection Fails
```
Error: connection timeout after 6 retries
```
**Check**:
1. TUN device is up: `ip link show etherguard-tcp0`
2. Routing is correct: `ip route`
3. Firewall allows TCP on the configured port
4. Remote peer also has FakeTCP enabled

### High CPU Usage
**Cause**: Packet processing overhead
**Solutions**:
- Reduce multi-queue count in TUN config
- Increase MTU to reduce packet count
- Consider hardware acceleration if available

## Future Enhancements

1. **Congestion Detection**: Detect network congestion and switch transports
2. **Parallel Transmission**: Send over both UDP and FakeTCP simultaneously (redundancy)
3. **Port Randomization**: Use random source ports for better NAT traversal
4. **TCP Options**: Add window scale, timestamps for better compatibility
5. **Connection Pooling**: Reuse TCP connections for multiple peers
6. **MTU Discovery**: Automatic MTU detection for FakeTCP
7. **TLS Wrapper**: Optional TLS wrapping for deeper inspection evasion

## Credits

Based on [phantun](https://github.com/dndx/phantun) by dndx - a TCP obfuscator that transforms UDP traffic into TCP.

## License

SPDX-License-Identifier: MIT
