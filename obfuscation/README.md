# EtherGuard-VPN Obfuscation

## Overview

This package implements zero-overhead packet obfuscation for EtherGuard-VPN, inspired by [swgp-go](https://github.com/database64128/swgp-go). The obfuscation layer helps bypass Deep Packet Inspection (DPI) while maintaining minimal performance overhead.

## How It Works

The zero-overhead mode uses a two-layer encryption approach:

1. **First 16 bytes**: Encrypted with AES block cipher
2. **Control packets**: Remainder is padded with random data and encrypted with XChaCha20-Poly1305
3. **Data packets**: Remainder is left unchanged (zero overhead)

This approach provides:
- Anti-DPI protection for control traffic
- Minimal overhead for data packets
- Randomized packet sizes for control packets to prevent traffic fingerprinting

## Configuration

### Edge Node Configuration

Add the following to your edge node configuration file (YAML):

```yaml
Obfuscation:
  Enabled: true
  PSK: "base64-encoded-32-byte-key"
```

### Super Node Configuration

Add the following to your super node configuration file (YAML):

```yaml
Obfuscation:
  Enabled: true
  PSK: "base64-encoded-32-byte-key"
```

### Generating a PSK

You can generate a random 32-byte PSK using:

```bash
# Generate random bytes and encode to base64
openssl rand -base64 32
```

**Important**: All nodes that communicate with each other must use the same PSK.

## Example Configuration

### Edge Node

```yaml
NodeID: 1
NodeName: "edge-node-1"
PrivKey: "your-private-key"
ListenPort: 51820

Obfuscation:
  Enabled: true
  PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

Interface:
  IType: "stdio"
  Name: "eg0"
  MTU: 1416
  # ... other interface settings

DynamicRoute:
  # ... routing settings

Peers:
  # ... peer configurations
```

### Super Node

```yaml
NodeName: "super-node"
PrivKeyV4: "your-private-key-v4"
PrivKeyV6: "your-private-key-v6"
ListenPort: 51820

Obfuscation:
  Enabled: true
  PSK: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

# ... other super node settings
```

## Protocol Details

### Control Packet Obfuscation

Control packets (Register, ServerUpdate, Ping, Pong, QueryPeer, BroadcastPeer) undergo full encryption:

```
[AES(first_16_bytes)] + [XChaCha20Poly1305(remaining + padding + length)] + [24-byte nonce]
```

The padding length is randomized to obscure packet sizes.

### Data Packet Obfuscation

Data packets only encrypt the first 16 bytes:

```
[AES(first_16_bytes)] + [remaining_bytes_unchanged]
```

This provides anti-DPI protection with zero additional overhead for data transfer.

## Performance

- **Control packets**: Minimal overhead due to encryption and padding (only affects infrequent control messages)
- **Data packets**: Zero overhead beyond first 16 bytes encryption
- **No MTU impact**: Does not reduce tunnel MTU

## Security Considerations

1. **PSK Management**: Keep your PSK secret and secure
2. **Key Rotation**: Consider rotating PSKs periodically
3. **Same PSK**: All communicating nodes must use the identical PSK
4. **Not a Replacement**: This is obfuscation, not a replacement for WireGuard's cryptography

## Troubleshooting

### Nodes Can't Connect

- Verify all nodes have the same PSK
- Ensure `Enabled: true` is set on all nodes
- Check logs for obfuscation-related errors

### Invalid PSK Error

The PSK must be:
- Exactly 32 bytes when decoded from base64
- Valid base64 encoding

To verify your PSK:

```bash
echo "YOUR_PSK_HERE" | base64 -d | wc -c
# Should output: 32
```

## Implementation Details

### Message Types

The obfuscation layer recognizes these control packet types:
- `MessageTypeRegister` (1)
- `MessageTypeServerUpdate` (2)
- `MessageTypePing` (3)
- `MessageTypePong` (4)
- `MessageTypeQueryPeer` (5)
- `MessageTypeBroadcastPeer` (6)

All other packet types are treated as data packets.

### Code Integration

Obfuscation is integrated at the network layer:
- **Send**: `device/peer.go:SendBuffer()` - encrypts before sending
- **Receive**: `device/receive.go:RoutineReceiveIncoming()` - decrypts after receiving

## References

- Original inspiration: [swgp-go](https://github.com/database64128/swgp-go)
- WireGuard protocol: [wireguard.com](https://www.wireguard.com/)
