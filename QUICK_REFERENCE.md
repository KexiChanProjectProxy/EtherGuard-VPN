# EtherGuard-VPN: Quick Reference Card

## Critical Logger Usage

### Basic Setup
```go
import "github.com/KusakabeSi/EtherGuard-VPN/mtypes"

// At function entry
critLogger := mtypes.NewCriticalLogger(2 * time.Minute)
defer critLogger.Stop()
defer critLogger.RecoverPanic()
```

### Logging Functions
```go
// Update activity (call regularly in main loops)
critLogger.UpdateActivity()

// Log critical error (continues execution)
critLogger.LogCritical("Database connection failed: %v", err)

// Log fatal error (exits after 3 seconds)
critLogger.LogFatal("Cannot bind to port: %v", err)
```

### Activity Monitoring Pattern
```go
go func() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            critLogger.UpdateActivity()
        }
    }
}()
```

---

## Default Config Settings

### Generate New Configs
```bash
# All have obfuscation + FakeTCP enabled by default
./etherguard -mode gencfg -cfgmode super -config gen.yaml
./etherguard -mode gencfg -cfgmode p2p -config gen.yaml
```

### Obfuscation Config
```yaml
Obfuscation:
  Enabled: true                      # Default: enabled
  PSK: "auto-generated-random-key"   # 32 bytes, base64
```

### FakeTCP Config
```yaml
FakeTCP:
  Enabled: true                      # Default: enabled
  TunName: "etherguard-tcp0"
  TunIPv4: "192.168.200.1/24"
  TunPeerIPv4: "192.168.200.2"
  TunIPv6: "fd00:200::1/64"         # Default: enabled
  TunPeerIPv6: "fd00:200::2"        # Default: enabled
  TunMTU: 1500
```

---

## Systemd Service (Quick)

**Create**: `/etc/systemd/system/etherguard.service`
```ini
[Unit]
Description=EtherGuard VPN
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/etherguard -mode edge -config /etc/etherguard/edge.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Commands**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable etherguard
sudo systemctl start etherguard
sudo systemctl status etherguard
sudo journalctl -u etherguard -f
```

---

## Common Commands

### Build
```bash
go build -v                          # Build
go build -o /usr/local/bin/etherguard  # Build and install
```

### Run
```bash
# Edge node
./etherguard -mode edge -config edge.yaml

# Super node
./etherguard -mode super -config super.yaml

# Print example config
./etherguard -mode edge -example
```

### Config Generation
```bash
# Generate configs
./etherguard -mode gencfg -cfgmode super -config gen.yaml

# Generate and print example
./etherguard -mode gencfg -cfgmode super -example
```

---

## Troubleshooting Quick Checks

### Check Logs
```bash
# Systemd
sudo journalctl -u etherguard -n 100 --no-pager

# Search for critical errors
sudo journalctl -u etherguard | grep CRITICAL

# Follow logs
sudo journalctl -u etherguard -f
```

### Check Process
```bash
# Is it running?
systemctl status etherguard
ps aux | grep etherguard

# Restart count (high count = issues)
systemctl show etherguard | grep NRestarts
```

### Check Network
```bash
# Check TUN interface
ip link show etherguard-tcp0
ip addr show etherguard-tcp0

# Check connections
ss -tulpn | grep etherguard
netstat -tulpn | grep 3000
```

### Test Connectivity
```bash
# Check if listening
nc -zv localhost 3000

# Capture traffic (check obfuscation)
tcpdump -i any -n port 3000 -X | head -100
```

---

## File Locations (Recommended)

```
/usr/local/bin/etherguard           # Binary
/etc/etherguard/                    # Configs
  ├── edge.yaml
  └── super.yaml
/var/lib/etherguard/                # Runtime data
/var/log/etherguard/                # Logs (if not using journald)
/etc/systemd/system/etherguard.service  # Systemd service
```

---

## Security Checklist

- [ ] Config files permission: `chmod 600 /etc/etherguard/*.yaml`
- [ ] Run as non-root user when possible
- [ ] Enable firewall rules
- [ ] Set up log rotation
- [ ] Monitor for critical errors
- [ ] Regular PSK rotation (high-security environments)
- [ ] Secure backup of configs
- [ ] Use HTTPS for API endpoints

---

## Performance Tuning

### For High Throughput
```yaml
Interface:
  MTU: 1420          # Adjust based on network

FakeTCP:
  TunMTU: 1500       # Match or slightly lower than interface MTU
```

### For Low Latency
```yaml
DynamicRoute:
  SendPingInterval: 10      # More frequent (default: 16)
  TimeoutCheckInterval: 10  # More frequent (default: 20)
```

### For Stability
```yaml
DynamicRoute:
  PeerAliveTimeout: 120     # Higher timeout (default: 70)
  ConnNextTry: 10           # Retry faster (default: 5)
```

---

## Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "address already in use" | Port conflict | Change ListenPort or kill conflicting process |
| "permission denied" | Insufficient permissions | Run with sudo or set capabilities |
| "DEADLOCK DETECTED" | Application frozen | Check logs, increase timeout, or fix hang |
| "TUN device not found" | TUN module not loaded | `modprobe tun` |
| "Failed to decrypt" | PSK mismatch | Verify ObfuscationPSK matches on both sides |

---

## Development Workflow

### Make Changes
```bash
# Edit code
vim mtypes/critical_logger.go

# Build and test
go build -v
./etherguard -mode edge -config test.yaml

# Run tests
go test ./... -v
```

### Deploy
```bash
# Build for production
go build -ldflags="-s -w" -o etherguard

# Install
sudo cp etherguard /usr/local/bin/
sudo systemctl restart etherguard
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `mtypes/critical_logger.go` | Critical error & deadlock detection |
| `mtypes/config.go` | Config structures (EdgeConfig, SuperConfig) |
| `gencfg/example_conf.go` | Default config templates |
| `obfuscation/zerooverhead.go` | Obfuscation implementation |
| `main.go` | Entry point |
| `main_edge.go` | Edge node implementation |
| `main_super.go` | Super node implementation |

---

## Quick Diagnostics

### Critical Logger Check
```bash
# Should see regular activity updates
journalctl -u etherguard | grep "UpdateActivity"

# Check for deadlocks
journalctl -u etherguard | grep "DEADLOCK"

# Check restart history
journalctl -u etherguard | grep "Program will exit"
```

### Obfuscation Check
```bash
# Capture first 32 bytes of packet
tcpdump -i any port 3000 -x -c 1 | head -20
# First 16 bytes should look random (encrypted)
```

### FakeTCP Check
```bash
# TUN interface should exist
ip link show | grep etherguard-tcp

# Should have IP addresses
ip addr show etherguard-tcp0
```

---

For detailed information, see:
- `CHANGES_SUMMARY.md` - Complete changes documentation
- `CRITICAL_LOGGER_INTEGRATION.md` - Integration guide
