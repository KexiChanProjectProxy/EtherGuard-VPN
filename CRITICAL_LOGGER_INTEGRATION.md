# Critical Logger and Auto-Restart Integration Guide

This document explains how the critical logger and auto-restart functionality work in EtherGuard-VPN.

## Features Added

### 1. Critical Logger (`mtypes/critical_logger.go`)

The `CriticalLogger` provides:
- **Critical error logging** with full stack traces
- **Deadlock detection** - monitors for application hang/freeze
- **Panic recovery** - catches panics, logs them, and triggers graceful restart
- **Auto-exit and restart** - exits the program after critical errors for external restart (systemd, supervisor, etc.)

### 2. Configuration Updates

#### Obfuscation (Zero-Overhead Encryption)
- **Default**: Enabled with randomized PSK
- Encrypts first 16 bytes of all packets with AES
- Control packets get full XChaCha20-Poly1305 encryption with random padding
- Data packets have zero overhead (only first 16 bytes encrypted)

Configuration in `EdgeConfig` and `SuperConfig`:
```yaml
Obfuscation:
  Enabled: true
  PSK: <base64-encoded-32-byte-key>  # Auto-generated random key
```

#### FakeTCP
- **Default**: Enabled with dual-stack (IPv4 + IPv6)
- Disguises UDP traffic as TCP to bypass firewalls
- Both IPv4 and IPv6 enabled by default

Configuration example:
```yaml
FakeTCP:
  Enabled: true
  TunName: "etherguard-tcp0"
  TunIPv4: "192.168.200.1/24"
  TunPeerIPv4: "192.168.200.2"
  TunIPv6: "fd00:200::1/64"
  TunPeerIPv6: "fd00:200::2"
  TunMTU: 1500
```

## Integration Example

### Using Critical Logger in main_edge.go or main_super.go

```go
package main

import (
    "time"
    "github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func Edge(configPath string, useUAPI bool, printExample bool, bindmode string) (err error) {
    // Create critical logger with 2-minute deadlock timeout
    critLogger := mtypes.NewCriticalLogger(2 * time.Minute)
    defer critLogger.Stop()

    // Add panic recovery at the top of the function
    defer critLogger.RecoverPanic()

    // Your existing initialization code...

    // Periodically update activity during normal operation
    // For example, in your main loop or goroutine:
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

    // Log critical errors when they occur
    if err := someOperation(); err != nil {
        critLogger.LogCritical("Failed to perform operation: %v", err)
        // Log but don't exit yet, continue with other recovery logic
    }

    // Log fatal errors that require immediate exit
    if err := criticalOperation(); err != nil {
        critLogger.LogFatal("Critical operation failed: %v", err)
        // This will log the error and exit after 3 seconds
    }

    // Rest of your code...
}
```

### Systemd Integration for Auto-Restart

Create a systemd service file (`/etc/systemd/system/etherguard.service`):

```ini
[Unit]
Description=EtherGuard VPN Service
After=network.target

[Service]
Type=simple
User=etherguard
Group=etherguard
WorkingDirectory=/opt/etherguard
ExecStart=/usr/local/bin/etherguard -mode edge -config /etc/etherguard/edge.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Restart on all exit codes
RestartForceExitStatus=1

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/etherguard

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable etherguard
sudo systemctl start etherguard
```

View logs:
```bash
sudo journalctl -u etherguard -f
```

### Supervisor Integration for Auto-Restart

Create supervisor config (`/etc/supervisor/conf.d/etherguard.conf`):

```ini
[program:etherguard]
command=/usr/local/bin/etherguard -mode edge -config /etc/etherguard/edge.yaml
directory=/opt/etherguard
user=etherguard
autostart=true
autorestart=true
startretries=999
redirect_stderr=true
stdout_logfile=/var/log/etherguard/output.log
stdout_logfile_maxbytes=50MB
stdout_logfile_backups=10
```

Control:
```bash
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start etherguard
sudo supervisorctl status etherguard
```

## Critical Error Scenarios

The critical logger will detect and handle:

1. **Deadlocks** - If no activity is recorded within the timeout period (default 2 minutes)
2. **Panics** - Any unhandled panic in goroutines (when using defer RecoverPanic)
3. **Fatal Errors** - Errors explicitly logged with LogFatal()
4. **Critical Errors** - Non-fatal but serious errors logged with LogCritical()

## Log Output Format

```
[CRITICAL] 2026/01/02 10:15:30.123456 critical_logger.go:45: CRITICAL ERROR: Failed to bind UDP socket: address already in use
Stack trace:
goroutine 1 [running]:
runtime/debug.Stack()
    /usr/local/go/src/runtime/debug/stack.go:24 +0x65
github.com/KusakabeSi/EtherGuard-VPN/mtypes.(*CriticalLogger).LogCritical(...)
    /home/user/EtherGuard-VPN/mtypes/critical_logger.go:45
...
```

## Best Practices

1. **Set appropriate deadlock timeout** - Too short may cause false positives, too long delays detection
2. **Update activity regularly** - Call `UpdateActivity()` in your main processing loops
3. **Use defer for panic recovery** - Always use `defer critLogger.RecoverPanic()` at function entry points
4. **Distinguish error levels**:
   - `LogCritical()` - Serious but potentially recoverable errors
   - `LogFatal()` - Errors requiring immediate restart
5. **Monitor logs** - Set up log monitoring/alerting for critical errors
6. **Test restart mechanism** - Verify your process manager restarts the service correctly

## Configuration Generation

When generating configs with `gencfg`, obfuscation and FakeTCP are now enabled by default:

```bash
# Generate super mode config
./etherguard -mode gencfg -cfgmode super -config gen_config.yaml

# Generate P2P mode config
./etherguard -mode gencfg -cfgmode p2p -config gen_config.yaml

# Generate static mode config
./etherguard -mode gencfg -cfgmode static -config gen_config.yaml
```

All generated configs will have:
- Obfuscation enabled with random PSK
- FakeTCP enabled with dual-stack IPv4/IPv6 support

To disable, edit the generated config files and set `Enabled: false` for the respective features.
