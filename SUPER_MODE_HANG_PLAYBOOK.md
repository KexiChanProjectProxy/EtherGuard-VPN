# Super Mode hang operator playbook

This playbook is for the next production Super Mode hang. It documents the diagnostics that already exist in this repo. It does not require a local repro environment.

## What is already implemented

- `EG_SUPER_CAPTURE_DIR` gates capture artifact writing. If it is unset, no capture signal handler is installed and no artifact is written.
- `SIGUSR1` writes a live capture artifact when `EG_SUPER_CAPTURE_DIR` is set.
- `EG_UAPI_TRACE` adds low noise UAPI timing markers to the normal service logs.
- `EG_SHUTDOWN_TRACE` keeps the bounded shutdown trace ring that is exported into the capture artifact.
- Progress snapshots are embedded into the same capture artifact. The artifact may include these sections:
  - `[device-v4-progress]`
  - `[device-v4-shutdown-trace]`
  - `[device-v6-progress]`
  - `[device-v6-shutdown-trace]`
  - `[super-events]`
  - `[graph-ntp]`
  - `[goroutines]`

## One time service setup before the next incident

Replace `etherguard` with the real systemd unit name if your service uses a different name.

```bash
SERVICE=etherguard
CAPTURE_DIR=/var/lib/etherguard/super-captures

sudo install -d -m 700 "$CAPTURE_DIR"
sudo install -d -m 755 /etc/systemd/system/${SERVICE}.service.d
sudo tee /etc/systemd/system/${SERVICE}.service.d/super-hang-capture.conf >/dev/null <<'EOF'
[Service]
Environment=EG_SUPER_CAPTURE_DIR=/var/lib/etherguard/super-captures
Environment=EG_UAPI_TRACE=1
Environment=EG_SHUTDOWN_TRACE=1
EOF
sudo systemctl daemon-reload
sudo systemctl restart "$SERVICE"
sudo systemctl show -p Environment "$SERVICE"
```

Expected result:

- `EG_SUPER_CAPTURE_DIR=/var/lib/etherguard/super-captures` is present in the unit environment.
- `EG_UAPI_TRACE=1` is present in the unit environment.
- `EG_SHUTDOWN_TRACE=1` is present in the unit environment.

## Primary live capture path

Use this first when the process still appears alive.

```bash
SERVICE=etherguard
CAPTURE_DIR=/var/lib/etherguard/super-captures
PID="$(sudo systemctl show -p MainPID --value "$SERVICE")"

sudo kill -USR1 "$PID"
sleep 2
sudo ls -l "$CAPTURE_DIR"
LATEST_ARTIFACT="$(sudo ls -1t "$CAPTURE_DIR"/super-capture-*.txt | head -n 1)"
sudo sed -n '1,120p' "$LATEST_ARTIFACT"
```

Artifact path and naming:

- Directory: `EG_SUPER_CAPTURE_DIR`, example `/var/lib/etherguard/super-captures`
- File name pattern: `super-capture-<utc-stamp>-<pid>-<seq>-<trigger>.txt`
- Expected live trigger suffix after `SIGUSR1`: `-signal-sigusr1.txt`

The first lines in a healthy capture should start like this:

```text
trigger=signal-sigusr1
pprof=<pprof-addr-or-empty>
captured_at=<utc timestamp>
pid=<pid>
```

## Fallback capture path when UAPI or pprof is unhealthy

Do not wait on `wg` or `pprof` if they are hanging. The fallback path is the same file artifact surface, but it uses the process signal and shutdown path instead of depending on UAPI or HTTP.

### Step 1, prove UAPI or pprof is unhealthy without blocking forever

```bash
SERVICE=etherguard

sudo timeout 10s wg show || printf 'wg show timed out or failed\n'
sudo timeout 5s curl -fsS http://127.0.0.1:6060/debug/pprof/goroutine?debug=2 >/tmp/etherguard-pprof-goroutines.txt || printf 'pprof timed out, failed, or is disabled\n'
sudo journalctl -u "$SERVICE" --since -15min --no-pager
```

### Step 2, force a live file capture that does not depend on UAPI or pprof

```bash
SERVICE=etherguard
CAPTURE_DIR=/var/lib/etherguard/super-captures
PID="$(sudo systemctl show -p MainPID --value "$SERVICE")"

sudo kill -USR1 "$PID"
sleep 2
sudo ls -l "$CAPTURE_DIR"
```

### Step 3, if no fresh artifact appears, trigger the shutdown capture path

```bash
SERVICE=etherguard
CAPTURE_DIR=/var/lib/etherguard/super-captures

sudo systemctl stop "$SERVICE"
sleep 2
sudo ls -l "$CAPTURE_DIR"
LATEST_ARTIFACT="$(sudo ls -1t "$CAPTURE_DIR"/super-capture-*.txt | head -n 1)"
sudo sed -n '1,160p' "$LATEST_ARTIFACT"
sudo journalctl -u "$SERVICE" --since -15min --no-pager
```

Expected shutdown trigger suffixes:

- `-shutdown-signal.txt`
- `-shutdown-device-wait.txt`
- `-runtime-error.txt`

If both `SIGUSR1` and shutdown fail to produce a fresh artifact, treat that as strong evidence for a whole process stall. Go to the branch guide below.

## First branch to read: UAPI stall or whole process stall

### Branch A, UAPI stall

This branch means the process is still running enough to write captures or logs, but the `wg` / UAPI path is wedged.

Run:

```bash
SERVICE=etherguard
CAPTURE_DIR=/var/lib/etherguard/super-captures
LATEST_ARTIFACT="$(sudo ls -1t "$CAPTURE_DIR"/super-capture-*.txt | head -n 1)"

sudo grep -n '^\[device-v[46]-progress\]\|^\[device-v[46]-shutdown-trace\]\|^\[super-events\]\|^\[graph-ntp\]\|^\[goroutines\]' "$LATEST_ARTIFACT"
sudo journalctl -u "$SERVICE" --since -15min --no-pager | grep 'UAPI trace:'
```

Interpret it as UAPI stalled when most of these are true:

- A fresh capture artifact exists after `SIGUSR1` or controlled shutdown.
- `wg show` timed out or blocked.
- UAPI trace logs show one of these unfinished pairs:
  - `accept wait-begin` with no later `accept wait-end`
  - `accept dispatch` with a very large `accept-to-handle=` delay later in the sequence
  - `get ipcMutex wait-begin` or `set ipcMutex wait-begin` with no matching `wait-end`
  - `get serialize begin` or `set apply begin` with no matching end marker
- The artifact still contains fresh progress sections or shutdown trace movement, which means the scheduler is still making progress outside the stuck UAPI path.

What to save:

- The newest `super-capture-*.txt`
- `journalctl -u "$SERVICE" --since -15min --no-pager`
- The exact wall clock time when `wg show` first started hanging

### Branch B, whole process stall

This branch means the process is not making enough progress to handle the live capture or the controlled shutdown path.

Treat it as whole process stalled when most of these are true:

- `wg show` hangs or times out.
- `pprof` hangs, fails, or is disabled.
- `SIGUSR1` does not create a fresh `super-capture-*.txt`.
- `systemctl stop` does not create a fresh `super-capture-*.txt` either, or it gets stuck waiting for the service to exit.
- No fresh `UAPI trace:` lines appear in the journal for the incident window.

What this means:

- The issue is likely broader than the UAPI lock path.
- Expect a scheduler wide wedge, a deadlock on a shared critical path, or a process state that cannot advance enough to write the artifact.
- Save the same journal window and note that both capture paths failed.

## Fast artifact reading guide

Use these commands on the newest artifact:

```bash
CAPTURE_DIR=/var/lib/etherguard/super-captures
LATEST_ARTIFACT="$(sudo ls -1t "$CAPTURE_DIR"/super-capture-*.txt | head -n 1)"

sudo sed -n '1,80p' "$LATEST_ARTIFACT"
sudo grep -n '^\[device-v4-progress\]\|^\[device-v4-shutdown-trace\]\|^\[device-v6-progress\]\|^\[device-v6-shutdown-trace\]\|^\[super-events\]\|^\[graph-ntp\]\|^\[goroutines\]' "$LATEST_ARTIFACT"
sudo grep -n 'device.closed send begin\|device.closed send end\|Device.Close\|closeBindLocked\|BindUpdate' "$LATEST_ARTIFACT"
```

Read it in this order:

1. Header lines, confirm `trigger=...`, `captured_at=...`, and `pid=...`.
2. `device-v4-shutdown-trace` and `device-v6-shutdown-trace`, check for a begin marker that never gets an end marker. A missing `device.closed send end` after `device.closed send begin` points at the unbuffered shutdown send. A missing `Device.Close state.stopping.Wait end` points at worker shutdown wait. A missing `closeBindLocked net.stopping.Wait end` points at bind shutdown wait.
3. `device-v4-progress` and `device-v6-progress`, check whether the node looks idle, blocked on send queue pressure, blocked on TUN read, blocked on TAP write, or blocked on TAP flush.
4. `super-events` and `graph-ntp`, check whether the Super event loop or NTP background work is still advancing.
5. `goroutines`, correlate blocked stacks with the stalled section above.

## Default safe behavior check

These diagnostics stay off unless the operator enables them with environment variables.

- `EG_SUPER_CAPTURE_DIR` unset: no capture signal handler, no artifact writes.
- `EG_UAPI_TRACE` unset: no UAPI trace log lines.
- `EG_SHUTDOWN_TRACE` unset: no shutdown trace ring export.
- Progress snapshots are exported only through the capture artifact when capture is enabled.

That keeps the default runtime low noise and unchanged until an operator opts in.
