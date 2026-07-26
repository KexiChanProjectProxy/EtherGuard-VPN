# Etherguard
[English](#) | [中文](README_zh.md)

## Super mode (HTTP-only Control API v2)

This mode is inspired by [n2n](https://github.com/ntop/n2n). There are 2 types of node: SuperNode and EdgeNode.
The SuperNode runs an HTTP-only control service. EdgeNodes register over HTTP, receive a peer snapshot, and exchange latency measurements. The SuperNode runs the [Floyd-Warshall Algorithm](https://en.wikipedia.org/wiki/Floyd%E2%80%93Warshall_algorithm) and distributes the routing result back to all EdgeNodes.

**Breaking change:** Super mode no longer uses a UDP listener, WireGuard private keys, UAPI, or the `wg` command on the Super side. If you have an existing v1 config with `PrivKeyV4`, `PrivKeyV6`, `ListenPort`, `FwMark`, `API_Prefix`, `ListenPort_EdgeAPI`, or `ListenPort_ManageAPI`, it will be rejected with a `legacy_udp_field` error. You must migrate to a v2 `SuperConfigV2` YAML before upgrading.

## Quick start

### 1. Generate configs

Edit `gensuper.yaml` with your network parameters, then generate all config files:

```bash
./etherguard-go -mode gencfg -cfgmode super -config example_config/super_mode/gensuper.yaml
```

The generator creates a v2 Super YAML and per-Edge YAML files with fresh per-Edge ControlPSKeys. Each Edge gets its own unique HMAC signing key, which appears only in that Edge's config and the matching Super peer entry.

### 2. Start the SuperNode

```bash
./etherguard-go -config example_config/super_mode/EgNet_super.yaml -mode super
```

The SuperNode listens on two TCP ports (Edge API and Management API). No UDP socket is created. If you pass a legacy v1 YAML file, the process exits immediately with:

```
control v2: legacy_udp_field: "PrivKeyV4" is no longer accepted in -mode super; use a v2 SuperConfigV2 YAML
```

### 3. Start EdgeNodes

```bash
./etherguard-go -config example_config/super_mode/EgNet_edge001.yaml -mode edge
./etherguard-go -config example_config/super_mode/EgNet_edge002.yaml -mode edge
```

### 4. Try it

The example configs use `stdio` mode. Type in one Edge window:

```
b1aaaaaaaaaa
```

The `b` is the broadcast address (`FF:FF:FF:FF:FF:FF`), `1` is the MAC address (`AA:BB:CC:DD:EE:01`), and `aaaaaaaaaa` is the payload. You should see the same string appear in the other Edge window.

## Architecture

### How it works

1. Each Edge sends a signed `POST /edge/v2/register` to the SuperNode, advertising its local and STUN-derived candidates.
2. The SuperNode records the Edge in its control state and returns a `ControlV2Snapshot` containing all known peers and current parameters.
3. Edges periodically send `POST /edge/v2/report` with latency observations (pong results) and refreshed candidates.
4. The SuperNode feeds latency data into the Floyd-Warshall graph and recalculates the NextHopTable.
5. Edges subscribe to `GET /edge/v2/events` (SSE stream) or poll `GET /edge/v2/snapshot` to detect changes.
6. When the snapshot revision changes, the Edge applies the new peer list and routing table to its WireGuard device.

### Control API v2 routes

All routes are served under the `APIPrefix` configured in the Super YAML (default `/edge/v2`).

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/edge/v2/register` | Edge introduces itself; returns initial snapshot |
| POST | `/edge/v2/report` | Edge sends pongs, candidate refreshes, heartbeat |
| GET | `/edge/v2/snapshot` | Edge fetches current peer snapshot (ETag/304) |
| GET | `/edge/v2/events` | SSE stream of state-change events |

### HMAC request signing

Every Control API v2 request carries four headers:

| Header | Value |
|--------|-------|
| `X-EG-NodeID` | Decimal NodeID |
| `X-EG-Timestamp` | Unix seconds |
| `X-EG-Nonce` | Unique per-request token |
| `X-EG-Signature` | `hex(HMAC-SHA256(key=ControlPSKey, msg=canonical))` |

The canonical string is:
```
METHOD\nescaped-path\nunix-timestamp\nnonce\nhex(SHA-256(body))
```

The Super verifies all four headers. Requests outside a 60-second clock skew window, with replayed nonces, oversized bodies (>1 MiB), or incorrect signatures are rejected with a uniform `"control auth failed"` response that never reveals which check failed or contains any key material.

**Security boundary:** The ControlPSKey is a per-Edge SECRET. It must never appear in URLs, log files, snapshots, or any HTTP response to other Edges. The `json:"-"` tag on `SuperNodeV2Ref.ControlPSKey` and `SuperConfigV2Peer.ControlPSKey` prevents serialization leaks.

### TLS via reverse proxy

The HMAC signature authenticates but does not encrypt. In production, you **must** run a reverse proxy (nginx, Caddy, etc.) in front of the SuperNode to provide TLS. The SuperNode itself only speaks HTTP.

```nginx
server {
    listen 443 ssl;
    ssl_certificate /etc/ssl/etherguard.crt;
    ssl_certificate_key /etc/ssl/etherguard.key;

    location /edge/v2/ {
        proxy_pass http://127.0.0.1:3456/edge/v2/;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_buffering off;
    }
    location /edge/v2/manage/ {
        proxy_pass http://127.0.0.1:3456/edge/v2/manage/;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### SSE with polling fallback

Edges connect to `GET /edge/v2/events` for real-time state-change notifications. The stream uses standard Server-Sent Events format:

- `id:` fields are monotonically increasing (`evt-N`).
- `event:` types are `peer_change`, `peer_gone`, `params_change`, or `revision`.
- `data:` carries JSON payload (e.g. `{\"node_id\":1,\"node_name\":\"Node001\"}`).

On reconnect, the Edge sends `Last-Event-ID` to resume from the retained buffer. If the server cannot replay (ID older than retention), the Edge must re-fetch the full snapshot.

Polling is fallback-only: `ControlHTTPClient.Sync` establishes SSE first, starts timed snapshot polling only after a stream connection or parse failure, and cancels polling as soon as a stream is healthy again. When the Super's event hub closes, in-flight SSE streams terminate so Edges detect the failure and fall back to polling. The Edge uses ETag/304 conditional requests to avoid transferring unchanged snapshots.

### STUN candidate discovery

The Super distributes STUN servers to all Edges via the `STUNServers` field in the parameters stream. Each Edge uses its existing WireGuard bind socket (same port as its UDP data path) to perform STUN binding requests. The XOR-MAPPED address becomes a `stun` candidate.

**Same-socket limitation:** STUN candidates are measured from the WireGuard bind. If a STUN server sees a different source port than the WireGuard socket, the candidate is invalid because the NAT mapping is port-specific. Edges do not create a second UDP socket for STUN.

Both `stun:host:port` and `stun://host:port` URI forms are accepted. Hosts may be IP literals (e.g. `stun:192.168.1.10:3478`) or syntactically valid DNS hostnames (e.g. `stun://local-stun.example:3478`). Validation performs no DNS I/O; it only checks the URI shape. DNS resolution happens at runtime inside `SuperSTUNManager`, under the configured per-server timeout, before the IP-only bind parser. Generic endpoint parsing (`conn/conn.go`) remains IP-literal-only; DNS hostnames are only resolved for STUN, not for peer endpoints. `STUNRefreshIntervalSeconds` actively schedules periodic discovery: each refresh preserves local candidates, replaces stale STUN-only candidates, and deduplicates the result. STUN discovery is not a keepalive.

### Direct connectivity and observed fallbacks

An omitted Edge `DirectConnectivity` block uses these dynamic Super-peer defaults:

| Key | Default seconds | Purpose |
|-----|----------------:|---------|
| PersistentKeepaliveSeconds | 25 | Keep NAT mappings for Super-discovered peers |
| SendPingIntervalSeconds | 16 | Direct-peer ping cadence |
| PeerAliveTimeoutSeconds | 70 | Edge-local dynamic-peer liveness timeout |
| TimeoutCheckIntervalSeconds | 10 | Offline check cadence |
| ConnNextTrySeconds | 5 | Delay before the next candidate try |

These settings apply only to Super-discovered peers; static peer policy is unchanged. They do not make STUN a keepalive.

An Edge may report at most 256 observed target endpoints per report. The Super publishes anonymous aggregate fallbacks only: at most 16 hints per target, including at most 14 IPv4 and 14 IPv6 hints. Reporter identities and timestamps are never included. Votes expire using the Super-side `PeerAliveTimeoutSeconds`.

Candidate classes always remain ordered local < STUN < observed. Reporter counts rank observed candidates only; they never let an observed candidate outrank local or STUN candidates.

### No relay / TURN

Unlike n2n, the SuperNode does not relay any packets. If UDP hole-punching between two Edges fails and no alternative route exists, those Edges cannot communicate. There is no fallback forwarding.

If you need connectivity between Edges that cannot hole-punch, deploy a relay node: a regular Edge on a public network with `interface=dummy`.

## SuperNode Config Parameter (v2)

| Key | Description |
|-----|-------------|
| NodeName | Node name (max 32 chars) |
| APIUrl | URL of the Edge API listener (e.g. `http://host:3456`) |
| APIPrefix | API path prefix (e.g. `/edge/v2`) |
| ManagementAuth | `{User, PasswordHash}` for `/manage/*` endpoints |
| STUNServers | List of STUN server URIs (`stun:host:port` or `stun://host:port`); hosts may be IP literals or DNS hostnames |
| STUNRequestTimeoutSeconds | Timeout per STUN request |
| STUNRefreshIntervalSeconds | Active interval for periodic STUN candidate discovery; this is not a keepalive |
| PollIntervalSeconds | Edge polling interval for snapshot |
| ReportIntervalSeconds | Edge report (pong/candidate) interval |
| HeartbeatIntervalSeconds | Edge heartbeat interval |
| EventReplay | SSE replay ring depth (default 256) |
| PeerAliveTimeoutSeconds | Seconds of inactivity before a peer is removed |
| UsePSKForInterEdge | Generate pairwise WireGuard PSKs for inter-Edge traffic |
| DampingFilterRadius | Low-pass filter window radius for latency smoothing |
| Peers | List of pre-authorized Edge peers |

### Peers (Super-side)

| Key | Description |
|-----|-------------|
| NodeID | Edge's node ID |
| NodeName | Edge's name |
| ControlPSKey | Per-Edge HMAC signing secret (never exposed to other Edges) |
| AdditionalCost | Extra forwarding cost in ms (`-1` = use Edge's own setting) |

## EdgeNode Config Parameter (v2)

### EdgeConfig Root

The Edge v2 config replaces the old `DynamicRoute.SuperNode` block with a `SuperNodeV2` reference. A v1 Edge config containing a `LegacySuper` key or a `DynamicRoute.SuperNode` key (including `UseSuperNode: false`) is rejected with a typed `legacy_udp_field` error; it never silently becomes static mode.

### SuperNodeV2

| Key | Description |
|-----|-------------|
| APIUrl | SuperNode's Edge API URL |
| APIPrefix | API path prefix (must match Super's `APIPrefix`) |
| NodeID | SuperNode's non-special NodeID |
| ControlPSKey | This Edge's HMAC signing secret (must match Super's peer entry) |

### Interface, LogLevel, Peers

These are identical to [Static Mode](../static_mode/README.md) configuration. In Super mode, the `Peers` list is typically empty since peer information is downloaded from the SuperNode.

## V1 config migration

If you run `-mode super` with an old v1 config, you will see:

```
Error: control v2: legacy_udp_field: "PrivKeyV4" is no longer accepted in -mode super
```

The rejected fields are: `PrivKeyV4`, `PrivKeyV6`, `ListenPort`, `FwMark`, `API_Prefix`, `ListenPort_EdgeAPI`, `ListenPort_ManageAPI`.

To migrate:
1. Generate a fresh v2 config: `./etherguard-go -mode gencfg -cfgmode super -config gensuper.yaml`
2. Review the generated `EgNet_super.yaml` and edge YAMLs.
3. Start with `-mode super -config EgNet_super.yaml`.

## VPP status

VPP integration is excluded and unvalidated in this release. No libmemif-equipped host ran `make vpp`. The migration touched `device/`, `main_edge.go`, and `main_super.go`, so VPP build or runtime regressions are possible. Validate `make vpp` on a host with libmemif before any release.

## HTTP Manage API

The legacy `/manage/*` endpoints are preserved for front-end tooling:

```bash
curl "http://127.0.0.1:3456/edge/v2/manage/super/state?Password=passwd_hash_example"
```

See the [legacy Manage API documentation](#http-manage-api) below for the full endpoint list (peer/add, peer/del, peer/update, super/update, super/state).

## Example configs

| File | Description |
|------|-------------|
| `gensuper.yaml` | Generator input for creating v2 configs |
| `EgNet_super.yaml` | Generated SuperNode v2 config |
| `EgNet_edge001.yaml` | Generated EdgeNode 1 v2 config |
| `EgNet_edge002.yaml` | Generated EdgeNode 2 v2 config |
| `EgNet_edge100.yaml` | Generated EdgeNode 100 v2 config |

## Next: [P2P Mode](../p2p_mode/README.md)
