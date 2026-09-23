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
| GET | `/edge/v2/cluster/link` | HTTP Upgrade, super-to-super only; HMAC(`Cluster.Secret`) |

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

    location /edge/v2/cluster/link {
        proxy_pass http://127.0.0.1:3456/edge/v2/cluster/link;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_read_timeout 90s;
        proxy_send_timeout 90s;
    }
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

**Multi-WAN edges:** on Linux, an Edge with several uplinks (for example several default routes) probes STUN once through every uplink, still from the same WireGuard socket. Each probe pins the uplink's source address and outgoing interface, so both per-interface default routes and `ip rule from <src>` policy routing are honoured. The Edge reports one `stun` candidate per distinct public `ip:port`, plus the mapping seen through the kernel's default route. At most one address per interface and family is probed, up to 8 uplinks, and only interfaces that are up and running count. With `--bindmode std` or on non-Linux platforms only the default-route mapping is discovered.

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

#### Lowest-latency endpoint selection

Once a peer is alive, the Edge keeps measuring every path to it: each (local uplink, remote candidate) pair gets one encrypted probe per round, and the peer moves to the fastest pair when it is clearly better for several rounds in a row. Each side only ranks its own outbound paths; the two directions may use different uplinks. Probes also keep the NAT mappings of alternate uplinks alive, so keep the probe interval below your NAT's UDP timeout (about 25 seconds is safe). Peers with a single path cost nothing. Probe results never feed route latency.

Besides published candidates, the Edge also probes peer-reflexive addresses: sources of authenticated packets from the peer that the roaming guard did not adopt. Behind a NAT with endpoint-dependent mapping, the port a peer sees differs from the STUN-reported port, so these addresses are the only way to reach that uplink. At most four are kept per peer, and they expire after the Edge-local peer alive timeout.

| Key | Default | Purpose |
|-----|--------:|---------|
| DisableEndpointSelection | false | Turn lowest-latency selection off |
| EndpointProbeIntervalSeconds | ping interval | Seconds between probe rounds |
| EndpointSwitchMarginMS | 5 | Minimum RTT gain in milliseconds before switching |
| EndpointSwitchMarginPercent | 15 | Minimum RTT gain as a percentage of the current RTT; the larger margin applies |
| EndpointSwitchRounds | 3 | Consecutive rounds the faster path must win before switching |

An Edge may report at most 256 observed target endpoints per report. The Super publishes anonymous aggregate fallbacks only: at most 16 hints per target, including at most 14 IPv4 and 14 IPv6 hints. Reporter identities and timestamps are never included. Votes expire using the Super-side `PeerAliveTimeoutSeconds`.

Candidate classes always remain ordered local < STUN < observed when an Edge tries to reach a peer that is not alive. Reporter counts rank observed candidates only; they never let an observed candidate outrank local or STUN candidates. Once the peer is alive, lowest-latency selection may move it to any candidate that measures faster.

## Super-owned listen port policy

`ListenPortPriority` is a **Super-only** ordered candidate list. It is the
single source of truth for which UDP listen port an Edge should bind first.
The Super publishes the list inside `ControlV2Parameters`; every Edge that
registers against that Super sees the same ordered set in its snapshot.

### Bootstrap-required startup

An Edge MUST fetch the policy from the Super's protected endpoint before
it binds any UDP socket. The first snapshot returned by
`POST /edge/v2/register` carries the `ListenPortPriority` field of the
current `ControlV2Parameters`; the Edge walks the list in declared order
and binds the first free port. If the Edge ever receives an updated
parameters stream (`event: params_change`), it rebinds to the new
candidate set without losing registered state.

If the Edge cannot reach the Super at startup (network down, certificate
error, etc.) it MUST NOT bind a port from a stale local policy — it has
no local policy. The Edge retries `register` with the configured
`PollIntervalSeconds` until a snapshot is delivered.

### Ordered candidate semantics

Entries are walked in the order they appear in YAML:

- A `Port:` entry is a single literal port.
- A `Range:` entry is an inclusive `[From, To]` range walked left-to-right.
- Later entries that repeat an already-claimed port are silently dropped
  (first-occurrence wins, deduped by integer value).
- The expansion cap is 256 unique ports; an entry that would push the
  candidate set past 256 fails at YAML parse with a typed
  `invalid_candidate` error rather than silently truncating.

Validation rejects: ports outside `[1, 65535]`, reversed ranges
(`From > To`), entries that set both `Port:` and `Range:`, empty entries,
and any policy whose unique expansion exceeds 256. All of these surface
as `SuperConfigV2.Validate()` errors so a malformed Super YAML fails
fast at startup.

### Port-zero fallback

If every candidate in `ListenPortPriority` is already in use on the host
(or all are denied by the OS / firewall), the Edge falls back to
`listen_port = 0` (kernel-assigned ephemeral port) and continues running.
The chosen ephemeral port is reported back to the Super in the next
`POST /edge/v2/report` so peers learn the actual bind even though the
policy itself was exhausted.

The fallback is **last-resort only**: the Edge does not skip candidates
in the declared order to reach port zero faster, and it does not abort
on a full miss. Falling back is logged at WARN so operators can tell a
"policy exhausted" Edge from a normal one.

### What Edge / client profiles MUST NOT carry

`ListenPortPriority` is exclusively a Super-side YAML key. The 100 Edge
profiles in this repo (`logs.yaml` and `ngsdn_edge002.yaml` …
`ngsdn_edge100.yaml`) MUST NOT carry:

- `ListenPortPriority` (the ordered candidate list)
- `ListenPort` (the bare v1 single-port field)
- `BootstrapListenPortPriority` or any similar local-port-policy key

Edges inherit the Super's policy through the parameters stream at every
`register` / `snapshot` fetch. Hardcoding a local port in an Edge
profile would silently override the Super's authoritative policy and
defeat the bootstrap-required startup contract. The corpus audit in
`docs_contract_test.go` enumerates every Edge file and fails if any of
those keys reappear.

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
| ListenPortPriority | Ordered, Super-owned UDP listen-port candidate list (see [Super-owned listen port policy](#super-owned-listen-port-policy)); Edges MUST NOT carry a local copy |
| Peers | List of pre-authorized Edge peers |
| Cluster | Optional active-active Super cluster (see [Multi-super control plane (active-active)](#multi-super-control-plane-active-active)); omit for a single Super |

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
| APIUrls | Ordered Super API URLs for sticky failover. When `Cluster` is set, generated profiles leave `APIUrl` empty and set `APIUrls` to this Super, then each `Cluster.Peers[].APIUrl` in config order |
| APIPrefix | API path prefix (must match Super's `APIPrefix`) |
| NodeID | SuperNode's non-special NodeID |
| ControlPSKey | This Edge's HMAC signing secret (must match Super's peer entry) |

### Interface, LogLevel, Peers

These are identical to [Static Mode](../static_mode/README.md) configuration. In Super mode, the `Peers` list is typically empty since peer information is downloaded from the SuperNode.

## Multi-super control plane (active-active)

An optional `Cluster` block runs two or more SuperNodes side by side. Each Super fully serves Edges on its own. Supers keep a persistent, encrypted, compressed HTTP Upgrade link and replicate control-plane state. Single-Super setups omit `Cluster` and stay unchanged.

The cluster is eventually consistent; converges within one ReportInterval after connectivity is restored. It does not provide strong consistency, leader election, or a shared database. VPN data-plane traffic is never relayed between Supers.

### What replicates vs what stays local

Replicated (last-write-wins by hybrid logical clock):

- Live Edge records (candidates, latency, observed-endpoint votes, last-seen)
- Registry, including `ControlPSKey` values
- Parameters: `STUNServers`, `STUNRequestTimeoutSeconds`, `STUNRefreshIntervalSeconds`, `PollIntervalSeconds`, `ReportIntervalSeconds`, `HeartbeatIntervalSeconds`, `EventReplay`, `RelayCostMS`, `ListenPortPriority`, `EndpointBlacklist`

Local to each Super (never overwritten by a replica apply):

- `NodeName`, `APIUrl`, `APIPrefix`, `ManagementAuth`, `Cluster`
- `PeerAliveTimeoutSeconds`, `UsePSKForInterEdge`, `DampingFilterRadius`

### Cluster

Omit the whole block for a single Super. When present, `SelfID` and `Secret` are required.

| Key | Default | Description |
|-----|---------|-------------|
| SelfID | (required) | This Super's `Vertex`. Non-zero, non-special, unique in the cluster |
| Secret | (required) | Shared cluster HMAC secret, `json:"-"`. At least 16 bytes. Never appears in `/manage/super/state` |
| Peers | `[]` | Other Supers in this cluster. `SuperID` must be unique and different from `SelfID` |
| HeartbeatSeconds | 10 | Cluster-link ping interval; must be positive |
| DeadAfterSeconds | 30 | Link dead after this many seconds without an authenticated record; must be greater than `HeartbeatSeconds` |
| ReconnectMinSeconds | 1 | Dial backoff floor |
| ReconnectMaxSeconds | 30 | Dial backoff ceiling; must be at least `ReconnectMinSeconds` |
| RemoteStaleGraceSeconds | 600 | After the link to a remote Super drops, keep that Super's live records for this many seconds (must be at least `PeerAliveTimeoutSeconds`). A zero value becomes `max(600, PeerAliveTimeoutSeconds)` |
| Compression | `zstd` | Inner stream compression: `zstd` or `none` |

### Cluster peers

| Key | Description |
|-----|-------------|
| SuperID | Peer's Super `Vertex`. Non-zero, non-special, not equal to `SelfID` |
| APIUrl | Peer's Edge API URL (`http` or `https`, host required). Used to dial `GET {APIPrefix}/cluster/link` |

Ready-to-run pair: `EgNet_super_cluster_a.yaml` (SelfID 1, `http://127.0.0.1:3456`) and `EgNet_super_cluster_b.yaml` (SelfID 2, `http://127.0.0.1:3457`). Both use the placeholder secret `REPLACE_WITH_32_RANDOM_CHARS`, which validates (`>=16` bytes) but is not a production secret.

`gensuper_cluster.yaml` is generator input for `-mode gencfg -cfgmode super`, not a runtime Super YAML. It copies `Cluster` into the generated Super config and emits Edge profiles with `APIUrls` listing every Super. The example generator input uses ports 3000/3001; the runtime pair above uses 3456/3457.

### Edge failover

Each Edge talks to one Super at a time. `SuperNodeV2.APIUrls` is the sticky failover list (`ResolveAPIUrls()` prepends legacy `APIUrl` when set, trims trailing `/`, and deduplicates in first-seen order).

Rotation happens only in the report loop, and only when more than one URL is configured:

- 3 consecutive qualifying report failures, or
- no qualifying success for `max(3×ReportInterval, 15s)`

Qualifying successes: Register 200, Report 2xx, Snapshot 200/304, SSE 200 connected. `ErrControlUnknownPeer` does not increment the failure counter (the Edge re-registers instead).

Selection is sticky-current: the Edge stays on the Super it rotated to. There is no automatic fail-back when a previous Super returns.

Bootstrap walks `APIUrls` in order with per-attempt budget `max(2s, remaining/len)` and starts the runtime on the first Super that returns a valid policy.

### Partition semantics

While the inter-Super link is up, remote-origin live records are kept even if those Edges are not reporting locally.

When the link is down, remote-origin records are evicted only after `RemoteStaleGraceSeconds` from `max(receivedAt, linkDownSince)`. That eviction is local: no tombstone, no outbox mutation. Local-origin records still sweep with `PeerAliveTimeoutSeconds`.

If an Edge switches Supers during a link outage, it disappears from the other half until the link heals and a `full_sync` runs. The Edge's new Super mints newer versions; after the link returns, last-write-wins merge restores a single view.

### Consistency

The cluster is eventually consistent; converges within one ReportInterval after connectivity is restored. Do not treat `/manage/super/state` or an Edge snapshot as a linearizable cluster-wide read.

### Security

The inter-Super link uses app-layer X25519 key agreement, HKDF, and ChaCha20-Poly1305 records (optional continuous zstd inside). That is defense-in-depth on top of whatever TLS the reverse proxy already terminates. TLS via the proxy is still required. App-layer encryption is not a TLS replacement. The Super itself still speaks only HTTP.

Handshake auth is HMAC-SHA256 of a canonical string keyed by `Cluster.Secret`. The request path is part of that canonical string, so a reverse proxy must not rewrite `/edge/v2/cluster/link`.

### Accepted risk

A captured signed Edge request replayed to the other Super within the ±60s timestamp-skew window (up to about 120s once clock skew between the two Supers is included) can re-assert that same Edge's own fields and its observed-endpoint votes. The Edge's next legitimate report mints a newer version and supersedes the replay. Impact is bounded and self-healing.

### nginx Upgrade for the cluster link

Copy this `location` verbatim. The path is part of the signed canonical string and must not be rewritten. `proxy_read_timeout` should be at least `3×HeartbeatSeconds` (90s covers the default 10s heartbeat with margin):

```nginx
location /edge/v2/cluster/link {
    proxy_pass http://127.0.0.1:3456/edge/v2/cluster/link;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_buffering off;
    proxy_read_timeout 90s;
    proxy_send_timeout 90s;
}
```

### Diagnostics: `/manage/cluster/state`

`GET {APIPrefix}/manage/cluster/state?Password=<hash>` is password-gated like mutating `/manage/*` routes.

With no `Cluster` configured the body is exactly `{"enabled":false}`.

With a cluster the body is `clusterStatus` (no separate `enabled` field):

```json
{
  "self_id": 1,
  "links": [
    {
      "super_id": 2,
      "api_url": "http://127.0.0.1:3457",
      "state": "connected",
      "dialer": true,
      "compression": "zstd",
      "connected_since": "2026-09-16T00:00:00Z",
      "last_rx_at": "2026-09-16T00:00:00Z",
      "last_full_sync_at": "2026-09-16T00:00:00Z",
      "tx": {"messages": 0, "inner_bytes": 0, "compressed_bytes": 0, "wire_bytes": 0},
      "rx": {"messages": 0, "inner_bytes": 0, "compressed_bytes": 0, "wire_bytes": 0}
    }
  ],
  "hlc": 0,
  "outbox_len": 0,
  "live_records": 0,
  "registry_entries": 0
}
```

`state` is `connected`, `connecting`, or `down`. `/manage/super/state` is unchanged and still redacts `Cluster.Secret`.

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
| `gensuper_cluster.yaml` | Generator input for a two-Super cluster (not a runtime Super YAML) |
| `EgNet_super.yaml` | Generated SuperNode v2 config |
| `EgNet_super_cluster_a.yaml` | Example runtime Super A (`Cluster.SelfID` 1) |
| `EgNet_super_cluster_b.yaml` | Example runtime Super B (`Cluster.SelfID` 2) |
| `EgNet_edge001.yaml` | Generated EdgeNode 1 v2 config |
| `EgNet_edge002.yaml` | Generated EdgeNode 2 v2 config |
| `EgNet_edge100.yaml` | Generated EdgeNode 100 v2 config |

## Next: [P2P Mode](../p2p_mode/README.md)
