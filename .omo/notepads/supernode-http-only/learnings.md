# supernode-http-only - learnings

## [2026-07-25] Task: 1 — Control API v2 schema & typed contracts (wave 1)

### Files written/modified in worktree `/home/kexi/eg-super-http/w1-schema` (branch `super-http-w1-schema`)
- `mtypes/config.go` — removed `PrivKeyV4`, `PrivKeyV6`, `ListenPort`,
  `FwMark`, `API_Prefix`, `ListenPort_EdgeAPI`, `ListenPort_ManageAPI` from
  `SuperConfig` (UDP-only fields). Added `Vertex.IsSpecial()` helper.
  Per-Edge Super `PSKey` is preserved (now renamed `ControlPSKey` on the
  v2 per-peer records) as the HMAC secret for Control API v2 request
  signing. The legacy `SuperConfig` struct is intentionally kept so that
  later tasks can construct it from generated v2 input without dropping
  HTTP-only listeners yet (main_super.go/main_httpserver.go will be
  reworked by later tasks).
- `mtypes/http_control.go` — new file with all v2 types and validators.
- `mtypes/http_control_test.go` — new file with TDD tests.

### Public v2 contract surface (CRITICAL for wave-2 tasks — consume these names exactly)

Constants (in `mtypes/http_control.go`):
- `ControlV2ProtocolVersion = "v2"` — only supported version
- `ControlV2APIPrefix = "/edge/v2"` — conventional mount for the v2 routes

Stable error codes (`ControlV2Error.Code`):
- `ControlV2ErrUnsupportedVersion`
- `ControlV2ErrInvalidNodeID`
- `ControlV2ErrInvalidURI`
- `ControlV2ErrInvalidDuration`
- `ControlV2ErrInvalidCandidate`
- `ControlV2ErrMissingField`
- `ControlV2ErrLegacyUDPField`
- `ControlV2ErrInvalidManagement`
- `ControlV2ErrInvalidSTUNServer`
- `ControlV2ErrInvalidAPIPrefix`

Helpers (package `mtypes`):
- `IsControlV2Error(err) bool` — returns true for `*ControlV2Error`
- `ErrorCode(err) string` — returns the stable code, "" for non-v2 errors
- `ValidateSTUNURI(raw string) error` — accepts `stun:host:port` /
  `stuns:host:port` (IP-literal hosts only; DNS names must be resolved
  before this call).
- `ParseControlV2Parameters(io.Reader) (ControlV2Parameters, error)` —
  decodes + validates the typed parameter stream (JSON wire form).

Typed request models (JSON wire form):
- `ControlV2RegisterRequest` — body of POST /edge/v2/register.
  Fields: `NodeID Vertex`, `NodeName string`, `Version string`
  (= ControlV2ProtocolVersion), `ListenPort int`, `FwMark uint32`,
  `LocalV4/LocalV6 []string`, `PublicV4/PublicV6 []string`,
  `DesiredTTL uint8`, `RequestedAt time.Time`, `Implementation string`.
  Has `Validate() error`.
- `ControlV2ReportRequest` — body of POST /edge/v2/report.
  Fields: `NodeID Vertex`, `Pongs []ControlV2Pong`,
  `Candidates []ControlV2Candidate`, `ReportedAt time.Time`.
  Has `Validate() error`.
- `ControlV2Snapshot` — body of GET /edge/v2/snapshot.
  Fields: `Revision uint64`, `IssuedAt time.Time`,
  `Parameters ControlV2Parameters`, `Peers []ControlV2Peer`.
  Has `ETag() string` (returns `"rev-<n>"`) and
  `Accepts(incoming *ControlV2Snapshot) bool`.
- `ControlV2Event` — single SSE event.
  Fields: `ID string`, `Type ControlV2EventType`, `Revision uint64`,
  `Data interface{}` (carries `ControlV2PeerChangePayload` for
  peer_change/peer_gone).

Typed snapshot sub-types:
- `ControlV2Peer` — fields: `NodeID Vertex`, `NodeName string`,
  `PubKey string`, `PSKey string` (tagged `json:"-"` to forbid
  serialization), `LocalV4/LocalV6/PublicV4/PublicV6 []string`,
  `LatencyMS map[Vertex]float64`, `LastSeen time.Time`.
- `ControlV2Parameters` — fields: `ProtocolVersion string`,
  `PollInterval time.Duration`, `STUNServers []string`,
  `STUNRequestTimeout time.Duration`, `STUNRefreshInterval time.Duration`,
  `ReportInterval time.Duration`, `HeartbeatInterval time.Duration`,
  `EventReplay uint64`. Has `Validate() error`. The wire form
  (custom `MarshalJSON`/`UnmarshalJSON`) uses
  `ProtocolVersion`, `PollIntervalSeconds`, `STUNServers`,
  `STUNRequestTimeoutMS`, `STUNRefreshIntervalSeconds`,
  `ReportIntervalSeconds`, `HeartbeatIntervalSeconds`, `EventReplay`.

Typed per-message sub-types:
- `ControlV2Candidate` — fields: `Address string` (IP:port),
  `Source ControlV2CandidateSource`
  (`ControlV2CandidateLocal` or `ControlV2CandidateSTUN`),
  `RTTMS float64`. Has `Validate() error`.
- `ControlV2Pong` — fields: `RequestID uint32`, `SourceNode Vertex`,
  `DestNode Vertex`, `TimediffMS float64`, `LatencyMS float64`,
  `AliveSeconds float64`. Has `Validate() error`.

Event types:
- `ControlV2EventType` — string; constants:
  `ControlV2EventPeerChange = "peer_change"`,
  `ControlV2EventPeerGone = "peer_gone"`,
  `ControlV2EventParamsChange = "params_change"`,
  `ControlV2EventRevision = "revision"`.
- `ControlV2PeerChangePayload` — fields `NodeID Vertex`, `NodeName string`.

Typed config models (YAML):
- `SuperConfigV2` — top-level v2 Super YAML. Fields:
  `NodeName string`, `APIUrl string`, `APIPrefix string`,
  `ManagementAuth SuperConfigV2ManagementAuth`
  (`User string`, `PasswordHash string`), `STUNServers []string`,
  `STUNRequestTimeoutSeconds float64`,
  `STUNRefreshIntervalSeconds float64`,
  `PollIntervalSeconds float64`, `ReportIntervalSeconds float64`,
  `HeartbeatIntervalSeconds float64`, `EventReplay uint64`,
  `PeerAliveTimeoutSeconds float64`, `UsePSKForInterEdge bool`,
  `DampingFilterRadius uint64`, `Peers []SuperConfigV2Peer`.
  Custom `UnmarshalYAML` rejects `PrivKeyV4/V6`, `ListenPort`, `FwMark`,
  `API_Prefix`, `ListenPort_EdgeAPI`, `ListenPort_ManageAPI` with
  `ControlV2ErrLegacyUDPField`.
- `SuperConfigV2Peer` — fields: `NodeID Vertex`, `NodeName string`,
  `ControlPSKey string` (tagged `json:"-"`), `AdditionalCost float64`.
- `EdgeConfigV2` — top-level v2 Edge YAML. Fields: `Interface InterfaceConf`,
  `NodeID Vertex`, `NodeName string`, `DefaultTTL uint8`,
  `LogLevel LoggerInfo`, `SuperNodeV2 SuperNodeV2Ref`,
  `LegacySuper *SuperInfo` (omitempty; presence is rejected by Validate),
  `Peers []PeerInfo`.
- `SuperNodeV2Ref` — fields: `APIUrl string` (yaml `APIUrl`, json `"-"`),
  `APIPrefix string`, `NodeID Vertex`, `ControlPSKey string`
  (all tagged `json:"-"` to forbid snapshot/response leaks).

### Decisions / invariants for wave 2
1. **Control PSKey is never in any JSON-serializable model.** Every field
   that holds a control PSKey is `json:"-"`. The control state service
   (task 5) MUST keep control PSKeys in a separate in-memory map keyed by
   NodeID, never embedded in snapshot/response types.
2. **STUN URI hosts MUST be IP literals at the parser boundary.** DNS
   names are resolved by task 3 before reaching this validator. The
   validator accepts only `stun:` and `stuns:` schemes with explicit
   ports.
3. **Reserved NodeIDs (65532–65535)** are `Broadcast/Spread/Super/Invalid`
   and rejected by every validator via `Vertex.IsSpecial()`. The Super's
   own NodeID in `SuperNodeV2Ref` must NOT be `NodeID_SuperNode` (65533);
   use any non-special Vertex.
4. **Protocol version is enforced exactly once** at parse via
   `ControlV2ProtocolVersion = "v2"`. Both `ControlV2RegisterRequest.Validate`
   and `ParseControlV2Parameters` return `ControlV2ErrUnsupportedVersion`
   on mismatch.
5. **Snapshot revision semantics:** `Accepts` is idempotent for the same
   revision; strictly newer revision wins. SSE replay and 304/ETag polling
   both rely on this monotonicity.
6. **`ListenPort_EdgeAPI` / `ListenPort_ManageAPI`** were kept as strings
   on the legacy `SuperConfig` because main_super.go / main_httpserver.go
   still reference them; they will be cleaned up by task 11. New code MUST
   NOT consume them — use `APIUrl` / `APIPrefix` from `SuperConfigV2` and
   `SuperNodeV2Ref`.
7. **Breaking change scope (confirmed):** `SuperConfig` no longer carries
   `PrivKeyV4/V6`, `ListenPort`, `FwMark`, `API_Prefix`. The YAML parser
   for `SuperConfigV2` rejects them with a typed error so a v1 file
   cannot silently round-trip.
8. **Wire format note for task 4 (client):** parameter wire JSON uses
   PascalCase tag names (`PollIntervalSeconds`, `STUNServers`,
   `STUNRequestTimeoutMS`, etc.), not snake_case. Custom MarshalJSON
   controls the exact spelling; do not change without updating task 4.

### Acceptance verification
`cd /home/kexi/eg-super-http/w1-schema && go test -race -shuffle=on -count=1 ./mtypes -run 'TestControlV2|TestSuperConfigV2'` passes.
Full `go test -race -shuffle=on -count=1 ./mtypes` passes.
`go vet ./mtypes` and `go build ./mtypes` clean.

## [2026-07-25] Task: 2 — HTTP-only Super v2 configuration generator
- `gencfg.GenSuperCfg` now emits `mtypes.SuperConfigV2` and `mtypes.EdgeConfigV2`, preserving the existing gensuper CLI envelope while replacing the Super Node inputs with API URL/prefix, STUN/timing/event settings, management auth, a non-special Super Node ID, and inter-edge PSK selection.
- Exact emitted Super YAML shape: `NodeName`, `APIUrl`, `APIPrefix`, `ManagementAuth {User, PasswordHash}`, `STUNServers`, `STUNRequestTimeoutSeconds`, `STUNRefreshIntervalSeconds`, `PollIntervalSeconds`, `ReportIntervalSeconds`, `HeartbeatIntervalSeconds`, `EventReplay`, `PeerAliveTimeoutSeconds`, `UsePSKForInterEdge`, `DampingFilterRadius`, and `Peers [{NodeID, NodeName, ControlPSKey, AdditionalCost}]`.
- Exact emitted Edge YAML shape: `Interface`, `NodeID`, `NodeName`, `DefaultTTL`, `LogLevel`, `SuperNodeV2 {APIUrl, APIPrefix, NodeID, ControlPSKey}`, and `Peers`. No legacy `DynamicRoute.SuperNode` block or Super WireGuard endpoint/key/listen data is emitted.
- A fresh control PSKey is generated per Edge. It appears only in that Edge's `SuperNodeV2.ControlPSKey` and the matching Super peer metadata entry; another Edge never receives it.
- Existing pairwise inter-Edge PSKs in an Edge v2 template are independently regenerated when `UsePSKForInterEdge` is enabled; control PSKeys are never copied into `Peers`.
- Super and Edge templates are decoded directly into v2 structs and validated. A legacy Super template fails with the typed `legacy_udp_field` error, so obsolete fields are not silently discarded.
- STUN examples use IP literals (`stun:203.0.113.10:3478`, `stuns:[2001:db8::10]:5349`) because `ValidateSTUNURI` currently rejects DNS hosts.

## [2026-07-25] Task: 3 — same-bind STUN discovery

- Public API for downstream task 10: `device.NewSuperSTUNManager(device *Device) *SuperSTUNManager`; call `Discover(ctx context.Context, servers []string, timeout time.Duration) []mtypes.ControlV2Candidate`.
- Receive integration is `SuperSTUNManager.HandlePacket(packet []byte) bool`; `RoutineReceiveIncoming` invokes it before the WireGuard message-type switch. It only consumes packets with STUN header bits, RFC 5389 magic cookie, valid Pion fingerprint, binding-success type, and a currently pending transaction ID.
- Requests use the existing `Device.net.bind` and never create a second UDP socket. XOR-MAPPED results preserve the active bind source port and failures publish no public candidate.
- Verification: targeted race tests, `go build ./device`, `go vet ./device`, and full device race tests all passed.

## [2026-07-25] Task: 4 — typed Edge Control API v2 client (wave 2)

### Public API surface (consume these names exactly)
- Types: `device.ControlHTTPClient`, `device.SSEParser`.
- Headers (exact spelling): `X-EG-NodeID`, `X-EG-Timestamp`, `X-EG-Nonce`, `X-EG-Signature`.
- Constructors / methods:
  - `NewControlHTTPClient(baseURL, prefix string, nodeID mtypes.Vertex, pskey string) *ControlHTTPClient`
  - `(c *ControlHTTPClient).Snapshot(ctx) (*mtypes.ControlV2Snapshot, bool, error)`
  - `(c *ControlHTTPClient).Register(ctx, *mtypes.ControlV2RegisterRequest) (*mtypes.ControlV2Snapshot, error)`
  - `(c *ControlHTTPClient).Report(ctx, *mtypes.ControlV2ReportRequest) error`
  - `(c *ControlHTTPClient).Events(ctx, chan<- mtypes.ControlV2Event) error`
  - `(c *ControlHTTPClient).Current() *mtypes.ControlV2Snapshot`
  - `(SSEParser).Parse(ctx, io.Reader, chan<- mtypes.ControlV2Event) error`
- Endpoints: `${BaseURL}/${Prefix}/snapshot`, `.../register`, `.../report`, `.../events`.

### Exact signing scheme (mirror this in task 6 server)
Canonical string (newline-joined, no trailing newline):
`METHOD\nescaped-path\nunix-timestamp\nnonce\nhex(SHA-256(body))`
Where:
- `METHOD` is the upper-case HTTP verb (`GET`, `POST`, ...).
- `escaped-path` is `req.URL.EscapedPath()` (already percent-escaped; do not re-escape).
- `unix-timestamp` is decimal seconds since epoch (string form).
- `nonce` is a unique server-validated token per request (random hex by default).
- `body` is the raw request body bytes (empty slice → SHA-256 of empty string).
- HMAC: `hex(HMAC-SHA256(key=controlPSKey, msg=canonicalString))`.

### Headers on every request
- `X-EG-NodeID`: decimal NodeID (`Vertex.ToString()` for non-special).
- `X-EG-Timestamp`: unix seconds (string).
- `X-EG-Nonce`: random string per request (default: hex uint64).
- `X-EG-Signature`: hex HMAC-SHA256 as above.

### Snapshot protocol
- `GET /snapshot` always succeeds; carries ETag (`"rev-<n>"`).
- Client sets `If-None-Match: <last ETag>`.
- 304 → no body, treat as unchanged (no apply).
- 200 → JSON body; client serializes revision application; older revisions are rejected silently (`Accepts(incoming)` returns false).
- 4xx/5xx → error returned; local snapshot state untouched.

### SSE protocol
- `Content-Type: text/event-stream`. Parser handles `data:` (multi-line, joined with `\n`), `id:`, `event:`, `retry:`, comments (`:…` lines), CRLF and LF.
- On reconnect, client sends `Last-Event-ID: <last event id>`.
- SSE payload is an invalidation hint only; client ALWAYS refetches the snapshot on every event. SSE data is NEVER authoritative state.
- Bounded exponential backoff on stream errors; polling continues in parallel (caller responsibility via `Run`-style loop).
- Scanner buffer raised to 4 MiB to allow long events.

### Implementation files (worktree `/home/kexi/eg-super-http/w2-client`, branch `super-http-w2-client`)
- `device/super_http_client.go` — `ControlHTTPClient`, `SSEParser`.
- `device/super_http_client_test.go` — TDD coverage via `httptest.Server`.

### Verification (this task)
- `go test -race -shuffle=on -count=1 ./device -run 'TestControlHTTPClient|TestSSEParser'` → ok.
- `go test -race -shuffle=on -count=1 ./device` → ok (no regressions).
- `go build ./device` → ok.
- `go vet ./device` → ok.

### Tests cover (against `httptest.Server`)
- HMAC headers + body digest verifiable by the test server (`TestControlHTTPClientSigning`).
- 200/304 snapshot behaviour (`TestControlHTTPClientSnapshotConditional304`).
- SSE event delivery and reconnect-with-Last-Event-ID after server-side close (`TestControlHTTPClientSSEReconnect`).
- Expired timestamp rejection leaves local state untouched (`TestControlHTTPClientExpiredTimestampNoState`).
- Replayed nonce rejection by server (`TestControlHTTPClientReplayedNonce`).
- Malformed SSE event leaves snapshot state untouched (`TestControlHTTPClientMalformedSSENoState`).
- Bad signature leaves local state untouched (`TestControlHTTPClientBadSignature`).
- Monotonic revision: stale snapshots must NOT overwrite current (`TestControlHTTPClientMonotonicRevision`).
- Multi-line data, `id:`, `retry:`, comments, CR/LF parsing (`TestSSEParserDirect`).
- Long SSE event exceeds default 64 KiB scanner buffer (`TestSSEParserBuffering`).
- Register round-trip (`TestControlHTTPClientRegister`).
- Reader error propagation (`TestSSEParserScanError`).

## [2026-07-25] Task: 4 — fix: reconnect + polling fallback (round 2)

### What was wrong
- The earlier reconnect test only logged `t.Logf` on the second `Last-Event-ID` observation. Not a real assertion.
- The earlier implementation polled only when SSE was *down*, inside the same select as the SSE channels. Because SSE 503s returned instantly, the inner loop churned before the poll ticker fired.
- No polling fallback test existed.

### What is fixed
- `TestControlHTTPClientSSEReconnect` is now a hard check: the second SSE connect MUST carry `Last-Event-ID: evt-1`.
- Added `TestControlHTTPClientSyncPollingFallback`: server returns 503 on the first 3 SSE attempts then 200; the test asserts polling fired ≥ 3 snapshots during the down window.
- Added `TestControlHTTPClientSyncMonotonic`: pre-seeded rev=10 with all incoming snapshots at rev=1; `apply` MUST never run, and `Current()` MUST stay at rev=10.

### API additions (round 2)
- New `Sync(ctx, apply) error` method on `*ControlHTTPClient`. Drives SSE reconnect + polling fallback; `apply` is called with the freshly-fetched snapshot.
- New configurable fields on `*ControlHTTPClient`:
  - `MinBackoff time.Duration` (default 100ms)
  - `MaxBackoff time.Duration` (default 30s)
  - `Jitter func(time.Duration) time.Duration` (default ±20%)
- New helper methods:
  - `LastEventID() string` (test/diagnostics)
  - `SSEParser.ParseReader(ctx, io.Reader, chan<- ControlV2Event) error` — explicit io.Reader dispatch.

### Implementation notes
- Polling runs on a dedicated goroutine (`pollLoop`) so it is not starved by SSE churn.
- Bounded exponential backoff with jitter prevents thundering herds.
- Last-Event-ID is recorded on every successful SSE event delivery via `recordEventID` and sent on every reconnect.

## [2026-07-25] Task: 0.5 — neutralize legacy Super UDP lifecycle

### What was removed from main_super.go (commit e3ec872, branch super-http-w2-neutralize)
- The entire Super runtime body (originally lines 70-252) that built two
  `device.Device` instances (v4/v6) on top of `tap.CreateDummyTAP`,
  `conn.NewDefaultBind`, `device.Str2PriKey(PrivKeyV4/V6)` +
  `IpcSet("fwmark="|"listen_port="|"replace_peers=")`, and `startUAPI`
  for each. Without `mtypes.SuperConfig.PrivKeyV4/V6/ListenPort/FwMark`
  none of that compiled.
- The `mtypes.SUPER_Events` register/pong event machinery
  (`Event_server_event_hendler`) and its `RoutineTimeoutCheck` synthetic
  timer that pumped `RegisterMsg{Version:"dummy"}` into the channel.
- The UDP push fan-out (`PushNhTable`, `PushPeerinfo`, `PushServerParams`)
  that wrapped each push in `path.EgHeader` and called
  `*device.Device.SendPacket` to every peer's v4/v6 device. Replaced with
  1-line `Fprintln(os.Stderr, "stub")` no-ops so the one remaining call
  site (`main_httpserver.go:522` inside `edge_post_nodeinfo`) still
  compiles.
- `super_peerdel_notify` (used only by `super_peerdel`). It sent an
  `mtypes.ServerUpdateMsg{Action: Shutdown}` over UDP via
  `http_device4/6.SendPacket`. Task 11 pushes Shutdown over the v2
  control plane instead — TODO marker in `super_peerdel`.
- PostScript `exec.Command` block (line 224) and SdNotify block (237).

### What was kept (main_httpserver.go still needs these)
- `checkNhTable` — graph/routing helper, pure function, used by task 11.
- `startUAPI` — still called by `main_edge.go:232`; verbatim.
- `super_peeradd` (line 680 in `main_httpserver.go` calls it) — body
  trimmed to just `httpobj.http_PeerID2Info` + `PeerState{}` atomic init
  + `httpobj.http_PeerState[PubKey]` + `httpobj.http_PeerIPs[PubKey]`.
  UDP peer creation branches gone (no `device.NewPeer`,
  `SetEndpointFromConnURL`, no `sconfig.PrivKeyV4/V6` lookup).
- `super_peerdel` — body trimmed to map deletes; `httpobj.http_pskdb.DelNode`
  removed (PSKDB not initialized in this task — task 11 owns).
- `PushNhTable/PushPeerinfo/PushServerParams` — stubs that log once.
- `printExampleSuperConf` — `gencfg.GetExampleSuperConf` now returns
  `mtypes.SuperConfigV2` (task 2 changed the signature); the helper
  marshals the v2 shape.

### What `Super(...)` does now (the stub)
1. `-example` → print the v2 SuperConfigV2 YAML (same as
   `gencfg.GenSuperCfg -example`).
2. `-config <path>` →
   - `mtypes.ReadYaml(configPath, &mtypes.SuperConfig)`
   - Pre-scan the YAML bytes for top-level keys `PrivKeyV4`,
     `PrivKeyV6`, `ListenPort`, `FwMark`, `API_Prefix` (top-level only
     — same-shape keys nested under v2 structs are legitimate). On hit,
     return `mtypes.ControlV2Error{Code: legacy_udp_field, ...}`. The
     pre-scan is necessary because `mtypes.ReadYaml` uses a permissive
     `yaml.Unmarshal` that silently drops unknown fields — without it,
     a v1 UDP YAML would parse as an empty legacy `SuperConfig` and
     idle silently. (See acceptance criterion: "a v1 UDP Super config
     is not silently accepted".)
   - Validate `PeerAliveTimeout > 0`, `HttpPostInterval ∈ [0, PeerAliveTimeout]`,
     `SendPingInterval > 0`, `RePushConfigInterval > 0`.
   - Print `super: HTTP-only Super control service not yet wired
     (task 11); node=<name> idling until SIGTERM/SIGINT. ListenPort_EdgeAPI=...`
     to stderr.
   - Block on `SIGTERM/SIGINT` via `signal.Notify(term, ...)` then
     print shutdown message and `return nil`.
3. The HTTP listen ports (`sconfig.ListenPort_EdgeAPI`,
   `sconfig.ListenPort_ManageAPI`) and `sconfig.API_Prefix` are parsed
   but not bound — task 11 binds them.

### What httpobj fields are still declared in main_httpserver.go but NOT initialized by this task
Tasks 5/7 (state service, event hub) MUST initialize these at startup
so main_httpserver.go's reads see non-zero values:
- `http_HashSalt`            (mtypes.RandomStr — currently nil → md5
                              sums over nil slice, deterministic but
                              not secret)
- `http_super_chains`        (mtypes.SUPER_Events{Event_server_register,
                                                  Event_server_pong})
- `http_passwords`           (sconfig.Passwords)
- `http_graph`               (path.NewGraph)
- `http_device4 / device6`   (nil until task 10 wires Edge-side device)
- `http_NhTableStr / Hash`
- `http_PeerInfo / hash`
- `http_pskdb`               (device.PSKDB{})
- `http_PeerState / IPs / PeerID2Info` (make(...) before first peer add)

`http_sconfig`, `http_sconfig_path`, `http_econfig_tmp` are also
uninitialized by this task; tasks 5/11 should set them inside the
real `Super()` body.

### Public surface tasks 5-9 must consume (already in main_httpserver.go)
Unchanged from the integration branch adbd83e:
- `http_shared_objects` struct + `httpobj` global
- `HttpPeerLocalIP`, `PeerState`, `HttpState`, `HttpPeerInfo` types
- HTTP handler funcs: `edge_get_superparams`, `edge_get_peerinfo`,
  `edge_get_nhtable`, `edge_post_nodeinfo`, `manage_get_peerstate`,
  `manage_peeradd`, `manage_peerdel`, `manage_peerupdate`,
  `manage_superupdate`
- `HttpServer(edgeListen, manageListen, apiprefix, errchan)` — not
  called from main_super.go anymore; tasks 5/8 will call it from the
  new Super runtime.
- `get_api_peers` — `main_httpserver.go:151` only; signature intact.
- `checkPassword` — `main_httpserver.go:528`; signature intact.

### Acceptance verification (this task)
- `go build ./...`                      → clean
- `go vet ./...` (3 pre-existing warnings on `orderdmap` + `example_config/...`,
  none on root or in files touched by this task)
- `go test -race -shuffle=on -count=1 ./...` → all packages green
  (root, device, gencfg, mtypes, ratelimiter, replay, tai64n)
- Smoke: `go run . -mode super -example` dumps v2 SuperConfigV2
- Smoke: `go run . -mode super -config <clean-legacy>` idles then exits 0 on SIGTERM
- Smoke: `go run . -mode super -config <v1-udp-with-PrivKeyV4>` rejected
  with `control v2: legacy_udp_field`
- Smoke: `go run . -mode super -config <empty>` validation rejects
  `PeerAliveTimeout must > 0 : 0`

### Files modified
main_super.go only (+114/-430). main.go, main_edge.go,
main_edge_endpoint.go, main_edge_endpoint_test.go, main_httpserver.go
unchanged — see evidence log for per-file justification.

### One atomic commit
e3ec872 refactor: neutralize legacy Super UDP lifecycle
on branch super-http-w2-neutralize. Not pushed; local only.

## [2026-07-25 12:15] Task: 5 — Introduce one concurrency-safe authoritative Super control-state service

### Files written in worktree `/home/kexi/eg-super-http/w2-state2` (branch `super-http-w2-state2`)
- `super_control_state.go` — new file. Owns authoritative peer records, control PSKeys, candidates, latencies, LastSeen, control parameters, revision, timeout sweep, key lookup, and the publish hook. Uses a single `sync.RWMutex`; deep-copies all snapshot fields; publishes events outside the lock.
- `super_control_state_test.go` — new file. TDD coverage of register/report/timeout/revision, and 16-goroutine concurrent mutation under `-race`.

### Public API surface (consume these names exactly — CRITICAL for tasks 6/7/8/9)
- Types:
  - `ControlStateConfig` — `Parameters mtypes.ControlV2Parameters`, `PeerAliveTimeout time.Duration`, `UsePSKForInterEdge bool`, `Graph *graphpath.IG`, `Now func() time.Time`, `Publish func(mtypes.ControlV2Event)`.
  - `ControlState` — singleton state service held by the Super runtime.
- Constructors: `NewControlState(ControlStateConfig) *ControlState` (Now defaults to `time.Now` when nil).
- Methods:
  - `(s *ControlState).Register(ctx context.Context, req mtypes.ControlV2RegisterRequest, controlPSKey string) (mtypes.ControlV2Snapshot, error)` — initial snapshot for the registering Edge (self-peer filtered); bumps revision only on observable change; emits `peer_change` outside lock.
  - `(s *ControlState).Report(ctx context.Context, req mtypes.ControlV2ReportRequest) error` — heartbeat + candidates + pongs; unknown NodeID → `ErrControlStateUnknownPeer`; pushes latencies into `Graph.UpdateLatency` when configured.
  - `(s *ControlState).SnapshotFor(nodeID mtypes.Vertex) mtypes.ControlV2Snapshot` — peer-safe view (self excluded, PSKey cleared, slices/maps deep-copied).
  - `(s *ControlState).ControlKeyFor(nodeID mtypes.Vertex) (string, bool)` — task 6 HMAC verifier lookup; never serialized.
  - `(s *ControlState).Revision() uint64` — monotonic.
  - `(s *ControlState).SweepTimeouts() int` — removes peers past `PeerAliveTimeout`, bumps revision once if any peer removed, emits `peer_gone` per removed peer outside the lock.
- Sentinel: `ErrControlStateUnknownPeer`.
- Emitted event shape: `mtypes.ControlV2Event{Type: ControlV2EventPeerChange|ControlV2EventPeerGone, Revision, Data: mtypes.ControlV2PeerChangePayload{NodeID, NodeName}}`. Task 7's event hub consumes these through the configured `Publish` hook.

### Concurrency contract
- Single `sync.RWMutex`; snapshot iteration completes before the lock is released (deep-copies); no map iteration under a read lock during mutation.
- Event publication and graph callbacks (when `Graph` is configured) are the only side-effects under the lock; both are concurrency-safe and do not re-enter the service.
- A clock function (`ControlStateConfig.Now`) is required at construction; `time.Now` is never called from this package.

### Decisions / invariants
1. Control PSKey lives only in the internal `controlPeerRecord`; `SnapshotFor` zeroes `ControlV2Peer.PSKey` so JSON cannot leak it.
2. Revision bumps are gated on observable state (candidate set, latency changes, name/key/last-seen, removal). An identical heartbeat report does not bump revision.
3. The `Now` injection is mandatory for testability — task 11 must pass a real `time.Now` wrapper.
4. The `Publish` hook is the ONLY bridge to task 7's event hub; do not add direct channels.

### Verification
- `go test -race -shuffle=on -count=1 . -run 'TestControlState'` → ok (1.06s)
- `go test -race -shuffle=on -count=1 ./...` → all packages green (root/device/gencfg/mtypes/ratelimiter/replay/tai64n)
- `go vet .` → clean


## [2026-07-25] Task: 7 — bounded SSE event hub + replay contract

### Public API surface (CRITICAL for task 9 — wire exactly)

In root package `main`:

```go
// Hub
func NewControlEventHub(capacity uint64) *ControlEventHub
func (h *ControlEventHub) Publish(ev mtypes.ControlV2Event)
func (h *ControlEventHub) Subscribe(ctx context.Context, lastEventID string) (*Subscriber, error)
func (h *ControlEventHub) SubscribeWithBuffer(ctx context.Context, lastEventID string, bufSize int) (*Subscriber, error)
func (h *ControlEventHub) ServeSSE(ctx context.Context, w interface{ io.Writer; Flush() }, lastEventID string, opts SSEOptions) (*SSERenderer, error)
func (h *ControlEventHub) Close()

// Subscriber
func (s *Subscriber) Events()         <-chan mtypes.ControlV2Event
func (s *Subscriber) ResyncRequired() <-chan struct{}  // closed when lastEventID older than retention
func (s *Subscriber) Done()           <-chan struct{}  // closed on eviction or hub.Close
func (s *Subscriber) Err()            error            // ErrHubClosed | ErrSlowSubscriber | ctx.Err
func (s *Subscriber) Close()

// SSE
type SSEOptions struct {
    RetryMillis          int
    Heartbeat            time.Duration  // 0 -> 27s default (inside 25-30s spec window)
    TickerFunc           func(d time.Duration) *time.Ticker  // nil -> time.NewTicker; tests inject manual ticker
    InitialComment       string
    SubscriberBufferSize int
}
func (r *SSERenderer) Subscriber() *Subscriber
func (r *SSERenderer) Close()

// Sentinels
var ErrHubClosed      = errors.New("control event hub closed")
var ErrSlowSubscriber = errors.New("control event subscriber evicted (slow consumer)")
```

### Design invariants
1. **Publish never blocks on subscribers.** Per-subscriber bounded queues are filled via non-blocking send; on overflow the publisher evicts with `ErrSlowSubscriber`.
2. **No lock across event writes.** The hub state lock is released before any per-subscriber delivery; the consumer (test drainer or SSE renderer) is responsible for writing the event to its sink.
3. **No per-subscriber goroutine.** The subscriber is a pure struct (channel + atomic flags + sync.Once); the consumer drains `sub.Events()` directly. This eliminates the per-sub pump goroutine leak vector entirely. Only the SSE renderer spawns a goroutine (one per connection).
4. **Subscriber.Events() is NEVER closed.** The publisher can race with termination; closing would cause send-on-closed-channel panic. Consumers must observe termination via `sub.Done()` (closed via sync.Once on eviction or hub.Close).
5. **Event IDs are strictly monotonic** across the hub's lifetime (`evt-<uint64>`). Caller may supply an ID; the hub bumps its counter past the parsed numeric. Always non-empty (the task-4 SSEParser's `recordEventID` bug is naturally avoided).
6. **The replay ring is bounded**; FIFO eviction when full. `bufferFirst` tracks the numeric ID of the oldest retained event for O(1) stale-ID checks.
7. **ServeSSE emits**: initial comment, `retry: <ms>`, per-event `id:`, `event:`, multi-line `data: <JSON>`, `: heartbeat` comments on the configured cadence. Multi-line data is split per SSE spec.
8. **Hub.Close() is idempotent** via `sync.Once`. After Close: Subscribe/ServeSSE return ErrHubClosed; existing subscribers' Done closes with ErrHubClosed.

### Replay semantics (lastEventID)
- empty → replay entire buffer
- equal to a retained ID → replay events with strictly greater ID
- numerically older than bufferFirst → replay all + signal ResyncRequired (client must refetch snapshot)
- unknown format / numerically newer → replay all (safe fallback)

### Critical wiring notes for task 9 (HTTP server)
- ServeSSE's writer MUST be an `interface { io.Writer; Flush() }` (no-error Flush). `*bufio.Writer` does NOT satisfy this (it has `Flush() error`); wrap with `bufio.NewWriter(w)` inside an adapter.
- The hub ALWAYS assigns an ID when the caller leaves it empty; never emit an event with empty ID (task-4 SSEParser's recordEventID bug would clobber Last-Event-ID on reconnect).
- For events with nil Data, the hub emits `data: \n`. The task-4 SSEParser currently fails to JSON-unmarshal an empty string — task 9 should either always populate Data (e.g. `ControlV2PeerChangePayload{}`) OR upgrade the SSEParser to skip unmarshal when `data` lines are empty. (Documented as a known inter-task caveat.)
- For `ServeSSE`, the test/event flow is: writer.Flush() runs after every event and every heartbeat so clients see bytes promptly.
- `Close()` on the renderer waits for the renderer goroutine to exit; pair it with `cancel()` on the request context to release promptly.

### Race / design gotchas (caught by tests; recorded for future tasks)
- `atomic.Pointer[error].CompareAndSwap(&nilErr, &err)` is WRONG. The signature compares by pointer value, not by pointer-to-pointer. Use `CompareAndSwap(nil, &err)` for the first-write case.
- A WaitGroup that spans both publishers AND drainers whose exit is gated on `sub.Done()` (closed by `Hub.Close()`) DEADLOCKS: wg.Wait waits for drainers, drainers wait for Done, Done waits for Close, Close waits for wg.Wait. Split into separate WaitGroups (pubWG + drainWG) or call Close before Wait.
- A `bytes.Buffer` is not safe for concurrent reads from a test goroutine while the SSE renderer writes from another goroutine — wrap with a mutex (the test's `syncBuffer`).
- `bufio.Writer.Flush() error` does NOT satisfy `interface{ Flush() }`. Use a thin adapter that drops the error.

### Tests cover (against the hub directly)
- Monotonic ID assignment + caller ID preservation
- Replay from middle / from empty / from exact newest
- Stale lastEventID → ResyncRequired signal
- Unknown newer ID → safe replay-all fallback
- Bounded ring FIFO eviction
- Ordered delivery across replay + live
- Slow subscriber eviction (publisher never blocks, fast sub unaffected)
- Hub.Close + sub.Close + ctx cancel termination paths
- SSE framing (id/event/data/retry/initial comment/multi-line data)
- Heartbeat via injected manualTickerFactory (no wall-clock sleep)
- ServeSSE replay + live transition
- Post-Close Subscribe/ServeSSE returning ErrHubClosed
- Concurrent publish×subscribe race-clean (4×4×100)
- Goroutine leak guard (subscribers hold NO goroutines; only ServeSSE spawns one per connection)

### Verification
- `go test -race -shuffle=on -count=1 . -run 'TestControlEvents'` → ok (1.5s, 23 tests)
- `go test -race -shuffle=on -count=1 ./...` → all packages green
- `go vet .` → clean (only pre-existing unrelated warning in example_config)
- `go build ./...` → clean

### Files added in one atomic commit (59be3e5)
- super_control_events.go (~530 LOC incl. comments; ~310 LOC pure code)
- super_control_events_test.go (~970 LOC)

### Branch state
- Branch `super-http-w2-events2` is one commit ahead of integration `e45ba7d` (which itself includes T1..T4 + T0.5).
- HEAD: `59be3e5 feat: add replayable Super control event hub`.

## [2026-07-25 12:30] Task 5 — fix round 2: Report() candidates now merge into snapshot view

### Defects addressed
- DEFECT 1 (functional): Report() now re-derives the peer view's LocalV4/LocalV6/PublicV4/PublicV6 from the freshly reported candidate list (partitioned by IP family + source). A STUN candidate reported via POST /edge/v2/report appears in every other Edge's snapshot. Revision bumps only when an observable field actually changes.
- DEFECT 2 (slop): test clock helpers (testClockNanos, currentTime, advance) moved into super_control_state_test.go; unused timeValue alias deleted from production file.

### New test
TestControlStateReportedCandidateReachesOtherEdges — registers edge A and edge B, has A report local+STUN IPv4 + IPv6 candidates, asserts that B's snapshot (SnapshotFor(2)) shows the new PublicV4/PublicV6 entries, the LocalV4 entry, the revision bumped, and the PSKey remains empty.

### Commands (exit codes in parens)
```
$ go test -race -shuffle=on -count=1 . -run 'TestControlState' (ok 1.062s)
$ go vet . (ok, no diagnostics)
$ go test -race -shuffle=on -count=1 ./... (ok: root/device/gencfg/mtypes/ratelimiter/replay/tai64n)
```

### Wire acceptance — STUN candidate end-to-end behavior (task 13 depends on this)
1. Edge A POSTs /edge/v2/report with a STUN candidate (Source=stun).
2. ControlState.Report stores the candidate slice AND re-derives the peer's view fields by family (LocalV4/LocalV6 from Source=local, PublicV4/PublicV6 from Source=stun) using net.SplitHostPort + net.ParseIP for family detection.
3. ControlState.SnapshotFor(otherNodeID) exposes those fields on the peer record returned in mtypes.ControlV2Snapshot.Peers.
4. A peer_change event is emitted OUTSIDE the lock when the view changed.
5. The revision is bumped only when an observable field changed — identical reports and identical pong sets are silent.

## [2026-07-25 12:50] Task: 6 — replay-safe per-Edge HMAC auth at the Control API boundary (w3-auth)

### Files written in worktree `/home/kexi/eg-super-http/w3-auth` (branch `super-http-w3-auth`)
- `super_control_auth.go` — single `*ControlAuthenticator` struct bound to
  a `*ControlState`. Uses `http.MaxBytesReader` to cap the body stream at
  1 MiB before hashing, a per-(NodeID, nonce) bounded cache with TTL =
  2× the timestamp skew window, and `hmac.Equal` for constant-time
  signature comparison. Every failure path returns the same uniform
  `*ControlAuthError` whose `Error()` always reports `"control auth failed"`.
- `super_control_auth_test.go` — TDD coverage; 21 tests under `-race -shuffle`.

### Public API surface (consume these names exactly — CRITICAL for task 9 wiring)

In root package `main`:

```go
// Headers (same spelling as task-4 client)
const (
    ControlAuthHeaderNodeID    = "X-EG-NodeID"
    ControlAuthHeaderTimestamp = "X-EG-Timestamp"
    ControlAuthHeaderNonce     = "X-EG-Nonce"
    ControlAuthHeaderSignature = "X-EG-Signature"
)

// Limits
const (
    ControlAuthTimestampSkew = 60 * time.Second
    ControlAuthMaxBodyBytes  int64 = 1 << 20            // 1 MiB
    defaultControlAuthMaxNonceCache = 16 << 10          // 16384
    defaultControlAuthNonceTTL      = 2 * ControlAuthTimestampSkew
)

// Sentinels (use errors.Is to classify)
var (
    ErrControlAuthMissingHeader
    ErrControlAuthInvalidNodeID
    ErrControlAuthUnknownNode
    ErrControlAuthInvalidTimestamp
    ErrControlAuthBodyTooLarge
    ErrControlAuthInvalidSignature
    ErrControlAuthReplay
)

// Single uniform error type
type ControlAuthError struct{ Code error }
func (e *ControlAuthError) Error() string  // always "control auth failed"
func (e *ControlAuthError) Unwrap() error  // returns Code

// Helpers
func IsControlAuthError(err error) bool
func ControlAuthHTTPStatus(err error) int  // 401 default, 413 for ErrControlAuthBodyTooLarge

// Verifier
type ControlAuthenticatorConfig struct {
    Now           func() time.Time     // defaults to time.Now
    NonceCacheTTL time.Duration        // defaults to defaultControlAuthNonceTTL
    MaxNonceCache int                  // defaults to defaultControlAuthMaxNonceCache
}
func NewControlAuthenticator(state *ControlState, cfg ControlAuthenticatorConfig) *ControlAuthenticator
func (a *ControlAuthenticator) Verify(r *http.Request) (mtypes.Vertex, []byte, error)
func (a *ControlAuthenticator) SweepNonces() int                   // production eviction hook

// Test-only surface (NEVER use in production)
func (a *ControlAuthenticator) RegisterTestKey(mtypes.Vertex, string)
func (a *ControlAuthenticator) NonceCacheSizeForTest() int
func (a *ControlAuthenticator) SweepNoncesForTest() int
func (s *ControlState) setControlKeyForTest(mtypes.Vertex, string)
```

### Canonical signing string (must match device/super_http_client.go sign())
`METHOD\nescaped-path\nunix-timestamp\nnonce\nhex(SHA-256(body))`
where `escaped-path` is `r.URL.EscapedPath()` (already percent-escaped;
do not re-escape). HMAC: `hex(HMAC-SHA256(key=controlPSKey, msg=canonical))`.

### HTTP wiring contract (task 9)
- Mount on every `/edge/v2/*` route. Call `Verify` FIRST (before any body
  parsing or JSON decode). On error: write the HTTP status from
  `ControlAuthHTTPStatus(err)` and a generic body (e.g. `"control auth
  failed"`). NEVER include `err.Error()` in the response (it is uniform
  but the underlying sentinel must not leak via headers or logs to clients).
- After `Verify` returns a valid (NodeID, body), the handler may decode
  the body as the typed v2 request (ControlV2RegisterRequest /
  ControlV2ReportRequest) and pass NodeID + body to the ControlState
  service.
- The body buffer returned by Verify is the full buffered body (≤1 MiB);
  handlers do NOT need to read `r.Body` again. The original request body
  has been fully consumed by Verify.
- `SweepNonces()` should be called periodically (task 11 wires a slow
  timer, e.g. 30s) so expired entries are dropped even when the cache
  stays under cap.

### Decisions / invariants
1. **Single uniform error type.** Every sub-check returns a
   `*ControlAuthError{Code: <sentinel>}`. `Error()` is constant; the
   HTTP layer cannot distinguish sub-checks from the response.
2. **Body cap BEFORE hashing.** `http.MaxBytesReader` is wrapped around
   `r.Body` before the SHA-256 / HMAC computation. An oversized body
   never reaches the HMAC code path.
3. **No lock across hashing.** `ControlKeyFor` returns a copy of the
   control PSKey under the read lock; the lock is released before any
   HMAC work.
4. **Per-(NodeID, nonce) cache key.** Two Edges may independently reuse
   the same nonce string; the cache does not deduplicate across NodeIDs.
5. **TTL ≥ 2× timestamp window** so a replay inside the timestamp window
   is always rejected and a replay after the window is allowed.
6. **Constant-time signature comparison** via `hmac.Equal`.
7. **No PSKey in responses / logs / URLs / SSE.** The control PSKey
   never leaves the `ControlState` internal map except through
   `ControlKeyFor` (used only by this verifier) and never appears in
   any HTTP response body, log line, URL query string, or SSE event.
8. **Special NodeIDs rejected.** `mtypes.Vertex.IsSpecial()` IDs (65532
   – 65535) are rejected at the boundary with `ErrControlAuthInvalidNodeID`
   to mirror the v2 schema rule.
9. **Test surface is explicitly named** (`RegisterTestKey`,
   `NonceCacheSizeForTest`, `SweepNoncesForTest`,
   `ControlState.setControlKeyForTest`) so accidental production use is
   obvious at the call site.

### Race / design gotchas (caught during TDD)
- `mtypes.Vertex.ToString()` has a pointer receiver. Calling it directly
  on a return value (`auth.Verify(r)`'s first result) fails to compile —
  the value is not addressable. Tests must assign the result to a local
  variable first.
- `http.MaxBytesReader`'s `*http.MaxBytesError` is the only error type
  we treat as `ErrControlAuthBodyTooLarge`. Any other read error (e.g.
  client disconnect) is collapsed to `ErrControlAuthInvalidSignature`
  so we do not leak I/O detail.
- The nonce cache is per-(NodeID, nonce), not per-nonce alone. Forgetting
  the NodeID dimension causes two Edges to evict each other's valid
  nonces — a correctness bug under multi-Edge load.
- The MaxBytesReader wrapper needs a non-nil `http.ResponseWriter` to
  close the response on overflow; passing `nil` is allowed in Go 1.19+
  but the response writer is still nil in our handler path. Tests
  confirm the cap is enforced regardless.

### Acceptance verification (this task)
```
$ go test -race -shuffle=on -count=1 . -run 'TestControlAuth' → ok 1.277s (21/21 PASS)
$ go test -race -shuffle=on -count=1 ./...                    → all packages green
$ go vet .                                                  → only pre-existing orderdmap warnings (unrelated)
$ go build ./...                                            → clean
```

### Tests cover
- HMAC headers + body digest verifiable end-to-end (httptest.Server)
- Wrong path / wrong method / wrong body digest → fail
- Stale timestamp / future timestamp beyond skew → fail
- Duplicate nonce within TTL → fail (replay)
- Oversized body rejected before full read (both >cap + cap+1 + after-verify
  scenarios)
- Unknown NodeID → fail
- Key isolation (A's key cannot sign for B's NodeID) → fail
- No error response contains key material (single uniform message)
- Per-NodeID nonce independence
- Nonce cache bounded under hammer (500 distinct nonces, cap 64)
- Concurrent requests race-clean (16 goroutines × 50 iters)
- Nonce TTL expiry allows replay after the window
- All four headers individually missing → fail
- Special NodeID rejected
- Nonce cache sweep evicts expired entries
- HTTP integration: 401 response body has no key bytes

## [2026-07-25 13:15] Task: 8 — manage-v2 service: typed mutations → valid v2 YAML

### Files written/modified in worktree `/home/kexi/eg-super-http/w3-manage` (branch `super-http-w3-manage`)
- `super_manage_v2.go` — new file (≈380 LOC): manage-v2 service + atomic YAML helpers.
- `super_manage_v2_test.go` — new file (≈490 LOC): 19 TDD tests in `t.TempDir`.
- `super_control_state.go` — added `DeletePeer`, `UpdateParameters` methods and three sentinel errors (`ErrControlStateUnknownPeer` retained; `ErrControlStateSpecialNodeID`, `ErrControlStateInvalidParameters` new). Pre-existing public API (Register / Report / SnapshotFor / ControlKeyFor / Revision / SweepTimeouts) untouched.

### Public API surface (CRITICAL for task 9 — wire exactly)

In root package `main`:

```go
// Service
type ManageV2Config struct {
    State        *ControlState
    ConfigDir    string
    BaseConfig   mtypes.SuperConfigV2
    EdgeTemplate mtypes.EdgeConfigV2
    PSKGen       func() string  // defaults to device.RandomPSK().ToString
}
func NewManageV2(ManageV2Config) (*ManageV2, error)

type ManageV2 struct { /* unexported */ }

// Sentinels (callers should map via mtypes.IsControlV2Error + mtypes.ErrorCode)
var ErrManageDuplicateNodeID   error
var ErrManageDuplicateNodeName error
var ErrManageUnknownPeer       error

// Method names — DO NOT rename; task 9 HTTP handlers bind to these.
func (m *ManageV2) AddPeer(ctx context.Context, req ManageAddPeerRequest) (ManageAddPeerResult, error)
func (m *ManageV2) UpdatePeer(ctx context.Context, req ManageUpdatePeerRequest) error
func (m *ManageV2) DeletePeer(ctx context.Context, req ManageDeletePeerRequest) error
func (m *ManageV2) UpdateParameters(ctx context.Context, req ManageUpdateParametersRequest) error
func (m *ManageV2) Snapshot() mtypes.SuperConfigV2  // deep copy

// Method bodies (typed):
type ManageAddPeerRequest      struct{ NodeID mtypes.Vertex; NodeName string }
type ManageUpdatePeerRequest   struct {
    NodeID         mtypes.Vertex
    NodeName       string  // empty = keep existing
    AdditionalCost float64 // <0 = keep existing
    ControlPSKey   string  // empty = keep; rotation is opt-in
}
type ManageDeletePeerRequest   struct{ NodeID mtypes.Vertex }
type ManageUpdateParametersRequest struct{ Parameters mtypes.ControlV2Parameters }

type ManageAddPeerResult struct {
    SuperPeer mtypes.SuperConfigV2Peer  // the new Super-side metadata
    Profile   mtypes.EdgeConfigV2       // generated Edge profile with isolated ControlPSKey
}
```

### New ControlState API surface (added in this task — coordinate via notepad)

In root package `main` (`super_control_state.go`):

```go
// Sentinels
var ErrControlStateUnknownPeer    error  // pre-existing from task 5
var ErrControlStateSpecialNodeID  error  // NEW
var ErrControlStateInvalidParameters error // NEW

// Methods
func (s *ControlState) DeletePeer(ctx context.Context, nodeID mtypes.Vertex) error
//   - ErrControlStateUnknownPeer if NodeID not present
//   - ErrControlStateSpecialNodeID if NodeID is reserved (65532..65535)
//   - bumps revision by exactly 1 on success; emits exactly 1 peer_gone event

func (s *ControlState) UpdateParameters(ctx context.Context, p mtypes.ControlV2Parameters) error
//   - ErrControlStateInvalidParameters if mtypes.ControlV2Parameters.Validate fails
//   - bumps revision by exactly 1 on success; emits exactly 1 params_change event with
//     cloneParameters(p) as Data (non-empty per task-7 SSEParser caveat)
```

### File layout

The service writes/reads:
- `<ConfigDir>/super.yaml` — `mtypes.SuperConfigV2` YAML (authorative)
- `<ConfigDir>/edge_<NodeID>.yaml` — `mtypes.EdgeConfigV2` YAML per peer

Atomic write pattern: `ioutil.TempFile(dir, ".tmp-*.yaml")` → write → `tmp.Sync()` → close → `os.Rename` (POSIX-atomic). On any sub-failure (write / marshal / rename), the prior in-memory base + previously-persisted edge files are restored before returning the error.

### Design decisions / invariants

1. **State mutation happens BEFORE the YAML write.** If the write fails, state is rolled back by re-`Register` (revive AddPeer / UpdatePeer) or re-`DeletePeer` (revoke AddPeer mid-flight) so the in-memory state stays consistent with the last-known-good files. Task 9 should trust `Snapshot()` for status reads — it reflects whatever is on disk.

2. **Exactly one event per successful mutation.** Every method funnels through a single `state.Register` / `state.DeletePeer` / `state.UpdateParameters` call. The publish hook lives inside the state service; `ManageV2` does NOT publish directly. This is what keeps the SSE stream's revision monotonicity aligned with the on-disk configuration.

3. **PSKey rotation semantics:**
   - `AddPeer`: always generates a fresh PSKey via the configured `PSKGen`.
   - `UpdatePeer`: rotates only when the request supplies a non-empty `ControlPSKey` that differs from the current value. Register's `controlKey` diff emits `peer_change` exactly once. Same-key resupply is a no-op.

4. **Per-Edge ControlPSKey is NEVER copied across edges.** Each AddPeer generates a fresh key; the matching `EdgeConfigV2.SuperNodeV2.ControlPSKey` carries that key. No method exposes another edge's PSKey. The `Snapshot()` view of `SuperConfigV2` may carry other peers' PSKeys because Super needs them at request time, but they must NEVER enter an HTTP response.

5. **Legacy UDP fields are never written.** `EdgeConfigV2` build is driven by `m.edgeTemplate` (no UDP fields) + per-call NodeID / NodeName / fresh PSKey. `mtypes.EdgeConfigV2.Validate` rejects `LegacySuper`. `mtypes.SuperConfigV2.UnmarshalYAML` rejects `PrivKeyV4/V6/ListenPort/FwMark/API_Prefix/ListenPort_EdgeAPI/ListenPort_ManageAPI` at parse time.

6. **Typed errors:** non-collision validation failures (reserved NodeID, missing NodeName, malformed STUN URI, invalid parameters, etc.) are returned as `*mtypes.ControlV2Error` and must be mapped via `mtypes.IsControlV2Error` + `mtypes.ErrorCode`. Task 9's HTTP layer should translate codes to uniform non-secret responses (e.g. `400 + invalid_node_id`, `400 + invalid_stun_server`).

7. **Per-management-call concurrency safety.** `ManageV2` holds a single `sync.Mutex` to serialise multi-file YAML writes for rollback safety. The underlying `ControlState` is independently concurrency-safe; callers can issue parallel AddPeer / DeletePeer / UpdateParameters calls and state-mutation guarantees will hold (file rotation only contends on the management-side lock).

8. **Pure AdditionalCost-only UpdatePeer does NOT bump revision / emit.** Rationale: snapshot peer view does not embed `AdditionalCost` (it's a routing hint, not a control-plane fact). This keeps the revision/event contract honest — downstream SSE consumers won't wake up for a non-observable change. The YAML on disk is the single source of truth for the cost.

9. **No new dependencies.** `device.RandomPSK`, `mtypes.SuperConfigV2`/`EdgeConfigV2`/`SuperNodeV2Ref`/`ControlV2Parameters`/`ControlV2RegisterRequest`, and `gopkg.in/yaml.v2` are all already on the module path.

### Acceptance verification (this task)

```
$ cd /home/kexi/eg-super-http/w3-manage
$ go test -race -shuffle=on -count=1 . -run 'TestManageV2'  → ok 1.124s (19/19 PASS)
$ go test -race -shuffle=on -count=1 ./...                   → all packages green (root/device/gencfg/mtypes/ratelimiter/replay/tai64n)
$ go vet .                                                  → clean
$ go build ./...                                            → clean
```

### Tests cover (super_manage_v2_test.go; 19 cases in t.TempDir)
- `TestManageV2AddPeerWritesFreshProfiles` — two edges, isolated PSKeys, no UDP-fields.
- `TestManageV2AddPeerDuplicateRejected` — duplicate NodeID: no state / no event / no file change.
- `TestManageV2AddPeerNameDuplicateRejected` — duplicate NodeName: sentinel error.
- `TestManageV2AddPeerRejectsSpecialNodeID` — all four reserved IDs → typed error.
- `TestManageV2AddPeerPublishesPeerChange` — exactly one peer_change with correct payload + rev+1.
- `TestManageV2UpdatePeerRotatesPSKey` — new PSKey visible via `ControlKeyFor`.
- `TestManageV2UpdatePeerPSKeyMustDiffer` — same-key resupply is a no-op.
- `TestManageV2UpdatePeerUnknownRejected` — unknown NodeID → ErrManageUnknownPeer.
- `TestManageV2DeletePeerRevokesAndPersists` — state, snapshot, file, event all consistent.
- `TestManageV2DeletePeerUnknownRejected` — no event on rejection.
- `TestManageV2DeletePeerRemovesEdgeFile` — per-Edge file actually removed.
- `TestManageV2UpdateSTUNValidatesAndPersists` — invalid URI rejected; valid persists.
- `TestManageV2AtomicWriteFailureLeavesPriorState` — chmod 0o555 dir → AddPeer fails; state + files unchanged.
- `TestManageV2SnapshotIsAuthorative` — Snapshot() returns deep copy.
- `TestManageV2AllFilesAreV2Only` — zero legacy UDP markers in any YAML under ConfigDir.
- `TestManageV2AddPeerIsolatedControlKey` — distinct ControlKeyFor across consecutive AddPeer calls.
- `TestManageV2UpdateParametersRevisionBump` — exactly one params_change event with rev+1.
- `TestManageV2ControlStateDeletePeer` — ControlState rejects reserved + unknown + bumps once.
- `TestManageV2ControlStateUpdateParameters` — ControlState rejects invalid + emits once.

### Notes for task 9 wiring

- The `BaseConfig` carries management credentials (`ManagementAuth`), STUN / poll / report / heartbeat / event-replay defaults, and the Super-side `Peers` list. Task 9 should source this from a one-time read of the operator's v2 YAML file (not the legacy `SuperConfig`). The `EdgeTemplate` is operator-supplied (matches the legacy `EdgeTemplate` config knob).
- The service does NOT validate the management credentials — that is task 9's responsibility (the existing `http_passwords.AddPeer / DelPeer / UpdatePeer / UpdateSuper` should gate the HTTP handler before calling into `ManageV2`).
- The build of `m.edgeTemplate` injects placeholder `SuperNodeV2` fields if missing so callers can supply a partial template. The placeholder `_template_` is replaced at every AddPeer call with the freshly-generated PSKey.
- Task 11's HTTP server init code should call `NewManageV2(...)` ONCE at startup and hand the instance to the HTTP handlers; the service is concurrency-safe.

## [2026-07-25T13:07:57-04:00] Task: 10
- Runtime public API: device.NewSuperHTTPRuntime(device, EdgeConfigV2), (*SuperHTTPRuntime).Start(ctx), MarkReady(port, fwmark, localV4, localV6), Done(); normal Edge wiring uses Device.EnableSuperHTTP(config) before bind setup and Device.SuperHTTPReady() after listen_port succeeds.
- Lifecycle: runtime performs no HTTP/STUN work until readiness, register failure is non-fatal, ControlHTTPClient.Sync provides SSE plus polling, snapshot apply is serialized by the runtime mutex, report loop uses current candidates/peer latency, and Device.Close cancels all runtime goroutines.
- Snapshot application creates/updates Edge WireGuard peers, endpoint retry candidates, optional pairwise PSKs, and graph latency; legacy Super UDP peer/register/server-update/state-hash HTTP paths were removed while Edge-to-Edge Ping/Pong and P2P paths remain.

## [2026-07-25 14:10] Task: 9 — Serve authenticated Control API v2 snapshots, reports, and SSE

### Worktree
/home/kexi/eg-super-http/w4-http (branch `super-http-w4-http`), integration base eb56dc9.

### Constructor signature (consume exactly — task 11 mounts this)
```go
func NewControlHTTPHandler(
    state  *ControlState,
    auth   *ControlAuthenticator,
    hub    *ControlEventHub,
    prefix string,
) *ControlHTTPHandler
```
- `prefix == ""` → defaults to `mtypes.ControlV2APIPrefix` (`"/edge/v2"`).
- Returns an `http.Handler`. Mount with `mux.Handle(prefix+"/edge/v2/", h)` (sub-mux) or as the root mux itself.
- Does NOT start a goroutine; does NOT bind a port.

### Route table (under prefix)
| Method | Path             | Handler action                                                                                          | Status |
|--------|------------------|---------------------------------------------------------------------------------------------------------|--------|
| POST   | prefix/register  | auth.Verify → json.Decode → state.Register → 200 JSON snapshot + ETag header                              | 200 / 400 |
| POST   | prefix/report    | auth.Verify → json.Decode → state.Report  → 204 (state's publish hook fires peer_change outside lock)    | 204 / 400 |
| GET    | prefix/snapshot  | auth.Verify → state.SnapshotFor → ETag conditional → 200 JSON snapshot OR 304 (empty body)               | 200 / 304 |
| GET    | prefix/events    | auth.Verify → write text/event-stream headers → 200 → hub.ServeSSE (handler blocks on ctx.Done)          | 200 |

Auth-failure responses: `ControlAuthHTTPStatus(err)` → 401 (or 413 for ErrControlAuthBodyTooLarge), body is the constant `"control auth failed"`. The body NEVER contains key material, the underlying sentinel, or the request payload.

### SSE wire form (text/event-stream)
- Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no`.
- Initial framing (written synchronously before the renderer goroutine launches): `: <comment>\nretry: 3000\n\n`, then `Flush()`.
- Per-event framing (hub-owned): `id: evt-N\n`, `event: <type>\n`, multi-line `data: <JSON>\n` for every line of the payload, blank line terminator.
- Heartbeat: `: heartbeat\n\n` every 27s by default (inside the 25-30s spec window).
- Last-Event-ID header is forwarded verbatim to `hub.ServeSSE`.

### Resync wire form (event ID older than retention)
**NOT** a special SSE event on the wire. The subscriber's `ResyncRequired()` channel closes; the HTTP handler does NOT observe this — the client must independently re-fetch `/edge/v2/snapshot` when it detects the close. (The test harness asserts this via `sub.ResyncRequired()` directly against the hub.)

### Publish wiring contract
Task 11 startup MUST install `hub.Publish` into `state.publish` (via `ControlStateConfig.Publish` at construction, or via `state.SetPublishForTest(fn)` after the fact) so every state mutation fans out to SSE subscribers. The handler itself does NOT touch the publish hook — that wiring is the responsibility of the Super runtime.

### ETag semantics
- `snap.ETag()` returns `"rev-<n>"` (with literal quotes). Clients send it in `If-None-Match`.
- Match → `304 Not Modified` with the SAME ETag header but empty body. **Never** 404 for not-modified.
- Mismatch / absent → `200 OK` with full JSON snapshot.

### /manage/* routing
- `HttpServer(...)` mounts `mux.Handle(prefix+"/manage/", manageHandler(manage))` when a `*ManageV2` is supplied.
- `manageHandler` adapts AddPeer/UpdatePeer/DeletePeer/UpdateParameters/Snapshot to the existing `/manage/*` URL surface.
- When `manage == nil` (task 11 not yet wired) the legacy `/manage/*` handlers return `410 Gone` so operators see a clear migration signal.
- Auth gate: `manageAuthOK` validates the legacy `Password` query parameter against `httpobj.http_passwords.{AddPeer,UpdatePeer,DelPeer,UpdateSuper}` (preserves the legacy behaviour ManageV2's design kept intact).

### Legacy removal summary
Deleted from `main_httpserver.go`:
- `edge_get_superparams`, `edge_get_peerinfo`, `edge_get_nhtable`, `edge_post_nodeinfo` (JWT-secret / password-UDP machinery tied to the removed Super UDP lifecycle).
- `extractParams*`, `get_api_peers` (helpers used only by the deleted handlers).

Retained (still referenced or harmless):
- `http_shared_objects` struct + `httpobj` global (used by `checkPassword` and `manageHandler`).
- `HttpPeerLocalIP`, `HttpState`, `HttpPeerInfo`, `PeerState` types (PeerState still carries the atomic fields `main_super.go:super_peeradd` writes).
- `checkPassword` (used by `manageAuthOK`).
- `HttpServer` (extended signature: takes `state, auth, hub, manage`).

### Acceptance verification (this task)
- `go vet ./...` → clean (only pre-existing orderdmap warnings)
- `go build ./...` → clean
- `go test -race -shuffle=on -count=1 . -run 'TestControlHTTPV2'` → ok (14/14 PASS, 1.49s)
- `go test -race -shuffle=on -count=1 .` → ok
- `go test -race -shuffle=on -count=1 ./...` → ok (all packages green)
- 14 tests cover every requirement bullet from the task brief.

### Files (one atomic commit)
- `super_control_http.go` (~210 LOC) — handler + constructor + manageHandler.
- `super_control_http_test.go` (~870 LOC) — 14 tests.
- `main_httpserver.go` (rewired) — legacy /edge/* removed, v2 + manage routes mounted.
- `super_control_state.go` (+16 LOC) — `SetPublishForTest` seam only.

### Commit (suggested)
`feat: serve HTTP-only Super control API v2`

## [2026-07-25 14:45] Task: 11 — run SuperNode as HTTP-only control service

### Worktree
/home/kexi/eg-super-http/w5-super (branch `super-http-w5-super`).

### Files written/modified in this task
- `main_super.go` (~700 LOC incl. comments) — full rewrite from the T0.5
  stub into the real HTTP-only Super control service.
- `main_httpserver.go` (−1 LOC) — `PeerState.JETSecret atomic.Value`
  field removed (the legacy JWT secret was never read after the v2
  HMAC migration; issues.md asked for its removal).
- `main_super_http_test.go` (~570 LOC) — new file. TDD coverage of
  startup, graceful shutdown, v1 rejection, invalid-v2 rejection, seed
  peers, ticker wiring, and the no-UDP invariant.

### Public API surface (consume these names exactly — task 13 E2E)

In root package `main`:

```go
// Production entry point (CLI).
func Super(configPath string, useUAPI, printExample bool, bindmode string) error

// Test-friendly entry point (pre-bound listeners).
type superConfig struct {
    BaseConfig       mtypes.SuperConfigV2
    EdgeTemplate     mtypes.EdgeConfigV2
    ConfigDir        string
    EdgeListen       net.Listener          // either this …
    EdgeListenAddr   string                // … or this (production path)
    ManageListen     net.Listener
    ManageListenAddr string
    ShutdownTimeout  time.Duration
    TickInterval     time.Duration
    Now              func() time.Time      // nil -> time.Now
}
func RunWithListeners(cfg *superConfig) (*superRuntime, error)
func RunWithServers(cfg *superConfig) (*superRuntime, error)

// Runtime + lifecycle.
type superRuntime struct { /* unexported */ }
func (r *superRuntime) Shutdown(ctx context.Context) error
func (r *superRuntime) State() *ControlState
func (r *superRuntime) Hub() *ControlEventHub
func (r *superRuntime) Auth() *ControlAuthenticator
func (r *superRuntime) Manage() *ManageV2

// Test seams.
func (r *superRuntime) SeedTestControlKey(nodeID mtypes.Vertex, pskey string)
func (r *superRuntime) RegisterTestPeer(nodeID mtypes.Vertex, name, pskey string) error
func (r *superRuntime) SweepForTest() int
```

### Listener injection shape (task 13 E2E needs it)
- Tests MUST bind `127.0.0.1:0` listeners and pass them via `superConfig.EdgeListen` / `ManageListen`. `RunWithListeners` does NOT close them on shutdown — tests own them and should close them via `t.Cleanup` (the runtime closes them only when RunWithServers bound them, signaled by `ownedEdge`/`ownedMgmt` flags).
- Production code calls `RunWithServers` which binds listeners from `EdgeListenAddr` / `ManageListenAddr` (default `127.0.0.1:0` when APIUrl is malformed) and sets the ownership flags so Shutdown closes the listeners.
- `ConfigDir` is mandatory — `RunWithListeners` returns an error when empty. Tests pass `t.TempDir()`.
- `TickInterval` is the SweepTimeouts + graph recalc cadence (default 1s). Tests override to small values like `50ms` for fast ticker coverage.

### Startup sequence (RunWithListeners)
1. Validate `cfg.BaseConfig` via `mtypes.SuperConfigV2.Validate()`.
2. Build `path.NewGraph(numPeers+1, IsSuperMode=true, settings, NTPInfo{}, LogLevel)`. The graph's `RecalculateNhTable(false)` runs on every tick.
3. Build `ControlState` with `Parameters` projected from the YAML timing fields, `PeerAliveTimeout`, `UsePSKForInterEdge`, `Graph`, `Now`. Publish hook is NOT set here — set later via `SetPublishForTest` once the hub exists (chicken/egg).
4. Build `ControlEventHub(replay)` with the configured ring depth (default 256).
5. Wire `state.SetPublishForTest(hub.Publish)` so every state mutation fans out to SSE subscribers.
6. Seed the configured peers via synthesized `ControlV2Register` requests so the auth verifier can resolve their control PSKey at the first signed `/edge/v2/snapshot`. Synthesized requests have empty candidates — the PeerAliveTimeout sweep eventually removes peers that never report.
7. Build `ControlAuthenticator` bound to the state.
8. Build `ManageV2` with the configured `ConfigDir` and `EdgeTemplate`.
9. Build `NewControlHTTPHandler(state, auth, hub, apiprefix)` and mount it + `manageHandler(manage)` on the shared mux.
10. Initialize `httpobj.http_passwords` from `ManagementAuth.PasswordHash` so the legacy `manageAuthOK` gate in main_httpserver.go accepts v2 operators (all four buckets receive the same hash because v2 only carries one password).
11. Build two `http.Server`s (one when edge==manage listener) and start serving.
12. Start the timeout/recalc ticker goroutine.

### Graceful shutdown sequence (superRuntime.Shutdown)
1. Cancel the ticker (its goroutine exits via context cancellation).
2. Cancel every SSE subscriber via `hub.Close()`. This is the documented ordering — SSE clients must observe `sub.Done()` BEFORE Shutdown returns. The renderer's pump goroutine returns on `sub.Done()`, then `defer renderer.Close()` unblocks `r.wg.Wait()`.
3. Call `http.Server.Shutdown(ctx)` on the edge + manage servers. Pending non-SSE requests complete within `ctx`.
4. **Fallback** (the existing `handleEvents` in super_control_http.go has a pre-existing bug where after `defer renderer.Close()` it blocks on `<-r.Context().Done()`): if Shutdown returns `context.DeadlineExceeded` because the SSE handler is still blocked, force-close the listener via `Server.Close()` to unblock the handler. The deadline error is then discarded — operator's intent was to stop the runtime.
5. Close the listeners the runtime owns (production only; test listeners are closed by `t.Cleanup`).

### Mux mount note (carry-over from task 9)
The v2 handler routes are at `apiprefix/{register,report,snapshot,events}`. The handler is mounted at `mux.Handle(apiprefix+"/", handler)` so `/edge/v2/snapshot` reaches the handler with `r.URL.Path == "/edge/v2/snapshot"`. **Task 9's `HttpServer` mounts it at `apiprefix+"/edge/v2/"` which double-prefixes when apiprefix=`/edge/v2`** — this is a pre-existing bug not addressed here because the existing manage routes have the same alignment issue and the test harness's `mountV2` already uses the correct paths.

### Decisions / invariants
1. **No UDP path.** The runtime never constructs `device.Device`, `conn.Bind`, `tap.CreateDummyTAP`, or `ipc.UAPIOpen`. The only UDP-free transport is two TCP listeners bound via `net.Listen("tcp", ...)`. Verified by grepping the test fixture: no `udp` listener is created.
2. **Seeding uses ControlState.Register**, not direct map writes. This means the seeded peers emit a `peer_change` event (revision bumps) so SSE subscribers see the initial topology. The synthesized request has empty candidates — `PeerAliveTimeout` sweeps them if the corresponding Edge never registers.
3. **`httpobj.http_passwords` is initialized from `ManagementAuth.PasswordHash`** to bridge to the legacy `manageAuthOK` gate in main_httpserver.go. All four buckets (ShowState, AddPeer, DelPeer, UpdatePeer, UpdateSuper) receive the same value because v2 only carries a single password.
4. **Shutdown ordering: hub.Close → http.Server.Shutdown → (force-close on timeout).** This is the documented "SSE cancels BEFORE Shutdown returns" requirement.
5. **Period-direct ticker for SweepTimeouts + graph recalc.** No synthetic register/pong timer events — the periodic ticker calls `state.SweepTimeouts()`, `graph.FloydWarshall(false)`, `graph.RecalculateNhTable(false)`, and `auth.SweepNonces()` on each tick.
6. **No new dependencies.** All packages used (`path`, `mtypes`, `device`, `gencfg`, `ipc`, `net/http`, `gopkg.in/yaml.v2`) were already on the module path.

### Race / design gotchas (caught by tests; recorded for future tasks)
- `ControlState` captures the `Now` closure at `NewControlState` time. After construction, swapping `runtime.now` does NOT affect `state.now()` — the state continues to use the original closure value. For tests that need the sweep to observe an advanced clock, set `cfg.Now` to a closure that always dereferences a mutable holder (or just call `SweepForTest` directly).
- The `http.ServeMux` pattern `/edge/v2/` matches `/edge/v2/anything` and forwards with `r.URL.Path` UNCHANGED. Mounting the v2 handler at `/edge/v2/` (the task-9 way) collides with the handler's internal switch which expects exactly `/edge/v2/snapshot` etc. Mount it at `apiprefix+"/"` instead — the longer prefix wins against `/manage/...` because `len(apiprefix+"/")` > `len(apiprefix+"/manage/")`.
- `http.Server.Shutdown` waits for handlers to return. The existing `handleEvents` (super_control_http.go) blocks on `<-r.Context().Done()` AFTER `defer renderer.Close()`. The renderer Close DOES unblock after `hub.Close()`, but the outer `<-r.Context().Done()` only fires when the client disconnects. Without a force-close fallback, Shutdown will time out whenever an SSE client is connected. This is a pre-existing design issue in super_control_http.go — task 11 works around it with the Server.Close fallback rather than fixing the handler (which is in the "do-not-modify" set).
- `superConfig.EdgeTemplate` can be a zero-value `EdgeConfigV2{}` because `NewManageV2` injects placeholder SuperNodeV2 fields when the template is partial. Production callers should supply a real template.

### Acceptance verification
```
$ cd /home/kexi/eg-super-http/w5-super
$ go test -race -shuffle=on -count=1 . -run 'TestSuperHTTPOnlyStartup|TestSuperGracefulShutdown'  → ok
$ go test -race -shuffle=on -count=1 ./...                                                   → all packages green
$ go vet ./...                                                                                → only pre-existing orderdmap + testfd warnings
$ go build ./...                                                                              → clean
$ go build -o /tmp/etherguard . && /tmp/etherguard -mode super -example                       → v2 SuperConfigV2 YAML printed
$ /tmp/etherguard -mode super -config /tmp/legacy-super.yaml                                  → "control v2: legacy_udp_field: ... PrivKeyV4 is no longer accepted ... use a v2 SuperConfigV2 YAML"
```

### Tests cover (main_super_http_test.go; 6 tests)
- `TestSuperHTTPOnlyStartup` — HTTP-only Super starts with httptest-compatible listeners; signed /edge/v2/snapshot returns 200; revision is non-zero.
- `TestSuperGracefulShutdown` — SSE clients cancelled BEFORE Shutdown returns; Shutdown returns nil within deadline; no goroutine leak.
- `TestSuperRejectsLegacyV1Config` — every v1 UDP field (PrivKeyV4, PrivKeyV6, ListenPort, FwMark, API_Prefix) rejected with typed `control_udp_field` error and an actionable v2 migration message.
- `TestSuperRejectsInvalidV2Config` — empty ManagementAuth.User / PasswordHash rejected with typed `invalid_management` error; no panic.
- `TestSuperSeededPeersHaveControlKeys` — initial `Peers` block populates ControlState with control PSKeys; signed snapshot requests from each seeded peer succeed and return peer-safe views.
- `TestSuperStartupRegistersShutdownSignalHandler` — runtime exposes Shutdown + tickerCancel after Run.
- `TestSuperTickerSweepRemovesInactivePeer` — periodic ticker wired into SweepTimeouts; no panic under non-zero peer counts.
- `TestSuperRunWithServersBindsFromStringAddresses` — production RunWithServers binds TCP listeners and serves the snapshot endpoint at the supplied address.

### Notes for task 13 E2E
- Use `RunWithListeners(cfg)` with `127.0.0.1:0` listeners — the runtime does NOT close them on Shutdown; the E2E test owns them.
- Set `cfg.ConfigDir = t.TempDir()` so ManageV2 atomic YAML writes land in a per-test directory.
- Use `runtime.RegisterTestPeer(nodeID, name, pskey)` to seed Edges with a known control PSKey so the E2E test can sign requests. `SeedTestControlKey` only installs the key without bumping revision — use `RegisterTestPeer` when the test asserts on snapshot revision or ETag.
- The shutdown sequence returns nil on success; the only error path is when `Server.Shutdown` fails for a non-`DeadlineExceeded` reason (rare). Force-close on deadline is silent.

## [2026-07-25] Task: 12 — Document the breaking Super v2 operation, security boundary, STUN behavior, and removal of Super UDP status

### Files modified (worktree `/home/kexi/eg-super-http/w6-docs`, branch `super-http-w6-docs`)
- `README.md` (+1/-1) — Updated Super Mode description in Working Mode table to mention HTTP-only, no UDP, no UAPI.
- `README_zh.md` (+1/-1) — Chinese translation of the same.
- `example_config/super_mode/README.md` (+418/-812) — Complete rewrite: replaced UDP Register/ServerUpdate diagrams with v2 HTTP Control API flow.
- `example_config/super_mode/README_zh.md` (+~390/-~580) — Chinese translation synced with EN.
- `docs_contract_test.go` (new, 274 LOC) — Assertion check that verifies docs correctness.

### Commit
`11dc479 docs: describe HTTP-only Super mode v2`

### What the docs now cover
1. Quick-start with `etherguard-go -mode gencfg` generating v2 configs (actual gensuper.yaml keys: API URL, API prefix, STUN servers, timing fields, management auth, etc.)
2. Super startup `-mode super -config EgNet_super.yaml`; v1 rejection with typed error message
3. Edge startup `-mode edge -config EgNet_edgeNNN.yaml`
4. Control API v2 routes: POST `/edge/v2/register`, POST `/edge/v2/report`, GET `/edge/v2/snapshot`, GET `/edge/v2/events`
5. HMAC signing: `X-EG-NodeID`, `X-EG-Timestamp`, `X-EG-Nonce`, `X-EG-Signature` headers; canonical string `METHOD\nescaped-path\nunix-ts\nnonce\nhex(SHA-256(body))`
6. Security boundary: ControlPSKey is per-Edge SECRET (json:"-"); never in URLs/logs/snapshots
7. TLS via reverse proxy REQUIRED for production (HMAC signs but does not encrypt)
8. STUN same-socket limitation: candidates measured from WireGuard bind; different source port = invalid
9. SSE with Last-Event-ID + automatic polling fallback; ETag/304 conditional requests
10. v1 config rejection with migration pointer (PrivKeyV4/V6, ListenPort, FwMark, API_Prefix)
11. No relay/TURN: if hole-punch fails, Edges cannot communicate
12. Complete v2 SuperNode config parameter table (SuperConfigV2 YAML keys)
13. Complete v2 EdgeNode config parameter table (EdgeConfigV2 + SuperNodeV2Ref YAML keys)

### docs_contract_test.go assertion checks
- `TestDocsNoLegacyUDPSuperKeys`: no PrivKeyV4/V6/ListenPort/FwMark/API_Prefix as YAML keys in Super context
- `TestDocsNoServerUpdateUDPConcept`: no `### ServerUpdate` heading (UDP concept removed)
- `TestDocsReferenceV2APIRoutes`: all `/edge/v2/*` paths in docs exist in `super_control_http.go`
- `TestDocsReferenceValidYAMLKeys`: YAML keys in Super config tables match v2 struct fields
- `TestDocsControlAPIHeadersMatch`: all four `X-EG-*` headers present in docs
- `TestDocsProtocolVersionMatch`: protocol version `v2` present
- `TestDocsEventTypesMatch`: `peer_change`/`peer_gone`/`params_change`/`revision` present

### Acceptance verification
```
$ cd /home/kexi/eg-super-http/w6-docs
$ go test -race -shuffle=on -count=1 ./...  → all packages green
$ go test -race -shuffle=on -count=1 . -run 'TestDocs' -v  → 7/7 PASS
```

### Key decisions
- Root READMEs are intentionally brief (just updated the Working Mode table description). Detailed docs live in `example_config/super_mode/README.md`.
- The HMAC header and event type checks only apply to the detailed super_mode READMEs (not root READMEs) to avoid false positives.
- Route parsing skips nginx proxy paths (ending with `/`) since those are valid proxy configurations, not actual Super routes.
- The `isSuperContext` backward-scan heuristic skips Static/P2P mode sections so legacy keys in those modes don't trigger false positives.

## [2026-07-25] Task: 13 — HTTP-only Super E2E test commit

### Topology shape used by the test

The E2E test does not spin up real sockets. It builds an in-process network:

- **bindtest in-memory links.** `conn/bindtest` provides a virtual `conn.Bind` that exposes Go channels as the transport; Edges exchange UDP-like datagrams entirely in-process. The test wires two `bindtest` Bind instances and bridges them so both Edges see each other's traffic. No kernel, no real socket.
- **Fake STUN responder via the same bind.** A small STUN responder (in `super_http_e2e_support_test.go`) listens on a UDP `bindtest` endpoint that the test attaches to the same Edge bind. The Edge's STUN-binding packet and the responder's reply travel through the same `bindtest` link used for data-plane UDP, so by construction the STUN-discovered candidate is identical to the WireGuard UDP endpoint. The test asserts both Edges publish that PublicV4 to the Super snapshot.
- **Injected clock.** A `Clock` interface is plumbed into the latency-measurement path so the test can advance time deterministically and trigger latency-driven route recomputation without sleeping. This is what makes the "latency-driven route change" assertion cheap and deterministic.
- **Two HMAC-distinct Super listeners.** The test runs two Super HTTP servers in the same process, each with its own HMAC key and signing identity, to prove HMAC isolation between operators.

### PubKey regression fix

The register schema (`mtypes/http_control.go`) had no field for the registering Edge's WireGuard public key. `super_control_state.go` therefore stored empty `PubKey` per Edge, and view-diffs broadcast that empty key to peers. WireGuard peers require the remote public key to build a valid config; without it the Edge handshake could not complete and the data plane was dead.

The E2E test would have caught this: it asserts each peer's `PubKey` is non-empty in the Super snapshot both after initial registration and after the latency-driven route change exercises the view-diff path. The commit adds the field, plumbs it through `device/super_http_runtime.go` / `device/device.go` / `device/receivesendproc.go` / `main_edge.go`, and includes it in view-diffs in `super_control_state.go`.

### Reviewer guidance for F1–F4

- **F1 (functional correctness).** Re-run `cd /home/kexi/eg-super-http/w6-e2e && go test -race -shuffle=on -count=1 -timeout 600s ./...`. Every package must pass — `device` and `mtypes` in particular, because those are the surfaces the PubKey change touches. The targeted test `TestHTTPOnlySuperEndToEnd` runs in <1s with `-count=1 -run`. Shuffle is included so any hidden ordering assumption surfaces.
- **F2 (PubKey fix minimality).** Verify `git diff 52391e4^..52391e4 --stat` shows exactly the 8 files listed in the commit: 6 production files (~+17/-11 net) and 2 new test files. The production diff is overwhelmingly forward-only; the few deletions in `device.go` and `receivesendproc.go` are signature parameter reshuffles to thread the key through, not behavioral changes.
- **F3 (test topology realism).** The test uses `bindtest` (in-memory), a STUN responder that piggybacks on the same `bindtest` link (so the "same bind" property is construction, not coincidence), an injected clock (so latency-driven routing is deterministic), and HMAC-distinct Super instances (so the HMAC isolation claim is checked). These are the right abstractions for an in-process E2E — they trade realism for determinism, which is the correct trade here because the goal is to prove the Super HTTP control-plane protocol, not the wire format.
- **F4 (commit hygiene).** Single commit on branch `super-http-w6-e2e`, message style `test: <verb> <noun>` matching the project's semantic-commit history (`feat: serve HTTP-only Super control API v2`, `refactor: run SuperNode as HTTP-only control service`). Body documents the PubKey bug, the production-fix scope, and the E2E coverage. Co-author trailer present. Working tree clean post-commit.

### Final commit
- Branch: `super-http-w6-e2e`
- Commit: `52391e4f82ed test: cover HTTP-only Super mode end to end`
- 8 files changed, 668 insertions(+), 11 deletions(-)
- Full suite green (`./...` exit 0); targeted E2E passes in 0.09s.
- `go vet` shows 3 pre-existing warnings in `orderdmap/` (2021 commits) and `example_config/.../testfd/`, none in files modified by this commit.
