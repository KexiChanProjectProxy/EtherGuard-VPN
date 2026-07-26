# supernode-http-only - Work Plan

## TL;DR (For humans)
<!-- Fill this LAST, after the detailed plan below is written, so it summarizes the REAL plan. -->
<!-- Plain English for a non-engineer: NO file paths, NO todo numbers, NO wave/agent/tool names. -->

**What you'll get:** Super mode will use a secure HTTP control API instead of a SuperNode UDP listener. Nodes will discover local and STUN-reflexive addresses, synchronize via SSE with polling fallback, and still send VPN traffic directly through Edge-to-Edge WireGuard links.

**Why this approach:** Address candidates must be measured from the same UDP socket that carries WireGuard, while HTTP is a better fit for authenticated coordination, reliable configuration delivery, and long-lived one-way update notifications.

**What it will NOT do:** It will not turn the SuperNode into a relay, TURN server, or VPN data forwarder. It will not preserve old UDP Super-mode configuration or alter Edge-to-Edge packet forwarding.

**Effort:** XL
**Risk:** High - the control-plane transport, authentication boundary, socket receive path, and generated configuration all change together.
**Decisions to sanity-check:** Breaking Control API v2; existing per-Edge Super `PSKey` becomes its HMAC secret but is never included in a peer snapshot; `pion/stun/v3` is the only new runtime dependency.

Your next move: start a separate execution session and use the required worktree discipline, or request the optional dual high-accuracy plan review. Full execution detail follows below.

---

> TL;DR (machine): XL/high-risk Control API v2 migration: remove Super UDP, add HMAC HTTP+SSE/poll sync and same-bind STUN candidates, preserve Edge data plane.

## Scope
### Must have
- A breaking **Control API v2**: `POST /edge/v2/register`, `POST /edge/v2/report`, `GET /edge/v2/snapshot`, and `GET /edge/v2/events` under the existing configured API prefix.
- SuperNode HTTP-only runtime: no WireGuard `Device`, UDP bind, Super peer, UAPI, UDP Register/Pong, or `ServerUpdate` transport.
- Request-level HMAC-SHA256 authentication keyed by the configured per-Edge Super `PSKey`: canonical method/path/timestamp/nonce/body-SHA-256 signing, constant-time comparison, body-size cap, timestamp window, and bounded nonce replay cache.
- Initial register snapshot; report-driven heartbeat and candidate/latency publication; versioned snapshot ETag/304 polling; SSE invalidations with event IDs, bounded replay, `Last-Event-ID`, heartbeat comments, reconnect, and automatic poll fallback.
- STUN candidates measured from the same active Edge WireGuard bind, STUN-magic-cookie demultiplexing before WireGuard dispatch, local-candidate inclusion, dual-stack server handling, bounded failover, and no fabricated public candidate on failure.
- Super-configured STUN server list and timing settings delivered as control parameters; v2 generator, examples, manage API config rewrites, Chinese/English docs, TDD coverage, and isolated git-worktree execution.
- Edge-to-Edge WireGuard peers, normal packet forwarding, Floyd-Warshall routing, and optional pairwise inter-Edge PSK behavior unchanged.
### Must NOT have (guardrails, anti-slop, scope boundaries)
- No SuperNode relay/data-plane forwarding, TURN server, NAT-type guarantee, WebSocket service, database, browser UI, or automatic v1 configuration migration.
- No standalone STUN UDP socket; a candidate with a source port different from the WireGuard bind is invalid for this feature.
- No exposure of an Edge's Super-control `PSKey` in v2 responses, logs, URLs, SSE data, or errors; only existing pairwise inter-Edge PSKs may be returned when enabled.
- No mutation, staging, stash, commit, or overwrite of the current dirty source worktree as migration preparation.

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: **TDD** using Go `testing`, `httptest`, `conn/bindtest`, race-enabled package tests, and a binary-level HTTP-only integration scenario.
- Each task follows red → green → refactor: first run the new test to prove the intended failure, then implement only enough to pass, then run its package with `-race -shuffle=on -count=1`.
- Evidence: `.omo/evidence/task-<N>-supernode-http-only.log` containing the exact command, exit status, happy-path assertion, and failure-path assertion; final evidence is `.omo/evidence/final-supernode-http-only-<verifier>.log`.
- Mandatory gates after merge: `go test -race -shuffle=on -count=1 ./...`, `go vet ./...`, `make`, and `make vpp` in an environment with VPP/libmemif installed. Do not claim the VPP gate passed without that command's log.

## Execution strategy
### Parallel execution waves
> Every wave is earliest-ready, not a barrier: begin a task immediately when its own dependencies merge into the integration base. Each concurrent task owns disjoint paths in a separate git worktree.
- Wave 1: **1**.
- Wave 2: **2, 3, 4, 5, 7** — each consumes only task 1's v2 contract and writes a disjoint generator, socket, client, state, or event-hub surface.
- Wave 3: **6, 8, 10** — 6 consumes state key lookup (5); 8 consumes generated v2 config plus state mutation (2, 5); 10 consumes working STUN and client modules (3, 4).
- Wave 4: **9** — HTTP route assembly needs state, authentication, events, and management surfaces (5, 6, 7, 8).
- Wave 5: **11** — the Super runtime may remove UDP only after route assembly is functional (9).
- Wave 6: **12, 13** — documentation requires generated config/routes/runtime (2, 9, 11); end-to-end proof requires all runtime data/control surfaces (3, 4, 9, 10, 11).

### Required git-worktree discipline
- Preserve the dirty source worktree. Before any worktree creation, record `GIT_MASTER=1 git status --porcelain` and `GIT_MASTER=1 git rev-parse HEAD` in `.omo/evidence/worktree-preflight-supernode-http-only.log`; do **not** stash, stage, or commit the unrelated Edge/P2P work.
- Create a clean integration branch from that recorded HEAD, then create one worktree per concurrently ready todo. Use names such as `super-http-w1-schema`, `super-http-w2-stun`, and `super-http-w2-client`; each worktree must start from the integration commit containing its named dependencies.
- Merge only an independently passing task commit into the integration branch. Rebase/reconcile the current dirty Edge/P2P work later in its own worktree; do not blend it into these task commits.
- Recompute the preflight HEAD at execution time because the current working tree is dirty and existing line references may drift. The task write sets below, not the current dirty files, define merge ownership.

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | none | 2, 3, 4, 5, 7 | none |
| 2 | 1 | 8, 12 | 3, 4, 5, 7 |
| 3 | 1 | 10, 13 | 2, 4, 5, 7 |
| 4 | 1 | 10, 13 | 2, 3, 5, 7 |
| 5 | 1 | 6, 8, 9 | 2, 3, 4, 7 |
| 6 | 5 | 9 | 8, 10 |
| 7 | 1 | 9 | 2, 3, 4, 5 |
| 8 | 2, 5 | 9, 12 | 6, 10 |
| 9 | 5, 6, 7, 8 | 11, 12, 13 | none |
| 10 | 3, 4 | 13 | 6, 8 |
| 11 | 9 | 12, 13 | none |
| 12 | 2, 9, 11 | none | 13 |
| 13 | 3, 4, 9, 10, 11 | none | 12 |

## Todos
> Implementation + Test = ONE todo. Never separate.
- [x] 1. [Ready wave: 1; Depends on: none; Writes: mtypes/config.go, mtypes/http_control.go, mtypes/http_control_test.go] Define the breaking Control API v2 schema and typed request/snapshot contracts
  - References (executor has NO interview context - be exhaustive): `mtypes/config.go:22-174` for current Edge/Super/peer types; `mtypes/metamessage.go:25-33,180-198` for legacy Register/report types; `gencfg/example_conf.go:191-290` for defaults.
  - What to do / Must NOT do: Remove Super UDP-only configuration (`PrivKeyV4`, `PrivKeyV6`, `ListenPort`, `FwMark`, Super endpoint/public-key fields, and Super UAPI-specific settings); retain each Edge's configured Super `PSKey` as its private control-auth key; add typed v2 register/report/snapshot/event/candidate and control-parameter models, including `STUNServers`, STUN request/refresh timing, poll interval, protocol version, and monotonic state revision. Parse and validate every URI, duration, NodeID, candidate, and protocol version once at the config/HTTP boundary. Do not expose a control PSKey through any API model.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 ./mtypes -run 'TestControlV2|TestSuperConfigV2'` proves valid v2 parsing, rejects legacy UDP Super fields, invalid STUN URIs/durations, special NodeIDs, malformed candidates, and unsupported API versions.
  - QA scenarios: Happy—marshal/unmarshal a valid Super+Edge v2 config and a complete snapshot without losing fields. Failure—each obsolete UDP field and a zero/malformed control setting fails validation with typed errors. Evidence `.omo/evidence/task-1-supernode-http-only.log`.
  - Commit: Y | `config: define HTTP-only Super control contracts`

- [x] 2. [Ready wave: 2; Depends on: 1; Writes: gencfg/example_conf.go, gencfg/gencfgSM.go, gencfg/gencfgSM_test.go, example_config/super_mode/gensuper.yaml, example_config/super_mode/EgNet_super.yaml, example_config/super_mode/EgNet_edge001.yaml, example_config/super_mode/EgNet_edge002.yaml, example_config/super_mode/EgNet_edge100.yaml] Generate only valid HTTP-only Super v2 configurations
  - Depends on task 1 because the generator must construct and validate the concrete v2 fields and remove the deleted UDP configuration from emitted files.
  - References (executor has NO interview context - be exhaustive): `gencfg/gencfgSM.go:157-297` for v1 Super/Edge generation; `gencfg/example_conf.go:18-289` for default templates; `example_config/super_mode/gensuper.yaml` and `EgNet_*.yaml` for examples to migrate.
  - What to do / Must NOT do: Generate a unique per-Edge control PSKey in both Super peer metadata and its own Edge config; include no Super WireGuard keys/endpoints/listen port; emit the Super-owned STUN list and Edge API URL; retain pairwise inter-Edge PSK generation semantics. Do not copy a control PSKey into another Edge configuration or peer-info fixture.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 ./gencfg -run 'TestGenSuperCfgHTTPOnly|TestGeneratedControlKeysAreIsolated'` creates configs in `t.TempDir`, asserts no obsolete UDP keys, asserts each Edge authenticates only with its own PSKey, and validates generated STUN settings.
  - QA scenarios: Happy—three generated edges share API settings and receive distinct private control keys. Failure—a template containing legacy Super UDP fields is rejected rather than silently emitted. Evidence `.omo/evidence/task-2-supernode-http-only.log`.
  - Commit: Y | `config: generate HTTP-only Super mode profiles`

- [x] 3. [Ready wave: 2; Depends on: 1; Writes: go.mod, go.sum, device/super_stun.go, device/super_stun_test.go, device/receive.go, device/receive_stun_test.go] Add same-bind STUN candidate discovery and safe receive-path demultiplexing
  - Depends on task 1 because the STUN server/timing contract and candidate types are consumed from its typed control parameters.
  - References (executor has NO interview context - be exhaustive): `conn/conn.go:23-48,104-122` for Bind/Endpoint; `device/receive.go:79-219` for raw UDP receive before WireGuard parsing; `device/peer.go:562-615` for endpoint/bind behavior; RFC 8489 Binding/XOR-MAPPED-ADDRESS; `github.com/pion/stun/v3` documentation.
  - What to do / Must NOT do: Add `github.com/pion/stun/v3`; create a context-owned STUN transaction manager that sends Binding requests with the existing `device.net.bind`, validates magic cookie plus transaction ID before the WireGuard message-type switch, and publishes only local plus successful XOR-MAPPED addresses. Resolve/attempt IPv4 and IPv6 configured UDP servers with bounded failover and request timeout. Do not open another UDP socket, classify NAT type, or let unknown STUN-looking packets bypass WireGuard validation.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 ./device -run 'TestSuperSTUN|TestReceiveDemultiplexesSTUNBeforeWireGuard'` proves a mapped candidate retains the active bind's source port, an unknown/malformed response is rejected, and a valid WireGuard initiation/transport packet still reaches its existing queue.
  - QA scenarios: Happy—two fake STUN servers return IPv4/IPv6 XOR-MAPPED candidates and the manager deduplicates them. Failure—the first server times out, all servers fail, or a packet has `0x01` first byte but no valid STUN cookie/transaction; local candidates remain and WireGuard dispatch is not corrupted. Evidence `.omo/evidence/task-3-supernode-http-only.log`.
  - Commit: Y | `feat: discover Super candidates through same-bind STUN`

- [x] 4. [Ready wave: 2; Depends on: 1; Writes: device/super_http_client.go, device/super_http_client_test.go] Implement the typed Edge Control API v2 client with signed snapshot, report, SSE, and poll behavior
  - Depends on task 1 because the client serializes and validates its v2 models, control PSKey, revisions, and timing settings.
  - References (executor has NO interview context - be exhaustive): `device/receivesendproc.go:407-658,899-1031` for current HTTP pulls/reports; `mtypes/config.go:157-168,226-246` for current API config/types; HTML Living Standard SSE §9.2; Go `net/http` `ResponseController` and `Request.Context` documentation.
  - What to do / Must NOT do: Use a tuned `net/http.Client` and context-driven operations; sign canonical requests using method, escaped path, timestamp, nonce, and SHA-256 body digest; fetch an initial/conditional snapshot; consume UTF-8 SSE events as hints; reconnect with `Last-Event-ID`; start interval polling after SSE failure while retrying SSE with bounded exponential backoff; serialize snapshot application by revision. Do not use bearer JWT bootstrap, query-string credentials, 404-as-not-modified, sleeps for synchronization, or make SSE payload authoritative state.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 ./device -run 'TestControlHTTPClient'` verifies HMAC headers and body digest, 200/304 snapshot behavior, event replay/reconnect, automatic polling fallback, and monotonic revision application against `httptest.Server`.
  - QA scenarios: Happy—register then SSE event triggers exactly one newer snapshot application. Failure—expired timestamp, replayed nonce, malformed event, dropped stream, 304 response, and stale snapshot each leave local peer/route state unchanged. Evidence `.omo/evidence/task-4-supernode-http-only.log`.
  - Commit: Y | `feat: add Edge HTTP control client`

- [x] 5. [Ready wave: 2; Depends on: 1; Writes: super_control_state.go, super_control_state_test.go] Introduce one concurrency-safe authoritative Super control-state service
  - Depends on task 1 because this service owns the typed peer records, control keys, candidates, graph inputs, parameters, and revision models defined there.
  - References (executor has NO interview context - be exhaustive): `main_httpserver.go:34-60,151-210,393-526` for global state/current report flow; `main_super.go:377-474` for register/pong/timer handling; `path/path.go:127-155,173-238,354-425` for graph recalculation; `mtypes/config.go:99-108` for peer policy.
  - What to do / Must NOT do: Replace cross-goroutine direct access to `httpobj` maps with a service that atomically registers/reports peers, updates `LastSeen`, records candidates, updates the graph, produces a per-request peer-safe snapshot, and increments a revision only for observable state changes. Snapshot map iteration before releasing locks; inject clock and publish change events outside locks. Do not retain `Event_server_register`, `Event_server_pong`, synthetic timer events, or map iteration during mutation.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestControlState'` proves registration/report updates, peer timeout removal from snapshots, graph-change revision behavior, and concurrent add/report/delete operations without a race or map panic.
  - QA scenarios: Happy—candidate/report update changes the snapshot revision and next-hop table only when graph output changes. Failure—unknown peer, wrong key, expired peer, duplicate report, and concurrent deletion are rejected or isolated without corrupting snapshots. Evidence `.omo/evidence/task-5-supernode-http-only.log`.
  - Commit: Y | `refactor: centralize Super control state`

- [x] 6. [Ready wave: 3; Depends on: 5; Writes: super_control_auth.go, super_control_auth_test.go] Enforce replay-safe per-Edge HMAC authentication at the Control API boundary
  - Depends on task 5 because authentication must resolve a registered Edge's control PSKey through the authoritative service without reading mutable maps directly.
  - References (executor has NO interview context - be exhaustive): `main_httpserver.go:212-526` for current weak read/JWT auth and inverted body check; `mtypes/config.go:99-108,157-168` for per-Edge control key placement; Go `crypto/hmac`, `crypto/sha256`, and `subtle`/constant-time comparison documentation.
  - What to do / Must NOT do: Parse headers into a typed signed-request value, enforce a fixed timestamp skew window and bounded per-Edge nonce TTL cache, limit body size before hashing, use `hmac.Equal`, and return uniform non-secret HTTP errors. Keep control PSKeys out of snapshots, logs, URL query strings, and SSE events. Do not preserve the legacy JWT-secret-via-UDP bootstrap or the inverted body-hash check in `edge_post_nodeinfo`.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestControlAuth'` proves a correctly signed request passes and bad signature, wrong path/method/digest, stale/future timestamp, duplicate nonce, oversized body, and unknown NodeID fail deterministically.
  - QA scenarios: Happy—each generated Edge key authenticates only its own NodeID. Failure—one Edge's key cannot impersonate another and no error response includes either key. Evidence `.omo/evidence/task-6-supernode-http-only.log`.
  - Commit: Y | `feat: secure Super control requests with HMAC`

- [x] 7. [Ready wave: 2; Depends on: 1; Writes: super_control_events.go, super_control_events_test.go] Build the bounded SSE event hub and replay contract
  - Depends on task 1 because event envelopes use the v2 state revision and event types defined in the shared contract.
  - References (executor has NO interview context - be exhaustive): `main_super.go:476-575` for replaced update-notification semantics; `main_httpserver.go:967-1026` for server ownership; WHATWG SSE `id`, `retry`, `Last-Event-ID`, and comment semantics; Go `Request.Context` and `ResponseController.Flush` documentation.
  - What to do / Must NOT do: Implement a bounded subscriber hub with monotonically increasing IDs, fixed-capacity replay, per-subscriber cancellation, slow-subscriber eviction, 25–30 second comment heartbeats, explicit `retry`, and graceful close support. Do not hold a state lock while writing an event, make arbitrary event payloads the source of truth, or leak goroutines after subscriber cancellation.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestControlEvents'` proves ordered delivery, replay after a known event ID, stale-ID snapshot-required behavior, cancellation cleanup, heartbeat emission, and bounded slow-subscriber behavior.
  - QA scenarios: Happy—reconnect receives only missed state-invalidations in order. Failure—an ID older than replay retention, a blocked client, and service shutdown cannot deadlock publishers or leak subscriber goroutines. Evidence `.omo/evidence/task-7-supernode-http-only.log`.
  - Commit: Y | `feat: add replayable Super control event hub`

- [x] 8. [Ready wave: 3; Depends on: 2, 5; Writes: super_manage_v2.go, super_manage_v2_test.go] Make Super management mutations produce valid v2 state and generated profiles
  - Depends on task 2 because add/update/delete must write the concrete generated v2 config shape; depends on task 5 because mutations must use its locked state and revision publication rather than direct global maps.
  - References (executor has NO interview context - be exhaustive): `main_httpserver.go:528-965` for current management/password/config-write behavior; `main_super.go:254-375` for current peer add/delete; `gencfg/gencfgSM.go:245-297` for generated peer/key behavior; task 2's emitted v2 schema.
  - What to do / Must NOT do: Move peer add/update/delete and Super parameter updates behind typed service methods, regenerate/write only v2 config, rotate/control per-Edge PSKeys safely, update STUN settings, and cause exactly one revision/event publication per successful mutation. Preserve management authentication behavior unless explicitly needed for the v2 schema. Do not retain device-peer creation, Super UDP shutdown packets, or write obsolete UDP fields.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestManageV2'` exercises add, update, delete, and STUN-setting changes in `t.TempDir`, verifies output parses as v2, and asserts revisions/events change once.
  - QA scenarios: Happy—adding a node returns a viable Edge v2 profile with an isolated control PSKey. Failure—duplicate/special NodeID, invalid STUN URI, failed atomic config write, and deletion of an active SSE subscriber leave a valid prior state and do not leak secrets. Evidence `.omo/evidence/task-8-supernode-http-only.log`.
  - Commit: Y | `feat: migrate Super management to control API v2`

- [x] 9. [Ready wave: 4; Depends on: 5, 6, 7, 8; Writes: super_control_http.go, super_control_http_test.go, main_httpserver.go] Serve authenticated Control API v2 snapshots, reports, and SSE without legacy Edge endpoints
  - Depends on task 5 for atomic snapshot/report state, task 6 for request authentication, task 7 for SSE subscription/replay, and task 8 for v2 management route ownership; the HTTP routes cannot compile or be independently tested until all four concrete APIs exist.
  - References (executor has NO interview context - be exhaustive): `main_httpserver.go:151-526,967-1026` for legacy Edge handlers/mux; `main_super.go:476-575` for ServerUpdate behavior replaced by event invalidation; task 5 state API, task 6 HMAC verifier, task 7 event hub, and task 8 management handlers.
  - What to do / Must NOT do: Mount `/edge/v2/register`, `/edge/v2/report`, `/edge/v2/snapshot`, and `/edge/v2/events`; register returns initial snapshot, report updates heartbeat/candidates/pongs, snapshot emits ETag/304, and SSE sets `text/event-stream`, no-buffer headers, initial comment/data flush, replay, and context cancellation. Remove legacy `/edge/*` handlers and ensure the Super-control PSKey is never in output. Retain management routes through task 8. Do not start another HTTP server for SSE or hold state locks across streaming writes.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestControlHTTPV2'` uses `httptest` to validate all routes, conditional ETag behavior, signed registration/report, SSE headers/initial flush/Last-Event-ID replay, and graceful request cancellation.
  - QA scenarios: Happy—an authenticated report alters state, yields an SSE invalidation, then a snapshot fetch returns the matching revision. Failure—unsigned request, cross-Edge impersonation, leaked PSKey in JSON/SSE, invalid JSON/gzip, stale event ID, and cancelled stream each have the defined safe result. Evidence `.omo/evidence/task-9-supernode-http-only.log`.
  - Commit: Y | `feat: serve HTTP-only Super control API v2`

- [x] 10. [Ready wave: 3; Depends on: 3, 4; Writes: device/super_http_runtime.go, device/super_http_runtime_test.go, device/device.go, device/receivesendproc.go, main_edge.go] Replace Edge Super UDP routines with the context-managed HTTP control runtime
  - Depends on task 3 because runtime candidate reports require same-bind STUN discovery, and task 4 because runtime lifecycle delegates all signed register/report/SSE/poll behavior to the tested client.
  - References (executor has NO interview context - be exhaustive): `main_edge.go:114-220` for Super peer creation; `device/device.go:327-425` for background-loop startup; `device/receivesendproc.go:150-161,304-405,835-1031` for Super-directed routines; `device/receive.go:494-604` for packet routing that must preserve Edge behavior.
  - What to do / Must NOT do: Start the HTTP control runtime only after the Edge bind/device is initialized; collect local/STUN candidates, register, apply initial snapshot into peers/graph, periodically report candidates and latency, and stop all control goroutines when the device closes. Remove Super-peer creation, `Send2Super`, `RoutineRegister`, Super-directed Pong, `ServerUpdate` processing, and HTTP download functions that require legacy state hashes. Do not remove Edge↔Edge Ping/Pong, P2P support, regular peer endpoint retry, or normal packet forwarding.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 ./device -run 'TestSuperHTTPRuntime'` demonstrates startup after bind readiness, initial snapshot peer creation, report scheduling, SSE-to-poll fallback, context shutdown, and unchanged Edge↔Edge packet path.
  - QA scenarios: Happy—runtime starts against a fake v2 server, applies a newer snapshot, and connects a discovered Edge peer. Failure—register failure, STUN failure, dropped SSE, stale snapshot, and cancellation neither abort Edge startup unnecessarily nor leave a Super peer/UDP retry loop behind. Evidence `.omo/evidence/task-10-supernode-http-only.log`.
  - Commit: Y | `refactor: move Edge Super control flow to HTTP`

- [x] 11. [Ready wave: 5; Depends on: 9; Writes: main_super.go, main_super_http_test.go] Remove the SuperNode WireGuard/UDP lifecycle and wire in the HTTP control service
  - Depends on task 9 because Super startup must instantiate its completed authenticated HTTP handlers; removing the devices before that output would leave no functional control plane.
  - References (executor has NO interview context - be exhaustive): `main_super.go:70-252` for Device/bind/UAPI lifecycle removal; `main_super.go:377-575` for event/push removal; `main_httpserver.go:967-1026` and task 9 for HTTP server replacement; `main.go:74-92` for preserving `-mode super`.
  - What to do / Must NOT do: Construct the control-state service, event hub, and graceful `http.Server`; validate v2 config; start/stop it on signal; use direct periodic timeout/recalculation ticks rather than synthetic register/pong channel events; remove dummy TAPs, binds, device peers, WireGuard private keys, UAPI, `wg` Super status, and device Wait selects. Keep `-mode super` as the CLI entry point and preserve graph calculation/routing semantics.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestSuperHTTPOnlyStartup|TestSuperGracefulShutdown'` starts an HTTP-only Super with `httptest`-compatible listeners, verifies no UDP bind/device is constructed, and confirms SSE clients are cancelled before shutdown returns.
  - QA scenarios: Happy—Super starts and serves register/snapshot without configured UDP keys/ports. Failure—legacy config, HTTP listener failure, invalid v2 config, and signal-driven shutdown return actionable errors without panic or leaked goroutines. Evidence `.omo/evidence/task-11-supernode-http-only.log`.
  - Commit: Y | `refactor: run SuperNode as HTTP-only control service`

- [x] 12. [Ready wave: 6; Depends on: 2, 9, 11; Writes: README.md, README_zh.md, example_config/super_mode/README.md, example_config/super_mode/README_zh.md] Document the breaking Super v2 operation, security boundary, STUN behavior, and removal of Super UDP status
  - Depends on task 2 for actual generated configuration, task 9 for final endpoint/event behavior, and task 11 for the final HTTP-only runtime/UAPI behavior that documentation must not misstate.
  - References (executor has NO interview context - be exhaustive): `README.md:44-50`; `example_config/super_mode/README.md:4-131,278-399`; task 2 examples; task 9 endpoint contract; task 11 runtime behavior.
  - What to do / Must NOT do: Replace UDP Register/ServerUpdate diagrams and commands with Control API v2 register/report/snapshot/events flow; document reverse-proxy TLS requirement, HMAC control-key handling, SSE/poll fallback, STUN list format and same-socket limitation, failed-hole-punch/relay limitation, and v1 rejection. Do not document PSKeys as safe to share, promises of NAT traversal, or `wg` SuperNode status.
  - Acceptance criteria (agent-executable): run a documentation assertion script or Go test that checks every referenced v2 config key and API path against generated v2 config/registered mux routes; run `go test -race -shuffle=on -count=1 ./...` after docs/example validation.
  - QA scenarios: Happy—documented quick-start generated config starts the HTTP-only test topology. Failure—search-based contract test rejects a stale legacy Super UDP key/path in Super-mode docs/examples. Evidence `.omo/evidence/task-12-supernode-http-only.log`.
  - Commit: Y | `docs: describe HTTP-only Super mode v2`

- [x] 13. [Ready wave: 6; Depends on: 3, 4, 9, 10, 11; Writes: super_http_e2e_test.go] Prove the complete HTTP-only control plane and direct Edge data-plane behavior in one automated topology
  - Depends on tasks 3 and 4 for real same-bind STUN/client behavior, task 9 for server API/SSE, task 10 for Edge runtime hookup, and task 11 for no-UDP Super startup; without those concrete outputs an end-to-end proof cannot run.
  - References (executor has NO interview context - be exhaustive): `conn/bindtest/bindtest.go` for in-memory bind topology; `device/bind_test.go` and `device/p2p_reliability_test.go` for test doubles; task 3 STUN manager; tasks 4/9 Control API; tasks 10/11 lifecycles.
  - What to do / Must NOT do: Build an automated local topology with an HTTP-only Super, two Edges, fake deterministic STUN responses, and controllable clock/network hooks. Assert registration, distinct authenticated identities, candidate exchange, direct peer handshake/traffic, latency report route change, SSE notification, poll recovery after forced SSE loss, and clean shutdown. Do not use wall-clock sleeps, manual terminal input, or assertions on private implementation state alone.
  - Acceptance criteria (agent-executable): `go test -race -shuffle=on -count=1 . -run 'TestHTTPOnlySuperEndToEnd'` passes all observable assertions and leaves no goroutines; then `go test -race -shuffle=on -count=1 ./...` passes repository-wide.
  - QA scenarios: Happy—two Edges exchange normal traffic after HTTP registration and candidate sync while Super never opens a UDP control listener. Failure—invalid HMAC, STUN outage, SSE disconnect, stale revision, and Edge deletion converge safely through polling/shutdown behavior. Evidence `.omo/evidence/task-13-supernode-http-only.log`.
  - Commit: Y | `test: cover HTTP-only Super mode end to end`

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [x] F1. [Parallel final batch; Writes: none] Audit every implementation task against this plan's v2 contracts, wave dependencies, worktree write ownership, TDD evidence, and must-not-have constraints
  - Verify: inspect task evidence plus `git diff`/worktree history; reject absent same-bind STUN proof, any UDP Super listener, any exposed control PSKey, or any mutation of the preserved dirty worktree. Evidence `.omo/evidence/final-supernode-http-only-plan.log`.
- [x] F2. [Parallel final batch; Writes: none] Run strict Go quality gates and review concurrency, HTTP boundary, SSE cancellation, and secret-handling correctness
  - Verify: `go vet ./...`, `go test -race -shuffle=on -count=1 ./...`, `make`, and `make vpp` where VPP/libmemif is available; inspect errors, race output, and dependency diff. Evidence `.omo/evidence/final-supernode-http-only-quality.log`.
- [x] F3. [Parallel final batch; Writes: none] Execute the HTTP-only two-Edge integration topology and retain its observable protocol transcript
  - Verify: run `go test -race -shuffle=on -count=1 . -run 'TestHTTPOnlySuperEndToEnd'`; assert no Super UDP control bind, valid STUN candidates, direct Edge traffic, SSE invalidation, polling recovery, deletion, and clean shutdown. Evidence `.omo/evidence/final-supernode-http-only-e2e.log`.
- [x] F4. [Parallel final batch; Writes: none] Audit scope fidelity and configuration/documentation migration completeness
  - Verify: compare generated Super/Edge v2 yaml and both language docs against the v2 schema/routes; reject legacy UDP Super keys, stale Register/ServerUpdate guidance, unapproved TURN/relay additions, and changes to Edge data-plane packet behavior. Evidence `.omo/evidence/final-supernode-http-only-scope.log`.

## Commit strategy
- One atomic commit per completed todo, always pairing code with its direct tests and keeping each worktree's owned path set isolated.
- Merge commits follow the dependency order: 1; then 2/3/4/5/7; then 6/8/10; then 9; then 11; then 12/13. Rebase each worktree on its recorded prerequisite integration commit before merging.
- Before creating any commit, run the git-master style-detection workflow in that worktree and use the detected repository message style; do not stage unrelated dirty source-tree files.
- Keep `go.mod` and `go.sum` only with task 3 because `pion/stun/v3` and its tests are inseparable.

## Success criteria
- A v2 Super config starts `-mode super` without UDP/WireGuard keys, a Super UDP listener, dummy TAP, or UAPI; a v1 Super config is rejected with a migration error.
- An Edge can authenticate its own signed register/report requests, but cannot impersonate another Edge; no control PSKey appears in HTTP/SSE payloads, URLs, errors, logs, examples, or generated peer snapshots.
- STUN binding requests and responses share the Edge's actual WireGuard UDP bind; magic-cookie/transaction dispatch prevents STUN responses from entering WireGuard handshake handling; all STUN failure still leaves local candidates and never invents external endpoints.
- SSE resumes from `Last-Event-ID` when replay exists, signals resync when it does not, and polling converges state after stream loss; a snapshot ETag yields 304 when unchanged.
- Edge↔Edge WireGuard normal traffic and routing continue to work without any Super UDP control transport.
- All task evidence exists, the final parallel verification batch approves, and the preserved dirty source worktree remains unmodified by this migration work.
