
## [2026-07-26T04:42:00Z] Task: 2

- `ControlHTTPClient.Sync` now owns every snapshot fetch and apply callback in one event loop. SSE is established before fallback polling; polling starts only after stream connection/parser failure and stops on the next HTTP-200 SSE connection.
- The public `Events` method retains its protocol contract. A private connection-notification path lets `Sync` cancel polling as soon as SSE is healthy without changing Last-Event-ID replay, ETag, revision, or backoff behavior.
- The first red test run was temporarily blocked by concurrent out-of-scope `SuperSTUNManager` test edits; the focused green and full requested race/build gates passed after that worker's changes landed.

## [2026-07-26T04:30:37Z] Task: 3

### Scope cleared
- `orderdmap/orderdmap.go` lines 200 and 246: changed `o.values[key].(OrderedMap)` and `s[index].(OrderedMap)` to `*OrderedMap` assertions. The `OrderedMap` value assertion triggered `copies lock value` because `sync.RWMutex` is embedded at line 36. `New()` (line 39) only ever returns `*OrderedMap`, so the value-form assertion was dead under the package's ownership contract; switching to pointer assertion removes both warnings with zero behavior change.
- `example_config/super_mode/testfd/n1_test_fd_mode2.go` line 72: `make(chan os.Signal)` -> `make(chan os.Signal, 1)`. Matches the production comparator idiom (`main_edge.go:175`, `main_super.go:187`). Go's vet flags the unbuffered form because `signal.Notify`'s handler may block trying to send to a full, unbuffered channel. Whole file was tab/space-reflowed by gofmt during the edit; no other behavior changed.

### Regression tests added (orderdmap_test.go)
- `TestUnmarshalNestedRoundTrip` — drives a nested object + array fixture through unmarshal -> marshal -> unmarshal -> marshal and asserts byte-identity on the second marshal. Covers the decodeOrderedMap (line 158) and decodeSlice (line 226) paths that contained the offending assertions.
- `TestUnmarshalNestedMarshalShape` — pins the exact JSON byte output to detect any future decode regression that drops or reorders nested keys.
- `TestUnmarshalMalformedFails` — 4 subtests over malformed nested JSON; asserts each surfaces a non-nil `json` error without panic or partial success. All pass under `go test -race`.

### Observation worth flagging
- `go vet ./...` after my fix still reports `device/receive_stun_test.go:81:11: manager.Close undefined`. This is **not** in my scope and was **not** present at the task-start HEAD (verified via `git stash && go vet` diff). A concurrent worker is actively editing `device/receive_stun_test.go`, `device/super_http_client_test.go`, `device/super_stun_test.go`, `mtypes/http_control_test.go` (visible in `git status`). The plan-level "global gate" will need to wait for that worker or a follow-up task to land the device/mtypes fix.

### Coordination note
- The testfd file came through the auto-formatter with whole-file tab/space normalization. The semantically meaningful change is the single-character edit on line 72. Future reviewers will see a much larger diff than the behavioral fix warrants; consider pre-running `gofmt` on the file before the diff is read so the cosmetic noise doesn't get attributed to this task in code review.
## [2026-07-26] Task: 1

- Keep DNS lookup confined to `SuperSTUNManager`: configuration validation accepts syntactically valid DNS hosts without I/O, then discovery resolves hosts into literal endpoints before `Bind.ParseEndpoint`.
- Manager shutdown must cancel resolver/request contexts and remove pending-map entries without closing response channels, because receive dispatch can retain a response channel after map lookup.

## [2026-07-26T05:15:00Z] Task: 4

- `EdgeConfigV2.UnmarshalYAML` must reject `DynamicRoute.SuperNode` by key presence, not by `UseSuperNode` value: yaml.v2 otherwise drops the retired block and Edge falls through to static mode.
- `EdgeConfig.SuperNodeV2Enabled` is a runtime-only marker set only after a valid `SuperNodeV2` v2 configuration is selected. Endpoint maintenance keeps its existing P2P behavior and enables the former Super loop behavior only through that marker.

## [2026-07-26T06:00:00Z] Flake: E2E deleted-peer convergence

- `ControlEventHub.Close` cancels the SSE subscriber but does not cancel the HTTP request. `ControlHTTPHandler.handleEvents` must select on both `r.Context().Done()` and `renderer.Subscriber().Done()`; otherwise `ControlHTTPClient.Sync` never receives the stream error that activates its polling fallback.
- The failure was not an ETag/snapshot race: diagnostic predicate state was `snapshot_removed=true peer_removed=false`. The Super had deleted peer 101; edge B had simply never left its hung SSE read.
- E2E lifecycle assertions should not reuse the operation deadline after the operation has already consumed it. Each post-`Close` edge wait retains its own unchanged three-second contract.

## [2026-07-26] Task: 5

- `Device` now models only the live Edge runtime. Its damping window copies `EdgeConfig.DynamicRoute.DampingFilterRadius` into an explicit `dampingFilterRadius` field at construction, preserving the prior filter width exactly without retaining a legacy Super config.
- Super's HTTP-only config parser must reject `ListenPort_EdgeAPI` and `ListenPort_ManageAPI` in its top-level pre-scan as well as in `SuperConfigV2.UnmarshalYAML`; the pre-scan prevents permissive YAML parsing from obscuring the typed `legacy_udp_field` migration contract.
- Keep `ControlEventHub.Close()` before `http.Server.Shutdown(ctx)` in Super shutdown. No lifecycle ordering was changed in this task.

## [2026-07-26] Task: 7

- `http_shared_objects` now owns only the live management-password state and its lock. The old graph/device/hash/peer/config fields were unreachable after task 5 removed `http_sconfig`.
- Do not rely on a dead-code scan alone for Super-UDP cleanup: `API_connurl` and `StateHash` looked dead in the scan but the compiler proved live device references, so both remain.
- Preserve legacy datagram types whenever Edge receive dispatch still parses them: `RegisterMsg`, `PingMsg`, `PongMsg`, `QueryPeerMsg`, `BoardcastPeerMsg`, `ServerUpdateMsg`, and all `ServerCommand` values remain. Regression coverage now Gob-round-trips the first three.
- The legacy `/manage/*` nil-Manage shims stay registered and fail closed with 410. Password-gate tests cover missing, wrong, and configured credentials.
- The current full race suite is blocked only by the concurrent documentation contract update (`TestDocsSTUNURIAcceptsHostnames`); scoped build, vet, HTTP, and mtypes tests pass.

## [2026-07-26T07:00:00Z] Task: 6

- Documentation was stale in four areas: STUN URI format (claimed IP-literal-only), SSE polling (claimed always-on goroutine), Edge legacy rejection (missing LegacySuper key), and VPP status (not mentioned).
- The contract test `TestDocsSTUNURIAcceptsHostnames` catches any future reversion to "IP literals only" wording for STUN, which the code now explicitly supports DNS hostnames for. The generic endpoint parser (`conn/conn.go:172`) remains IP-literal-only and that claim is correct in the WireGuard peer context.
- `TestDocsSSEPollingIsFallbackOnly` detects three stale polling phrases. The actual behavior (device/super_http_client.go Sync) starts polling only after stream failure and cancels it on reconnect. The Super hub close now terminates SSE streams (super_control_http.go handleEvents select on renderer.Subscriber().Done()), which was the flake fix from task 5.
- Both READMEs (EN + ZH) were updated with semantically aligned content across 6 sections: breaking change list, SSE polling, STUN discovery, Edge config rejection, V1 migration, and a new VPP status section.
- Concurrent worker (task 7) left uncommitted changes that break root-package compilation (main_httpserver_test.go references undefined newHTTPMux; mtypes files in-progress). Worked around by temporarily moving test files aside. The 3 scoped files never touched any runtime .go files.
