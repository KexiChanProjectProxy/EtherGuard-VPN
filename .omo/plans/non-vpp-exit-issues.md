# non-vpp-exit-issues - Work Plan

## TL;DR (For humans)
**What you'll get:** The remaining HTTP-only migration debt will be resolved without touching VPP: hostname-capable STUN discovery, deterministic teardown, true SSE fallback polling, retired legacy Super configuration types, and removal of proven UDP-era dead code.

**Why this approach:** The live Edge runtime—not the HTTP-only Super—still carries the old configuration types, so retirement is staged behind behavior-preserving Edge migration. Network lifecycle changes stay local to STUN and SSE instead of broadening generic WireGuard endpoint rules.

**What it will NOT do:** It will not build, test, remove, or alter VPP. It will not remove the registered 410 Manage API shims, renumber Gob-encoded commands, add TURN/relay support, or create periodic STUN refresh.

**Effort:** XL
**Risk:** High — this removes public legacy configuration structs and touches concurrent Edge lifecycle paths.
**Decisions to sanity-check:** Legacy `SuperConfig` and `SuperInfo` compatibility ends now; all work is TDD; DNS is resolved only inside the STUN manager; VPP remains deliberately unvalidated.

Your next move: start a worker session with `/start-work`. Full execution detail follows below.

## Scope
### Must have
- Accept syntactically valid STUN/STUNS DNS hostnames at the configuration boundary, resolve them with a cancellable, testable STUN-specific resolver before the IP-only bind parser, and accept both RFC URI forms: `stun:host:port` and `stun://host:port`.
- Give `SuperSTUNManager` a race-safe close contract that rejects new work, wakes in-flight discovery, and is invoked from `Device.Close` without closing response channels or mutating the manager pointer.
- Replace always-on snapshot polling with a single serialized `Sync` state machine: poll only after SSE fails, stop polling as soon as an SSE stream is healthy, and keep SSE-triggered and poll-triggered application mutually exclusive.
- Remove both legacy configuration types and their active device/config/generator/test/fixture dependencies; preserve static and P2P semantics and fail fast rather than silently discarding retired Super UDP configuration.
- Delete only proven-unreachable Super UDP remnants and correct all three documented non-VPP vet findings.
- Preserve and re-verify the already-correct register-time STUN candidate labels and SSE shutdown order.
### Must NOT have (guardrails, anti-slop, scope boundaries)
- Do not touch VPP source, tags, Makefile targets, CI build variants, libmemif setup, or `make vpp`; record the handover’s unvalidated VPP gate as residual excluded risk.
- Do not relax generic `conn.parseEndpoint` hostname policy; DNS resolution belongs exclusively to STUN discovery.
- Do not add DNS cache/retry policy, TURN/relay support, periodic STUN refresh, or unrelated CI/Makefile modernization.
- Do not remove or reroute the five registered 410-Gone `/manage/*` shims, alter live Ping/Pong/Register protocol types, or renumber/remove `ServerCommand` Gob values.

## Verification strategy
> Zero human intervention - all verification is agent-executed.
- Test decision: TDD using Go’s standard `testing` package. Each task captures the named focused test failing before implementation, then records the passing focused test and its affected package race test.
- Evidence: `.omo/evidence/task-<N>-non-vpp-exit-issues.log` for each implementation task and `.omo/evidence/final-<N>-non-vpp-exit-issues.log` for final verifiers.
- Global non-VPP gates (run after integration and in F2):
  - `go build ./... && go vet ./...`
  - `go test -race -shuffle=on -count=1 -timeout 900s ./...`
  - `go test -race -count=1 . -run 'TestHTTPOnlySuperEndToEnd'`
- The current `go vet ./...` warnings are intentional red-phase evidence for task 3; completion requires a zero-warning exit, not an accepted baseline.

## Execution strategy
### Parallel execution waves
Wave 1 starts all independent fixes: STUN lifecycle (1), SSE fallback state machine (2), and vet debt (3). Task 4 follows task 1’s exclusive `mtypes/http_control.go` handoff. Task 5 follows tasks 1 and 4 because it takes exclusive ownership of the already-modified `device/device.go` and consumes the new Edge-mode marker. Once task 5 completes, documentation integration (6) and corpse cleanup (7) are independently ready and can run concurrently.

### Dependency matrix
| Todo | Depends on | Blocks | Can parallelize with |
| --- | --- | --- | --- |
| 1 | none | 4, 5, 6 | 2, 3 |
| 2 | none | 6 | 1, 3 |
| 3 | none | none | 1, 2 |
| 4 | 1 | 5, 6 | none |
| 5 | 1, 4 | 6, 7 | none |
| 6 | 1, 2, 4, 5 | final verification | 7 |
| 7 | 5 | final verification | 6 |

Cross-wave reasons:
- **1 → 4 exclusive-write handoff:** task 1 owns `mtypes/http_control.go` to correct STUN validation; task 4 subsequently removes `EdgeConfigV2.LegacySuper` in that same file without a concurrent edit conflict.
- **1 → 5 exclusive-write handoff:** task 1 owns `device/device.go` to wire manager shutdown; task 5 subsequently removes its legacy SuperConfig path without a concurrent edit conflict.
- **4 → 5 concrete-output and exclusive-write handoff:** task 5 consumes task 4’s replacement Edge mode marker and takes the next exclusive change to `mtypes/config.go` / Edge configuration flow.
- **1, 2, 4, 5 → 6 concrete-output dependencies:** task 6 documents the completed STUN syntax, fallback polling, and exact v1 migration/rejection behavior; it must not document provisional contracts.
- **5 → 7 concrete-output dependency:** `SUPER_Events`, legacy config-backed http fields, and dependent protocol remnants are deletable only once task 5 has removed their final device references.

## Todos
> Implementation + Test = ONE todo. Never separate.
<!-- APPEND TASK BATCHES BELOW THIS LINE WITH edit/apply_patch - never rewrite the headers above. -->
- [x] 1. [Ready wave: 1; Depends on: none; Writes: mtypes/http_control.go, mtypes/http_control_test.go, device/super_stun.go, device/super_stun_test.go, device/receive_stun_test.go, device/device.go] Make DNS STUN discovery and manager shutdown race-safe without widening generic endpoint parsing
  - What to do / Must NOT do: Change `ValidateSTUNURI` to validate both `stun:` and `stun://` syntaxes with a required syntactically valid host and explicit valid port, but perform no DNS I/O. Replace single-address STUN URI handling with a context-aware, injectable resolver seam in `SuperSTUNManager`; attempt resolved literal addresses under the configured per-server timeout before reaching `Bind.ParseEndpoint`. Add a manager `Close` state/done signal protected by its mutex; make `Discover`/requests exit on manager close or caller cancellation; invoke it from `Device.Close` after control cancellation. Never close a pending response channel and never nil `device.superSTUN`, because `HandlePacket` can retain a channel after its map lookup and the receive loop reads the pointer concurrently. Do not modify `conn/conn.go`.
  - References (executor has NO interview context - be exhaustive): `mtypes/http_control.go:636-671` validator; `mtypes/http_control.go:548-551,353-355` callers; `device/super_stun.go:19-137` manager/request/packet/URI flow; `conn/conn.go:172-200` IP-only endpoint boundary; `device/device.go:612-643` close order; `device/super_http_runtime.go:146-164` sole manager caller; `device/receive.go:130` receive dispatch; `mtypes/http_control_test.go:236-279`; `device/super_stun_test.go`; `device/receive_stun_test.go`.
  - Acceptance criteria (agent-executable): focused tests prove a hostname and `stun://host:port` validate; malformed/empty host, missing port, unsupported scheme, invalid port, and malformed authority still return the typed invalid-STUN error; a fake resolver yields literal endpoints consumed by the existing fake bind; literal URIs bypass resolver; resolver/context cancellation and `Close` during an in-flight request return promptly; packet delivery after `Close` does not panic or consume stale work. `go test -race ./mtypes ./device -run 'Test(ControlV2Parameters|SuperConfigV2|SuperSTUN|ReceiveDemultiplexesSTUN)'` passes.
  - QA scenarios (name the exact tool + invocation): happy — run the focused command above and record DNS-to-literal candidate plus clean close in `.omo/evidence/task-1-non-vpp-exit-issues.log`; failure — inject resolver error/timeout and malformed URI cases, assert no candidate and no pending-map leak under `-race`, in the same evidence log.
  - Commit: Y | `fix(stun): support hostname discovery and deterministic shutdown`

- [x] 2. [Ready wave: 1; Depends on: none; Writes: device/super_http_client.go, device/super_http_client_test.go, device/super_http_runtime_test.go] Implement a serialized SSE-first synchronization state machine with polling only during stream failure
  - What to do / Must NOT do: Replace `Sync` plus its permanently launched `pollLoop` topology with one owner of every `Snapshot` and apply callback. Establish SSE first; only enable timed snapshot polling after a connection/parse failure; cancel it immediately on a healthy reconnection; retain bounded backoff, ETag semantics, monotonic revision filtering, Last-Event-ID replay, and context shutdown. Update the `Sync`/polling comments to say fallback-only. Do not add periodic STUN refresh or change server event semantics.
  - References (executor has NO interview context - be exhaustive): `device/super_http_client.go:341-441` current unconditional poll topology; `device/super_http_client.go:281-303,314-322,187-195` SSE/replay contracts; `device/super_http_client.go:99-133` conditional snapshot semantics; `device/super_http_runtime.go:132-144` downstream application lock; `device/super_http_client_test.go:463-561,563+`; `device/super_http_runtime_test.go:57-105`; `.omo/notepads/supernode-http-only/HANDOVER.md:33-35` required protocol behavior.
  - Acceptance criteria (agent-executable): tests count HTTP snapshot requests and prove there are no timer polls while an SSE stream remains healthy beyond the initial/event-driven fetches; a dropped/failed stream enables polling; reconnect cancels polling; concurrent event/tick paths cannot invoke apply concurrently; stale revisions, 304, replay ID, backoff, and cancellation tests still pass. `go test -race ./device -run 'Test(ControlHTTPClient|SuperHTTPRuntime)'` passes.
  - QA scenarios (name the exact tool + invocation): happy — hold a healthy SSE stream and assert no interval request, then force a drop and assert snapshot progress followed by polling stop after reconnect; failure — return repeated 503/malformed SSE and assert bounded reconnect plus cancellation without goroutine leak. Save both traces in `.omo/evidence/task-2-non-vpp-exit-issues.log`.
  - Commit: Y | `fix(control): poll snapshots only while SSE is unavailable`

- [x] 3. [Ready wave: 1; Depends on: none; Writes: orderdmap/orderdmap.go, orderdmap/orderdmap_test.go, example_config/super_mode/testfd/n1_test_fd_mode2.go] Clear the documented non-VPP vet debt without copying locks or using an unsafe signal channel
  - What to do / Must NOT do: Replace lock-copying `OrderedMap` value assertions in JSON nested-map decode with pointer-safe handling consistent with `orderedmap.New()` ownership; add a regression round-trip for nested objects/arrays preserving order and values. Buffer the testfd signal channel exactly as production entry points already do. Do not refactor unrelated `OrderedMap` locking behavior or change VPP code.
  - References (executor has NO interview context - be exhaustive): `orderdmap/orderdmap.go:32-45,140-265`; specific value assertions `:200-205,246-251`; `example_config/super_mode/testfd/n1_test_fd_mode2.go:57-76`; safe comparator examples `main_edge.go:174-176`, `main_super.go:186-189`; handover baseline statement `.omo/notepads/supernode-http-only/HANDOVER.md:63-66`.
  - Acceptance criteria (agent-executable): new ordered-map regression locks the expected nested JSON order/value behavior; `go test -race ./orderdmap`; `go vet ./...` exits zero and no longer reports either lock-copy or signal-channel diagnostic.
  - QA scenarios (name the exact tool + invocation): happy — marshal/unmarshal nested map-and-array fixtures then compare ordered output in `go test -race ./orderdmap`; failure — exercise malformed nested JSON and assert decode errors without partial success. Store vet and test output in `.omo/evidence/task-3-non-vpp-exit-issues.log`.
  - Commit: Y | `fix(vet): avoid ordered-map lock copies and buffer signals`

- [x] 4. [Ready wave: 2; Depends on: 1; Writes: mtypes/config.go, mtypes/http_control.go, mtypes/http_control_test.go, main_edge.go, main_edge_endpoint_test.go, device/receivesendproc.go, gencfg/example_conf.go, gencfg/gencfgNM.go, gencfg regression tests, super_http_e2e_support_test.go, all checked-in static/P2P Edge YAML fixtures and super_mode/testfd/n1_fd.yaml] Retire `SuperInfo` and migrate Edge mode selection to an explicit v2-safe runtime marker
  - Concrete consumed output: task 1 exclusively hands off `mtypes/http_control.go` after finalizing STUN validation; this task must apply its `EdgeConfigV2.LegacySuper` deletion on that completed file to avoid a symmetric write conflict.
  - What to do / Must NOT do: Remove `DynamicRouteInfo.SuperNode` and `EdgeConfigV2.LegacySuper`, replace all live `UseSuperNode` guards with a dedicated non-legacy Edge runtime marker derived from valid `SuperNodeV2` presence, and preserve the exact static/P2P gating behavior in endpoint retry/ping loops. Update generation, examples, E2E fixtures, and direct test constructors. Add strict pre-scan/error handling so a legacy Super edge block is rejected with the established typed legacy-field contract rather than silently becoming static mode; decide and test the same rejection for `UseSuperNode:false`, then remove obsolete blocks from all checked-in static/P2P/testfd YAML. Do not edit public documentation in this task; task 6 owns final documentation after the behavior is complete.
  - References (executor has NO interview context - be exhaustive): `mtypes/config.go:147-183`; `mtypes/http_control.go:584-612`; `main_edge.go:40-56,123-140`; `device/receivesendproc.go:446,497,512`; `gencfg/example_conf.go:65-74,116-118,161-200`; `gencfg/gencfgNM.go:202,237-242`; `super_http_e2e_support_test.go:344-361`; `device/peer_endpoint_lock_test.go:44`; all fixtures named in Writes; `.omo/notepads/supernode-http-only/HANDOVER.md:19-22`.
  - Acceptance criteria (agent-executable): no Go reference to `mtypes.SuperInfo` remains; a v2 edge config enables only Super-mode behavior; static/P2P configs retain their former loop behavior; every retired `DynamicRoute.SuperNode` input fails explicitly instead of falling through; generator/example and E2E fixtures compile and validate. `go test -race -shuffle=on -count=1 ./mtypes ./gencfg ./device . -run 'Test(HTTPOnly|Edge|ControlV2|SuperConfigV2)'` passes.
  - QA scenarios (name the exact tool + invocation): happy — parse/generate representative v2, static, and P2P fixtures and execute the focused race suite; failure — feed old edge Super blocks with both true/false enable flags and assert the exact typed rejection. Capture in `.omo/evidence/task-4-non-vpp-exit-issues.log`.
  - Commit: Y | `refactor(config): remove legacy edge super configuration`

- [x] 5. [Ready wave: 3; Depends on: 1, 4; Writes: device/device.go, device/peer.go, device/receivesendproc.go, device/uapi.go, affected device regression tests, main_edge.go, main_httpserver.go, main_super.go, main_super_http_test.go, mtypes/config.go, mtypes/http_control.go] Remove `SuperConfig` and the obsolete in-device Super-node construction path while retaining Edge behavior
  - Concrete consumed output: task 1 exclusively handed off `device/device.go` after adding manager shutdown; task 4 supplies the replacement Edge mode marker and removes `SuperInfo` consumers. This task cannot safely remove the shared legacy constructor/config fields before both outputs exist.
  - What to do / Must NOT do: Simplify `NewDevice` and `Device` to the Edge-only construction actually used by `main_edge.go`; remove `IsSuperNode`, `SuperConfig`, super-only channels/paths, `LookupPeerIDAtConfig`’s obsolete Super branch, and legacy `SuperConfig` reads such as damping/reset/peer lookup. Rehome the live Edge damping value to an explicit non-legacy Device/Edge field so `device/peer.go` behavior stays identical. Remove `mtypes.SuperConfig` only after all readers, test helpers, HTTP-object fields, and parser checks are migrated; extend the Super legacy-field pre-scan to reject `ListenPort_EdgeAPI` and `ListenPort_ManageAPI` as documentation promises. Keep the HTTP-only Super runtime on `SuperConfigV2`, preserve the existing `hub.Close`-before-shutdown code, and do not modify VPP selection.
  - References (executor has NO interview context - be exhaustive): `device/device.go:29-135,332-460,612-643`; `device/peer.go:170`; `device/receivesendproc.go:570-571`; `device/uapi.go:284`; `main_edge.go:136-140`; `main_super.go:65-96,581-626`; `main_httpserver.go:23-49`; `mtypes/config.go:47-73`; `mtypes/http_control.go:497-580`; `main_super_http_test.go:358+`; `super_http_e2e_support_test.go:358-361`; `.omo/notepads/supernode-http-only/HANDOVER.md:19-22`; `example_config/super_mode/README.md` V1 migration section.
  - Acceptance criteria (agent-executable): `grep -rn 'mtypes\.SuperConfig\|SuperConfigPath\|IsSuperNode' --include='*.go' .` finds no retired production/type reference (allow only any deliberately documented migration text); HTTP-only Super accepts v2 and rejects every documented legacy field including both listener names; Edge damping and UAPI public-key handling retain expected behavior. `go test -race -shuffle=on -count=1 ./device ./mtypes ./gencfg .` passes.
  - QA scenarios (name the exact tool + invocation): happy — run the package race suite plus `go test -race -count=1 . -run 'Test(SuperRejectsLegacyV1Config|HTTPOnlySuperEndToEnd)'`; failure — create configs with each retired listener key and assert typed `legacy_udp_field`, then run targeted device tests for damping and UAPI lookup. Record in `.omo/evidence/task-5-non-vpp-exit-issues.log`.
  - Commit: Y | `refactor(super): remove legacy super config runtime`

- [x] 6. [Ready wave: 4; Depends on: 1, 2, 4, 5; Writes: example_config/super_mode/README.md, example_config/super_mode/README_zh.md, docs_contract_test.go] Synchronize public HTTP-only Super documentation with completed non-VPP behavior
  - Concrete consumed output: tasks 1, 2, 4, and 5 respectively supply the implemented STUN syntax/resolution contract, fallback-only polling contract, Edge legacy-block rejection, and Super legacy-key rejection; documentation must reflect those concrete outcomes rather than an interim design.
  - What to do / Must NOT do: Update the English and Chinese Super-mode READMEs and documentation contract test to state both supported STUN URI forms and runtime-only DNS resolution, fallback-only polling, the precise rejected v1 Super and Edge fields, and the unchanged one-shot STUN refresh behavior. Explicitly record that VPP remains excluded/unvalidated. Do not alter examples to depend on public third-party STUN DNS availability, claim generic endpoint hostname support, or change runtime files.
  - References (executor has NO interview context - be exhaustive): `example_config/super_mode/README.md` sections “SSE with polling fallback”, “STUN candidate discovery”, “V1 config migration”, and “EdgeNode Config Parameter”; `example_config/super_mode/README_zh.md` corresponding sections; `mtypes/http_control.go` final validator; `device/super_stun.go` final resolver path; `device/super_http_client.go` final Sync contract; `main_edge.go` final legacy edge rejection; `main_super.go:581-626` final Super pre-scan; `docs_contract_test.go`; `.omo/notepads/supernode-http-only/HANDOVER.md:12-17`.
  - Acceptance criteria (agent-executable): documentation contract tests assert no stale “IP literals only” or “always-on dedicated polling goroutine” claim, enumerate the actual rejected legacy listener fields, and state VPP is excluded; `go test -race -count=1 . -run 'TestDocs'` passes.
  - QA scenarios (name the exact tool + invocation): happy — run documentation contract tests and compare each public statement to its final source contract; failure — make a temporary stale wording change and assert the contract test rejects it. Save evidence to `.omo/evidence/task-6-non-vpp-exit-issues.log`.
  - Commit: Y | `docs(super): document final HTTP-only migration behavior`

- [x] 7. [Ready wave: 4; Depends on: 5; Writes: main_httpserver.go, main_httpserver_test.go, mtypes/config.go, mtypes/metamessage.go, affected mtypes regression tests] Delete only unreachable Super UDP corpses after legacy device references are gone
  - Concrete consumed output: task 5 removes the final `SUPER_Events`, `SuperConfig`, and device-backed HTTP-object references; only then can this task prove and delete their dependent types without creating temporary compile failures.
  - What to do / Must NOT do: Reduce `http_shared_objects` to its live `http_passwords` state and lock, delete its unreferenced fields and dependent local structs, then remove only now-unreferenced legacy API types/parsers (`SUPER_Events`, API peer-info/super-params corpses, and other proven dead symbols). Remove stale blank-import keepers and comments that claim 410 handlers mutate `httpobj`; clean imports. Preserve `httpobj.http_passwords`, `manageAuthOK`, `manageHandler`, every 410 shim and route registration, live `PingMsg`/`PongMsg`/`RegisterMsg`, all `ServerCommand` numeric values, and `ServerUpdateMsg` unless a direct current-reference proof requires otherwise.
  - References (executor has NO interview context - be exhaustive): `main_httpserver.go:1-160,300-323`; `main_httpserver.go:161-190`; `mtypes/metamessage.go:55-103,105-203`; `mtypes/config.go:241-261`; `main_super.go:632-645`; `device/receivesendproc.go:150-176`; `path/path.go:174,183,527,550`; `.omo/notepads/supernode-http-only/HANDOVER.md:65-66`; `docs_contract_test.go`.
  - Acceptance criteria (agent-executable): a targeted handler test proves each legacy route remains registered and returns 410 when `manage == nil`; password-backed ManageV2 behavior remains intact; no deleted type/symbol has a live reference; `go build ./...`, `go vet ./...`, and `go test -race -shuffle=on -count=1 ./...` pass.
  - QA scenarios (name the exact tool + invocation): happy — run handler/contract tests plus full race suite and inspect retained route responses; failure — assert the 410 path stays fail-closed for missing/wrong legacy credentials and that the cleanup has not removed a live Ping/Pong/Register serialization path. Save evidence to `.omo/evidence/task-7-non-vpp-exit-issues.log`.
  - Commit: Y | `refactor(http): remove unreachable super udp remnants`

## Final verification wave
> Runs in parallel after ALL todos. ALL must APPROVE. Surface results and wait for the user's explicit okay before declaring complete.
- [x] F1. [Parallel final batch; Writes: none] Audit implemented files against this plan’s non-VPP scope, exact dependency handoffs, and retained-compatibility guardrails
  - Verify no VPP path was changed; compare changes with Scope Must NOT Have; confirm `ServerCommand` values, 410 shims, generic `conn.parseEndpoint`, periodic STUN refresh, candidate-label mapping, and hub-before-server shutdown order were preserved. Evidence: `.omo/evidence/final-1-non-vpp-exit-issues.log`.
- [x] F2. [Parallel final batch; Writes: none] Run the full non-VPP compile, vet, race, and HTTP-only E2E quality gates
  - Run the three commands under Verification strategy verbatim; capture exit codes and summaries, requiring zero `go vet` diagnostics. Evidence: `.omo/evidence/final-2-non-vpp-exit-issues.log`.
- [x] F3. [Parallel final batch; Writes: none] Exercise end-to-end failure and lifecycle behavior for STUN, SSE fallback, legacy config rejection, and graceful Super shutdown
  - Run the targeted tests named in todos 1, 2, 4, and 5 plus `TestSuperGracefulShutdown` and direct register candidate-source coverage; confirm all failure paths fail closed and cancellation terminates. Evidence: `.omo/evidence/final-3-non-vpp-exit-issues.log`.
- [x] F4. [Parallel final batch; Writes: none] Independently review public configuration and documentation migration fidelity
  - Parse all checked-in static, P2P, and v2 Super fixtures; compare English/Chinese Super docs against runtime contracts for DNS STUN, fallback-only polling, and explicit legacy rejection; confirm excluded VPP validation remains an openly recorded residual risk. Evidence: `.omo/evidence/final-4-non-vpp-exit-issues.log`.

## Commit strategy
- One atomic commit per completed implementation todo, in numeric order after its stated dependencies are merged.
- Do not mix generated evidence, test logs, unrelated formatting, or VPP edits into implementation commits.
- Final verification is read-only and produces evidence only; it creates no product commit.

## Success criteria
- `mtypes.SuperConfig` and `mtypes.SuperInfo` are absent from compiled Go code; all former config inputs either map to v2 behavior or fail with an explicit typed legacy-field error.
- DNS STUN URIs validate in both supported syntax forms, resolve within cancellation/timeout bounds only inside STUN discovery, and cannot panic during Device shutdown under the race detector.
- Healthy SSE streams produce no timer polls; failed streams poll until reconnect; no snapshot apply callback executes concurrently.
- Only unreachable UDP-era structures are gone; required HTTP management compatibility and wire numeric stability remain observable.
- `go vet ./...` is clean and all three non-VPP golden gates pass.
- Candidate source labels and SSE shutdown ordering remain green under their existing regression tests.
