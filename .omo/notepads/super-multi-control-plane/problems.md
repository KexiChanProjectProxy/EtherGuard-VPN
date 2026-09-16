# Problems — super-multi-control-plane

Unresolved blockers and technical debt discovered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## 2026-09-16 — Pre-existing device test failure (baseline, not our scope)

- `go test -race ./device` consistently FAILS (not flaky, reproduced 3x): `TestSuperHTTPRuntimeListenPortBootstrapWrongKeyRefusesAndLeavesNoListener` reports "wrong-key bootstrap leaked 3 goroutines".
- This is in the user's pre-existing baseline commit (0050fe2), not introduced by this plan's todos 1-6.
- Todos 17/18 heavily modify `device/super_http_client.go` and `device/super_http_runtime.go` — RE-CHECK this test after Wave 4 lands. If still failing, it must be fixed before the plan's Success Criteria (`go test -race ./...` exit 0) and Final Wave F1/F3 can pass, since it's a hard gate.
- Action for orchestrator: track separately; do not let it block Wave 2/3 (isolated to ./device package tests, unrelated to root-package cluster work).

## 2026-09-16 — Pre-existing data race: graphpath.IG concurrent RecalculateNhTable/UpdateLatency

- CONFIRMED pre-existing (verified against commit 524a1ea, BEFORE our baseline commit 0050fe2): `ControlState.Report()` called `s.graph.UpdateLatency(...)` while holding `s.mu`, but `superRuntime.runTicker()` calls `r.graph.RecalculateNhTable(false)` with NO lock at all. `graphpath.IG`'s `edgelock *sync.RWMutex` only protects `Vert`/`edges` fields (see `RemoveVirt`), NOT `dlTable`/`nhTable`/`recalculateTime`/`changed` which `RecalculateNhTable` reads/writes unprotected. `ControlState.mu` was never shared with the ticker's call path, so this race existed originally — it's not introduced by any of todos 1-11.
- Detected via: `go test -race -shuffle=on -count=1 -run 'TestHTTPOnlySuperEndToEnd$' -count=5 .` reproduces "WARNING: DATA RACE" between `path.(*IG).RecalculateNhTable` (write, called from `runTicker`) and `path.(*IG).ShouldUpdate`/`CheckAnyShouldUpdate` (read, also from `runTicker` in a DIFFERENT run) AND from `ControlState.Report → graph.UpdateLatency → UpdateLatencyMulti → RecalculateNhTable` (write, from the HTTP handler goroutine). Flaky: reproduces roughly 1-in-3 to 1-in-5 full-suite runs under `-race -shuffle=on`.
- Action for orchestrator: this is OUT OF SCOPE for the plan's explicit todos (no todo addresses `graphpath.IG` thread-safety), but the plan's Success Criteria requires `go test -race -shuffle=on -count=1 ./...` exit 0. Must be fixed (likely: add a mutex around `RecalculateNhTable`'s table-swap fields, or serialize ticker+Report calls into the graph) as a SEPARATE small fix task before the Final Verification Wave, alongside the `device` package's `TestSuperHTTPRuntimeListenPortBootstrapWrongKeyRefusesAndLeavesNoListener` goroutine leak (see the other problems.md entry above). Do NOT let this block Wave 2/3/4 progress — schedule a fix pass before Final Wave F1-F4.

## 2026-09-16 — Update: device goroutine leak FIXED (incidental); cmd/eg-tcpmesh race is unrelated untracked content

- The previously-tracked `device` package pre-existing goroutine leak (`TestSuperHTTPRuntimeListenPortBootstrapWrongKeyRefusesAndLeavesNoListener`, "leaked 3 goroutines") is now RESOLVED as of todo 18's commit: todo 18 added `defer c.InvalidateHTTP()` to `ControlHTTPClient.Bootstrap` (device/super_http_client.go) to close idle connections after every bootstrap attempt. Verified via 5x repeated `-race -count=5` run, plus full `./device` package suite green. No further action needed for this item.
- STILL OPEN: the `graphpath.IG` concurrent-access data race (superRuntime.runTicker's RecalculateNhTable vs ControlState.Report's graph.UpdateLatency) — confirmed pre-existing (predates the whole plan, verified against commit 524a1ea). Still reproduces intermittently in `go test -race -shuffle=on -count=1 .` (root package). MUST be fixed before Final Wave (Success Criteria requires a clean `go test -race ./...`).
- NEW OBSERVATION: `cmd/eg-tcpmesh` (untracked, NOT part of git history, explicitly forbidden to stage/commit per this plan's guardrails) has ITS OWN pre-existing data race (`TestMeshConnectsBothWaysAndLogsDrop`). This package has no `go.mod` of its own so `go test ./...` picks it up, but it is scratch/experimental content unrelated to this repo's committed history (see project memory: eg-tcpmesh is a separate unrelated tool). This is NOT part of the super-multi-control-plane deliverable and will not exist in a clean checkout of this git history — do not attempt to fix it. When running the Final Wave's `go test -race ./...` gate, either scope the command to exclude `./cmd/...` (e.g. run against `go list ./... | grep -v /cmd/eg-tcpmesh`) or note this specific untracked-package failure as expected/ignorable in the evidence.

## 2026-09-16 — RESOLVED: pre-existing graphpath.IG recalculation race

- RESOLVED in the standalone `path` fix after `d833634`: an IG-scoped `routelock` now serializes UpdateLatency/RemoveVirt with full Floyd-Warshall and next-hop-table recalculation, and read-locks every computed routing-table reader. `edgelock` remains unchanged for `Vert`/`edges`; the nested lock order is always `routelock -> edgelock`.
- The focused path regression test reproduced the original race twice before the fix and is clean after it. The complete tracked-package `go test -race -shuffle=on -count=1` run passes with zero race reports, and build/vet remain clean.
- Separate verification note: repeated root/focused runs may fail `TestHTTPOnlySuperEndToEnd` because a background Edge report overwrites the manual 4.5ms latency while that test waits for SSE before asserting it. Temporary diagnostics observed the manual Report complete with `latency=4.5` and `next=102`; the identical convergence failure reproduces on detached baseline `d833634`, so it is not caused by this synchronization fix. Full outputs are in `.omo/evidence/super-multi-control-plane/fix-graphpath-race.txt`.

## 2026-09-16 — RESOLVED: HTTP-only Super e2e convergence and handshake-ordering flakes

- Root cause was test orchestration, not a production convergence delay: automatic 10ms full-state reports from Edge A could retract the manually injected latency/observed state, while the observed-fallback setup treated raw bind delivery as proof that the receiving device had completed handshake processing.
- Resolution: stop A's control runtime before each scenario enters its manual full-state-report phase; require B's connection URL before handshake setup; reset B's stale startup handshake attempt with `ExpireCurrentKeypairs` before sending the explicit initiation. Assertions and the 3s timeout are unchanged.
- RESOLVED verification: focused affected tests passed 10/10 with `-race -shuffle=on`; the complete root package passed ten consecutive `go test -race -shuffle=on -count=1 .` runs; build and vet both passed. Evidence: `.omo/evidence/super-multi-control-plane/fix-e2e-convergence-flake.txt`.
