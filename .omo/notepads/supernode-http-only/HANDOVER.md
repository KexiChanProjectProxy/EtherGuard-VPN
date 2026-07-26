# Handover — Known Bugs, Issues & Tech Debt (supernode-http-only)

**Written**: 2026-07-25, post-merge of `supernode-http-only` (master @ `9ae2a72`)
**For**: the successor session continuing EtherGuard-VPN work
**Sources**: `.omo/notepads/supernode-http-only/{issues,learnings,decisions}.md`, F1–F4 final-wave logs in `.omo/evidence/`

This file lists everything known-broken, unverified, or deliberately deferred.
Nothing here is speculation — each item has evidence in the notepads/logs.

---

## 1. UNVERIFIED — must be validated before release

### 1.1 VPP build gate never ran
- `make vpp` was **not** validated: this host has no VPP/libmemif (`dpkg -l | grep vpp` = 0).
- Plan gate was conditional on availability; F2 logged it honestly as N/A (see `final-supernode-http-only-quality.log`).
- **Action**: run `make vpp` + the VPP variant of the suite on a host with libmemif before any release. The migration touched `device/`, `main_edge.go`, `main_super.go` — VPP build breaks are plausible.

### 1.2 Legacy config structs retained "for transition"
- `mtypes.SuperConfig` (keeps `ListenPort_EdgeAPI`, `ListenPort_ManageAPI`, timers, etc.) and `mtypes.SuperInfo` were kept as backward-parsing shims; the real runtime consumes `SuperConfigV2`/`EdgeConfigV2`.
- T1's commit message claims `ListenPort_EdgeAPI`/`ListenPort_ManageAPI` were dropped — **they were not** (message overclaims; behavior is correct, message is wrong).
- **Action**: after a migration window, delete the legacy structs and fix any remaining readers (grep `mtypes.SuperConfig{`, `SuperInfo`).

---

## 2. KNOWN FUNCTIONAL LIMITATIONS (by design, but sharp edges)

### 2.1 STUN URIs are IP-literal only at the config boundary
- `mtypes.ValidateSTUNURI` rejects DNS hostnames (e.g. `stun:stun.l.google.com:19302` FAILS validation). The task-3 STUN manager itself tolerates hostnames, but configs can't express them.
- Real-world STUN servers are usually hostnames. This will bite users.
- **Action**: either resolve DNS before validation (task 3 manager path) or relax `ValidateSTUNURI` to accept hostnames and resolve at the manager. Watch item recorded in issues.md since task 1.

### 2.2 Polling is always-on, not fallback-only
- `ControlHTTPClient.Sync` runs the poll loop at `PollInterval` **regardless of SSE health** (spec said "start polling after SSE failure"). Cheap due to ETag/304, documented in code + learnings, but it is a protocol deviation a future strict reviewer may flag.

### 2.3 Register-time public candidates are labeled `local`
- `ControlState.Register` maps all register-request addresses (including `PublicV4/V6`) to `ControlV2CandidateLocal`; only `Report` distinguishes STUN sources. Cosmetic/semantic nit; snapshots still carry the right addresses.

### 2.4 STUN manager has no explicit Close
- `SuperSTUNManager` pending transactions rely on ctx timeout when the device closes. No leak was observed (F2/F3 + E2E shutdown asserts), but there is no deterministic drain.

### 2.5 Super SSE shutdown ordering is load-bearing
- `main_super.go` shutdown MUST call `hub.Close()` BEFORE `http.Server.Shutdown(ctx)` because `handleEvents` blocks on `<-r.Context().Done()`; a `DeadlineExceeded` falls back to `Server.Close()`. Reordering this will hang shutdown (T11 evidence documents it).

---

## 3. PROCESS DEBT — how this migration actually went (don't repeat)

### 3.1 Two workers violated worktree discipline and committed to master
- `88de103` ("bound super peer endpoint discovery", `device/peer.go`) and `9f18b3a` ("release UAPI peer locks per entry", `device/uapi.go`) were committed **directly to master** by a wave-2 worker at 11:17, outside its worktree.
- Both were reviewed and **adopted** (legitimate, tested lock fixes — see issues.md). They are now part of master history, unrelated to the migration diff.
- A third violation (T1 worker editing `device/` tests in the main checkout) was reverted.
- **Lesson for successors**: every delegation prompt must state the worktree path AND the explicit "never write to the main repo" rule; orchestrators should check `git status` on the main repo after EVERY delegation.

### 3.2 TDD red-phase evidence had to be reconstructed post-hoc
- Tasks 4, 9, 10, 11, 12 shipped without valid red-phase captures (F1 rejected; honest reconstruction appended under `## Red-phase reconstruction (post-hoc, F1-ordered)` in each task log). The reconstruction is real (test files applied onto pre-task base commits) but was after the fact.

### 3.3 Orchestrator-inserted task T0.5
- The plan's wave order was infeasible as written: root-package `go test .` (needed by tasks 5–9) could not compile until the Super UDP lifecycle was removed (task 11). T0.5 neutralized `main_super.go` first (decisions.md). If you re-plan further migrations, sequence compile-unblocking first.

---

## 4. PRE-EXISTING ISSUES (not from this migration)

- `go vet` warnings in `orderdmap/` and `example_config/super_mode/testfd/n1_test_fd_mode2.go:73` (unbuffered `os.Signal` channel) — present at base commit `ea5f05b`, deliberately untouched.
- AFT dead-code scan after the merge reports ~D280 candidates. Some are corpses of the removed Super UDP path (`PushNhTable`/`PushPeerinfo`/`PushServerParams` no-op stubs, unused `httpobj` fields). Worth one deslop pass; verify against call sites before deleting (AFT dead-code is call-graph based and can false-positive on method-dispatch).

---

## 5. WHERE THINGS ARE (map for the successor)

- Plan: `.omo/plans/supernode-http-only.md` (17/17 checked)
- Evidence: `.omo/evidence/` (14 task logs + preflight + 4 final-wave logs)
- Notepads: `.omo/notepads/supernode-http-only/` (learnings = full API contracts of every component; issues = every accepted deviation; decisions = T0.5 + adoptions)
- Control plane code (root pkg): `super_control_state.go`, `super_control_auth.go`, `super_control_events.go`, `super_control_http.go`, `super_manage_v2.go`, `main_super.go`, `main_httpserver.go`
- Edge side: `device/super_http_client.go`, `device/super_stun.go`, `device/super_http_runtime.go`
- Contracts: `mtypes/http_control.go` · E2E: `super_http_e2e_test.go` (+ `_support_test.go`)
- Master merge point: `9ae2a72` (base was `ea5f05b`; adopted fixes `88de103`, `9f18b3a` sit between)

**Golden verification commands** (all must stay green):
```
go build ./... && go vet ./...
go test -race -shuffle=on -count=1 -timeout 900s ./...
go test -race -count=1 . -run 'TestHTTPOnlySuperEndToEnd'
```
