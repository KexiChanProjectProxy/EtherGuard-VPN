# Issues — super-multi-control-plane

Problems and gotchas encountered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## 2026-09-16 — Full race-suite blockers observed during task 9 follow-up

- `cmd/eg-tcpmesh.TestMeshConnectsBothWaysAndLogsDrop` consistently reports a race between background `log.Logger.Printf` writes and test-side `bytes.Buffer.String` reads (`cmd/eg-tcpmesh/main.go:267/287/291`, `cmd/eg-tcpmesh/main_test.go:30/49`). This is outside task 9 and `cmd/` was not modified.
- `device.TestSuperHTTPRuntimeListenPortBootstrapWrongKeyRefusesAndLeavesNoListener` reports a goroutine delta of 3 from lingering `httptest.Server`/HTTP transport goroutines. This is outside task 9 and `device/` was not modified.
- Task 9's affected auth/bootstrap regression tests pass independently under the race detector after the helper fix.

---

## 2026-09-16 — F1/F2 final-verification claims: fabricated vs genuine

F1's design-non-compliance findings against §E/§F/§H/§I/§J were re-checked against the actual plan text in `.omo/plans/super-multi-control-plane.md`. They are **not** plan requirements — the reviewer invented normative text that does not appear in those sections. Do not re-litigate or "fix" them:

- §E handshake reply canonical string is 5 components (`"eg-cluster/1-reply\n"+clientNonce+"\n"+serverID+"\n"+base64(serverEph)+"\n"+compression`). There is no 8-component reply string in the plan.
- §F message list has no `sync_done`; full_sync completion is `Part == Of`.
- §G dials from both sides (`One linkPeer per Cluster.Peers entry: dial loop`) and dedups by keeping the session whose DIALER SuperID is lower. Lower-ID-only dialing is not specified.
- §H `bootstrapInitialBind` iterates `ResolveAPIUrls()` sequentially with per-attempt budget `max(2s, total/len)`. Overlapping 2-second staggered attempts are not specified.
- Todo 10 ManageV2 persist-then-commit is `build newBase+profile → atomicWriteConfigs → state.CommitRegistry(...) → persistClusterState()` with no reload step.
- `s.now()`-under-lock in `super_control_replica.go` matches the existing `Register`/`Report` convention; production `now = time.Now` takes no lock.

Two F2 findings **were** genuine and are fixed:

- Issue B: §E "First inner message in each direction MUST be `hello`; anything else → close." `readerLoop` now rejects a non-hello first inbound envelope (`ErrClusterFirstMessageNotHello`). Regression: `TestClusterSessionRejectsNonHelloFirstMessage`.
- Issue C: Sync `streamEvents` swallowed `Snapshot` errors after `stopPolling()`, leaving the client with neither a stream-driven update nor active polling. On that error path we now `Logf` and `startPolling()`. Regression: `TestControlHTTPClientSyncRestartsPollingWhenStreamEventSnapshotFails`.

---

## 2026-09-16 — F1/F2 re-review (post-67f238c): wall clock vs hello-before-Run

Two genuine, small findings on top of `67f238c`. Neither reverts the earlier flake fixes.

### F1 — `time.Now()` in `readRecord` for OS socket deadlines

Commit `18905ac` (todo 25) correctly stopped using the injected logical clock `s.now()` for `net.Conn.SetReadDeadline`. Frozen e2e clocks made that deadline expire immediately and produced spurious `ErrClusterLinkDead`. Regression: `TestClusterSessionStaleLogicalClockKeepsSocketDeadlineAlive`.

The F1 guardrail still wants no `time.Now()` *calls* in cluster method bodies — only constructor defaults. Resolution: add `clusterSessionConfig.WallNow` / `clusterSession.wallNow`, defaulted to `time.Now` in `newClusterSession`, and use `s.wallNow().Add(s.deadAfter)` in `readRecord`. Tests continue to freeze only the logical `Now` clock; they do not override `WallNow`, so OS deadlines stay on real wall time in production and in e2e.

Do **not** point `wallNow` at `s.now` — that reintroduces the 18905ac flake.

`grep -n 'time.Now()' super_cluster_*.go` still hits `clusterAuthenticator.currentTime`'s nil-fallback (`super_cluster_handshake.go`). That is a pre-existing constructor-equivalent default (`newClusterManager` already injects `now`); it is not a new method-body clock. Session files now only *assign* `time.Now` as `Now`/`WallNow` defaults.

### F2 — hello queued after `session.Run()` started

`adoptSession` launched `session.Run` before `session.Send(hello)`. `Run` starts the writer loop, whose heartbeat ticker can fire a `ping` as the first outbound envelope. Combined with the new hello-first reader (`ErrClusterFirstMessageNotHello` from 67f238c), a validly-short `HeartbeatSeconds` could make the peer reject a legitimate link.

Fix: `Send(hello)` (and `close(helloDone)`) **before** starting `session.Run`. `sendCh` is buffered (256), so the hello sits in FIFO until the writer starts. `helloDone`, winner/loser close, and the Send-error path are unchanged in meaning; `Run` still starts after Send so `wg.Add(1)` stays balanced even if Send fails (Run sees the closed session and returns).

Writer loop also `drainSendQueue()` before `time.NewTicker`: a short heartbeat can make `ticker.C` ready on the first `select`, and Go would then pick ping vs hello at random even with hello already queued. Draining pre-queued envelopes (the hello) before the ticker exists makes hello-first hold for any positive `HeartbeatSeconds`. Hello-first enforcement itself is unchanged.

Regression: `TestClusterManagerHelloSentBeforeHeartbeat` (1ms heartbeat, simultaneous dial, first inbound type is `hello` on both sides).

---

## 2026-09-16 — Deterministic drain-before-ticker proof + device failover wait

### Drain-before-ticker is now a session-level unit test (red-then-green)

`TestClusterManagerHelloSentBeforeHeartbeat` still covers the adopt path, but a 1ms heartbeat cannot *force* `ticker.C` ready on the first `select`. The new `TestClusterSessionDrainsQueuedHelloBeforeHeartbeatTicker` does:

- Pre-queue hello + a follow-up envelope (proves drain empties the *whole* `sendCh`, not just one item).
- Inject `newHeartbeatTicker` that records `len(sendCh)` at ticker-creation time and returns a channel that already has a tick buffered.
- Assert the factory sees `len(sendCh)==0`. That is independent of Go `select` fairness.

Red-then-green: temporarily removing the `drainSendQueue()` call before `heartbeatTicker()` failed 3/3 with `heartbeat ticker created with 2 envelopes still queued`. Restored drain: 10/10 pass under `-race`.

### `TestSuperHTTPRuntimeReregisterBypassesThrottleOnSwitch` (device)

Failed once during a full-suite `-race -shuffle=on` run at `waitRuntimeCondition(..., b.registerCalls == 1)` (1s). Isolated `go test -race -count=20` of that test and `./device` with `-shuffle=on -count=10` both passed.

Cause: `go test $(go list ./...)` runs packages in parallel. The root package's ~100s race suite starves the device package. After `close(allowReports)`, failover still needs three wall-clock `ReportInterval` (20ms) ticks plus B's register; those timers stretch under load and can miss a 1s deadline. Not a production logic bug — the 30s per-epoch reregister throttle is correctly bypassed on `SwitchBase` (new epoch).

Fix: widen the B-register wait to 5s (matches the production report HTTP timeout) in this test and the sibling `TestSuperHTTPRuntimeFailoverAfterThreeReportFailures`, which uses the same close-reports-then-wait-for-B pattern.

---

## 2026-09-16 — Final load-dependent e2e flakes (mesh recheck + freeze-reader)

These are the last flakes found in this plan's QA journey. Both only showed under full-suite `-race` load; each passed in isolation.

### `TestE2EMultiSuperTopologySmoke/three_supers_form_a_full_mesh`

Observed 1/3 full-suite runs: `super 1 links = 2 total, 1 connected; want 2/2` at the single-shot recheck after `awaitE2E` had already seen `connected==2` for all three supers.

Cause: poll-then-recheck TOCTOU. `awaitE2E` confirmed the mesh, then a non-retrying `t.Fatalf` re-read `Status().Links` and caught a brief link flap. `WaitLinked` in the same file does not do this.

Fix: fold `len(links)==2 && connected==2` for every super into the `awaitE2E` condition and delete the single-shot recheck. Correctness bar unchanged; only polling discipline.

### `TestMultiSuperE2EShutdownWithBlockedLink`

Observed on the next full-suite pass while verifying the mesh fix: `awaitE2E` at the `readerFrozen` wait timed out in 1s.

Cause: `FreezeReaderForTest` only set a flag. `readerLoop` checks it at the top of the loop, but the reader is usually blocked in `ReadMessage`. Freeze then depended on the next heartbeat (100ms) arriving before the 500ms socket `deadAfter` timeout. Under load the timeout won, the session died with `ErrClusterLinkDead`, and `readerFrozen` stayed false.

Fix: expire the read deadline when freeze is requested, and honor `freezeReader` on the resulting read error so the reader parks without closing the conn. Regression: `TestClusterSessionFreezeReaderStopsBlockedReadWithoutClosing` (hour heartbeat / 2h deadAfter — freeze cannot wait for traffic).

Verification after both fixes: `go test -race -run TestE2EMultiSuperTopologySmoke -count=20` PASS; full scoped suite `-race -shuffle=on` ×3 PASS.

---

## 2026-09-16 — Frozen-reader shutdown e2e: watchdog window + dual-dial loser close (final flake)

Observed on full-suite `-race -shuffle=on` attempt 5/5 after the freeze-wake fix (`4494da0`): `TestMultiSuperE2EShutdownWithBlockedLink` fatals with `freezing B's cluster reader closed the underlying session`. Isolation looked green until the incomplete first fix (hour-wide heartbeat/deadAfter only) still failed 1/30 in ~0.10s — too fast for a 2h watchdog, so that diagnosis was real but not sufficient.

Two closers, both test-timing, neither a production bug:

1. **Watchdog.** Empty `e2eClusterOptions{}` defaults heartbeat/deadAfter to 100ms/500ms. Freeze parks B's reader so `lastRX` stops. `Run`'s `deadTicker` is independent of freeze flags and closes when `now-lastRX > deadAfter`. Under race-suite load the 500ms window can elapse during the 1s `readerFrozen` wait. Production watchdog is correct; this test then calls `Shutdown` with a 3s budget, so the default window is also too tight for the rest of the scenario.

2. **Dual-dial loser.** `WaitLinked` only waits for `state=="connected"`. Both supers dial (`ReconnectMinSeconds=0.05`). `adoptSession` keeps the session whose dialer SuperID is lower and `loser.Close()`s the other. A=Vertex(1), B=Vertex(2), so the stable session is A-as-dialer. If the test snapshots B's session while B-as-dialer is still current, the in-flight A-dial handshake then closes that pointer. Freeze parks the already-closed (or just-closed) session; `readerFrozen` is true and `closed()` is true within ~100ms. This is why the hour-wide window still failed in isolation.

Fix in this test only: `heartbeat: time.Hour, deadAfter: 2*time.Hour` (same window as `TestClusterSessionFreezeReaderStopsBlockedReadWithoutClosing`) **and** wait until B's session is the hijack-stable winner before freeze. Assertions unchanged (readerFrozen, session still open after freeze, Shutdown nil within 3s, A's sessions/goroutines gone, edge dial refused).

This is (hopefully truly) the last flake in this plan's QA journey. If another one appears in the verification passes, document it the same way.
