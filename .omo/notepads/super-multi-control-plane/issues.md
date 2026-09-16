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
