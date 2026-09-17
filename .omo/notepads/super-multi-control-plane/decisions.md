# Decisions — super-multi-control-plane

Architectural choices and rationales discovered during work on this plan.

_Auto-scaffolded by /start-work. Append new entries below - never overwrite._

---

## 2026-09-16 — Task 1 baseline commit

- Baseline commit: `0050fe251fc0d2d655920659cdb6d9543ab726cc`
- Subject: `fix(device): baseline network-recovery changes (InvalidateHTTP, netlink refresh, sticky endpoints)`
- Staged/committed exactly 13 paths (12 modified tracked + new `device/sticky_linux_test.go`). `KexiSdnConfig/` and `cmd/` left untracked.
- `go build ./...` passed.
- `go test -race -shuffle=on -count=1 ./device` **failed** (pre-existing): `TestSuperHTTPRuntimeListenPortBootstrapWrongKeyRefusesAndLeavesNoListener` reported `goroutine delta = 3` / leaked 3 goroutines. Failure recorded in `.omo/evidence/super-multi-control-plane/task-1-super-multi-control-plane.txt`.
- Post-commit porcelain also still shows untracked plan artifacts (`.omo/evidence/`, `.omo/notepads/`, `.omo/plans/`) in addition to `KexiSdnConfig/` and `cmd/`. Those `.omo/` paths were not part of the baseline file list and were not staged.

---

## 2026-09-16 — Tasks 2-6 atomic commits

Five NEW_COMMITS_ONLY on `master` (baseline `0050fe2` not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-2-6-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 2 | `46c969ab32f76996d815b7a960be337517829bab` | feat(cluster): add zstd stream codec and klauspost/compress dependency |
| 3 | `66dffc8d8262eb26e90b6138d3c9c6bd740186b1` | feat(mtypes): add Cluster config schema and multi-URL SuperNodeV2 reference |
| 4 | `f0b77781a4793f6b2a3b31e260e0ef1e30178a52` | feat(cluster): add hybrid logical clock and ClusterVersion ordering |
| 5 | `f9b69bc09e795d56d482f6690a86cda303f7ea2f` | fix(super): scope management password to the owning runtime |
| 6 | `bbabc63d49c43a6a63dcabdc022205e8e7c9ed3c` | feat(cluster): add X25519/HKDF key schedule and AEAD record layer |

Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Tasks 7 and 11 atomic commits

Two NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-7-11-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 7 | `8814dcf9c0d98238c196b581e41741d4db4bd32d` | feat(super): version-stamp control records and add replication outbox |
| 11 | `8933b361ef2cfb3ba885e4eb22780f9d5e74581d` | feat(cluster): define replication wire protocol DTOs |

Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`. All source files committed.

---

## 2026-09-16 — Tasks 8 and 9 atomic commits

Two NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-8-9-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 8 | `6a780f6e596b235754265915c08e2bca59f936d5` | feat(super): idempotent replicated record apply with batch revisioning |
| 9 | `290aa91e33acb75f111b9ea040eb1a7e7088c3b7` | feat(super): versioned registry and parameters with origin-aware timeout sweep |

Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`. All source files committed.

---

## 2026-09-16 — Task 10 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-10-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 10 | `dd87d1ca571ed848102eae3befce5e3108e7198f` | refactor(manage): persist-then-commit mutations with replicated registry and cluster state file |

Staged/committed exactly 8 paths. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Tasks 12 and 13 atomic commits

Two NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-12-13-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 12 | `659d22a2f7fd453df4286df4020b593d79e16094` | feat(cluster): add encrypted compressed link session with heartbeat and counters |
| 13 | `690a8fb5d9a2b509002edcfb2721d0ca7af7a073` | feat(cluster): HTTP upgrade handshake with HMAC mutual authentication |

Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`. All source files committed.

---

## 2026-09-16 — Task 14 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-14-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 14 | `4ff613c9a22eff55051ed01d16fd475e010cb66b` | feat(cluster): link manager with dedupe, coalescing queues, full sync and forwarding |

Staged/committed exactly 2 paths: `super_cluster_manager.go`, `super_cluster_manager_test.go`. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Task 15 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-15-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 15 | `b1ffb4744b86bd6ce1d6a816ebd2d1595fb3135f` | feat(super): wire cluster link manager into the runtime and diagnostics |

Staged/committed exactly 3 paths: `main_super.go`, `main_httpserver.go`, `main_super_cluster_runtime_test.go`. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Tasks 16, 17, 21 atomic commits

Three NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-16-17-21-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 16 | `917734b9fe6510067af015f98cbf553c9289c547` | test(super): cover origin-aware sweep and grace eviction through the runtime ticker |
| 17 | `55ee8e78e05dde4c2b679b96667935a80559d3ed` | feat(edge): epoch-scoped control client with base switching and resilient sync |
| 21 | `85c9b9de86d740178e29b853d73c7b7889d93795` | feat(gencfg): emit multi-super APIUrls in generated edge profiles |

Staged/committed exactly the listed paths per todo. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Tasks 18 and 20 atomic commits

Two NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-18-20-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 18 | `9f4b24bb85b7571366289bb4008f094e81039df4` | feat(edge): sticky-current super failover with epoch-scoped re-registration |
| 20 | `2091ede170cb2b173bbc0a6ee31dbb99e866a8b7` | feat(edge): ordered multi-super bootstrap with per-attempt budgets |

Staged/committed exactly the listed paths per todo. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Task 19 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-19-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 19 | `d833634b213cd94a83591a67e516459b58b5db56` | feat(edge): plumb multi-super URL list into the edge runtime |

Staged/committed exactly 6 paths: `device/super_http_runtime.go`, `main_edge.go`, `super_manage_v2.go`, `device/super_http_enable_test.go`, `main_edge_v2_detect_test.go`, `mtypes/edge_config_v2_api_urls_test.go`. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Tasks 22 and 26 atomic commits

Two NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-22-26-commits-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 22 | `1f4aaf743ef1a34a5ac88997e649ebbd16b187ec` | test(e2e): multi-super topology helpers with link gate and production shutdown |
| 26 | `2d7dea790f94442d8f2311466a3a6ff6767bdc80` | docs(super): document multi-super active-active control plane and cluster config |

Staged/committed exactly the listed paths per todo. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Task 23 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-23-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 23 | `9af72228e832d9ec0a428ee40d1b3fbf3623c726` | test(e2e): multi-super convergence, partition, failover and registry replication |

Staged/committed exactly 3 paths: `super_cluster_e2e_test.go`, `device/super_http_runtime.go`, `super_http_e2e_support_test.go`. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `.omo/plans/super-multi-control-plane.md`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Task 24 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-24-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 24 | `49991efcc671a7dc3fdfad14ebc6773e5aa49e2b` | test(cluster): compression counters and memory budget |

Staged/committed exactly 5 paths: `super_cluster_e2e_test.go`, `super_cluster_session.go`, `super_cluster_mem_test.go`, `super_cluster_codec_instances_test.go`, `.omo/plans/super-multi-control-plane.md` (plan file included this once because todo 24 added verification commands to Success criteria). Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `KexiSdnConfig/`, `cmd/`. Plan file is now tracked.

---

## 2026-09-16 — Task 25 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-25-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 25 | `18905accef08d55ce9aaf987057eff8257c26d78` | test(e2e): edge failover, bootstrap fallback and revision reset across supers |

Staged/committed exactly 7 paths: `super_cluster_e2e_test.go`, `super_http_e2e_support_test.go`, `device/super_http_runtime.go`, `super_cluster_session_io.go`, `super_cluster_session_test.go`, `super_cluster_session_test_helpers_test.go`, `.omo/plans/super-multi-control-plane.md`. Body also records the genuine flake-fix: `clusterSession.readRecord` now uses wall-clock time for the OS socket read deadline (regression: `TestClusterSessionStaleLogicalClockKeepsSocketDeadlineAlive`). Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `KexiSdnConfig/`, `cmd/`.

---

## 2026-09-16 — Task 27 atomic commit

One NEW_COMMITS_ONLY on `master` (prior history not rewritten). Evidence: `.omo/evidence/super-multi-control-plane/task-27-commit-super-multi-control-plane.txt`.

| Todo | Hash | Subject |
|------|------|---------|
| 27 | `e42c7a39131502c278b5db66d3fd69608f1d77d3` | test(cluster): shutdown with blocked links and proxy upgrade with custom prefix |

Staged/committed exactly 5 paths: `super_cluster_e2e_test.go`, `super_cluster_session.go`, `super_cluster_session_io.go`, `super_http_e2e_support_test.go`, `.omo/plans/super-multi-control-plane.md`. Post-commit porcelain left untracked: `.omo/evidence/super-multi-control-plane/`, `.omo/notepads/super-multi-control-plane/`, `KexiSdnConfig/`, `cmd/`. Final implementation todo of the 27-todo plan.
