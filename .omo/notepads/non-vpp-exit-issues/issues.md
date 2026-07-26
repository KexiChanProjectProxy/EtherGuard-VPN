
## [2026-07-26T05:05Z] Issue: PRE-EXISTING flaky golden gate TestHTTPOnlySuperEndToEnd
- Orchestrator-measured: fails at `super_http_e2e_test.go:126` ("polling removes deleted peer after SSE forcibly unavailable", 3s convergence window) ~50% of runs under `-race`.
- Reproduced at plan base commit 96d8354 (2/4 FAIL), post-wave-1 2344f4d (3/3 FAIL), and post-task-4 e78013f (2/3 FAIL). NOT introduced by any task in this plan.
- Blocks F2/F3 reliability. Root-cause fix dispatched as unplanned gate-blocking work.
- Strong hypothesis: `device.applySuperHTTPSnapshot` removes peers via `device.RemovePeer(peer.handshake.remoteStatic)`; if the handshake has not completed, `remoteStatic` is zero-valued and removal silently targets the wrong key — a handshake-timing race.
