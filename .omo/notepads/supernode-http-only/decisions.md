# supernode-http-only - decisions

## [2026-07-25] Orchestrator decision: wave resequencing for root-package compilation
After T1, root package (main_super.go) references removed SuperConfig fields (PrivKeyV4/FwMark/API_Prefix/ListenPort) and cannot compile until T11 (wave 5) — but T5/T6/T7/T8/T9 all have `go test .` acceptance requiring root compilation from wave 2 on. Plan ordering is infeasible as written.
Resolution: insert micro-task T0.5 after T2 merges — neutralize the legacy Super UDP lifecycle in main_super.go (and any compile blockers in main_httpserver.go) to a minimal compiling shell WITHOUT adding the HTTP service. T11 (wave 5) then wires the HTTP control service into that shell. All other wave ordering unchanged.
Execution order: [T2,T3,T4 parallel] -> T0.5 -> [T5,T7 parallel] -> [T6,T8,T10 parallel] -> T9 -> T11 -> [T12,T13 parallel] -> F1-F4.

## [2026-07-25] Orchestrator decision: adopt 88de103 + pre-authorization record
- Adopted master commit 88de103 (peer endpoint lock fix) on the same basis as 9f18b3a. Both are wave-2 worker discipline violations, both legitimate tested fixes, both outside the integration diff. Final integration→master merge unifies them; the full race suite will re-run post-merge.
- docs_contract_test.go (root) was pre-authorized in the T12 delegation as the docs assertion mechanism; F4 also pre-approved it. super_http_e2e_support_test.go was pre-authorized in the T13 delegation ("optional *_test.go helpers").
