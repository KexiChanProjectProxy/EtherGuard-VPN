
## [2026-07-26T06:10Z] Decision: F1 waiver for device/receive.go in ca48c5e
F1 rejected ca48c5e for touching device/receive.go, absent from task 5's Writes list. Orchestrator review: the diff is exclusively the removal of `IsSuperNode` receive-dispatch branches — the core of task 5's "remove super-only channels/paths" mandate. The plan's Writes list omitted the file; the change is in-spirit, minimal, and required for compilation after SuperConfig removal. WAIVED; evidence appended to final-1 log.

## [2026-07-26T06:10Z] Decision: F3 rejection basis corrected (HANDOVER 2.3 was wrong)
super_control_state.go Register maps LocalV4/V6->ControlV2CandidateLocal and PublicV4/V6->ControlV2CandidateSTUN, byte-identical at pre-plan base 96d8354 (introduced by 78fb077, pre-migration). HANDOVER 2.3's claim that all register addresses map to Local was factually wrong. Plan must-have "preserve the already-correct register-time STUN candidate labels" confirms current behavior is intended. Gap closed by pinning regression test instead of behavior change.
