# Problems — edge-multi-wan-endpoints

Unresolved blockers and technical debt discovered during work on this plan.

---

## 2026-09-23 — Open items

- Windows build of `conn` is broken on master before this work: `*WinRingBind` lacks `EnabledAf`. Not touched.
- `--bindmode std` and non-Linux platforms cannot pin per datagram, so they discover only the default-route mapping.
- Under very high packet rates a probe on a much slower path can fall outside the replay window and count as a miss (conservative: never switches to it).
