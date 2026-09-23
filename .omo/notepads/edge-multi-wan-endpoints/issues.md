# Issues — edge-multi-wan-endpoints

Gotchas and review findings discovered during work on this plan.

---

## 2026-09-23 — Found by the real-kernel run

- STUN refresh starvation (pre-existing): `stunLoop` restarted its timer on every snapshot apply, so with 1 s polling the periodic refresh never ran. Fixed in 2cbf69e; the STUN server now logs a round per interval.
- Endpoint-dependent NAT left one uplink unreachable from the peer through its STUN candidate. Fixed with peer-reflexive candidates (afd57b9).
- Older peers answer probes with legacy pongs carrying alternate-path latency. Mitigated with silent-peer backoff (4944cdd).

## 2026-09-23 — Independent review

- Pin flag was stored after peer.Unlock in applyProbedEndpoint; an inbound packet could overwrite the choice. Fixed (d72d27a).
- A dead pinned path was only left after the full streak (about 5 rounds). Now one round when the current pair misses twice (d72d27a).
- Pre-existing, not touched: RoutineSendPacket shadows elem and leaks one pooled outbound element per iteration until the next.
