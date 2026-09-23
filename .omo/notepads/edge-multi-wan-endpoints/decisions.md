# Decisions — edge-multi-wan-endpoints

Architectural choices and rationales discovered during work on this plan.

---

## 2026-09-23 — Design choices

- Keep one socket; pin per datagram via an optional `conn.EndpointSourcePinner` capability (Linux only).
- Always run the unpinned STUN pass as slot 0 so results are a strict superset of the old behaviour (covers CGNAT tun uplinks the source filter drops).
- One source per (interface, family), carrier required, cap 8, sorted by ifindex then family.
- RTT from a local monotonic `sentAt` keyed by PingMsg.RequestID, not PingTime (graph clock is NTP-adjusted and Round(0) strips monotonic time).
- Each side ranks only its own outbound legs; the receiver does not follow the sender. Asymmetric paths are fine for WireGuard and mutual following would flap.
- The chosen endpoint is pinned; inbound packets do not replace it while the peer is alive. Refused sources become peer-reflexive candidates (max 4, expire after PeerAliveTimeout) ranked ahead of published candidates.
- The prober ignores the retry loop's 20 s handshake hold; min samples (3) plus the streak (default 3 rounds) damp switching.
- User decisions: probe local uplink x remote pairs; hysteresis with configurable knobs; both Super v2 and P2P modes.

## 2026-09-23 — Commits

| Todo | Hash | Subject |
|------|------|---------|
| | edb4d9b | feat(conn): pin per-datagram source address and interface on Linux binds |
| | 9ab3817 | feat(device): enumerate one pinnable STUN source per uplink and family |
| | 1c30eac | feat(device): discover a STUN mapping for every uplink on multi-WAN edges |
| | fd467b4 | feat(mtypes): configure lowest-latency endpoint selection |
| | 286418d | feat(device): probe every uplink x candidate pair and use the fastest |
| | 4169c9d | fix(device): let endpoint probing run during the retry hold and expose an uplink seam |
| | b5a1e38 | test(e2e): multi-WAN STUN candidates and lowest-latency convergence |
| | eef9ae4 | docs(edge): document multi-WAN STUN discovery and endpoint selection |
| | 2cbf69e | fix(device): stop snapshot churn from starving periodic STUN refresh |
| | afd57b9 | feat(device): probe peer-reflexive addresses behind endpoint-dependent NATs |
| | 5d7c5bd | test(e2e): reach an uplink behind an endpoint-dependent NAT |
| | 409219d | docs(edge): describe peer-reflexive endpoint probing |
| | 4944cdd | fix(device): back off endpoint probing for peers that never answer |
| | d72d27a | fix(device): pin before publishing a probed endpoint and fail over fast |
