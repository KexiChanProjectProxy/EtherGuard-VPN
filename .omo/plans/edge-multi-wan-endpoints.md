# edge-multi-wan-endpoints - Work Plan

## TL;DR (For humans)

**What you'll get:** On a machine with several uplinks (several default routes, or per-uplink policy routing), the Edge now learns the public address of every uplink, not just the one the kernel prefers. Peers then measure every usable path to each other and move to the fastest one, and move back when conditions change.

**Why this approach:** The single WireGuard socket is kept. Each STUN request and each latency probe is pinned to one uplink's source address and interface per datagram, which respects per-interface default routes and `ip rule from <src>` policy routing. Probes ride inside the encrypted session and never disturb routing latency or WireGuard timers.

**What it will NOT do:** It adds no second socket, no TURN or relay, and no per-socket interface binding. Per-datagram pinning is Linux-only; `--bindmode std` and other platforms keep today's behaviour for discovery and probe remote candidates only.

**Effort:** L  **Risk:** Medium - touches the send path and the roaming guard.  **Decisions to sanity-check:** receiver does not follow the sender's path choice; old peers that do not echo RequestID are backed off, not excluded.

---

> TL;DR (machine): L effort, medium risk; 9 todos + 4 final checks, all done. Approved plan: ~/.claude/plans/functional-brewing-parasol.md.

## Scope

### Must have
- C1 One STUN candidate per uplink with a distinct public `ip:port`, from the same WireGuard socket.
- C2 Default-route (unpinned) STUN pass always runs, so behaviour is a strict superset of before.
- C3 Live peers are probed per (local uplink x remote candidate) pair; the fastest pair wins with hysteresis.
- C4 Works in Super v2 and P2P modes; static and roaming-disabled peers excluded.
- C5 Configurable: DisableEndpointSelection, probe interval, absolute and percent margin, rounds.

### Must NOT have
- No Super or wire-protocol schema change (PublicV4/V6 are already lists; PingMsg.RequestID already exists).
- Probes never feed SingleWayLatency, OutboundLatency or the routing graph.
- Off-path probes never touch WireGuard keepalive or handshake timers.

## Verification strategy
- TDD with `go test -race -shuffle=on -count=1`; gates `go build ./... && CGO_ENABLED=0 go build ./... && go vet . ./conn ./device ./mtypes ./gencfg`.
- Real-kernel check in unprivileged user and network namespaces: two uplinks behind two nftables MASQUERADE NATs, netem delay, real `etherguard-go` Super and edges.
- Evidence: `.omo/evidence/edge-multi-wan-endpoints/`.

## Todos
- [x] 1. conn: `EndpointSourcePinner` on `LinuxSocketBind` (edb4d9b)
- [x] 2. device: one STUN source per (interface, family) (9ab3817)
- [x] 3. device: per-uplink concurrent STUN discovery, random transaction IDs (1c30eac)
- [x] 4. mtypes: endpoint selection knobs, validation, hydration (fd467b4)
- [x] 5. device: explicit-endpoint send path, RequestID echo, prober (286418d, 4169c9d)
- [x] 6. e2e: multi-WAN STUN, Super and P2P convergence, disabled control (b5a1e38)
- [x] 7. docs: Super and P2P guides, docs contract (eef9ae4)
- [x] 8. Fixes found by the real-kernel run: STUN refresh starvation (2cbf69e); peer-reflexive candidates for endpoint-dependent NATs (afd57b9, 5d7c5bd, 409219d)
- [x] 9. Review hardening: silent-peer probe backoff (4944cdd); pin-before-publish race and fast failover of a failing current path (d72d27a)

## Final verification wave
- [x] F1. Full race suite green.
- [x] F2. E2E suites repeated with `-count=3` and `-count=5` green.
- [x] F3. Real-kernel namespace run, metric and policy routing: every uplink discovered, both edges switch within ~3 probe rounds.
- [x] F4. Independent correctness review of the diff.

## Commit strategy
- One conventional commit per todo on `master`; scopes `conn`, `device`, `mtypes`, `e2e`, `docs`.

## Success criteria
- `go build ./...`, `CGO_ENABLED=0 go build ./...`, `go vet` exit 0; `go test -race -shuffle=on -count=1 ./...` clean.
