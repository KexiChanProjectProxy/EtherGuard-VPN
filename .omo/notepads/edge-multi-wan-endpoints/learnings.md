# Learnings — edge-multi-wan-endpoints

Conventions, patterns, and successful approaches discovered during work on this plan.

---

## 2026-09-23 — Kernel and NAT behaviour

- Pin both `ipi_spec_dst` and `ipi_ifindex`: oif alone breaks `ip rule from <src>` tables, src alone lets the main-table default send wan2's address out wan1.
- IPv4 with oif set and no usable route is a silent on-link drop (sendmsg returns 0), so uplink probes must run concurrently.
- IPv6 pin with a non-local or tentative source makes `send6` hit EINVAL, clear src and resend via the default route. Detect with `endpoint.SrcIP().IsUnspecified()` after Send and do not attribute the reply.
- nftables MASQUERADE is endpoint-dependent: the port toward a peer can differ from the STUN-reported port (seen: 16386 to STUN, 52857 to the peer). Published STUN candidates can then be unreachable; the peer-reflexive source of authenticated packets is the only usable address.
- pion/stun `stun.Build` only randomizes the transaction ID when `stun.TransactionID` is passed as a setter.

## 2026-09-23 — Test harness

- The e2e fabric edges hit WireGuard's simultaneous-initiation race (both responses rejected, 5 s retry). Drop one side's initiations to keep tests fast.
- `peerEndpointRetryHeld` (20 s) blocks the retry loop after every endpoint change; a strict fabric that drops the first candidate stalls connection setup for 20 s.
- Unprivileged `unshare --user --map-root-user --net --mount --fork` supports veth moves (`ip link set dev X netns PID`), nft NAT and tc netem; tc and nft live in /usr/sbin. `$(cmd &)` hangs when the background job inherits the pipe.
