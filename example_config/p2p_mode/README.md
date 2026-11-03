# Etherguard
[English](#) | [中文](README_zh.md)

## P2P Mode

P2P Mode is inspired by [tinc](https://github.com/gsliepen/tinc), There are no SuperNode. All EdgeNode will exchange information each other.  
EdgeNodes are keep trying to connect each other, and notify all other peers success or not.  
All edges runs [Floyd-Warshall Algorithm](https://en.wikipedia.org/wiki/Floyd–Warshall_algorithm) locally and find the best route by it self.  
**Not recommend to use this mode in production environment, not test yet.**

## Quick Start
First, edit the `gensp2p.yaml`

```yaml
Config output dir: /tmp/eg_gen_static    # Profile output location
Enable generated config overwrite: false # Allow overwrite while output the config
Add NodeID to the interface name: false  # Add NodeID to the interface name in generated edge config
ConfigTemplate for edge node: ""         # Profile Template
Network name: "EgNet"
Edge Node:
  MacAddress prefix: ""                 # Leave blank to generate randomly
  IPv4 range: 192.168.76.0/24           # By the way, the IP part can be omitted.
  IPv6 range: fd95:71cb:a3df:e586::/64  # The only purpose of this field is to call the ip command after startup to add an ip to the tap interface
  IPv6 LL range: fe80::a3df:0/112       # 
Edge Nodes:                             # Node related settings
  1:
    Endpoint(optional): 127.0.0.1:3001
  2:
    Endpoint(optional): 127.0.0.1:3002
  3:
    Endpoint(optional): 127.0.0.1:3003
  4:
    Endpoint(optional): 127.0.0.1:3004
  5:
    Endpoint(optional): 127.0.0.1:3005
  6:
    Endpoint(optional): 127.0.0.1:3006
```

Run this, it will generate the required configuration file
```
./etherguard-go -mode gencfg -cfgmode p2p -config example_config/p2p_mode/genp2p.yaml
```

Deploy these configuration files to the corresponding nodes, and then execute  
```
./etherguard-go -config [config path] -mode edge
```

you can turn off unnecessary logs to increase performance after it works.

## PureP2P mode

PureP2P makes EtherGuard a plain L2 overlay: every edge sits on one Ethernet segment with the peers it reaches directly, and nothing else. Edges still exchange peer information and keep trying to connect to every peer they learn about, but they never relay data and never compute routes. Routing and path selection are left to whatever runs on top of the tap, such as a routing daemon or an SDN controller.

```yaml
DynamicRoute:
  P2P:
    UseP2P: true
    PureP2P: true
    SendPeerInterval: 20
```

Packet | PureP2P behaviour
-------|:-----
Unicast data | Sent only when the destination is a live direct peer, otherwise dropped
Broadcast data | Sent to every live direct peer and never re-forwarded by receivers
Ping | Unchanged: sent to every peer with TTL 0 for liveness and hole punching
Pong | Sent straight back to the pinger instead of being flooded
QueryPeer / BroadcastPeer | Unchanged: flooded with the duplicate check, so peer information still crosses several hops

Peer discovery, endpoint retry and hole punching, lowest-latency endpoint selection, `EndpointBlacklist`, `SaveNewPeers` and `PersistentKeepalive` work as in normal P2P mode.

`GraphRecalculateSetting` and `NextHopTable` are ignored. NTP is turned off, because no one-way latency is used. The edge refuses to start when `PureP2P` is set without `UseP2P`, or together with a SuperNodeV2 block.

Run PureP2P on every node of a network or on none. A normal P2P node still floods pongs and expects other nodes to relay for it.

The upper layer can tell which neighbours are live from the UAPI peer state: `endpoint`, `last_handshake_time_sec` and `rx_bytes`.

## Lowest-latency endpoint selection

When a peer is alive and has more than one path (several known endpoints, or several local uplinks on Linux), the edge sends one encrypted probe per path each round and moves the peer to a faster path once it wins by a clear margin for several rounds in a row, or once it is faster in every round, however slightly, for a longer run. Probes keep alternate NAT mappings alive and never feed route latency. Tune it under `DynamicRoute`:

```yaml
DynamicRoute:
  DisableEndpointSelection: false   # turn selection off
  EndpointProbeInterval: 0          # seconds between rounds; 0 = SendPingInterval
  EndpointSwitchMarginMS: 0         # 0 = 5 ms
  EndpointSwitchMarginPercent: 0    # 0 = 15 %; the larger margin applies
  EndpointSwitchRounds: 0           # 0 = 3 consecutive rounds winning by the margin
  EndpointSwitchPersistRounds: 0    # 0 = 10 consecutive rounds faster in every sample, no margin
```

On Linux, the edge first asks the kernel (the same lookup `ip route get` performs) whether each leg has a real route, and leaves out legs that have none: IPv6 legs on a host without an IPv6 route, and IPv4 legs out of an interface that only reaches the peer because the kernel treats an unrouted destination as on-link, such as a WireGuard tunnel whose AllowedIPs do not cover the peer. Per-uplink STUN discovery uses the same check. Skipped legs are logged at verbose level as `Route check skipped leg`; if the lookup itself fails, the leg is kept.

Edges also share what they observe. Besides the endpoint an edge uses for each live peer, it advertises that peer's peer-reflexive addresses: sources of the peer's authenticated packets that it did not adopt, for example a multi-WAN peer's other uplinks. When an edge's own session to that peer is down, advertised addresses become retry candidates. While the session is up they are probe-only candidates for lowest-latency selection (at most six per peer, kept for at least two broadcast rounds), so a faster path learned from another edge is measured without disturbing the working one.

## Endpoint blacklist

`DynamicRoute.EndpointBlacklist` lists IP addresses or CIDRs (up to 256) that must never be used as a peer endpoint. Blacklisted addresses are removed from every peer's candidate list, are never probed or switched to, are not advertised as this edge's own endpoints, and datagrams from them are dropped. A peer currently on a blacklisted endpoint is moved to another candidate. The list is read at startup; an invalid entry, or setting it outside P2P mode, is a startup error. In Super mode use the Super's `EndpointBlacklist` parameter instead.

```yaml
DynamicRoute:
  EndpointBlacklist:
    - 203.0.113.12      # a single address
    - 100.64.0.0/10     # a whole range
```

[WIP]