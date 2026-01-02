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

## EdgeNode Config Parameter

P2P mode uses the same [EdgeConfig structure](../static_mode/README.md#EdgeConfig) as static mode, with dynamic routing enabled.

For detailed configuration parameters, refer to:
- [Interface](../static_mode/README.md#Interface) - Interface related config
- [LogLevel](../static_mode/README.md#LogLevel) - Log related settings
- [DynamicRoute](../super_mode/README.md#DynamicRoute) - Dynamic Route related settings
- [P2P](#P2P) - P2P mode specific settings
- [FakeTCP](#FakeTCP) - FakeTCP transport settings
- [Obfuscation](#Obfuscation) - Obfuscation settings
- [Peers](../static_mode/README.md#Peers) - Peer info

<a name="P2P"></a>P2P      | Description
--------------------|:-----
UseP2P                  | Enable P2P mode (must be true for P2P mode)
SendPeerInterval        | Interval to exchange peer information with other nodes (sec)
[GraphRecalculateSetting](../super_mode/README.md#GraphRecalculateSetting) | Floyd-Warshall algorithm related parameters

<a name="FakeTCP"></a>FakeTCP      | Description
--------------------|:-----
Enabled             | Enable FakeTCP transport for TCP obfuscation (default: true)
TunName             | TUN device name for FakeTCP (e.g., "etherguard-tcp0")
TunIPv4             | Local IPv4 address for TUN device (e.g., "192.168.200.1/24")
TunPeerIPv4         | Peer IPv4 address for TUN device (e.g., "192.168.200.2")
TunIPv6             | Local IPv6 address for TUN device (optional)
TunPeerIPv6         | Peer IPv6 address for TUN device (optional)
TunMTU              | MTU for TUN device (default: 1500)

<a name="Obfuscation"></a>Obfuscation      | Description
--------------------|:-----
Enabled             | Enable obfuscation with zero-overhead encryption (default: true)
PSK                 | Pre-shared key for obfuscation (32 bytes base64 encoded)<br>Leave empty to disable obfuscation

[WIP]