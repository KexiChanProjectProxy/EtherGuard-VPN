#!/bin/bash
# Runs inside: unshare --user --map-root-user --net --mount --fork
# This namespace is edge B's host (two uplinks). Children: nat1, nat2, inet.
set -u
S=$1; MODE=${2:-metric}
export PATH=$PATH:/usr/sbin:/sbin
cd $S
mkns() { unshare --net sleep infinity >/dev/null 2>&1 & echo $!; }
P1=$(mkns); P2=$(mkns); PI=$(mkns); sleep 0.3
nsx() { local p=$1; shift; nsenter --net=/proc/$p/ns/net "$@"; }
ip link set lo up
for p in $P1 $P2 $PI; do nsx $p ip link set lo up; done
# edge B <-> NATs
ip link add name wan1 type veth peer name n1in netns $P1
ip link add name wan2 type veth peer name n2in netns $P2
ip addr add 192.0.2.2/24 dev wan1; ip link set wan1 up
ip addr add 198.51.100.2/24 dev wan2; ip link set wan2 up
nsx $P1 ip addr add 192.0.2.1/24 dev n1in; nsx $P1 ip link set n1in up
nsx $P2 ip addr add 198.51.100.1/24 dev n2in; nsx $P2 ip link set n2in up
# NATs <-> inet
nsx $P1 ip link add name n1out type veth peer name i1 netns $PI
nsx $P2 ip link add name n2out type veth peer name i2 netns $PI
nsx $P1 ip addr add 203.0.113.11/32 dev n1out; nsx $P1 ip link set n1out up; nsx $P1 ip route add default dev n1out
nsx $P2 ip addr add 203.0.113.12/32 dev n2out; nsx $P2 ip link set n2out up; nsx $P2 ip route add default dev n2out
nsx $PI ip addr add 203.0.113.100/32 dev lo
nsx $PI ip link set i1 up; nsx $PI ip link set i2 up
nsx $PI ip route add 203.0.113.11/32 dev i1; nsx $PI ip route add 203.0.113.12/32 dev i2
nat() {
  nsx $1 sysctl -qw net.ipv4.ip_forward=1
  printf 'table ip nat {
  chain post {
    type nat hook postrouting priority 100; policy accept;
    oifname "%s" masquerade
  }
}
' $2 | nsx $1 nft -f - && echo "nat ok on $2"
}
nat $P1 n1out
nat $P2 n2out
# edge B routing: two default routes, or policy routing for wan2
if [ "$MODE" = metric ]; then
  ip route add default via 192.0.2.1 dev wan1 metric 100
  ip route add default via 198.51.100.1 dev wan2 metric 200
else
  ip route add default via 192.0.2.1 dev wan1 metric 100
  ip rule add from 198.51.100.2 table 200
  ip route add default via 198.51.100.1 dev wan2 table 200
fi
echo "== routes ($MODE)"; ip route; ip rule | grep -v "^0:\|32766\|32767"
# services in inet: STUN, Super, edge A (node 1)
nsx $PI ./stunsrv.bin 203.0.113.100 > stun.log 2>&1 &
nsx $PI ./eg -mode super -config cfg/EgNet_super.yaml > super.log 2>&1 &
sleep 1
nsx $PI ./eg -mode edge -config cfg/EgNet_edge1.yaml > edgeA.log 2>&1 &
# edge B (node 2) on the multi-WAN host
./eg -mode edge -config cfg/EgNet_edge2.yaml > edgeB.log 2>&1 &
( timeout 60 tcpdump -lni wan1 -c 400 udp > tcpdump_wan1.log 2>&1 & timeout 60 tcpdump -lni wan2 -c 400 udp > tcpdump_wan2.log 2>&1 & )
sleep 20
echo "== phase1 done"
# Phase 2: slow down B's current uplink toward inet and watch both edges switch
cur=$(grep -o "switched to lower-latency path.*" edgeA.log edgeB.log | tail -2)
tc qdisc add dev wan1 root netem delay 60ms
nsx $PI tc qdisc add dev i1 root netem delay 60ms
echo "== netem on wan1 path at $(date +%T)"
sleep 25
tc qdisc del dev wan1 root; nsx $PI tc qdisc del dev i1 root
tc qdisc add dev wan2 root netem delay 60ms
nsx $PI tc qdisc add dev i2 root netem delay 60ms
echo "== netem moved to wan2 path at $(date +%T)"
sleep 25
echo "== done"
kill $(jobs -p) 2>/dev/null; pkill -P $$ 2>/dev/null
kill $P1 $P2 $PI 2>/dev/null
sleep 1
