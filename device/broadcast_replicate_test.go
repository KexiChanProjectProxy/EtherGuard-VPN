package device

import (
	"sort"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func newP2PTestDevice(t *testing.T) *Device {
	t.Helper()
	device := newPureP2PTestDevice(t)
	device.EdgeConfig.DynamicRoute.P2P.PureP2P = false
	return device
}

type sentCopy struct{ peer, dst mtypes.Vertex }

func sortedCopies(sent []pureSent) []sentCopy {
	out := make([]sentCopy, 0, len(sent))
	for _, s := range sent {
		out = append(out, sentCopy{peer: s.peer.ID, dst: s.dst})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].dst != out[j].dst {
			return out[i].dst < out[j].dst
		}
		return out[i].peer < out[j].peer
	})
	return out
}

// In P2P mode a broadcast leaves as one unicast copy per destination, each
// handed to that destination's next hop, so delivery no longer depends on a
// relay's graph agreeing with the origin's.
func TestP2PBoardcastPacketReplicatesPerDestination(t *testing.T) {
	device := newP2PTestDevice(t)
	addTestPeer(device, 50, true)
	addTestPeer(device, 51, true)
	addTestPeer(device, 57, true)
	pong := func(u, v mtypes.Vertex, s float64) []mtypes.PongMsg {
		return []mtypes.PongMsg{
			{Src_nodeID: u, Dst_nodeID: v, Timediff: s, TimeToAlive: 3600},
			{Src_nodeID: v, Dst_nodeID: u, Timediff: s, TimeToAlive: 3600},
		}
	}
	var pongs []mtypes.PongMsg
	pongs = append(pongs, pong(1, 50, 0.020)...)
	pongs = append(pongs, pong(1, 51, 0.010)...)
	pongs = append(pongs, pong(1, 57, 0.030)...) // slower than 1 -> 51 -> 57
	pongs = append(pongs, pong(51, 57, 0.012)...)
	device.graph.UpdateLatencyMulti(pongs, true, false)

	frame := dataFrame(mtypes.NodeID_Broadcast)
	device.BoardcastPacket(map[mtypes.Vertex]bool{}, path.NormalPacket, 200, frame, MessageTransportOffsetContent)

	got := sortedCopies(drainPureSent(t, device))
	want := []sentCopy{{peer: 50, dst: 50}, {peer: 51, dst: 51}, {peer: 51, dst: 57}}
	if len(got) != len(want) {
		t.Fatalf("copies = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("copies = %+v, want %+v", got, want)
		}
	}
	header, _ := path.NewEgHeader(frame[:path.EgHeaderLen], 1400)
	if header.GetDst() != mtypes.NodeID_Broadcast {
		t.Fatalf("caller's frame dst = %v, want broadcast (must not be modified)", header.GetDst())
	}
}

func TestP2PBoardcastPacketHonoursSkipList(t *testing.T) {
	device := newP2PTestDevice(t)
	addTestPeer(device, 50, true)
	addTestPeer(device, 51, true)
	device.graph.UpdateLatencyMulti([]mtypes.PongMsg{
		{Src_nodeID: 1, Dst_nodeID: 50, Timediff: 0.01, TimeToAlive: 3600},
		{Src_nodeID: 1, Dst_nodeID: 51, Timediff: 0.01, TimeToAlive: 3600},
	}, true, false)

	device.BoardcastPacket(map[mtypes.Vertex]bool{50: true}, path.NormalPacket, 200, dataFrame(mtypes.NodeID_Broadcast), MessageTransportOffsetContent)

	got := sortedCopies(drainPureSent(t, device))
	if len(got) != 1 || got[0] != (sentCopy{peer: 51, dst: 51}) {
		t.Fatalf("copies = %+v, want only 51", got)
	}
}
