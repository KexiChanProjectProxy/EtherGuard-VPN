package path

import (
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

// Node IDs from the 2026-11-28 incident: the origin (1), the relay it chose
// (51) and the destination that stopped hearing its broadcasts (57).
const (
	divOrigin mtypes.Vertex = 1
	divRelay  mtypes.Vertex = 51
	divDest   mtypes.Vertex = 57
)

// p2pGraph builds an edge graph with the production P2P settings
// (JitterTolerance 50 ms, multiplier 1.1).
func p2pGraph(t *testing.T) *IG {
	t.Helper()
	g, err := NewGraph(0, false, mtypes.GraphRecalculateSetting{
		JitterTolerance:           50,
		JitterToleranceMultiplier: 1.1,
		TimeoutCheckInterval:      5,
		RecalculateCoolDown:       5,
	}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}
	return g
}

// triangle returns symmetric one-way latencies (seconds) for 1, 51 and 57.
func triangle(originDest, originRelay, relayDest float64) []mtypes.PongMsg {
	edge := func(u, v mtypes.Vertex, s float64) []mtypes.PongMsg {
		return []mtypes.PongMsg{
			{Src_nodeID: u, Dst_nodeID: v, Timediff: s, TimeToAlive: 3600},
			{Src_nodeID: v, Dst_nodeID: u, Timediff: s, TimeToAlive: 3600},
		}
	}
	var pongs []mtypes.PongMsg
	pongs = append(pongs, edge(divOrigin, divDest, originDest)...)
	pongs = append(pongs, edge(divOrigin, divRelay, originRelay)...)
	pongs = append(pongs, edge(divRelay, divDest, relayDest)...)
	return pongs
}

// treeDelivery follows the P2P broadcast tree from origin the way the edges
// do: origin sends to GetBoardcastList(origin), and each receiver relays to
// GetBoardcastThroughList computed on its own graph. It returns the set of
// nodes that receive the frame.
func treeDelivery(origin mtypes.Vertex, views map[mtypes.Vertex]*IG) map[mtypes.Vertex]bool {
	got := map[mtypes.Vertex]bool{origin: true}
	type hop struct{ to, from mtypes.Vertex }
	queue := []hop{}
	for next := range views[origin].GetBoardcastList(origin) {
		queue = append(queue, hop{to: next, from: origin})
	}
	for len(queue) > 0 {
		h := queue[0]
		queue = queue[1:]
		if got[h.to] {
			continue
		}
		got[h.to] = true
		relays, _ := views[h.to].GetBoardcastThroughList(h.to, h.from, origin)
		for next := range relays {
			queue = append(queue, hop{to: next, from: h.to})
		}
	}
	return got
}

// Two graphs that are fed the same samples end up with different next hops
// when they recalculated at different moments, and stay that way: P2P mode
// only recalculates when a weight changes bucket (0-50 ms is one bucket with
// the production settings), while Floyd-Warshall uses the raw latencies.
func TestP2PGraphsFedSameSamplesStayDivergent(t *testing.T) {
	early := triangle(0.030, 0.010, 0.012) // direct 30 ms > 22 ms via 51
	late := triangle(0.020, 0.015, 0.012)  // direct 20 ms < 27 ms via 51

	origin := p2pGraph(t)
	origin.UpdateLatencyMulti(early, true, false)
	origin.UpdateLatencyMulti(late, true, false)

	relay := p2pGraph(t) // e.g. restarted, or first recalculated later
	relay.UpdateLatencyMulti(late, true, false)

	for i := 0; i < 5; i++ { // identical samples from now on
		origin.UpdateLatencyMulti(late, true, false)
		relay.UpdateLatencyMulti(late, true, false)
		origin.RecalculateNhTable(false)
		relay.RecalculateNhTable(false)
	}

	if got := origin.Next(divOrigin, divDest); got != divRelay {
		t.Fatalf("origin's next hop 1->57 = %v, want 51 (frozen at its first recalculation)", got)
	}
	if got := relay.Next(divOrigin, divDest); got != divDest {
		t.Fatalf("relay's next hop 1->57 = %v, want 57 (direct)", got)
	}
}

// When the origin's graph sends a destination through a relay whose own graph
// does not, the relay drops the broadcast: the destination never receives it,
// although unicast still reaches it hop by hop.
func TestP2PBroadcastTreeBlackHolesOnDivergentGraphs(t *testing.T) {
	origin := p2pGraph(t)
	origin.UpdateLatencyMulti(triangle(0.030, 0.010, 0.012), true, false)
	relay := p2pGraph(t)
	relay.UpdateLatencyMulti(triangle(0.020, 0.015, 0.012), true, false)
	dest := p2pGraph(t)
	dest.UpdateLatencyMulti(triangle(0.020, 0.015, 0.012), true, false)
	views := map[mtypes.Vertex]*IG{divOrigin: origin, divRelay: relay, divDest: dest}

	if got := treeDelivery(divOrigin, views); got[divDest] {
		t.Fatalf("broadcast reached 57 (%v); the tree was expected to black-hole it", got)
	}

	// Unicast is unaffected: origin hands the frame to 51 and 51 forwards it.
	if hop := origin.Next(divOrigin, divDest); hop != divRelay {
		t.Fatalf("origin unicast hop = %v, want 51", hop)
	}
	if hop := relay.Next(divRelay, divDest); hop != divDest {
		t.Fatalf("relay unicast hop = %v, want 57", hop)
	}

	// With identical graphs the same tree does deliver.
	same := map[mtypes.Vertex]*IG{divOrigin: origin, divRelay: origin, divDest: origin}
	if got := treeDelivery(divOrigin, same); !got[divDest] {
		t.Fatalf("broadcast with consistent graphs = %v, want 57 included", got)
	}
}
