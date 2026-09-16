package path

import (
	"sync"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestIGRoutingTablesRemainRaceFreeDuringConcurrentRecalculation(t *testing.T) {
	// Given
	const nodeCount = 32
	const transientNode = mtypes.Vertex(500)
	g, err := NewGraph(nodeCount, true, mtypes.GraphRecalculateSetting{
		JitterTolerance:           0.001,
		JitterToleranceMultiplier: 1,
	}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("NewGraph() error = %v", err)
	}

	pongs := make([]mtypes.PongMsg, 0, nodeCount*(nodeCount-1))
	for src := mtypes.Vertex(1); src <= nodeCount; src++ {
		for dst := mtypes.Vertex(1); dst <= nodeCount; dst++ {
			if src == dst {
				continue
			}
			pongs = append(pongs, mtypes.PongMsg{
				Src_nodeID:  src,
				Dst_nodeID:  dst,
				Timediff:    float64((src+dst)%10+1) / 1000,
				TimeToAlive: 3600,
			})
		}
	}
	g.UpdateLatencyMulti(pongs, true, false)

	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(4)

	// When
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			g.RecalculateNhTable(true)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			g.FloydWarshall(false)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			g.RemoveVirt(transientNode, false, false)
			g.UpdateLatency(transientNode, 1, 0.001, 3600, 0, true, true)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for i := 0; i < 100; i++ {
			_ = g.Next(1, nodeCount)
			_ = g.GetDtst(true)[1][nodeCount]
			_ = g.GetBoardcastList(1)
			_, _ = g.Path(1, nodeCount)
		}
	}()

	close(start)
	workers.Wait()

	// Then
	g.UpdateLatency(1, nodeCount, 0.0001, 3600, 0, true, false)
	g.RecalculateNhTable(false)
	if got := g.Next(1, nodeCount); got != nodeCount {
		t.Fatalf("Next(1, %d) = %d, want direct next hop %d", nodeCount, got, nodeCount)
	}
}
