//go:build membudget

package main

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const clusterMemoryBudgetBytes = 48 << 20

type clusterMemoryBudgetRecord struct {
	register   mtypes.ControlV2RegisterRequest
	controlKey string
	report     mtypes.ControlV2ReportRequest
}

func TestClusterMemoryBudget(t *testing.T) {
	workload := buildClusterMemoryBudgetWorkload()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	topology := newE2EMultiSuperTopology(t, 3, e2eClusterOptions{
		heartbeat:   time.Hour,
		deadAfter:   2 * time.Hour,
		compression: "zstd",
	})
	for left := range topology.supers {
		for right := range topology.supers {
			if left != right {
				WaitLinked(t, topology, left, right, 3*time.Second)
			}
		}
	}
	fixedTime := time.Date(2041, time.February, 3, 4, 5, 6, 0, time.UTC)
	setE2EClusterClocks(topology, fixedTime)

	state := topology.supers[0].runtime.State()
	for recordIndex, record := range workload {
		if _, err := state.Register(context.Background(), record.register, record.controlKey); err != nil {
			t.Fatalf("register memory-budget edge %d: %v", record.register.NodeID, err)
		}
		if (recordIndex+1)%100 == 0 || recordIndex+1 == len(workload) {
			for superIndex := 1; superIndex < len(topology.supers); superIndex++ {
				WaitApplied(t, topology, superIndex, record.register.NodeID, func(peer mtypes.ControlV2Peer) bool {
					return peer.PubKey == record.register.PubKey
				}, 5*time.Second)
			}
		}
	}
	awaitE2E(t, 15*time.Second, func() bool { return clusterMemoryTopologySettled(topology) })

	for round := 1; round <= 2; round++ {
		setE2EClusterClocks(topology, fixedTime.Add(time.Duration(round)*100*time.Millisecond))
		wantLastSeen := topology.supers[0].clock.Now().Round(0).UTC()
		for recordIndex, record := range workload {
			if err := state.Report(context.Background(), record.report); err != nil {
				t.Fatalf("report memory-budget edge %d round %d: %v", record.report.NodeID, round, err)
			}
			if (recordIndex+1)%20 == 0 || recordIndex+1 == len(workload) {
				for superIndex := 1; superIndex < len(topology.supers); superIndex++ {
					WaitApplied(t, topology, superIndex, record.report.NodeID, func(peer mtypes.ControlV2Peer) bool {
						return peer.LastSeen.Round(0).UTC().Equal(wantLastSeen)
					}, 5*time.Second)
				}
			}
		}
		awaitE2E(t, 15*time.Second, func() bool { return clusterMemoryTopologySettled(topology) })
	}

	for superIndex := range topology.supers {
		live, tombstones := topology.supers[superIndex].runtime.State().ExportLive()
		if len(live) != len(workload) || len(tombstones) != 0 {
			t.Fatalf("super %d live/tombstone counts = %d/%d, want %d/0", superIndex, len(live), len(tombstones), len(workload))
		}
		for peerIndex := range topology.supers {
			if superIndex == peerIndex {
				continue
			}
			counts := topology.supers[superIndex].runtime.Cluster().CodecInstancesForTest(topology.supers[peerIndex].id)
			if counts.Encoders != 1 || counts.Decoders != 1 {
				t.Fatalf("super %d link to %d codec instances = %+v, want one encoder and one decoder", superIndex, peerIndex, counts)
			}
		}
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	delta := uint64(0)
	if after.HeapInuse > before.HeapInuse {
		delta = after.HeapInuse - before.HeapInuse
	}
	t.Logf("HeapInuse delta: %d bytes (%.2f MiB); before=%d after=%d", delta, float64(delta)/(1<<20), before.HeapInuse, after.HeapInuse)
	if delta >= clusterMemoryBudgetBytes {
		t.Fatalf("HeapInuse delta = %d bytes, want < %d bytes", delta, clusterMemoryBudgetBytes)
	}
	runtime.KeepAlive(topology)
}

func buildClusterMemoryBudgetWorkload() []clusterMemoryBudgetRecord {
	const (
		recordCount     = 500
		firstEdgeNodeID = 2001
	)
	fixedTime := time.Date(2041, time.February, 3, 4, 5, 6, 0, time.UTC)
	workload := make([]clusterMemoryBudgetRecord, recordCount)
	for recordIndex := range recordCount {
		nodeID := mtypes.Vertex(firstEdgeNodeID + recordIndex)
		targetIndex := (recordIndex + 1) % recordCount
		targetID := mtypes.Vertex(firstEdgeNodeID + targetIndex)
		thirdOctet := recordIndex/250 + 1
		fourthOctet := recordIndex%250 + 1
		localAddress := fmt.Sprintf("10.41.%d.%d:%d", thirdOctet, fourthOctet, 20000+recordIndex)
		publicAddress := fmt.Sprintf("198.18.%d.%d:%d", thirdOctet, fourthOctet, 30000+recordIndex)
		targetThirdOctet := targetIndex/250 + 1
		targetFourthOctet := targetIndex%250 + 1
		observedAddress := fmt.Sprintf("203.0.%d.%d:%d", targetThirdOctet, targetFourthOctet, 40000+targetIndex)
		workload[recordIndex] = clusterMemoryBudgetRecord{
			register: mtypes.ControlV2RegisterRequest{
				NodeID:         nodeID,
				NodeName:       fmt.Sprintf("memory-edge-%04d", nodeID),
				PubKey:         fmt.Sprintf("memory-public-key-%04d-repetitive-fixture", nodeID),
				Version:        mtypes.ControlV2ProtocolVersion,
				ListenPort:     20000 + recordIndex,
				LocalV4:        []string{localAddress},
				PublicV4:       []string{publicAddress},
				DesiredTTL:     64,
				RequestedAt:    fixedTime,
				Implementation: "cluster-memory-budget-fixture",
			},
			controlKey: fmt.Sprintf("memory-control-key-%04d-repetitive-fixture", nodeID),
			report: mtypes.ControlV2ReportRequest{
				NodeID: nodeID,
				Candidates: []mtypes.ControlV2Candidate{
					{Address: localAddress, Source: mtypes.ControlV2CandidateLocal},
					{Address: publicAddress, Source: mtypes.ControlV2CandidateSTUN},
				},
				Observed: []mtypes.ControlV2ObservedEndpoint{{
					TargetNodeID: targetID,
					Address:      observedAddress,
				}},
				ReportedAt: fixedTime,
			},
		}
	}
	return workload
}

func clusterMemoryTopologySettled(topology *e2eMultiSuper) bool {
	for superIndex := range topology.supers {
		state := topology.supers[superIndex].runtime.State()
		state.mu.RLock()
		outboxEmpty := len(state.outbox) == 0 && !state.resyncNeeded
		state.mu.RUnlock()
		if !outboxEmpty {
			return false
		}

		manager := topology.supers[superIndex].runtime.Cluster()
		manager.mu.Lock()
		peers := make([]*clusterLinkPeer, 0, len(manager.peers))
		for _, peer := range manager.peers {
			peers = append(peers, peer)
		}
		manager.mu.Unlock()
		for _, peer := range peers {
			if peer.queue.Len() != 0 || peer.session == nil || peer.session.closed() || len(peer.session.sendCh) != 0 {
				return false
			}
		}
	}
	for left := range topology.supers {
		for right := range topology.supers {
			if left == right {
				continue
			}
			leftStats := LinkStats(topology, left, right)
			rightStats := LinkStats(topology, right, left)
			if leftStats.TX.Messages != rightStats.RX.Messages {
				return false
			}
		}
	}
	return true
}
