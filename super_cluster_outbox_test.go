package main

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestClusterOutboxRegisterReportAliveDelete(t *testing.T) {
	// Given a clustered state with a frozen clock and an event collector.
	now := time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC)
	var events []mtypes.ControlV2Event
	state := NewControlState(ControlStateConfig{
		SelfID:           7,
		PeerAliveTimeout: time.Minute,
		Now:              func() time.Time { return now },
		Publish:          func(event mtypes.ControlV2Event) { events = append(events, event) },
	})
	if !state.ClusterEnabled() {
		t.Fatal("cluster state with non-zero SelfID is disabled")
	}

	// When the peer registers.
	if _, err := state.Register(context.Background(), controlRegisterRequest(101, "edge-101"), "key-101"); err != nil {
		t.Fatalf("register: %v", err)
	}
	mutations, resync := state.DrainOutbox()

	// Then registration produces one versioned peer_upsert.
	if resync || len(mutations) != 1 {
		t.Fatalf("register drain = %d mutations, resync=%v", len(mutations), resync)
	}
	registerMutation := mutations[0]
	if registerMutation.Kind != "peer_upsert" || registerMutation.NodeID != 101 || registerMutation.Peer == nil {
		t.Fatalf("register mutation = %#v", registerMutation)
	}
	version1 := registerMutation.Version
	if version1.IsZero() || version1.Origin != 7 || registerMutation.Origin != 7 || registerMutation.Peer.Version != version1 || registerMutation.Peer.Origin != 7 {
		t.Fatalf("register version/origin = mutation %#v peer %#v", registerMutation, registerMutation.Peer)
	}
	revisionAfterRegister := state.Revision()
	eventsAfterRegister := len(events)

	// When an identical heartbeat-only report arrives.
	now = now.Add(time.Second)
	if err := state.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 101}); err != nil {
		t.Fatalf("heartbeat report: %v", err)
	}
	mutations, resync = state.DrainOutbox()

	// Then it produces peer_alive with a newer version but no revision or SSE event.
	if resync || len(mutations) != 1 {
		t.Fatalf("heartbeat drain = %d mutations, resync=%v", len(mutations), resync)
	}
	aliveMutation := mutations[0]
	if aliveMutation.Kind != "peer_alive" || aliveMutation.Alive == nil || aliveMutation.Alive.NodeID != 101 {
		t.Fatalf("heartbeat mutation = %#v", aliveMutation)
	}
	version2 := aliveMutation.Version
	if !version1.Less(version2) || aliveMutation.Alive.Version != version2 || !aliveMutation.Alive.LastSeen.Equal(now) {
		t.Fatalf("heartbeat version/payload = %#v after %#v", aliveMutation, version1)
	}
	if state.Revision() != revisionAfterRegister || len(events) != eventsAfterRegister {
		t.Fatalf("heartbeat changed revision/events: %d/%d -> %d/%d", revisionAfterRegister, eventsAfterRegister, state.Revision(), len(events))
	}

	// When the peer reports a new candidate and its own observed-endpoint vote.
	now = now.Add(time.Second)
	report := mtypes.ControlV2ReportRequest{
		NodeID: 101,
		Candidates: []mtypes.ControlV2Candidate{{
			Address: "198.51.100.101:51820",
			Source:  mtypes.ControlV2CandidateSTUN,
		}},
		Observed: []mtypes.ControlV2ObservedEndpoint{{
			TargetNodeID: 202,
			Address:      "203.0.113.202:51820",
		}},
	}
	if err := state.Report(context.Background(), report); err != nil {
		t.Fatalf("changed report: %v", err)
	}
	mutations, resync = state.DrainOutbox()

	// Then the upsert is newer and its immutable candidate view matches snapshots.
	if resync || len(mutations) != 1 || mutations[0].Kind != "peer_upsert" || mutations[0].Peer == nil {
		t.Fatalf("changed report drain = %#v, resync=%v", mutations, resync)
	}
	upsertMutation := mutations[0]
	version3 := upsertMutation.Version
	if !version2.Less(version3) || upsertMutation.Peer.Version != version3 {
		t.Fatalf("changed report version = %#v after %#v", version3, version2)
	}
	if !reflect.DeepEqual(upsertMutation.Peer.Observed, report.Observed) {
		t.Fatalf("replicated observed votes = %#v, want %#v", upsertMutation.Peer.Observed, report.Observed)
	}
	wantCandidate := mtypes.ControlV2Candidate{Address: "198.51.100.101:51820", Source: mtypes.ControlV2CandidateSTUN}
	if !reflect.DeepEqual(upsertMutation.Peer.Candidates, []mtypes.ControlV2Candidate{wantCandidate}) {
		t.Fatalf("replicated candidates = %#v", upsertMutation.Peer.Candidates)
	}
	snapshotPeer := observedPeer(t, state.SnapshotFor(202), 101)
	mutationView := mtypes.ControlV2Peer{
		NodeID:      upsertMutation.Peer.NodeID,
		NodeName:    upsertMutation.Peer.NodeName,
		PubKey:      upsertMutation.Peer.PubKey,
		LocalV4:     []string{},
		LocalV6:     []string{},
		PublicV4:    []string{},
		PublicV6:    []string{},
		RelayCostMS: cloneFloat64Ptr(upsertMutation.Peer.RelayCostMS),
		LatencyMS:   cloneLatency(upsertMutation.Peer.LatencyMS),
		LastSeen:    upsertMutation.Peer.LastSeen,
	}
	mergeCandidatesIntoView(&mutationView, upsertMutation.Peer.Candidates)
	mutationView.LocalV4 = append([]string{}, mutationView.LocalV4...)
	mutationView.LocalV6 = append([]string{}, mutationView.LocalV6...)
	mutationView.PublicV4 = append([]string{}, mutationView.PublicV4...)
	mutationView.PublicV6 = append([]string{}, mutationView.PublicV6...)
	if !reflect.DeepEqual(mutationView, snapshotPeer) {
		t.Fatalf("mutation candidate view = %#v, snapshot view = %#v", mutationView, snapshotPeer)
	}
	upsertMutation.Peer.Candidates[0].Address = "192.0.2.1:1"
	if got := observedPeer(t, state.SnapshotFor(202), 101).PublicV4; len(got) != 1 || got[0] != wantCandidate.Address {
		t.Fatalf("outbox payload aliases state: %#v", got)
	}

	// When the peer exceeds its alive timeout and is swept.
	now = now.Add(time.Minute + time.Nanosecond)
	if removed := state.SweepTimeouts(); removed != 1 {
		t.Fatalf("sweep removed %d peers, want 1", removed)
	}
	mutations, resync = state.DrainOutbox()

	// Then the delete has the next version and the live tombstone matches it.
	if resync || len(mutations) != 1 || mutations[0].Kind != "peer_delete" || mutations[0].NodeID != 101 {
		t.Fatalf("delete drain = %#v, resync=%v", mutations, resync)
	}
	version4 := mutations[0].Version
	if !version3.Less(version4) || state.liveTombstones[101] != version4 {
		t.Fatalf("delete version/tombstone = %#v / %#v after %#v", version4, state.liveTombstones[101], version3)
	}
}

func TestClusterOutboxOverflowSetsResync(t *testing.T) {
	// Given single-Super mode, which keeps a bounded history while cluster links are disabled.
	state := NewControlState(ControlStateConfig{})
	if state.ClusterEnabled() {
		t.Fatal("zero SelfID unexpectedly enabled clustering")
	}
	if _, err := state.Register(context.Background(), controlRegisterRequest(101, "edge-101"), "key-101"); err != nil {
		t.Fatalf("register: %v", err)
	}

	// When 4097 accepted mutations are produced without draining.
	for i := 0; i < 4096; i++ {
		if err := state.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 101}); err != nil {
			t.Fatalf("report %d: %v", i, err)
		}
	}
	mutations, resync := state.DrainOutbox()

	// Then the overflowing delta set is discarded and a full resync is requested.
	if !resync || len(mutations) != 0 {
		t.Fatalf("overflow drain = %d mutations, resync=%v", len(mutations), resync)
	}
}

func TestClusterOutboxOrderMatchesVersion(t *testing.T) {
	// Given a clustered state shared by concurrent local writers.
	state := NewControlState(ControlStateConfig{SelfID: 9})
	const (
		workers    = 16
		operations = 100
	)
	errCh := make(chan error, workers)
	var wg sync.WaitGroup

	// When each writer performs an ordered mix of Register and Report calls.
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			nodeID := mtypes.Vertex(100 + worker)
			for operation := 0; operation < operations; operation++ {
				if operation%2 == 0 {
					_, err := state.Register(context.Background(), controlRegisterRequest(nodeID, fmt.Sprintf("edge-%d", nodeID)), fmt.Sprintf("key-%d", nodeID))
					if err != nil {
						errCh <- fmt.Errorf("worker %d register %d: %w", worker, operation, err)
						return
					}
					continue
				}
				if err := state.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: nodeID}); err != nil {
					errCh <- fmt.Errorf("worker %d report %d: %w", worker, operation, err)
					return
				}
			}
		}(worker)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	mutations, resync := state.DrainOutbox()

	// Then each node's drained mutation order agrees with strictly increasing versions and sequences.
	if resync || len(mutations) != workers*operations {
		t.Fatalf("ordered drain = %d mutations, resync=%v", len(mutations), resync)
	}
	lastVersion := make(map[mtypes.Vertex]ClusterVersion, workers)
	lastSequence := make(map[mtypes.Vertex]uint64, workers)
	for _, mutation := range mutations {
		if previous, ok := lastVersion[mutation.NodeID]; ok && !previous.Less(mutation.Version) {
			t.Fatalf("node %d version order: %#v then %#v", mutation.NodeID, previous, mutation.Version)
		}
		if previous, ok := lastSequence[mutation.NodeID]; ok && mutation.Seq <= previous {
			t.Fatalf("node %d sequence order: %d then %d", mutation.NodeID, previous, mutation.Seq)
		}
		lastVersion[mutation.NodeID] = mutation.Version
		lastSequence[mutation.NodeID] = mutation.Seq
	}
}

func TestClusterOutboxNoIOUnderLock(t *testing.T) {
	// Given a publish callback that immediately re-enters the state through DrainOutbox.
	callbackRan := make(chan struct{})
	var state *ControlState
	state = NewControlState(ControlStateConfig{
		SelfID: 12,
		Publish: func(mtypes.ControlV2Event) {
			state.DrainOutbox()
			close(callbackRan)
		},
	})
	finished := make(chan error, 1)

	// When registration emits its existing peer_change event.
	go func() {
		_, err := state.Register(context.Background(), controlRegisterRequest(101, "edge-101"), "key-101")
		finished <- err
	}()

	// Then the callback and registration both complete without deadlocking on ControlState.mu.
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("register: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("register deadlocked while publish callback drained the outbox")
	}
	select {
	case <-callbackRan:
	case <-time.After(2 * time.Second):
		t.Fatal("publish callback did not complete")
	}
}
