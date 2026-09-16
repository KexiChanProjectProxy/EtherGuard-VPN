package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const superRuntimeSweepPeerAlive = 50 * time.Millisecond

type superRuntimeSweepPair struct {
	a      *superRuntime
	b      *superRuntime
	aClock *e2eClock
	bClock *e2eClock
}

type superRuntimeSweepOptions struct {
	aPeerAlive time.Duration
	bPeerAlive time.Duration
}

func TestSuperRuntimeRemoteRecordsSurviveLocalTimeoutWhileLinked(t *testing.T) {
	// Given two linked runtimes with a remote record from A and a local sweep sentinel on B.
	pair := newSuperRuntimeSweepPair(t, superRuntimeSweepOptions{
		aPeerAlive: superRuntimeSweepPeerAlive,
		bPeerAlive: superRuntimeSweepPeerAlive,
	})
	waitForSuperRuntimeSweep(t, "cluster link to connect", func() bool {
		return superRuntimeSweepLinkIs(pair.b, "connected")
	})
	if err := pair.a.RegisterTestPeer(101, "edge-a", "edge-a-key"); err != nil {
		t.Fatalf("register remote peer on A: %v", err)
	}
	if err := pair.b.RegisterTestPeer(102, "edge-b-sweep-sentinel", "edge-b-key"); err != nil {
		t.Fatalf("register local sweep sentinel on B: %v", err)
	}
	waitForSuperRuntimeSweep(t, "A peer to replicate to B", func() bool {
		return superRuntimeSweepHasPeer(pair.b, 101)
	})

	// When B's frozen clock advances beyond ten local peer-alive timeouts.
	pair.bClock.Advance(11 * superRuntimeSweepPeerAlive)
	waitForSuperRuntimeSweep(t, "B ticker to remove its local sentinel", func() bool {
		return !superRuntimeSweepHasPeer(pair.b, 102)
	})

	// Then the same ticker pass retains A's remote-origin record while the link stays up.
	if !superRuntimeSweepHasPeer(pair.b, 101) {
		t.Fatal("B evicted A's remote-origin peer while the cluster link was up")
	}
	if !superRuntimeSweepLinkIs(pair.b, "connected") {
		t.Fatal("cluster link went down during linked remote-retention test")
	}
}

func TestSuperRuntimeRemoteRecordsEvictedAfterGraceWhenLinkDown(t *testing.T) {
	// Given a replicated A-origin record on B.
	pair := newSuperRuntimeSweepPair(t, superRuntimeSweepOptions{
		aPeerAlive: superRuntimeSweepPeerAlive,
		bPeerAlive: superRuntimeSweepPeerAlive,
	})
	waitForSuperRuntimeSweep(t, "cluster link to connect", func() bool {
		return superRuntimeSweepLinkIs(pair.b, "connected")
	})
	if err := pair.a.RegisterTestPeer(101, "edge-a", "edge-a-key"); err != nil {
		t.Fatalf("register peer on A: %v", err)
	}
	waitForSuperRuntimeSweep(t, "A peer to replicate to B", func() bool {
		return superRuntimeSweepHasPeer(pair.b, 101)
	})

	// When A stops, B observes the origin link down, and B's clock advances past grace.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := pair.a.Shutdown(shutdownCtx); err != nil {
		shutdownCancel()
		t.Fatalf("shutdown A: %v", err)
	}
	shutdownCancel()
	waitForSuperRuntimeSweep(t, "B to observe A link down", func() bool {
		return superRuntimeSweepLinkIs(pair.b, "down")
	})
	if !superRuntimeSweepHasPeer(pair.b, 101) {
		t.Fatal("B evicted A's peer before remote stale grace elapsed")
	}
	managerCtx, managerCancel := context.WithTimeout(context.Background(), 3*time.Second)
	if err := pair.b.Cluster().Shutdown(managerCtx); err != nil {
		managerCancel()
		t.Fatalf("stop B cluster manager: %v", err)
	}
	managerCancel()
	pair.b.State().DrainOutbox()
	pair.bClock.Advance(1100 * time.Millisecond)
	waitForSuperRuntimeSweep(t, "B ticker to evict A peer after grace", func() bool {
		return !superRuntimeSweepHasPeer(pair.b, 101)
	})

	// Then grace eviction is local-only: no live tombstone and no peer_delete mutation.
	if superRuntimeSweepHasTombstone(pair.b.State(), 101) {
		t.Fatal("remote grace eviction created a live tombstone on B")
	}
	mutations, resync := pair.b.State().DrainOutbox()
	if resync {
		t.Fatal("remote grace eviction unexpectedly requested a full resync")
	}
	for _, mutation := range mutations {
		if mutation.Kind == clusterMessagePeerDelete && mutation.NodeID == 101 {
			t.Fatal("remote grace eviction emitted peer_delete from B")
		}
	}
}

func TestSuperRuntimeLocalSweepReplicatesDelete(t *testing.T) {
	// Given an A-local edge replicated to B, whose clock and longer timeout remain untouched.
	pair := newSuperRuntimeSweepPair(t, superRuntimeSweepOptions{
		aPeerAlive: superRuntimeSweepPeerAlive,
		bPeerAlive: time.Second,
	})
	waitForSuperRuntimeSweep(t, "cluster link to connect", func() bool {
		return superRuntimeSweepLinkIs(pair.b, "connected")
	})
	if err := pair.a.RegisterTestPeer(101, "edge-a", "edge-a-key"); err != nil {
		t.Fatalf("register peer on A: %v", err)
	}
	waitForSuperRuntimeSweep(t, "A peer to replicate to B", func() bool {
		return superRuntimeSweepHasPeer(pair.b, 101)
	})

	// When only A's frozen clock advances beyond its local timeout.
	pair.aClock.Advance(2 * superRuntimeSweepPeerAlive)
	waitForSuperRuntimeSweep(t, "A ticker to sweep its local peer", func() bool {
		return !superRuntimeSweepHasPeer(pair.a, 101)
	})
	waitForSuperRuntimeSweep(t, "peer_delete to remove the B copy", func() bool {
		return !superRuntimeSweepHasPeer(pair.b, 101)
	})

	// Then B lost the record while linked and without advancing its own clock, proving replicated deletion.
	if !superRuntimeSweepLinkIs(pair.b, "connected") {
		t.Fatal("cluster link went down before replicated peer_delete reached B")
	}
	if !superRuntimeSweepHasTombstone(pair.a.State(), 101) {
		t.Fatal("A local timeout did not create a live tombstone")
	}

	// And the existing runtime ticker also reaches inline live-tombstone TTL maintenance.
	pair.aClock.Advance(minimumLiveTombstoneExpiry + time.Second)
	waitForSuperRuntimeSweep(t, "A ticker to expire the live tombstone", func() bool {
		return !superRuntimeSweepHasTombstone(pair.a.State(), 101)
	})
}

func newSuperRuntimeSweepPair(t *testing.T, options superRuntimeSweepOptions) superRuntimeSweepPair {
	t.Helper()
	edgeA := listenSuperRuntimeTest(t)
	manageA := listenSuperRuntimeTest(t)
	edgeB := listenSuperRuntimeTest(t)
	manageB := listenSuperRuntimeTest(t)
	clockA := newE2EClock()
	clockB := newE2EClock()

	type nodeConfig struct {
		selfID, peerID mtypes.Vertex
		edge, manage   net.Listener
		peerURL        string
		clock          *e2eClock
		peerAlive      time.Duration
	}
	start := func(node nodeConfig) *superRuntime {
		base := validBaseConfig()
		base.APIUrl = "http://" + node.edge.Addr().String()
		base.PeerAliveTimeoutSeconds = node.peerAlive.Seconds()
		base.Cluster = nil
		cluster := &mtypes.SuperConfigV2Cluster{
			SelfID: node.selfID, Secret: superRuntimeClusterTestSecret,
			Peers:                   []mtypes.SuperConfigV2ClusterPeer{{SuperID: node.peerID, APIUrl: node.peerURL}},
			HeartbeatSeconds:        0.5,
			DeadAfterSeconds:        1,
			ReconnectMinSeconds:     0.1,
			ReconnectMaxSeconds:     0.1,
			RemoteStaleGraceSeconds: 1,
			Compression:             "none",
		}
		if err := cluster.Validate(node.peerAlive.Seconds()); err != nil {
			t.Fatalf("validate cluster override for super %d: %v", node.selfID, err)
		}
		runtime, err := RunWithListeners(&superConfig{
			BaseConfig: base, EdgeTemplate: validEdgeTemplate(), ClusterOverride: cluster,
			ConfigDir: t.TempDir(), EdgeListen: node.edge, ManageListen: node.manage,
			ShutdownTimeout: 3 * time.Second, TickInterval: 10 * time.Millisecond, Now: node.clock.Now,
		})
		if err != nil {
			t.Fatalf("RunWithListeners(%d): %v", node.selfID, err)
		}
		return runtime
	}

	a := start(nodeConfig{
		selfID: 1, peerID: 2, edge: edgeA, manage: manageA,
		peerURL: "http://" + edgeB.Addr().String(), clock: clockA, peerAlive: options.aPeerAlive,
	})
	b := start(nodeConfig{
		selfID: 2, peerID: 1, edge: edgeB, manage: manageB,
		peerURL: "http://" + edgeA.Addr().String(), clock: clockB, peerAlive: options.bPeerAlive,
	})
	t.Cleanup(func() {
		shutdownSuperRuntimeForTest(t, a)
		shutdownSuperRuntimeForTest(t, b)
	})
	return superRuntimeSweepPair{a: a, b: b, aClock: clockA, bClock: clockB}
}

func waitForSuperRuntimeSweep(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", description)
		case <-ticker.C:
		}
	}
}

func superRuntimeSweepLinkIs(runtime *superRuntime, want string) bool {
	status := runtime.Cluster().Status()
	return len(status.Links) == 1 && status.Links[0].State == want
}

func superRuntimeSweepHasPeer(runtime *superRuntime, nodeID mtypes.Vertex) bool {
	for _, peer := range runtime.State().SnapshotFor(60000).Peers {
		if peer.NodeID == nodeID {
			return true
		}
	}
	return false
}

func superRuntimeSweepHasTombstone(state *ControlState, nodeID mtypes.Vertex) bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	_, ok := state.liveTombstones[nodeID]
	return ok
}
