package main

// allow: SIZE_OK — the required manager integration matrix shares one real-HTTP topology fixture.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const clusterManagerTestSecret = "cluster-manager-shared-secret-2026"

type clusterManagerTestOptions struct {
	heartbeat time.Duration
	deadAfter time.Duration
	reconnect time.Duration
	grace     time.Duration
	peerAlive time.Duration
	badDial   map[[2]mtypes.Vertex]bool
}

type clusterManagerTestClock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *clusterManagerTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().UTC().Add(c.offset)
}

func (c *clusterManagerTestClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.offset += delta
	c.mu.Unlock()
}

type clusterManagerTestNode struct {
	id      mtypes.Vertex
	clock   *clusterManagerTestClock
	state   *ControlState
	manage  *ManageV2
	manager *clusterManager
	server  *httptest.Server
	dir     string

	published atomic.Int64
	started   bool
}

type clusterManagerTestTopology struct {
	ctx    context.Context
	cancel context.CancelFunc
	nodes  map[mtypes.Vertex]*clusterManagerTestNode
}

func newClusterManagerTestTopology(
	t *testing.T,
	ids []mtypes.Vertex,
	links [][2]mtypes.Vertex,
	opts clusterManagerTestOptions,
) *clusterManagerTestTopology {
	t.Helper()
	if opts.heartbeat == 0 {
		opts.heartbeat = 20 * time.Millisecond
	}
	if opts.deadAfter == 0 {
		opts.deadAfter = 200 * time.Millisecond
	}
	if opts.reconnect == 0 {
		opts.reconnect = 10 * time.Millisecond
	}
	if opts.peerAlive == 0 {
		opts.peerAlive = 100 * time.Millisecond
	}
	if opts.grace == 0 {
		opts.grace = 500 * time.Millisecond
	}

	ctx, cancel := context.WithCancel(context.Background())
	topology := &clusterManagerTestTopology{ctx: ctx, cancel: cancel, nodes: make(map[mtypes.Vertex]*clusterManagerTestNode, len(ids))}
	for _, id := range ids {
		node := &clusterManagerTestNode{
			id:    id,
			clock: &clusterManagerTestClock{},
			dir:   t.TempDir(),
		}
		node.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if node.manager == nil {
				http.Error(w, "cluster manager unavailable", http.StatusServiceUnavailable)
				return
			}
			node.manager.AcceptUpgrade(w, r)
		}))
		topology.nodes[id] = node
	}

	peerURLs := make(map[mtypes.Vertex]map[mtypes.Vertex]string, len(ids))
	for _, link := range links {
		left, right := topology.node(t, link[0]), topology.node(t, link[1])
		if peerURLs[left.id] == nil {
			peerURLs[left.id] = make(map[mtypes.Vertex]string)
		}
		if peerURLs[right.id] == nil {
			peerURLs[right.id] = make(map[mtypes.Vertex]string)
		}
		peerURLs[left.id][right.id] = right.server.URL
		peerURLs[right.id][left.id] = left.server.URL
	}
	for direction := range opts.badDial {
		if opts.badDial[direction] {
			peerURLs[direction[0]][direction[1]] = "http://127.0.0.1:1"
		}
	}

	for _, id := range ids {
		node := topology.node(t, id)
		peers := make([]mtypes.SuperConfigV2ClusterPeer, 0, len(peerURLs[id]))
		for peerID, apiURL := range peerURLs[id] {
			peers = append(peers, mtypes.SuperConfigV2ClusterPeer{SuperID: peerID, APIUrl: apiURL})
		}
		cluster := mtypes.SuperConfigV2Cluster{
			SelfID:                  id,
			Secret:                  clusterManagerTestSecret,
			Peers:                   peers,
			HeartbeatSeconds:        opts.heartbeat.Seconds(),
			DeadAfterSeconds:        opts.deadAfter.Seconds(),
			ReconnectMinSeconds:     opts.reconnect.Seconds(),
			ReconnectMaxSeconds:     (4 * opts.reconnect).Seconds(),
			RemoteStaleGraceSeconds: opts.grace.Seconds(),
			Compression:             "none",
		}
		base := validBaseConfig()
		base.NodeName = fmt.Sprintf("super-%d", id)
		base.APIUrl = node.server.URL
		base.PeerAliveTimeoutSeconds = opts.peerAlive.Seconds()
		base.Cluster = &cluster
		node.state = NewControlState(ControlStateConfig{
			Parameters:       buildControlV2Parameters(base),
			PeerAliveTimeout: opts.peerAlive,
			RemoteStaleGrace: opts.grace,
			SelfID:           id,
			Now:              node.clock.Now,
			Publish:          func(mtypes.ControlV2Event) { node.published.Add(1) },
		})
		manage, err := NewManageV2(ManageV2Config{
			State:        node.state,
			ConfigDir:    node.dir,
			BaseConfig:   base,
			EdgeTemplate: validEdgeTemplate(),
			PSKGen:       func() string { return fmt.Sprintf("manager-test-key-%d", id) },
		})
		if err != nil {
			t.Fatalf("new manage v2 for super %d: %v", id, err)
		}
		node.manage = manage
		node.manager = newClusterManager(clusterManagerConfig{
			Cluster:   &cluster,
			APIPrefix: mtypes.ControlV2APIPrefix,
			State:     node.state,
			Manage:    node.manage,
			HLC:       node.state.hlc,
			Now:       node.clock.Now,
		})
		if node.manager == nil {
			t.Fatalf("new cluster manager for super %d returned nil", id)
		}
	}

	t.Cleanup(func() {
		cancel()
		for _, node := range topology.nodes {
			if node.started {
				ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
				_ = node.manager.Shutdown(ctx)
				stop()
			}
		}
		for _, node := range topology.nodes {
			node.server.Close()
		}
	})
	return topology
}

func (topology *clusterManagerTestTopology) node(t *testing.T, id mtypes.Vertex) *clusterManagerTestNode {
	t.Helper()
	node := topology.nodes[id]
	if node == nil {
		t.Fatalf("missing cluster test node %d", id)
	}
	return node
}

func (topology *clusterManagerTestTopology) start(t *testing.T, ids ...mtypes.Vertex) {
	t.Helper()
	for _, id := range ids {
		node := topology.node(t, id)
		if node.started {
			continue
		}
		node.manager.Start(topology.ctx)
		node.started = true
	}
}

func (topology *clusterManagerTestTopology) startTogether(t *testing.T, ids ...mtypes.Vertex) {
	t.Helper()
	ready := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range ids {
		node := topology.node(t, id)
		if node.started {
			continue
		}
		node.started = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			node.manager.Start(topology.ctx)
		}()
	}
	close(ready)
	wg.Wait()
}

func (topology *clusterManagerTestTopology) shutdown(t *testing.T, id mtypes.Vertex, timeout time.Duration) error {
	t.Helper()
	node := topology.node(t, id)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := node.manager.Shutdown(ctx)
	node.started = false
	return err
}

func waitClusterManagerCondition(t *testing.T, timeout time.Duration, condition func() bool, description string) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
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

func waitClusterManagerLinked(t *testing.T, topology *clusterManagerTestTopology, left, right mtypes.Vertex) {
	t.Helper()
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		return clusterManagerLinkState(topology.node(t, left).manager.Status(), right) == "connected" &&
			clusterManagerLinkState(topology.node(t, right).manager.Status(), left) == "connected"
	}, fmt.Sprintf("supers %d and %d to link", left, right))
}

func clusterManagerLinkState(status clusterStatus, peerID mtypes.Vertex) string {
	for _, link := range status.Links {
		if link.SuperID == peerID {
			return link.State
		}
	}
	return ""
}

func clusterManagerStatusLink(t *testing.T, status clusterStatus, peerID mtypes.Vertex) clusterLinkStatus {
	t.Helper()
	for _, link := range status.Links {
		if link.SuperID == peerID {
			return link
		}
	}
	t.Fatalf("missing status link for peer %d: %#v", peerID, status.Links)
	return clusterLinkStatus{}
}

func clusterManagerEstablishedSessions(manager *clusterManager) int {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	count := 0
	for _, peer := range manager.peers {
		if peer.session != nil {
			count++
		}
	}
	return count
}

func clusterManagerSnapshotPeer(state *ControlState, nodeID mtypes.Vertex) (mtypes.ControlV2Peer, bool) {
	for _, peer := range state.SnapshotFor(60000).Peers {
		if peer.NodeID == nodeID {
			return peer, true
		}
	}
	return mtypes.ControlV2Peer{}, false
}

func clusterManagerRecordVersion(state *ControlState, nodeID mtypes.Vertex) (ClusterVersion, bool) {
	state.mu.RLock()
	defer state.mu.RUnlock()
	record, ok := state.peers[nodeID]
	if !ok {
		return ClusterVersion{}, false
	}
	return record.version, true
}

func TestClusterManagerTwoNodesConvergeLive(t *testing.T) {
	// Given two linked cluster managers.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{})
	topology.start(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	a, b := topology.node(t, 1), topology.node(t, 2)

	// When A registers and reports a live edge.
	if _, err := a.state.Register(context.Background(), controlRegisterRequest(101, "edge-101"), "edge-key-101"); err != nil {
		t.Fatalf("register edge on A: %v", err)
	}
	if err := a.state.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 101}); err != nil {
		t.Fatalf("report edge on A: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		_, ok := clusterManagerSnapshotPeer(b.state, 101)
		return ok
	}, "edge 101 to replicate to B")
	revision := b.state.Revision()
	before, ok := clusterManagerRecordVersion(b.state, 101)
	if !ok {
		t.Fatal("replicated edge 101 has no version on B")
	}

	// Then a heartbeat-only report advances the version without changing B's revision.
	if err := a.state.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 101}); err != nil {
		t.Fatalf("heartbeat report on A: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		after, exists := clusterManagerRecordVersion(b.state, 101)
		return exists && after.Newer(before)
	}, "heartbeat version to advance on B")
	if got := b.state.Revision(); got != revision {
		t.Fatalf("B revision after heartbeat = %d, want %d", got, revision)
	}
}

func TestClusterManagerFullSyncOnConnect(t *testing.T) {
	// Given A with 300 live records before either manager links.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{})
	a, b := topology.node(t, 1), topology.node(t, 2)
	for id := mtypes.Vertex(100); id < 400; id++ {
		if _, err := a.state.Register(context.Background(), controlRegisterRequest(id, "edge-"+id.ToString()), "key-"+id.ToString()); err != nil {
			t.Fatalf("register edge %d on A: %v", id, err)
		}
	}

	// When both managers start and exchange their initial full sync.
	topology.start(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	waitClusterManagerCondition(t, 3*time.Second, func() bool {
		return len(b.state.SnapshotFor(60000).Peers) == 300
	}, "all 300 live records to full-sync to B")

	// Then batching changes B at most once per <=200-record part.
	if revision := b.state.Revision(); revision > 2 {
		t.Fatalf("B revision after 300-record full sync = %d, want <= 2", revision)
	}
	if published := b.published.Load(); published > 2 {
		t.Fatalf("B publish count after 300-record full sync = %d, want <= 2", published)
	}
}

func TestClusterManagerRegistryReplicates(t *testing.T) {
	// Given two connected managers with independent config directories.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{})
	topology.start(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	a, b := topology.node(t, 1), topology.node(t, 2)

	// When A adds a managed peer.
	result, err := a.manage.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 120, NodeName: "edge-120"})
	if err != nil {
		t.Fatalf("add peer on A: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		key, ok := b.state.ControlKeyFor(120)
		return ok && key == result.SuperPeer.ControlPSKey
	}, "registry entry 120 to replicate to B")
	persisted := readSuperYAML(t, filepath.Join(b.dir, "super.yaml"))
	if len(persisted.Peers) != 1 || persisted.Peers[0].NodeID != 120 {
		t.Fatalf("B persisted peers after registry upsert = %#v", persisted.Peers)
	}

	// Then deleting it on A creates the replicated tombstone on B.
	if err := a.manage.DeletePeer(context.Background(), ManageDeletePeerRequest{NodeID: 120}); err != nil {
		t.Fatalf("delete peer on A: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		_, keyPresent := b.state.ControlKeyFor(120)
		version, tombstonePresent := b.state.RegistryVersion(120)
		return !keyPresent && tombstonePresent && !version.IsZero()
	}, "registry tombstone 120 to replicate to B")
}

func TestClusterManagerDedupeSimultaneousDial(t *testing.T) {
	// Given A and B configured to dial each other from a shared start barrier.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{})

	// When both dial loops start simultaneously.
	topology.startTogether(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	a, b := topology.node(t, 1), topology.node(t, 2)
	waitClusterManagerCondition(t, time.Second, func() bool {
		if clusterManagerEstablishedSessions(a.manager) != 1 || clusterManagerEstablishedSessions(b.manager) != 1 {
			return false
		}
		aLink := clusterManagerStatusLink(t, a.manager.Status(), 2)
		bLink := clusterManagerStatusLink(t, b.manager.Status(), 1)
		return aLink.Dialer && !bLink.Dialer
	}, "simultaneous links to deduplicate")

	// Then the sole surviving session was dialed by the lower SuperID.
	aLink := clusterManagerStatusLink(t, a.manager.Status(), 2)
	bLink := clusterManagerStatusLink(t, b.manager.Status(), 1)
	if !aLink.Dialer || bLink.Dialer {
		t.Fatalf("winning dial direction: A dialer=%v B dialer=%v, want true/false", aLink.Dialer, bLink.Dialer)
	}
}

func TestClusterManagerOneWayReachability(t *testing.T) {
	// Given A's dial URL for B is unreachable while B can dial A.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{
		badDial: map[[2]mtypes.Vertex]bool{{1, 2}: true},
	})
	topology.startTogether(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	a, b := topology.node(t, 1), topology.node(t, 2)

	// When each side creates a local live record.
	if _, err := a.state.Register(context.Background(), controlRegisterRequest(101, "edge-a"), "key-a"); err != nil {
		t.Fatalf("register edge on A: %v", err)
	}
	if _, err := b.state.Register(context.Background(), controlRegisterRequest(102, "edge-b"), "key-b"); err != nil {
		t.Fatalf("register edge on B: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		_, atB := clusterManagerSnapshotPeer(b.state, 101)
		_, atA := clusterManagerSnapshotPeer(a.state, 102)
		return atA && atB
	}, "one-way session to carry traffic in both directions")

	// Then B remains the dialer and A does not need a successful outbound dial.
	if aLink, bLink := clusterManagerStatusLink(t, a.manager.Status(), 2), clusterManagerStatusLink(t, b.manager.Status(), 1); aLink.Dialer || !bLink.Dialer {
		t.Fatalf("one-way dial direction: A dialer=%v B dialer=%v, want false/true", aLink.Dialer, bLink.Dialer)
	}
}

func TestClusterManagerThreeNodeForwarding(t *testing.T) {
	// Given the only links are A-B and B-C.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2, 3}, [][2]mtypes.Vertex{{1, 2}, {2, 3}}, clusterManagerTestOptions{})
	topology.startTogether(t, 1, 2, 3)
	waitClusterManagerLinked(t, topology, 1, 2)
	waitClusterManagerLinked(t, topology, 2, 3)
	a, c := topology.node(t, 1), topology.node(t, 3)

	// When A registers a live edge.
	if _, err := a.state.Register(context.Background(), controlRegisterRequest(101, "edge-101"), "key-101"); err != nil {
		t.Fatalf("register edge on A: %v", err)
	}
	wantVersion, ok := clusterManagerRecordVersion(a.state, 101)
	if !ok {
		t.Fatal("A record 101 has no source version")
	}
	waitClusterManagerCondition(t, 3*time.Second, func() bool {
		gotVersion, exists := clusterManagerRecordVersion(c.state, 101)
		return exists && gotVersion == wantVersion
	}, "A record to traverse B and reach C")

	// Then B forwarded the exact source version and origin without minting either.
	gotVersion, _ := clusterManagerRecordVersion(c.state, 101)
	if gotVersion != wantVersion || gotVersion.Origin != 1 {
		t.Fatalf("C version = %#v, want exact A version %#v", gotVersion, wantVersion)
	}
	mutations, _ := c.state.DrainOutbox()
	for _, mutation := range mutations {
		if mutation.NodeID == 101 && mutation.Version != wantVersion {
			t.Fatalf("C outbox re-minted forwarded mutation: %#v", mutation)
		}
	}
}

func TestClusterManagerLinkDownStatus(t *testing.T) {
	// Given A and B are linked and A holds a B-origin live record.
	grace := 300 * time.Millisecond
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{grace: grace})
	topology.startTogether(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	a, b := topology.node(t, 1), topology.node(t, 2)
	if _, err := b.state.Register(context.Background(), controlRegisterRequest(101, "edge-b"), "key-b"); err != nil {
		t.Fatalf("register B-origin edge: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		_, ok := clusterManagerSnapshotPeer(a.state, 101)
		return ok
	}, "B-origin record to replicate to A")

	// When B shuts down its manager and the session closes.
	if err := topology.shutdown(t, 2, 2*time.Second); err != nil {
		t.Fatalf("shutdown B manager: %v", err)
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		a.state.mu.RLock()
		status := a.state.originLinks[2]
		a.state.mu.RUnlock()
		return !status.up && !status.since.IsZero()
	}, "A to record B's origin link as down")
	if _, ok := clusterManagerSnapshotPeer(a.state, 101); !ok {
		t.Fatal("A evicted the B-origin record before the remote stale grace elapsed")
	}

	// Then advancing the injected clock beyond grace allows the normal sweep to evict it.
	a.clock.Advance(grace + time.Millisecond)
	a.state.SweepTimeouts()
	if _, ok := clusterManagerSnapshotPeer(a.state, 101); ok {
		t.Fatal("A retained the B-origin record after the remote stale grace elapsed")
	}
}

func TestClusterManagerQueueOverflowFullSync(t *testing.T) {
	// Given A's per-link queue overflows before the managers start.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{})
	a, b := topology.node(t, 1), topology.node(t, 2)
	a.manager.mu.Lock()
	queue := a.manager.peers[2].queue
	a.manager.mu.Unlock()
	for i := 0; i <= clusterOutQueueMaxKeys; i++ {
		nodeID := mtypes.Vertex(1000 + i)
		version := ClusterVersion{HLC: uint64(i + 1), Origin: 1}
		queue.Enqueue(clusterMutation{
			Kind: clusterMessagePeerUpsert, NodeID: nodeID, Version: version, Origin: 1,
			Peer: &clusterPeerRecord{NodeID: nodeID, NodeName: "queued", PubKey: "queued", LastSeen: a.clock.Now(), Version: version, Origin: 1},
		})
	}
	if !queue.NeedsFullSync() || queue.Len() != 0 {
		t.Fatalf("overflowed queue state: needs_full_sync=%v len=%d, want true/0", queue.NeedsFullSync(), queue.Len())
	}
	for id := mtypes.Vertex(100); id < 400; id++ {
		if _, err := a.state.Register(context.Background(), controlRegisterRequest(id, "edge-"+id.ToString()), "key-"+id.ToString()); err != nil {
			t.Fatalf("register edge %d after queue overflow: %v", id, err)
		}
	}

	// When the link starts, queue flush must recover through a fresh full sync.
	topology.startTogether(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	waitClusterManagerCondition(t, 3*time.Second, func() bool {
		left, _ := a.state.ExportLive()
		right, _ := b.state.ExportLive()
		return reflect.DeepEqual(left, right) && !queue.NeedsFullSync() && queue.Len() == 0
	}, "overflowed link to converge through full sync")

	// Then the queue is drained and both exported live sets are identical.
	if queue.NeedsFullSync() || queue.Len() != 0 {
		t.Fatalf("queue after recovery: needs_full_sync=%v len=%d", queue.NeedsFullSync(), queue.Len())
	}
}

func TestClusterManagerShutdownClosesSessions(t *testing.T) {
	// Given two linked managers and the goroutine baseline before they start.
	topology := newClusterManagerTestTopology(t, []mtypes.Vertex{1, 2}, [][2]mtypes.Vertex{{1, 2}}, clusterManagerTestOptions{})
	baseline := runtime.NumGoroutine()
	topology.startTogether(t, 1, 2)
	waitClusterManagerLinked(t, topology, 1, 2)
	a := topology.node(t, 1)
	a.manager.mu.Lock()
	session := a.manager.peers[2].session
	a.manager.mu.Unlock()
	if session == nil {
		t.Fatal("A has no established session before shutdown")
	}

	// When both managers shut down through the production lifecycle method.
	if err := topology.shutdown(t, 1, 2*time.Second); err != nil {
		t.Fatalf("shutdown A manager: %v", err)
	}
	if err := topology.shutdown(t, 2, 2*time.Second); err != nil {
		t.Fatalf("shutdown B manager: %v", err)
	}

	// Then the hijacked session is closed and manager goroutines return near baseline.
	if !session.closed() {
		t.Fatal("A session remained open after manager shutdown")
	}
	waitClusterManagerCondition(t, 2*time.Second, func() bool {
		return runtime.NumGoroutine() <= baseline+3
	}, "cluster manager goroutines to return to baseline")
}
