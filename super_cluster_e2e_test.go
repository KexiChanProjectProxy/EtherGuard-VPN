package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

type e2eClusterEdge struct {
	device    *device.Device
	runtime   *device.SuperHTTPRuntime
	cancel    context.CancelFunc
	bind      *e2eBind
	publicKey device.NoisePublicKey
	key       string
}

func TestMultiSuperE2EConverge(t *testing.T) {
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	fabric := newE2EFabric()
	edge101 := newMultiSuperE2EEdge(t, topology, fabric, 0, 101, []string{topology.supers[0].edgeURL, topology.supers[1].edgeURL})
	edge102 := newMultiSuperE2EEdge(t, topology, fabric, 1, 102, []string{topology.supers[1].edgeURL, topology.supers[0].edgeURL})
	WaitApplied(t, topology, 0, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge101.publicKey.ToString()
	}, 3*time.Second)
	WaitApplied(t, topology, 1, 102, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge102.publicKey.ToString()
	}, 3*time.Second)
	WaitApplied(t, topology, 1, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge101.publicKey.ToString()
	}, 3*time.Second)
	WaitApplied(t, topology, 0, 102, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge102.publicKey.ToString()
	}, 3*time.Second)

	client101 := newE2ESnapshotClient(topology.supers[0], 101, edge101.key)
	client102 := newE2ESnapshotClient(topology.supers[1], 102, edge102.key)
	peer102 := waitE2ESnapshotPeer(t, client101, 102, 3*time.Second)
	peer101 := waitE2ESnapshotPeer(t, client102, 101, 3*time.Second)
	if peer101.PubKey != edge101.publicKey.ToString() || peer102.PubKey != edge102.publicKey.ToString() {
		t.Fatalf("replicated snapshot public keys = (%q, %q), want (%q, %q)", peer101.PubKey, peer102.PubKey, edge101.publicKey.ToString(), edge102.publicKey.ToString())
	}

	awaitE2E(t, 3*time.Second, func() bool {
		return edge101.device.LookupPeer(edge102.publicKey) != nil && edge102.device.LookupPeer(edge101.publicKey) != nil &&
			edge101.device.GetConnurl(102) != "" && edge102.device.GetConnurl(101) != ""
	})
	stopE2EEdgeRuntime(t, edge101, 3*time.Second)
	stopE2EEdgeRuntime(t, edge102, 3*time.Second)
	assertE2EDirectTraffic(t, edge101, edge102, 3*time.Second)

	reporter101 := newE2ESnapshotClient(topology.supers[0], 101, edge101.key)
	reporter102 := newE2ESnapshotClient(topology.supers[1], 102, edge102.key)
	reportE2ELatency(t, reporter101, topology.supers[0].clock, 101, 102, peer101, 4.5)
	reportE2ELatency(t, reporter102, topology.supers[1].clock, 102, 101, peer102, 4.5)

	peer102 = waitE2ESnapshotPeerMatching(t, client101, 102, 3*time.Second, func(peer mtypes.ControlV2Peer) bool {
		return peer.LatencyMS[101] == 4.5
	})
	if peer102.LatencyMS[101] != 4.5 {
		t.Fatalf("A snapshot for 101 has latency 102->101 = %v, want 4.5", peer102.LatencyMS[101])
	}
}

func TestMultiSuperE2ELinkCutKeepsBothHalves(t *testing.T) {
	opts := e2eClusterOptions{grace: 10 * time.Second}
	topology := newE2EMultiSuperTopology(t, 2, opts)
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	setE2EReportInterval(t, topology, 50*time.Millisecond)

	fabric := newE2EFabric()
	edge101 := newMultiSuperE2EEdge(t, topology, fabric, 0, 101, []string{topology.supers[0].edgeURL, topology.supers[1].edgeURL})
	edge102 := newMultiSuperE2EEdge(t, topology, fabric, 1, 102, []string{topology.supers[1].edgeURL, topology.supers[0].edgeURL})
	WaitApplied(t, topology, 0, 102, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge102.publicKey.ToString() }, 3*time.Second)
	WaitApplied(t, topology, 1, 101, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge101.publicKey.ToString() }, 3*time.Second)

	eventCtx, cancelEvents := context.WithCancel(context.Background())
	defer cancelEvents()
	subscriber, err := topology.supers[0].runtime.Hub().SubscribeWithBuffer(eventCtx, "", 1024)
	if err != nil {
		t.Fatalf("subscribe to A control events: %v", err)
	}
	defer subscriber.Close()

	CutLink(topology, 0, 1)
	awaitE2E(t, time.Second, func() bool { return !e2eLinkConnected(topology, 0, 1) && !e2eLinkConnected(topology, 1, 0) })
	peerAlive := topology.supers[0].runtime.State().peerAliveTimeout
	if peerAlive <= 0 || 5*peerAlive >= opts.grace {
		t.Fatalf("test timing invalid: 5*PeerAliveTimeout=%v grace=%v", 5*peerAlive, opts.grace)
	}
	advanceE2ESupersWhileReporting(t, topology, 0, 101, 1, 102, 5*peerAlive)
	if _, ok := e2ePeerFromState(topology.supers[0].runtime.State(), 101, 102); !ok {
		t.Fatal("A lost remote-origin edge 102 before remote stale grace")
	}
	assertNoE2EPeerGone(t, subscriber)

	HealLink(topology, 0, 1)
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	waitE2EPeerViewsEqual(t, topology, 0, 1, 3*time.Second)

	CutLink(topology, 0, 1)
	awaitE2E(t, time.Second, func() bool { return !e2eLinkConnected(topology, 0, 1) && !e2eLinkConnected(topology, 1, 0) })
	advanceE2ESupersWhileReporting(t, topology, 0, 101, 1, 102, opts.grace+time.Second)
	awaitE2E(t, 3*time.Second, func() bool {
		_, ok := e2ePeerFromState(topology.supers[0].runtime.State(), 101, 102)
		return !ok
	})
	waitE2EPeerGone(t, subscriber, 102, 3*time.Second)

	HealLink(topology, 0, 1)
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	WaitApplied(t, topology, 0, 102, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge102.publicKey.ToString() }, 3*time.Second)
	awaitE2E(t, 3*time.Second, func() bool { return edge101.device.LookupPeer(edge102.publicKey) != nil })
}

func TestMultiSuperE2ESuperDeathFailover(t *testing.T) {
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	setE2EReportInterval(t, topology, 50*time.Millisecond)

	fabric := newE2EFabric()
	edge101 := newMultiSuperE2EEdge(t, topology, fabric, 0, 101, []string{topology.supers[0].edgeURL, topology.supers[1].edgeURL})
	edge102 := newMultiSuperE2EEdge(t, topology, fabric, 1, 102, []string{topology.supers[1].edgeURL, topology.supers[0].edgeURL})
	edge101.runtime.SetFailoverThresholdsForTest(300 * time.Millisecond)
	WaitApplied(t, topology, 1, 101, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge101.publicKey.ToString() }, 3*time.Second)
	WaitApplied(t, topology, 0, 102, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge102.publicKey.ToString() }, 3*time.Second)
	awaitE2E(t, 2*time.Second, func() bool {
		key, ok := topology.supers[1].runtime.State().ControlKeyFor(101)
		return ok && key == edge101.key
	})

	eventCtx, cancelEvents := context.WithCancel(context.Background())
	defer cancelEvents()
	subscriber, err := topology.supers[1].runtime.Hub().SubscribeWithBuffer(eventCtx, "", 1024)
	if err != nil {
		t.Fatalf("subscribe to B control events: %v", err)
	}
	defer subscriber.Close()

	ShutdownSuper(t, topology, 0)
	awaitE2E(t, 2*time.Second, func() bool {
		if _, ok := e2eLiveRecord(topology.supers[1].runtime.State(), 102); !ok {
			t.Fatal("edge 102 disappeared from B during A failover")
		}
		record, ok := e2eLiveRecord(topology.supers[1].runtime.State(), 101)
		return ok && record.Origin == topology.supers[1].id
	})
	assertNoE2EPeerGone(t, subscriber)

	stopE2EEdgeRuntime(t, edge101, 3*time.Second)
	stopE2EEdgeRuntime(t, edge102, 3*time.Second)
	bBefore, bDeletesBefore := topology.supers[1].runtime.State().ExportLive()
	oldA := topology.supers[0]
	oldA.proxy.Close()
	restarted := newE2ESuperFrom(t, oldA.dir, oldA.id, oldA.clock)
	topology.supers[0] = *restarted
	topology.proxies[0] = restarted.proxy
	topology.edgeListeners[0] = restarted.edgeLn
	topology.manageListeners[0] = restarted.manageLn

	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	WaitApplied(t, topology, 0, 101, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge101.publicKey.ToString() }, 3*time.Second)
	WaitApplied(t, topology, 0, 102, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge102.publicKey.ToString() }, 3*time.Second)
	bAfter, bDeletesAfter := topology.supers[1].runtime.State().ExportLive()
	if !reflect.DeepEqual(bBefore, bAfter) || !reflect.DeepEqual(bDeletesBefore, bDeletesAfter) {
		t.Fatalf("B records changed when A returned: before=%+v/%+v after=%+v/%+v", bBefore, bDeletesBefore, bAfter, bDeletesAfter)
	}
}

func TestMultiSuperE2ERegistryReplicates(t *testing.T) {
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)

	status, body := postE2EManageJSON(t, topology.supers[0], "peer/add", []byte(`{"NodeID":103,"NodeName":"edge-103"}`))
	if status != http.StatusOK {
		t.Fatalf("POST A peer/add status=%d body=%s", status, body)
	}
	profile := readEdgeYAML(t, filepath.Join(topology.supers[0].dir, "edge_103.yaml"))
	oldKey := profile.SuperNodeV2.ControlPSKey
	awaitE2E(t, 2*time.Second, func() bool {
		key, ok := topology.supers[1].runtime.State().ControlKeyFor(103)
		return ok && key == oldKey
	})

	fabric := newE2EFabric()
	edge103 := startMultiSuperE2EEdge(t, topology, fabric, 1, 103, profile.NodeName, oldKey, []string{topology.supers[1].edgeURL})
	WaitApplied(t, topology, 1, 103, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge103.publicKey.ToString() }, 3*time.Second)
	WaitApplied(t, topology, 0, 103, func(peer mtypes.ControlV2Peer) bool { return peer.PubKey == edge103.publicKey.ToString() }, 3*time.Second)
	stopE2EEdgeRuntime(t, edge103, 3*time.Second)

	const newKey = "edge-103-rotated-control-key"
	status, body = postE2EManageJSON(t, topology.supers[1], "peer/update", []byte(`{"NodeID":103,"ControlPSKey":"edge-103-rotated-control-key","AdditionalCost":-1}`))
	if status != http.StatusOK {
		t.Fatalf("POST B peer/update status=%d body=%s", status, body)
	}
	for index := range topology.supers {
		index := index
		awaitE2E(t, 2*time.Second, func() bool {
			key, ok := topology.supers[index].runtime.State().ControlKeyFor(103)
			return ok && key == newKey
		})
	}

	for index := range topology.supers {
		super := topology.supers[index]
		if got := signedE2ESnapshotStatus(t, super, 103, oldKey, fmt.Sprintf("old-%d", index)); got != http.StatusUnauthorized {
			t.Fatalf("old key status on super %d = %d, want 401", index, got)
		}
		if got := signedE2ESnapshotStatus(t, super, 103, newKey, fmt.Sprintf("new-%d", index)); got < 200 || got >= 300 {
			t.Fatalf("new key status on super %d = %d, want 2xx", index, got)
		}
	}
}

func TestMultiSuperE2EThreeSuperForwarding(t *testing.T) {
	topology := newE2EMultiSuperTopology(t, 3, e2eClusterOptions{linkPairs: [][2]int{{0, 1}, {1, 2}}})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	WaitLinked(t, topology, 1, 2, 3*time.Second)
	WaitLinked(t, topology, 2, 1, 3*time.Second)

	fabric := newE2EFabric()
	edge101 := newMultiSuperE2EEdge(t, topology, fabric, 0, 101, []string{topology.supers[0].edgeURL})
	WaitApplied(t, topology, 2, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge101.publicKey.ToString()
	}, 3*time.Second)
	record, ok := e2eLiveRecord(topology.supers[2].runtime.State(), 101)
	if !ok {
		t.Fatal("edge 101 missing from C after A-B-C forwarding")
	}
	if record.Origin != topology.supers[0].id {
		t.Fatalf("edge 101 origin on C = %d, want A super ID %d", record.Origin, topology.supers[0].id)
	}
	for _, link := range topology.supers[0].runtime.Cluster().Status().Links {
		if link.SuperID == topology.supers[2].id {
			t.Fatal("A unexpectedly has a direct cluster link to C")
		}
	}
}

func newMultiSuperE2EEdge(t *testing.T, topology *e2eMultiSuper, fabric *e2eFabric, home int, id mtypes.Vertex, urls []string) *e2eClusterEdge {
	t.Helper()
	ctx, cancelAdd := context.WithTimeout(context.Background(), time.Second)
	result, err := topology.supers[home].runtime.Manage().AddPeer(ctx, ManageAddPeerRequest{NodeID: id, NodeName: fmt.Sprintf("edge-%d", id)})
	cancelAdd()
	if err != nil {
		t.Fatalf("add managed edge %d on super %d: %v", id, home, err)
	}
	return startMultiSuperE2EEdge(t, topology, fabric, home, id, result.SuperPeer.NodeName, result.SuperPeer.ControlPSKey, urls)
}

func startMultiSuperE2EEdge(t *testing.T, topology *e2eMultiSuper, fabric *e2eFabric, home int, id mtypes.Vertex, name, key string, urls []string) *e2eClusterEdge {
	t.Helper()
	privateKey, publicKey := device.RandomKeyPair()
	ip := net.ParseIP(fmt.Sprintf("198.51.100.%d", id))
	bind := newE2EBind(fabric, ip, ip, uint16(id), true)
	edge, runtime, cancel := newE2EEdge(t, id, name, key, "", bind, newE2ETap(), privateKey, e2eRetryConfig{}, nil, urls)
	topology.edges = append(topology.edges, edge)
	topology.edgeRuntimes = append(topology.edgeRuntimes, runtime)
	topology.edgeCancels = append(topology.edgeCancels, cancel)
	return &e2eClusterEdge{device: edge, runtime: runtime, cancel: cancel, bind: bind, publicKey: publicKey, key: key}
}

func postE2EManageJSON(t *testing.T, super e2eSuper, route string, body []byte) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, super.manageURL+"/edge/v2/manage/"+route+"?Password="+super.hash, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create management request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send management request: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read management response: %v", err)
	}
	return response.StatusCode, responseBody
}

func signedE2ESnapshotStatus(t *testing.T, super e2eSuper, nodeID mtypes.Vertex, key, nonce string) int {
	t.Helper()
	endpoint := strings.TrimRight(super.edgeURL, "/") + mtypes.ControlV2APIPrefix + "/snapshot"
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("create signed snapshot request: %v", err)
	}
	timestamp := strconv.FormatInt(super.clock.Now().Unix(), 10)
	digest := sha256.Sum256(nil)
	canonical := request.Method + "\n" + request.URL.EscapedPath() + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(digest[:])
	signature := mtypes.HMACSHA256([]byte(key), []byte(canonical))
	request.Header.Set(device.HeaderNodeID, nodeID.ToString())
	request.Header.Set(device.HeaderTimestamp, timestamp)
	request.Header.Set(device.HeaderNonce, nonce)
	request.Header.Set(device.HeaderSignature, hex.EncodeToString(signature))
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("send signed snapshot request: %v", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}

func newE2ESnapshotClient(super e2eSuper, nodeID mtypes.Vertex, key string) *device.ControlHTTPClient {
	client := device.NewControlHTTPClient(super.edgeURL, mtypes.ControlV2APIPrefix, nodeID, key)
	client.Now = super.clock.Now
	return client
}

func waitE2ESnapshotPeer(t *testing.T, client *device.ControlHTTPClient, nodeID mtypes.Vertex, timeout time.Duration) mtypes.ControlV2Peer {
	t.Helper()
	return waitE2ESnapshotPeerMatching(t, client, nodeID, timeout, func(mtypes.ControlV2Peer) bool { return true })
}

func waitE2ESnapshotPeerMatching(t *testing.T, client *device.ControlHTTPClient, nodeID mtypes.Vertex, timeout time.Duration, predicate func(mtypes.ControlV2Peer) bool) mtypes.ControlV2Peer {
	t.Helper()
	var found mtypes.ControlV2Peer
	var lastErr error
	var lastSnapshot *mtypes.ControlV2Snapshot
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		snapshot, _, err := client.Snapshot(ctx)
		cancel()
		if err != nil || snapshot == nil {
			lastErr = err
		} else {
			lastSnapshot = snapshot
			var ok bool
			found, ok = e2ePeer(snapshot, nodeID)
			if ok && predicate(found) {
				return found
			}
		}
		timer := time.NewTimer(5 * time.Millisecond)
		<-timer.C
	}
	t.Fatalf("snapshot peer %d did not converge: last error=%v last snapshot=%+v", nodeID, lastErr, lastSnapshot)
	return mtypes.ControlV2Peer{}
}

func stopE2EEdgeRuntime(t *testing.T, edge *e2eClusterEdge, timeout time.Duration) {
	t.Helper()
	edge.cancel()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-edge.runtime.Done():
	case <-timer.C:
		t.Fatal("edge runtime did not stop before deadline")
	}
}

func assertE2EDirectTraffic(t *testing.T, source, destination *e2eClusterEdge, timeout time.Duration) {
	t.Helper()
	drainE2ESignals(source.bind.responses)
	drainE2ETransports(destination.bind.transports)
	peer := source.device.LookupPeer(destination.publicKey)
	peer.ExpireCurrentKeypairs()
	if err := peer.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("start direct Edge handshake: %v", err)
	}
	source.device.SendPacket(peer, path.NormalPacket, 64, e2eNormalPacket(t, source.device.ID, destination.device.ID), device.MessageTransportOffsetContent)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-source.bind.responses:
	case <-timer.C:
		t.Fatal("direct Edge handshake response did not arrive before deadline")
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(timeout)
	select {
	case usage := <-destination.bind.transports:
		if usage != path.NormalPacket {
			t.Fatalf("direct Edge transport usage = %v, want %v", usage, path.NormalPacket)
		}
	case <-timer.C:
		t.Fatal("direct Edge transport packet did not cross the fake fabric before deadline")
	}
}

func reportE2ELatency(t *testing.T, client *device.ControlHTTPClient, clock *e2eClock, source, destination mtypes.Vertex, peer mtypes.ControlV2Peer, latency float64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Report(ctx, &mtypes.ControlV2ReportRequest{
		NodeID: source, Candidates: e2eCandidates(peer), ReportedAt: clock.Now(),
		Pongs: []mtypes.ControlV2Pong{{SourceNode: source, DestNode: destination, LatencyMS: latency, AliveSeconds: 5}},
	}); err != nil {
		t.Fatalf("report latency %d->%d: %v", source, destination, err)
	}
}

func setE2EReportInterval(t *testing.T, topology *e2eMultiSuper, interval time.Duration) {
	t.Helper()
	parameters := topology.supers[0].runtime.State().SnapshotFor(mtypes.NodeID_SuperNode).Parameters
	parameters.ReportInterval = interval
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err := topology.supers[0].runtime.Manage().UpdateParameters(ctx, ManageUpdateParametersRequest{Parameters: parameters})
	cancel()
	if err != nil {
		t.Fatalf("set E2E report interval: %v", err)
	}
	for index := range topology.supers {
		index := index
		awaitE2E(t, 3*time.Second, func() bool {
			return topology.supers[index].runtime.State().SnapshotFor(mtypes.NodeID_SuperNode).Parameters.ReportInterval == interval
		})
	}
}

func advanceE2ESupersWhileReporting(t *testing.T, topology *e2eMultiSuper, leftSuper int, leftNode mtypes.Vertex, rightSuper int, rightNode mtypes.Vertex, total time.Duration) {
	t.Helper()
	step := topology.supers[leftSuper].runtime.State().peerAliveTimeout / 2
	if step <= 0 {
		t.Fatal("peer alive timeout must be positive")
	}
	for advanced := time.Duration(0); advanced < total; {
		increment := min(step, total-advanced)
		leftBefore := e2eRecordVersion(t, topology.supers[leftSuper].runtime.State(), leftNode)
		rightBefore := e2eRecordVersion(t, topology.supers[rightSuper].runtime.State(), rightNode)
		topology.supers[leftSuper].clock.Advance(increment)
		topology.supers[rightSuper].clock.Advance(increment)
		awaitE2E(t, time.Second, func() bool {
			return e2eRecordVersion(t, topology.supers[leftSuper].runtime.State(), leftNode).Newer(leftBefore) &&
				e2eRecordVersion(t, topology.supers[rightSuper].runtime.State(), rightNode).Newer(rightBefore)
		})
		advanced += increment
	}
}

func e2eRecordVersion(t *testing.T, state *ControlState, nodeID mtypes.Vertex) ClusterVersion {
	t.Helper()
	record, ok := e2eLiveRecord(state, nodeID)
	if ok {
		return record.Version
	}
	t.Fatalf("live record %d not found", nodeID)
	return ClusterVersion{}
}

func e2eLiveRecord(state *ControlState, nodeID mtypes.Vertex) (clusterPeerRecord, bool) {
	live, _ := state.ExportLive()
	for _, record := range live {
		if record.NodeID == nodeID {
			return record, true
		}
	}
	return clusterPeerRecord{}, false
}

func e2ePeerFromState(state *ControlState, requester, nodeID mtypes.Vertex) (mtypes.ControlV2Peer, bool) {
	snapshot := state.SnapshotFor(requester)
	return e2ePeer(&snapshot, nodeID)
}

func waitE2EPeerViewsEqual(t *testing.T, topology *e2eMultiSuper, left, right int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var leftPeers, rightPeers []mtypes.ControlV2Peer
	for time.Now().Before(deadline) {
		leftPeers = topology.supers[left].runtime.State().SnapshotFor(mtypes.NodeID_SuperNode).Peers
		rightPeers = topology.supers[right].runtime.State().SnapshotFor(mtypes.NodeID_SuperNode).Peers
		if reflect.DeepEqual(normalizeE2EPeerTimes(leftPeers), normalizeE2EPeerTimes(rightPeers)) {
			return
		}
		timer := time.NewTimer(5 * time.Millisecond)
		<-timer.C
	}
	t.Fatalf("peer views did not converge: left=%+v right=%+v", leftPeers, rightPeers)
}

func normalizeE2EPeerTimes(peers []mtypes.ControlV2Peer) []mtypes.ControlV2Peer {
	normalized := append([]mtypes.ControlV2Peer(nil), peers...)
	for index := range normalized {
		normalized[index].LastSeen = normalized[index].LastSeen.UTC()
	}
	return normalized
}

func assertNoE2EPeerGone(t *testing.T, subscriber *Subscriber) {
	t.Helper()
	for {
		select {
		case event := <-subscriber.Events():
			if event.Type == mtypes.ControlV2EventPeerGone {
				t.Fatalf("unexpected peer_gone during remote retention window: %+v", event)
			}
		default:
			return
		}
	}
}

func waitE2EPeerGone(t *testing.T, subscriber *Subscriber, nodeID mtypes.Vertex, timeout time.Duration) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event := <-subscriber.Events():
			if event.Type == mtypes.ControlV2EventPeerGone && e2eEventNodeID(event) == nodeID {
				return
			}
		case <-subscriber.Done():
			t.Fatalf("event subscriber ended before peer_gone: %v", subscriber.Err())
		case <-timer.C:
			t.Fatalf("peer_gone for %d did not arrive before deadline", nodeID)
		}
	}
}

func e2eEventNodeID(event mtypes.ControlV2Event) mtypes.Vertex {
	switch payload := event.Data.(type) {
	case mtypes.ControlV2PeerChangePayload:
		return payload.NodeID
	case *mtypes.ControlV2PeerChangePayload:
		return payload.NodeID
	default:
		return mtypes.NodeID_Invalid
	}
}

func drainE2ESignals(signals <-chan struct{}) {
	for {
		select {
		case <-signals:
		default:
			return
		}
	}
}

func drainE2ETransports(transports <-chan path.Usage) {
	for {
		select {
		case <-transports:
		default:
			return
		}
	}
}
