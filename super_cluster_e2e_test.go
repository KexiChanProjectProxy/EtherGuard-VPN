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
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
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

type clusterCounterEdgeWorkload struct {
	register   mtypes.ControlV2RegisterRequest
	controlKey string
	reports    []mtypes.ControlV2ReportRequest
}

type clusterCompressionRun struct {
	live       []clusterPeerRecord
	tombstones []clusterDelete
	stats      clusterLinkStats
}

func TestClusterCompressionCounters(t *testing.T) {
	workload := buildClusterCounterWorkload()
	var zstdRun, noneRun clusterCompressionRun

	t.Run("zstd", func(t *testing.T) {
		zstdRun = runClusterCompressionCounterMode(t, "zstd", workload)
	})
	t.Run("none", func(t *testing.T) {
		noneRun = runClusterCompressionCounterMode(t, "none", workload)
	})

	if !reflect.DeepEqual(zstdRun.live, noneRun.live) || !reflect.DeepEqual(zstdRun.tombstones, noneRun.tombstones) {
		t.Fatalf("compression modes produced different decoded state: zstd=%+v/%+v none=%+v/%+v", zstdRun.live, zstdRun.tombstones, noneRun.live, noneRun.tombstones)
	}
	if zstdRun.stats.TX.InnerBytes != noneRun.stats.TX.InnerBytes {
		t.Fatalf("TX inner bytes differ for identical workload: zstd=%d none=%d", zstdRun.stats.TX.InnerBytes, noneRun.stats.TX.InnerBytes)
	}
	if zstdRun.stats.TX.CompressedBytes >= noneRun.stats.TX.CompressedBytes/3 {
		t.Fatalf("zstd compressed bytes = %d, want < one third of none bytes %d", zstdRun.stats.TX.CompressedBytes, noneRun.stats.TX.CompressedBytes)
	}
}

func buildClusterCounterWorkload() []clusterCounterEdgeWorkload {
	const (
		edgeCount       = 20
		reportsPerEdge  = 30
		firstEdgeNodeID = 1001
	)
	fixedTime := time.Date(2040, time.January, 2, 3, 4, 5, 0, time.UTC)
	workload := make([]clusterCounterEdgeWorkload, edgeCount)
	for edgeIndex := range edgeCount {
		nodeID := mtypes.Vertex(firstEdgeNodeID + edgeIndex)
		targetIndex := (edgeIndex + 1) % edgeCount
		targetID := mtypes.Vertex(firstEdgeNodeID + targetIndex)
		localAddress := fmt.Sprintf("10.40.0.%d:%d", edgeIndex+1, 20000+edgeIndex)
		publicAddress := fmt.Sprintf("198.51.100.%d:%d", edgeIndex+1, 30000+edgeIndex)
		observedAddress := fmt.Sprintf("203.0.113.%d:%d", targetIndex+1, 32000+targetIndex)
		candidates := []mtypes.ControlV2Candidate{
			{Address: localAddress, Source: mtypes.ControlV2CandidateLocal},
			{Address: publicAddress, Source: mtypes.ControlV2CandidateSTUN},
		}
		reports := make([]mtypes.ControlV2ReportRequest, reportsPerEdge)
		for reportIndex := range reportsPerEdge {
			reports[reportIndex] = mtypes.ControlV2ReportRequest{
				NodeID: nodeID,
				Pongs: []mtypes.ControlV2Pong{{
					RequestID:    uint32(edgeIndex + 1),
					SourceNode:   nodeID,
					DestNode:     targetID,
					TimediffMS:   0.5,
					LatencyMS:    float64(reportIndex + 1),
					AliveSeconds: 60,
				}},
				Candidates: append([]mtypes.ControlV2Candidate(nil), candidates...),
				Observed: []mtypes.ControlV2ObservedEndpoint{{
					TargetNodeID: targetID,
					Address:      observedAddress,
				}},
				ReportedAt: fixedTime,
			}
		}
		workload[edgeIndex] = clusterCounterEdgeWorkload{
			register: mtypes.ControlV2RegisterRequest{
				NodeID:         nodeID,
				NodeName:       fmt.Sprintf("compression-edge-%04d", nodeID),
				PubKey:         fmt.Sprintf("compression-public-key-%04d-repetitive-fixture", nodeID),
				Version:        mtypes.ControlV2ProtocolVersion,
				ListenPort:     20000 + edgeIndex,
				LocalV4:        []string{localAddress},
				PublicV4:       []string{publicAddress},
				DesiredTTL:     64,
				RequestedAt:    fixedTime,
				Implementation: "cluster-compression-counter-fixture",
			},
			controlKey: fmt.Sprintf("compression-control-key-%04d-repetitive-fixture", nodeID),
			reports:    reports,
		}
	}
	return workload
}

func runClusterCompressionCounterMode(t *testing.T, compression string, workload []clusterCounterEdgeWorkload) clusterCompressionRun {
	t.Helper()
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{
		heartbeat:   time.Hour,
		deadAfter:   2 * time.Hour,
		compression: compression,
	})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	setE2EClusterClocks(topology, time.Date(2040, time.January, 2, 3, 4, 5, 0, time.UTC))

	baselineLeft, baselineRight := waitClusterCounterMeasurementStart(t, topology)

	for _, edge := range workload {
		if _, err := topology.supers[0].runtime.State().Register(context.Background(), edge.register, edge.controlKey); err != nil {
			t.Fatalf("register deterministic edge %d in %s topology: %v", edge.register.NodeID, compression, err)
		}
		WaitApplied(t, topology, 1, edge.register.NodeID, func(peer mtypes.ControlV2Peer) bool {
			return peer.PubKey == edge.register.PubKey
		}, 3*time.Second)
		for _, report := range edge.reports {
			if err := topology.supers[0].runtime.State().Report(context.Background(), report); err != nil {
				t.Fatalf("report deterministic edge %d in %s topology: %v", report.NodeID, compression, err)
			}
			targetID := report.Pongs[0].DestNode
			latencyMS := report.Pongs[0].LatencyMS
			WaitApplied(t, topology, 1, report.NodeID, func(peer mtypes.ControlV2Peer) bool {
				return peer.LatencyMS[targetID] == latencyMS
			}, 3*time.Second)
		}
	}

	lastEdge := workload[len(workload)-1]
	lastReport := lastEdge.reports[len(lastEdge.reports)-1]
	lastTargetID := lastReport.Pongs[0].DestNode
	lastLatencyMS := lastReport.Pongs[0].LatencyMS
	WaitApplied(t, topology, 1, lastReport.NodeID, func(peer mtypes.ControlV2Peer) bool {
		return peer.LatencyMS[lastTargetID] == lastLatencyMS
	}, 3*time.Second)

	leftLive, leftTombstones := topology.supers[0].runtime.State().ExportLive()
	rightLive, rightTombstones := topology.supers[1].runtime.State().ExportLive()
	leftLive = normalizeClusterPeerRecordTimes(leftLive)
	rightLive = normalizeClusterPeerRecordTimes(rightLive)
	if !reflect.DeepEqual(leftLive, rightLive) || !reflect.DeepEqual(leftTombstones, rightTombstones) {
		t.Fatalf("decoded %s state differs (receivedAt is not exported): left=%+v/%+v right=%+v/%+v", compression, leftLive, leftTombstones, rightLive, rightTombstones)
	}

	left := clusterLinkStatsDelta(t, LinkStats(topology, 0, 1), baselineLeft)
	right := clusterLinkStatsDelta(t, LinkStats(topology, 1, 0), baselineRight)
	if left.TX.Messages != right.RX.Messages {
		t.Fatalf("%s link message counts are asymmetric: A TX=%d B RX=%d", compression, left.TX.Messages, right.RX.Messages)
	}
	wantMessages := uint64(len(workload) * (1 + len(workload[0].reports)))
	if left.TX.Messages != wantMessages {
		t.Fatalf("%s workload messages = %d, want %d", compression, left.TX.Messages, wantMessages)
	}
	assertClusterWireOverhead(t, compression, left.TX)
	return clusterCompressionRun{live: leftLive, tombstones: leftTombstones, stats: left}
}

func normalizeClusterPeerRecordTimes(records []clusterPeerRecord) []clusterPeerRecord {
	normalized := append([]clusterPeerRecord(nil), records...)
	for index := range normalized {
		normalized[index].LastSeen = normalized[index].LastSeen.Round(0).UTC()
	}
	return normalized
}

func setE2EClusterClocks(topology *e2eMultiSuper, fixed time.Time) {
	for index := range topology.supers {
		clock := topology.supers[index].clock
		clock.Advance(fixed.Sub(clock.Now()))
	}
}

func clusterLinkStatsDelta(t *testing.T, after, before clusterLinkStats) clusterLinkStats {
	t.Helper()
	return clusterLinkStats{
		TX:          clusterDirectionStatsDelta(t, after.TX, before.TX),
		RX:          clusterDirectionStatsDelta(t, after.RX, before.RX),
		Dialer:      after.Dialer,
		Compression: after.Compression,
	}
}

func clusterDirectionStatsDelta(t *testing.T, after, before clusterDirectionStats) clusterDirectionStats {
	t.Helper()
	if after.Messages < before.Messages || after.InnerBytes < before.InnerBytes || after.CompressedBytes < before.CompressedBytes || after.WireBytes < before.WireBytes {
		t.Fatalf("cluster link counters decreased: before=%+v after=%+v", before, after)
	}
	return clusterDirectionStats{
		Messages:        after.Messages - before.Messages,
		InnerBytes:      after.InnerBytes - before.InnerBytes,
		CompressedBytes: after.CompressedBytes - before.CompressedBytes,
		WireBytes:       after.WireBytes - before.WireBytes,
	}
}

func waitClusterCounterMeasurementStart(t *testing.T, topology *e2eMultiSuper) (clusterLinkStats, clusterLinkStats) {
	t.Helper()
	var previousLeft, previousRight clusterLinkStats
	stablePolls := 0
	awaitE2E(t, 3*time.Second, func() bool {
		if !clusterCounterEndpointIdle(&topology.supers[0], topology.supers[1].id) ||
			!clusterCounterEndpointIdle(&topology.supers[1], topology.supers[0].id) {
			stablePolls = 0
			return false
		}
		currentLeft := LinkStats(topology, 0, 1)
		currentRight := LinkStats(topology, 1, 0)
		if currentLeft.TX.Messages < 2 || currentRight.TX.Messages < 2 ||
			currentLeft.TX.Messages != currentRight.RX.Messages || currentRight.TX.Messages != currentLeft.RX.Messages {
			stablePolls = 0
			return false
		}
		if currentLeft == previousLeft && currentRight == previousRight {
			stablePolls++
		} else {
			stablePolls = 0
			previousLeft, previousRight = currentLeft, currentRight
		}
		return stablePolls >= 5
	})
	return previousLeft, previousRight
}

func clusterCounterEndpointIdle(super *e2eSuper, peerID mtypes.Vertex) bool {
	state := super.runtime.State()
	state.mu.RLock()
	stateIdle := len(state.outbox) == 0 && !state.resyncNeeded
	state.mu.RUnlock()
	if !stateIdle {
		return false
	}

	manager := super.runtime.Cluster()
	manager.mu.Lock()
	peer := manager.peers[peerID]
	var queue *clusterOutQueue
	var session *clusterSession
	if peer != nil {
		queue = peer.queue
		session = peer.session
	}
	manager.mu.Unlock()
	return queue != nil && session != nil && !session.closed() && queue.Len() == 0 &&
		!queue.NeedsFullSync() && len(session.sendCh) == 0
}

func assertClusterWireOverhead(t *testing.T, compression string, stats clusterDirectionStats) {
	t.Helper()
	minimumWireBytes := stats.CompressedBytes + 20*stats.Messages
	if stats.WireBytes < minimumWireBytes {
		t.Fatalf("%s wire bytes = %d, want at least compressed bytes %d + 20*messages %d", compression, stats.WireBytes, stats.CompressedBytes, stats.Messages)
	}
}

func TestMultiSuperE2EEdgeStartsWhenFirstSuperDown(t *testing.T) {
	// Given: B authorizes the Edge and publishes a concrete pre-bind policy,
	// while the first configured Super endpoint is shut down.
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	port := 51101
	parameters := topology.supers[1].runtime.State().SnapshotFor(mtypes.NodeID_SuperNode).Parameters
	parameters.ListenPortPriority = mtypes.ListenPortPriority{{Port: &port}}
	parameters.ReportInterval = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := topology.supers[1].runtime.Manage().UpdateParameters(ctx, ManageUpdateParametersRequest{Parameters: parameters}); err != nil {
		cancel()
		t.Fatalf("publish B bootstrap parameters: %v", err)
	}
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	added, err := topology.supers[1].runtime.Manage().AddPeer(ctx, ManageAddPeerRequest{NodeID: 101, NodeName: "edge-101"})
	cancel()
	if err != nil {
		t.Fatalf("add edge 101 on B: %v", err)
	}
	ShutdownSuper(t, topology, 0)
	urls := []string{topology.supers[0].edgeURL, topology.supers[1].edgeURL}
	config := mtypes.EdgeConfigV2{
		NodeID:     101,
		NodeName:   added.SuperPeer.NodeName,
		DefaultTTL: 64,
		SuperNodeV2: mtypes.SuperNodeV2Ref{
			APIUrls:      urls,
			APIPrefix:    mtypes.ControlV2APIPrefix,
			NodeID:       1,
			ControlPSKey: added.SuperPeer.ControlPSKey,
		},
	}

	// When: production bootstrap walks A then B and hands the selected index to
	// a real Edge runtime.
	bootstrapCtx, cancelBootstrap := context.WithTimeout(context.Background(), 5*time.Second)
	ports, startIndex, err := bootstrapInitialBind(bootstrapCtx, config)
	cancelBootstrap()
	if err != nil {
		t.Fatalf("bootstrap with A down and B healthy: %v", err)
	}
	if startIndex != 1 {
		t.Fatalf("bootstrap start index = %d, want 1", startIndex)
	}
	if len(ports) != 1 || ports[0] != uint16(port) {
		t.Fatalf("bootstrap ports = %v, want [%d]", ports, port)
	}

	var logMu sync.Mutex
	var logged []string
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...interface{}) {
			logMu.Lock()
			logged = append(logged, fmt.Sprintf(format, args...))
			logMu.Unlock()
		},
	}
	fabric := newE2EFabric()
	privateKey, publicKey := device.RandomKeyPair()
	bind := newE2EBind(fabric, net.ParseIP("198.51.100.101"), net.ParseIP("198.51.100.101"), ports[0], true)
	edge, runtime, cancelEdge := newE2EEdge(
		t, 101, added.SuperPeer.NodeName, added.SuperPeer.ControlPSKey, "", bind, newE2ETap(), privateKey,
		e2eRetryConfig{}, nil, urls, withE2EEdgeStartIndex(startIndex), withE2EEdgeLogger(logger),
	)
	topology.edges = append(topology.edges, edge)
	topology.edgeRuntimes = append(topology.edgeRuntimes, runtime)
	topology.edgeCancels = append(topology.edgeCancels, cancelEdge)
	WaitApplied(t, topology, 1, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == publicKey.ToString()
	}, 3*time.Second)
	registeredVersion := e2eRecordVersion(t, topology.supers[1].runtime.State(), 101)
	awaitE2E(t, 2*time.Second, func() bool {
		return e2eRecordVersion(t, topology.supers[1].runtime.State(), 101).Newer(registeredVersion)
	})

	// Then: the runtime remains alive on B and its Sync loop never aborts.
	select {
	case <-runtime.Done():
		t.Fatal("edge runtime stopped after bootstrap fallback")
	default:
	}
	logMu.Lock()
	defer logMu.Unlock()
	for _, line := range logged {
		if strings.Contains(line, "HTTP control sync stopped") {
			t.Fatalf("unexpected sync-loop abort log after bootstrap fallback: %q", line)
		}
	}
}

type e2eEdgeControlProxyRequest struct {
	nodeID      string
	path        string
	lastEventID string
	status      int
}

type e2eEdgeControlProxy struct {
	server *httptest.Server

	mu       sync.RWMutex
	target   *url.URL
	requests []e2eEdgeControlProxyRequest
}

func newE2EEdgeControlProxy(t *testing.T, rawTarget string) *e2eEdgeControlProxy {
	t.Helper()
	target, err := url.Parse(rawTarget)
	if err != nil {
		t.Fatalf("parse edge control proxy target %q: %v", rawTarget, err)
	}
	proxy := &e2eEdgeControlProxy{target: target}
	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.serveHTTP))
	t.Cleanup(func() {
		proxy.server.CloseClientConnections()
		proxy.server.Close()
	})
	return proxy
}

func (proxy *e2eEdgeControlProxy) URL() string {
	return proxy.server.URL
}

func (proxy *e2eEdgeControlProxy) SetTarget(t *testing.T, rawTarget string) {
	t.Helper()
	target, err := url.Parse(rawTarget)
	if err != nil {
		t.Fatalf("parse replacement edge control proxy target %q: %v", rawTarget, err)
	}
	proxy.mu.Lock()
	proxy.target = target
	proxy.mu.Unlock()
}

func (proxy *e2eEdgeControlProxy) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	proxy.mu.Lock()
	requestIndex := len(proxy.requests)
	proxy.requests = append(proxy.requests, e2eEdgeControlProxyRequest{
		nodeID:      request.Header.Get(device.HeaderNodeID),
		path:        request.URL.Path,
		lastEventID: request.Header.Get("Last-Event-ID"),
	})
	target := proxy.target
	proxy.mu.Unlock()
	if target == nil {
		proxy.setStatus(requestIndex, http.StatusServiceUnavailable)
		http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	reverseProxy.ModifyResponse = func(response *http.Response) error {
		proxy.setStatus(requestIndex, response.StatusCode)
		return nil
	}
	reverseProxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
		proxy.setStatus(requestIndex, http.StatusBadGateway)
		http.Error(writer, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
	}
	reverseProxy.ServeHTTP(writer, request)
}

func (proxy *e2eEdgeControlProxy) setStatus(index, status int) {
	proxy.mu.Lock()
	proxy.requests[index].status = status
	proxy.mu.Unlock()
}

func (proxy *e2eEdgeControlProxy) count(nodeID, pathSuffix string, status int) int {
	proxy.mu.RLock()
	defer proxy.mu.RUnlock()
	count := 0
	for _, request := range proxy.requests {
		if request.nodeID != nodeID || !strings.HasSuffix(request.path, pathSuffix) {
			continue
		}
		if status != 0 && request.status != status {
			continue
		}
		count++
	}
	return count
}

func (proxy *e2eEdgeControlProxy) successfulCount(nodeID, pathSuffix string) int {
	proxy.mu.RLock()
	defer proxy.mu.RUnlock()
	count := 0
	for _, request := range proxy.requests {
		if request.nodeID == nodeID && strings.HasSuffix(request.path, pathSuffix) && request.status >= 200 && request.status < 300 {
			count++
		}
	}
	return count
}

func (proxy *e2eEdgeControlProxy) eventIDs(nodeID string) []string {
	proxy.mu.RLock()
	defer proxy.mu.RUnlock()
	ids := make([]string, 0)
	for _, request := range proxy.requests {
		if request.nodeID == nodeID && strings.HasSuffix(request.path, "/events") {
			ids = append(ids, request.lastEventID)
		}
	}
	return ids
}

func TestMultiSuperE2EEdgeSwitchResetsRevision(t *testing.T) {
	// Given: Edge 101 is authorized by both Supers, then A and B are partitioned
	// so A can advance far beyond B's independent revision history.
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	setE2EReportInterval(t, topology, 50*time.Millisecond)
	aProxy := newE2EEdgeControlProxy(t, topology.supers[0].edgeURL)
	bProxy := newE2EEdgeControlProxy(t, topology.supers[1].edgeURL)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	added101, err := topology.supers[0].runtime.Manage().AddPeer(ctx, ManageAddPeerRequest{NodeID: 101, NodeName: "edge-101"})
	cancel()
	if err != nil {
		t.Fatalf("add edge 101 on A: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		key, ok := topology.supers[1].runtime.State().ControlKeyFor(101)
		return ok && key == added101.SuperPeer.ControlPSKey
	})
	CutLink(topology, 0, 1)
	awaitE2E(t, 3*time.Second, func() bool {
		return !e2eLinkConnected(topology, 0, 1) && !e2eLinkConnected(topology, 1, 0)
	})

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	added102, err := topology.supers[1].runtime.Manage().AddPeer(ctx, ManageAddPeerRequest{NodeID: 102, NodeName: "edge-102"})
	cancel()
	if err != nil {
		t.Fatalf("add edge 102 on B: %v", err)
	}
	fabric := newE2EFabric()
	edge102 := startMultiSuperE2EEdge(t, topology, fabric, 1, 102, added102.SuperPeer.NodeName, added102.SuperPeer.ControlPSKey, []string{topology.supers[1].edgeURL})
	WaitApplied(t, topology, 1, 102, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge102.publicKey.ToString()
	}, 3*time.Second)

	edge101 := startMultiSuperE2EEdge(t, topology, fabric, 0, 101, added101.SuperPeer.NodeName, added101.SuperPeer.ControlPSKey, []string{aProxy.URL(), bProxy.URL()})
	WaitApplied(t, topology, 0, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge101.publicKey.ToString()
	}, 3*time.Second)

	// When: authenticated reports drive A above revision 100 and A is shut down,
	// forcing the real Edge runtime to switch epochs to B.
	driver := device.NewControlHTTPClient(aProxy.URL(), mtypes.ControlV2APIPrefix, 101, added101.SuperPeer.ControlPSKey)
	driver.Now = topology.supers[0].clock.Now
	for i := 0; i < 110; i++ {
		relayCost := float64(i % 2)
		reportCtx, cancelReport := context.WithTimeout(context.Background(), time.Second)
		err := driver.Report(reportCtx, &mtypes.ControlV2ReportRequest{
			NodeID:      101,
			RelayCostMS: &relayCost,
			ReportedAt:  topology.supers[0].clock.Now(),
		})
		cancelReport()
		if err != nil {
			t.Fatalf("drive A revision with report %d: %v", i, err)
		}
	}
	awaitE2E(t, 5*time.Second, func() bool {
		return topology.supers[0].runtime.State().SnapshotFor(101).Revision >= 100
	})
	client101 := edge101.runtime.ControlClientForTest()
	awaitE2E(t, 5*time.Second, func() bool {
		current := client101.Current()
		return current != nil && current.Revision >= 100
	})
	ShutdownSuper(t, topology, 0)
	WaitApplied(t, topology, 1, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge101.publicKey.ToString()
	}, 5*time.Second)

	// Then: B's low revision becomes the new baseline, its peer set is applied,
	// and the first B event stream starts without replay state from A.
	awaitE2E(t, 5*time.Second, func() bool {
		current := client101.Current()
		if current == nil || current.Revision == 0 || current.Revision >= 20 || len(current.Peers) != 1 {
			return false
		}
		return current.Peers[0].NodeID == 102 && current.Peers[0].PubKey == edge102.publicKey.ToString()
	})
	awaitE2E(t, 5*time.Second, func() bool {
		return len(bProxy.eventIDs("101")) > 0
	})
	if eventIDs := bProxy.eventIDs("101"); eventIDs[0] != "" {
		t.Fatalf("B first SSE Last-Event-ID = %q, want empty", eventIDs[0])
	}
}

func TestMultiSuperE2EEdgeNoFailbackWhileHealthy(t *testing.T) {
	// Given: a real Edge starts on A through a stable proxy address and B has
	// received the replicated registry key needed for failover.
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	setE2EReportInterval(t, topology, 50*time.Millisecond)
	aProxy := newE2EEdgeControlProxy(t, topology.supers[0].edgeURL)
	bProxy := newE2EEdgeControlProxy(t, topology.supers[1].edgeURL)
	fabric := newE2EFabric()
	edge101 := newMultiSuperE2EEdge(t, topology, fabric, 0, 101, []string{aProxy.URL(), bProxy.URL()})
	edge101.runtime.SetFailoverThresholdsForTest(300 * time.Millisecond)
	awaitE2E(t, 3*time.Second, func() bool {
		key, ok := topology.supers[1].runtime.State().ControlKeyFor(101)
		return ok && key == edge101.key && aProxy.successfulCount("101", "/report") > 0
	})

	// When: A is shut down, the Edge becomes healthy on B, and A is restarted
	// behind the same reachable proxy URL.
	ShutdownSuper(t, topology, 0)
	awaitE2E(t, 5*time.Second, func() bool {
		record, ok := e2eLiveRecord(topology.supers[1].runtime.State(), 101)
		return ok && record.Origin == topology.supers[1].id && bProxy.successfulCount("101", "/report") > 0
	})
	oldA := topology.supers[0]
	oldA.proxy.Close()
	restarted := newE2ESuperFrom(t, oldA.dir, oldA.id, oldA.clock)
	topology.supers[0] = *restarted
	topology.proxies[0] = restarted.proxy
	topology.edgeListeners[0] = restarted.edgeLn
	topology.manageListeners[0] = restarted.manageLn
	aProxy.SetTarget(t, restarted.edgeURL)
	HealLink(topology, 0, 1)
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	WaitApplied(t, topology, 0, 101, func(peer mtypes.ControlV2Peer) bool {
		return peer.PubKey == edge101.publicKey.ToString()
	}, 3*time.Second)

	// Then: twenty further successful B report intervals produce no request to
	// the now-healthy A endpoint, proving there is no automatic fail-back.
	aRequests := aProxy.count("101", "", 0)
	bReports := bProxy.successfulCount("101", "/report")
	awaitE2E(t, 5*time.Second, func() bool {
		return bProxy.successfulCount("101", "/report") >= bReports+20
	})
	if got := aProxy.count("101", "", 0); got != aRequests {
		t.Fatalf("edge sent %d requests to recovered A during 20 healthy B reports, want 0", got-aRequests)
	}
	if record, ok := e2eLiveRecord(topology.supers[1].runtime.State(), 101); !ok || record.Origin != topology.supers[1].id {
		t.Fatalf("B live record after recovered A = %+v, ok=%v; want origin %d", record, ok, topology.supers[1].id)
	}
}

func TestMultiSuperE2EEdge401OnMissingKeyRotates(t *testing.T) {
	// Given: registry replication is cut before Edge 101 is added to A, leaving
	// B intentionally unable to authenticate that Edge's control key.
	topology := newE2EMultiSuperTopology(t, 2, e2eClusterOptions{})
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	setE2EReportInterval(t, topology, 50*time.Millisecond)
	aProxy := newE2EEdgeControlProxy(t, topology.supers[0].edgeURL)
	bProxy := newE2EEdgeControlProxy(t, topology.supers[1].edgeURL)
	CutLink(topology, 0, 1)
	awaitE2E(t, 3*time.Second, func() bool {
		return !e2eLinkConnected(topology, 0, 1) && !e2eLinkConnected(topology, 1, 0)
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	added, err := topology.supers[0].runtime.Manage().AddPeer(ctx, ManageAddPeerRequest{NodeID: 101, NodeName: "edge-101"})
	cancel()
	if err != nil {
		t.Fatalf("add isolated edge 101 on A: %v", err)
	}
	if key, ok := topology.supers[1].runtime.State().ControlKeyFor(101); ok {
		t.Fatalf("B unexpectedly has isolated edge key %q", key)
	}
	fabric := newE2EFabric()
	edge101 := startMultiSuperE2EEdge(t, topology, fabric, 0, 101, added.SuperPeer.NodeName, added.SuperPeer.ControlPSKey, []string{aProxy.URL(), bProxy.URL()})
	edge101.runtime.SetFailoverThresholdsForTest(300 * time.Millisecond)
	awaitE2E(t, 3*time.Second, func() bool {
		return aProxy.successfulCount("101", "/report") > 0
	})

	// When: A dies, B answers three-report failure windows with 401 while dead A
	// answers alternate windows with 502, exercising repeated selector rotation.
	ShutdownSuper(t, topology, 0)
	awaitE2E(t, 8*time.Second, func() bool {
		return bProxy.count("101", "/report", http.StatusUnauthorized) >= 6 &&
			aProxy.count("101", "/report", http.StatusBadGateway) >= 6
	})
	select {
	case <-edge101.runtime.Done():
		t.Fatal("edge runtime stopped while cycling between dead A and unauthorized B")
	default:
	}

	// Then: restarting A and healing replication lets whichever Super is current
	// authenticate, register, and resume successful reports without a crash.
	oldA := topology.supers[0]
	oldA.proxy.Close()
	restarted := newE2ESuperFrom(t, oldA.dir, oldA.id, oldA.clock)
	topology.supers[0] = *restarted
	topology.proxies[0] = restarted.proxy
	topology.edgeListeners[0] = restarted.edgeLn
	topology.manageListeners[0] = restarted.manageLn
	aProxy.SetTarget(t, restarted.edgeURL)
	HealLink(topology, 0, 1)
	WaitLinked(t, topology, 0, 1, 3*time.Second)
	WaitLinked(t, topology, 1, 0, 3*time.Second)
	awaitE2E(t, 10*time.Second, func() bool {
		key, ok := topology.supers[1].runtime.State().ControlKeyFor(101)
		return ok && key == edge101.key
	})
	successfulReports := aProxy.successfulCount("101", "/report") + bProxy.successfulCount("101", "/report")
	awaitE2E(t, 10*time.Second, func() bool {
		return aProxy.successfulCount("101", "/report")+bProxy.successfulCount("101", "/report") > successfulReports
	})
	for index := range topology.supers {
		WaitApplied(t, topology, index, 101, func(peer mtypes.ControlV2Peer) bool {
			return peer.PubKey == edge101.publicKey.ToString()
		}, 3*time.Second)
	}
	select {
	case <-edge101.runtime.Done():
		t.Fatal("edge runtime stopped instead of recovering after A restart")
	default:
	}
}
