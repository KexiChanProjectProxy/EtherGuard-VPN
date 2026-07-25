package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

func TestHTTPOnlySuperEndToEnd(t *testing.T) {
	// Given an HTTP-only Super with two real Edge devices on bindtest links.
	topology := newE2ETopology(t)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := topology.shutdown(ctx); err != nil {
			t.Errorf("topology shutdown: %v", err)
		}
	})

	if topology.edgeListener.Addr().Network() != "tcp" || topology.manageListener.Addr().Network() != "tcp" {
		t.Fatal("HTTP-only Super exposed a non-TCP control listener")
	}
	if topology.runtime.State() == nil || topology.runtime.Hub() == nil || topology.runtime.Auth() == nil || topology.runtime.Manage() == nil {
		t.Fatal("HTTP-only Super did not expose its control-plane runtime services")
	}

	wrongIdentity := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 102, topology.keyA)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, _, err := wrongIdentity.Snapshot(ctx); err == nil {
		t.Fatal("Edge A control key authenticated as Edge B")
	}

	// When both runtimes register and report their same-bind STUN candidates.
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, err := topology.snapshot(ctx, 102, topology.keyB)
		if err != nil {
			return false
		}
		peer, found := e2ePeer(snapshot, 101)
		return found && len(peer.LocalV4) == 1 && len(peer.PublicV4) == 1
	})

	// Then the peer-safe HTTP snapshot exposes the other Edge's same-bind
	// candidates and WireGuard identity, never the control key.
	snapshotB, err := topology.snapshot(ctx, 102, topology.keyB)
	if err != nil {
		t.Fatalf("Edge B snapshot: %v", err)
	}
	peerA, found := e2ePeer(snapshotB, 101)
	if !found {
		t.Fatal("Edge B snapshot omitted registered Edge A")
	}
	if peerA.PubKey != topology.pubA.ToString() {
		t.Fatalf("Edge A public key in snapshot = %q, want %q", peerA.PubKey, topology.pubA.ToString())
	}
	if peerA.PSKey != "" {
		t.Fatal("Edge B snapshot exposed Edge A control key")
	}
	assertSameBindCandidate(t, peerA.LocalV4[0], peerA.PublicV4[0], "198.51.100.101")

	awaitE2E(t, 3*time.Second, func() bool {
		return topology.edgeA.LookupPeer(topology.pubB) != nil && topology.edgeB.LookupPeer(topology.pubA) != nil &&
			topology.edgeA.GetConnurl(102) != "" && topology.edgeB.GetConnurl(101) != ""
	})
	peerToB := topology.edgeA.LookupPeer(topology.pubB)
	if err := peerToB.SendHandshakeInitiation(false); err != nil {
		t.Fatalf("start direct Edge handshake: %v", err)
	}
	payload := e2eNormalPacket(t, 101, 102)
	topology.edgeA.SendPacket(peerToB, path.NormalPacket, 64, payload, device.MessageTransportOffsetContent)
	select {
	case <-topology.bindA.responses:
	case <-ctx.Done():
		t.Fatal("direct Edge handshake response did not arrive before deadline")
	}
	select {
	case usage := <-topology.bindB.transports:
		if usage != path.NormalPacket {
			t.Fatalf("direct Edge transport usage = %v, want %v", usage, path.NormalPacket)
		}
	case <-ctx.Done():
		t.Fatal("direct Edge transport packet did not cross the bind topology before deadline")
	}

	// When a real report changes latency, the Super publishes an SSE
	// invalidation and recalculates the direct next hop.
	before := snapshotB.Revision
	subscriber, err := topology.runtime.Hub().Subscribe(ctx, "")
	if err != nil {
		t.Fatalf("subscribe to Super event hub: %v", err)
	}
	t.Cleanup(subscriber.Close)
	topology.clock.Advance(time.Millisecond)
	reporter := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, 101, topology.keyA)
	if err := reporter.Report(ctx, &mtypes.ControlV2ReportRequest{
		NodeID:     101,
		Candidates: e2eCandidates(peerA),
		Pongs: []mtypes.ControlV2Pong{{
			SourceNode:   101,
			DestNode:     102,
			LatencyMS:    4.5,
			AliveSeconds: 5,
		}},
		ReportedAt: topology.clock.Now(),
	}); err != nil {
		t.Fatalf("report latency: %v", err)
	}
	awaitSSERevision(t, ctx, subscriber.Events(), before)
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, snapshotErr := topology.snapshot(ctx, 102, topology.keyB)
		peer, exists := e2ePeer(snapshot, 101)
		return snapshotErr == nil && exists && peer.LatencyMS[102] == 4.5 && topology.runtime.graph.Next(101, 102) == 102
	})

	// When SSE is forcibly unavailable, polling still removes a deleted peer.
	topology.runtime.Hub().Close()
	if err := topology.runtime.Manage().DeletePeer(ctx, ManageDeletePeerRequest{NodeID: 101}); err != nil {
		t.Fatalf("delete Edge A: %v", err)
	}
	awaitE2E(t, 3*time.Second, func() bool {
		snapshot, snapshotErr := topology.snapshot(ctx, 102, topology.keyB)
		_, exists := e2ePeer(snapshot, 101)
		return snapshotErr == nil && !exists && topology.edgeB.LookupPeer(topology.pubA) == nil
	})

	// Then every runtime stops through its documented lifecycle.
	shutdownCtx, stopShutdown := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopShutdown()
	if err := topology.shutdown(shutdownCtx); err != nil {
		t.Fatalf("clean topology shutdown: %v", err)
	}
	select {
	case <-topology.edgeA.Wait():
	case <-shutdownCtx.Done():
		t.Fatal("Edge A did not close")
	}
	select {
	case <-topology.edgeB.Wait():
	case <-shutdownCtx.Done():
		t.Fatal("Edge B did not close")
	}
}

func (topology *e2eTopology) snapshot(ctx context.Context, nodeID mtypes.Vertex, key string) (*mtypes.ControlV2Snapshot, error) {
	client := device.NewControlHTTPClient(topology.baseURL, mtypes.ControlV2APIPrefix, nodeID, key)
	snapshot, _, err := client.Snapshot(ctx)
	return snapshot, err
}

func awaitE2E(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-timeoutTimer.C:
			t.Fatal("end-to-end condition did not converge")
		}
	}
}

func e2ePeer(snapshot *mtypes.ControlV2Snapshot, nodeID mtypes.Vertex) (mtypes.ControlV2Peer, bool) {
	if snapshot == nil {
		return mtypes.ControlV2Peer{}, false
	}
	for _, peer := range snapshot.Peers {
		if peer.NodeID == nodeID {
			return peer, true
		}
	}
	return mtypes.ControlV2Peer{}, false
}

func assertSameBindCandidate(t *testing.T, local, mapped, wantIP string) {
	t.Helper()
	_, localPort, err := net.SplitHostPort(local)
	if err != nil {
		t.Fatalf("local candidate %q: %v", local, err)
	}
	mappedIP, mappedPort, err := net.SplitHostPort(mapped)
	if err != nil {
		t.Fatalf("mapped candidate %q: %v", mapped, err)
	}
	if mappedIP != wantIP || mappedPort != localPort {
		t.Fatalf("mapped candidate = %s, want %s with active bind port %s", mapped, wantIP, localPort)
	}
}

func e2eNormalPacket(t *testing.T, source, destination mtypes.Vertex) []byte {
	t.Helper()
	packet := make([]byte, path.EgHeaderLen+14)
	header, err := path.NewEgHeader(packet[:path.EgHeaderLen], 1400)
	if err != nil {
		t.Fatalf("create EtherGuard header: %v", err)
	}
	header.SetSrc(source)
	header.SetDst(destination)
	copy(packet[path.EgHeaderLen:], []byte{0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00})
	return packet
}

func e2eCandidates(peer mtypes.ControlV2Peer) []mtypes.ControlV2Candidate {
	candidates := make([]mtypes.ControlV2Candidate, 0, len(peer.LocalV4)+len(peer.PublicV4))
	for _, address := range peer.LocalV4 {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: address, Source: mtypes.ControlV2CandidateLocal})
	}
	for _, address := range peer.PublicV4 {
		candidates = append(candidates, mtypes.ControlV2Candidate{Address: address, Source: mtypes.ControlV2CandidateSTUN})
	}
	return candidates
}

func awaitSSERevision(t *testing.T, ctx context.Context, events <-chan mtypes.ControlV2Event, revision uint64) {
	t.Helper()
	for {
		select {
		case event := <-events:
			if event.Type == mtypes.ControlV2EventPeerChange && event.Revision > revision {
				return
			}
		case <-ctx.Done():
			t.Fatal("SSE invalidation did not arrive before deadline")
		}
	}
}
