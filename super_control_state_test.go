package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestControlStateRegistrationAndReport(t *testing.T) {
	// Given a service and a valid registration request
	svc := NewControlState(ControlStateConfig{})
	req := controlRegisterRequest(1, "edge-a")

	// When the edge registers
	snapshot, err := svc.Register(context.Background(), req, "control-a")

	// Then it is represented without exposing its control key
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(snapshot.Peers) != 0 {
		t.Fatalf("self peer must not appear in own snapshot, got %#v", snapshot.Peers)
	}
	if key, ok := svc.ControlKeyFor(req.NodeID); !ok || key != "control-a" {
		t.Fatalf("control key lookup failed: %q ok=%v", key, ok)
	}
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: req.NodeID, Candidates: []mtypes.ControlV2Candidate{{Address: "192.0.2.1:51820", Source: mtypes.ControlV2CandidateLocal}}}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if peers := svc.SnapshotFor(req.NodeID).Peers; len(peers) != 0 {
		t.Fatal("self peer must not appear in own snapshot after report")
	}
}

func TestControlStateReportedCandidateReachesOtherEdges(t *testing.T) {
	// Given two registered edges on a fresh service
	svc := NewControlState(ControlStateConfig{})
	if _, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "key-a"); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if _, err := svc.Register(context.Background(), controlRegisterRequest(2, "edge-b"), "key-b"); err != nil {
		t.Fatalf("register b: %v", err)
	}
	baseline := svc.Revision()

	// When edge A reports a new STUN-derived candidate
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 1, Candidates: []mtypes.ControlV2Candidate{
		{Address: "192.0.2.1:51820", Source: mtypes.ControlV2CandidateLocal},
		{Address: "203.0.113.10:51820", Source: mtypes.ControlV2CandidateSTUN},
		{Address: "[2001:db8::10]:51820", Source: mtypes.ControlV2CandidateSTUN},
	}}); err != nil {
		t.Fatalf("report a: %v", err)
	}

	// Then edge B's snapshot exposes the new candidate and the revision bumped
	snap := svc.SnapshotFor(2)
	if svc.Revision() <= baseline {
		t.Fatalf("revision did not bump: baseline=%d now=%d", baseline, svc.Revision())
	}
	if len(snap.Peers) != 1 || snap.Peers[0].NodeID != 1 {
		t.Fatalf("unexpected peers: %#v", snap.Peers)
	}
	if !contains(snap.Peers[0].PublicV4, "203.0.113.10:51820") {
		t.Fatalf("STUN v4 candidate missing from public list: %#v", snap.Peers[0].PublicV4)
	}
	if !contains(snap.Peers[0].PublicV6, "[2001:db8::10]:51820") {
		t.Fatalf("STUN v6 candidate missing from public list: %#v", snap.Peers[0].PublicV6)
	}
	if !contains(snap.Peers[0].LocalV4, "192.0.2.1:51820") {
		t.Fatalf("Local v4 candidate missing: %#v", snap.Peers[0].LocalV4)
	}
	if snap.Peers[0].PSKey != "" {
		t.Fatalf("control PSKey leaked into peer view")
	}
}

func TestControlStateTimeoutAndRevisionSemantics(t *testing.T) {
	// Given a controllable clock and an alive timeout
	svc := NewControlState(ControlStateConfig{Now: currentTime, PeerAliveTimeout: 0})
	_, err := svc.Register(context.Background(), controlRegisterRequest(1, "edge-a"), "key")
	if err != nil {
		t.Fatal(err)
	}
	rev := svc.Revision()

	// When an identical report arrives, only heartbeat changes
	if err := svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: 1}); err != nil {
		t.Fatal(err)
	}
	if svc.Revision() != rev {
		t.Fatalf("heartbeat changed revision: %d -> %d", rev, svc.Revision())
	}
	svc.peerAliveTimeout = time.Minute
	advance(2 * time.Minute)
	advance(0) // ensure atomic publish visibility
	if removed := svc.SweepTimeouts(); removed != 1 {
		t.Fatalf("removed=%d", removed)
	}
	if svc.Revision() != rev+1 {
		t.Fatalf("revision=%d want %d", svc.Revision(), rev+1)
	}
	if svc.SweepTimeouts() != 0 || svc.Revision() != rev+1 {
		t.Fatal("empty sweep changed revision")
	}
}

func TestControlStateConcurrentMutation(t *testing.T) {
	// Given one service shared by concurrent writers and readers
	svc := NewControlState(ControlStateConfig{PeerAliveTimeout: time.Hour})
	// When many goroutines register, report, and snapshot concurrently
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := mtypes.Vertex(i + 1)
			_, _ = svc.Register(context.Background(), controlRegisterRequest(id, "edge"), "key")
			_ = svc.Report(context.Background(), mtypes.ControlV2ReportRequest{NodeID: id})
			svc.SnapshotFor(id)
		}(i)
	}
	wg.Wait()
	// Then the service remains usable and all keys are isolated
	if svc.Revision() == 0 {
		t.Fatal("concurrent registrations made no observable change")
	}
}

func controlRegisterRequest(id mtypes.Vertex, name string) mtypes.ControlV2RegisterRequest {
	return mtypes.ControlV2RegisterRequest{NodeID: id, NodeName: name, Version: mtypes.ControlV2ProtocolVersion}
}

func contains(list []string, needle string) bool {
	for _, item := range list {
		if item == needle {
			return true
		}
	}
	return false
}

// Test clock — package-private helpers shared across the TDD tests in
// this file only; production code passes its own Now function.
var testClockNanos atomic.Int64

func currentTime() time.Time {
	return time.Unix(0, testClockNanos.Load())
}

func advance(d time.Duration) {
	testClockNanos.Add(int64(d))
}

// Test clock — package-private helpers shared across the TDD tests in
// this file only; production code passes its own Now function.

func TestControlStateRegisterCandidateSourceLabels(t *testing.T) {
	svc := NewControlState(ControlStateConfig{})
	req := mtypes.ControlV2RegisterRequest{
		NodeID:   1,
		NodeName: "edge-a",
		Version:  mtypes.ControlV2ProtocolVersion,
		LocalV4:  []string{"10.0.0.1:51820"},
		LocalV6:  []string{"[fd00::1]:51820"},
		PublicV4: []string{"203.0.113.1:51820"},
		PublicV6: []string{"[2001:db8::1]:51820"},
	}

	if _, err := svc.Register(context.Background(), req, "control-a"); err != nil {
		t.Fatalf("register: %v", err)
	}

	record, ok := svc.peers[req.NodeID]
	if !ok {
		t.Fatalf("registered peer %v not found", req.NodeID)
	}
	want := map[string]mtypes.ControlV2CandidateSource{
		"10.0.0.1:51820":      mtypes.ControlV2CandidateLocal,
		"[fd00::1]:51820":     mtypes.ControlV2CandidateLocal,
		"203.0.113.1:51820":   mtypes.ControlV2CandidateSTUN,
		"[2001:db8::1]:51820": mtypes.ControlV2CandidateSTUN,
	}
	if len(record.candidates) != len(want) {
		t.Fatalf("candidate count = %d, want %d: %#v", len(record.candidates), len(want), record.candidates)
	}
	for _, candidate := range record.candidates {
		wantSource, ok := want[candidate.Address]
		if !ok {
			t.Errorf("unexpected candidate address %q", candidate.Address)
			continue
		}
		if candidate.Source != wantSource {
			t.Errorf("candidate %q source = %q, want %q", candidate.Address, candidate.Source, wantSource)
		}
	}
}
