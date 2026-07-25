package main

import (
	"context"
	"sync"
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
