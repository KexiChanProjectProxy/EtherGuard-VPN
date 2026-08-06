package main

import (
	"context"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func TestControlStateReportPongsReplaceCompleteLatencySet(t *testing.T) {
	// Given a reporting edge with two published directed latency measurements.
	svc := NewControlState(ControlStateConfig{})
	for _, req := range []mtypes.ControlV2RegisterRequest{
		controlRegisterRequest(1, "reporter"),
		controlRegisterRequest(4, "reader"),
	} {
		if _, err := svc.Register(context.Background(), req, "control-key"); err != nil {
			t.Fatalf("register node %d: %v", req.NodeID, err)
		}
	}
	var events []mtypes.ControlV2Event
	svc.SetPublishForTest(func(event mtypes.ControlV2Event) { events = append(events, event) })
	initial := mtypes.ControlV2ReportRequest{
		NodeID: 1,
		Pongs: []mtypes.ControlV2Pong{
			{SourceNode: 1, DestNode: 2, LatencyMS: 7, AliveSeconds: 70},
			{SourceNode: 1, DestNode: 3, LatencyMS: 9, AliveSeconds: 70},
		},
	}
	if err := svc.Report(context.Background(), initial); err != nil {
		t.Fatalf("initial report: %v", err)
	}

	// When the next complete report omits destination 3.
	revision := svc.Revision()
	eventCount := len(events)
	current := mtypes.ControlV2ReportRequest{
		NodeID: 1,
		Pongs:  []mtypes.ControlV2Pong{{SourceNode: 1, DestNode: 2, LatencyMS: 7, AliveSeconds: 70}},
	}
	if err := svc.Report(context.Background(), current); err != nil {
		t.Fatalf("current report: %v", err)
	}

	// Then the omitted edge is withdrawn with one revision and peer-change event.
	latencies := observedPeer(t, svc.SnapshotFor(4), 1).LatencyMS
	if len(latencies) != 1 || latencies[2] != 7 {
		t.Fatalf("latencies after omission = %#v, want map[2:7]", latencies)
	}
	if svc.Revision() != revision+1 || len(events) != eventCount+1 {
		t.Fatalf("omission revision/events = %d/%d, want %d/%d", svc.Revision(), len(events), revision+1, eventCount+1)
	}
	lastEvent := events[len(events)-1]
	if lastEvent.Type != mtypes.ControlV2EventPeerChange || lastEvent.Revision != svc.Revision() {
		t.Fatalf("omission event = %#v", lastEvent)
	}

	// Repeating the same complete set must be invisible to snapshot consumers.
	revision = svc.Revision()
	eventCount = len(events)
	if err := svc.Report(context.Background(), current); err != nil {
		t.Fatalf("repeat current report: %v", err)
	}
	if svc.Revision() != revision || len(events) != eventCount {
		t.Fatalf("unchanged complete set changed revision/events: %d/%d", svc.Revision(), len(events))
	}
}
