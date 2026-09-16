package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

type clusterProtoTestFixtures struct {
	peer           clusterPeerRecord
	alive          clusterAlive
	delete         clusterDelete
	registry       clusterRegistryEntry
	registryDelete clusterRegistryDelete
	params         clusterParams
	fullSync       clusterFullSync
}

func newClusterProtoTestFixtures() clusterProtoTestFixtures {
	now := time.Date(2026, time.September, 16, 12, 34, 56, 789000000, time.UTC).Truncate(time.Microsecond)
	relayCost := 12.5
	port := 51820
	peerVersion := ClusterVersion{HLC: 101, Origin: mtypes.Vertex(1)}
	registryVersion := ClusterVersion{HLC: 102, Origin: mtypes.Vertex(2)}
	paramsVersion := ClusterVersion{HLC: 103, Origin: mtypes.Vertex(1)}
	peer := clusterPeerRecord{
		NodeID:   mtypes.Vertex(101),
		NodeName: "edge-101",
		PubKey:   "public-key",
		Candidates: []mtypes.ControlV2Candidate{
			{Address: "192.0.2.10:51820", Source: mtypes.ControlV2CandidateLocal, RTTMS: 1.25},
		},
		RelayCostMS: &relayCost,
		LatencyMS:   map[mtypes.Vertex]float64{mtypes.Vertex(102): 8.75},
		Observed: []mtypes.ControlV2ObservedEndpoint{
			{TargetNodeID: mtypes.Vertex(102), Address: "198.51.100.20:51820"},
		},
		LastSeen: now,
		Version:  peerVersion,
		Origin:   mtypes.Vertex(1),
	}
	registry := clusterRegistryEntry{
		NodeID:         mtypes.Vertex(101),
		NodeName:       "edge-101",
		ControlPSKey:   "cluster-private-key",
		AdditionalCost: 10.5,
		Version:        registryVersion,
		Origin:         mtypes.Vertex(2),
	}
	params := clusterParams{
		Parameters: mtypes.ControlV2Parameters{
			ProtocolVersion:     mtypes.ControlV2ProtocolVersion,
			PollInterval:        3 * time.Second,
			STUNServers:         []string{"stun:stun.example.com:3478"},
			STUNRequestTimeout:  1500 * time.Millisecond,
			STUNRefreshInterval: 45 * time.Second,
			ReportInterval:      5 * time.Second,
			HeartbeatInterval:   2 * time.Second,
			EventReplay:         64,
			RelayCostMS:         &relayCost,
			ListenPortPriority:  mtypes.ListenPortPriority{{Port: &port}},
			EndpointBlacklist:   []string{"203.0.113.0/24"},
		},
		Version: paramsVersion,
	}
	alive := clusterAlive{NodeID: peer.NodeID, Version: ClusterVersion{HLC: 104, Origin: peer.Origin}, LastSeen: now.Add(time.Second)}
	deleted := clusterDelete{NodeID: peer.NodeID, Version: ClusterVersion{HLC: 105, Origin: peer.Origin}}
	registryDelete := clusterRegistryDelete{NodeID: registry.NodeID, Version: ClusterVersion{HLC: 106, Origin: registry.Origin}}
	return clusterProtoTestFixtures{
		peer:           peer,
		alive:          alive,
		delete:         deleted,
		registry:       registry,
		registryDelete: registryDelete,
		params:         params,
		fullSync: clusterFullSync{
			Part:               1,
			Of:                 1,
			Live:               []clusterPeerRecord{peer},
			LiveTombstones:     []clusterDelete{deleted},
			Registry:           []clusterRegistryEntry{registry},
			RegistryTombstones: []clusterRegistryTombstone{{NodeID: registry.NodeID, Version: registryDelete.Version, Origin: registry.Origin, DeletedAt: now}},
			Params:             &params,
		},
	}
}

func TestClusterProtoRegistryCarriesKey(t *testing.T) {
	// Given a cluster-private registry entry containing its control key.
	envelope := clusterEnvelope{T: clusterMessageRegistryUpsert, Registry: &clusterRegistryEntry{NodeID: mtypes.Vertex(101), ControlPSKey: "k"}}

	// When the envelope is encoded for the cluster link.
	encoded, err := encodeClusterEnvelope(envelope)

	// Then the raw wire JSON carries the key rather than applying log redaction.
	if err != nil {
		t.Fatalf("encode registry envelope: %v", err)
	}
	if !strings.Contains(string(encoded), `"control_pskey":"k"`) {
		t.Fatalf("encoded registry envelope omitted control_pskey: %s", encoded)
	}
}

func TestClusterProtoRoundTripAll(t *testing.T) {
	// Given one populated envelope for every protocol message type.
	fixtures := newClusterProtoTestFixtures()
	tests := []struct {
		name     string
		envelope clusterEnvelope
	}{
		{"hello", clusterEnvelope{T: clusterMessageHello, Hello: &clusterHello{SuperID: mtypes.Vertex(1), Proto: clusterProtoVersion, HLC: 100}, HLC: 100}},
		{"full_sync", clusterEnvelope{T: clusterMessageFullSync, FullSync: &fixtures.fullSync, HLC: 103}},
		{"peer_upsert", mutationToEnvelope(clusterMutation{Kind: clusterMessagePeerUpsert, Peer: &fixtures.peer, Version: fixtures.peer.Version})},
		{"peer_alive", mutationToEnvelope(clusterMutation{Kind: clusterMessagePeerAlive, Alive: &fixtures.alive, Version: fixtures.alive.Version})},
		{"peer_delete", mutationToEnvelope(clusterMutation{Kind: clusterMessagePeerDelete, NodeID: fixtures.delete.NodeID, Version: fixtures.delete.Version})},
		{"registry_upsert", mutationToEnvelope(clusterMutation{Kind: clusterMessageRegistryUpsert, Registry: &fixtures.registry, Version: fixtures.registry.Version})},
		{"registry_delete", mutationToEnvelope(clusterMutation{Kind: clusterMessageRegistryDelete, NodeID: fixtures.registryDelete.NodeID, Version: fixtures.registryDelete.Version})},
		{"params_update", mutationToEnvelope(clusterMutation{Kind: clusterMessageParamsUpdate, Params: &fixtures.params, Version: fixtures.params.Version})},
		{"ping", clusterEnvelope{T: clusterMessagePing, HLC: 107}},
		{"pong", clusterEnvelope{T: clusterMessagePong, HLC: 108}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When the envelope is encoded and decoded.
			encoded, err := encodeClusterEnvelope(test.envelope)
			if err != nil {
				t.Fatalf("encode envelope: %v", err)
			}
			decoded, err := decodeClusterEnvelope(encoded)

			// Then all payload values, times, maps, slices, and pointed-to values round-trip.
			if err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			if !reflect.DeepEqual(decoded, test.envelope) {
				t.Fatalf("round trip mismatch:\n got: %#v\nwant: %#v", decoded, test.envelope)
			}
		})
	}
}

func TestClusterProtoSplitFullSync(t *testing.T) {
	// Given 450 live records plus full-sync metadata and the default-sized workload.
	fixtures := newClusterProtoTestFixtures()
	live := make([]clusterPeerRecord, 450)
	for i := range live {
		live[i] = clusterPeerRecord{NodeID: mtypes.Vertex(1000 + i), Version: ClusterVersion{HLC: uint64(i + 1), Origin: mtypes.Vertex(1)}}
	}
	tombstones := []clusterDelete{fixtures.delete}
	registry := []clusterRegistryEntry{fixtures.registry}
	registryTombstones := fixtures.fullSync.RegistryTombstones

	// When the live records are split with a batch size of 200.
	parts := splitFullSync(live, tombstones, registry, registryTombstones, &fixtures.params, 200)

	// Then live records are bounded and all non-live metadata appears only in part one.
	if len(parts) != 3 {
		t.Fatalf("parts = %d, want 3", len(parts))
	}
	wantLive := []int{200, 200, 50}
	for i, part := range parts {
		if part.Part != i+1 || part.Of != 3 || len(part.Live) != wantLive[i] {
			t.Fatalf("part %d = {Part:%d Of:%d Live:%d}, want {Part:%d Of:3 Live:%d}", i, part.Part, part.Of, len(part.Live), i+1, wantLive[i])
		}
	}
	if !reflect.DeepEqual(parts[0].LiveTombstones, tombstones) || !reflect.DeepEqual(parts[0].Registry, registry) || !reflect.DeepEqual(parts[0].RegistryTombstones, registryTombstones) || !reflect.DeepEqual(parts[0].Params, &fixtures.params) {
		t.Fatal("part one omitted full-sync metadata")
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i].LiveTombstones) != 0 || len(parts[i].Registry) != 0 || len(parts[i].RegistryTombstones) != 0 || parts[i].Params != nil {
			t.Fatalf("part %d repeated full-sync metadata: %#v", i+1, parts[i])
		}
	}
}

func TestClusterProtoRejectsMissingType(t *testing.T) {
	// When an envelope without the required type discriminator is decoded.
	_, err := decodeClusterEnvelope([]byte(`{}`))

	// Then decoding rejects it.
	if err == nil {
		t.Fatal("decodeClusterEnvelope accepted an envelope without t")
	}
}

func TestClusterProtoStringRedactsKey(t *testing.T) {
	// Given a registry entry containing a secret control key.
	entry := clusterRegistryEntry{NodeID: mtypes.Vertex(101), NodeName: "edge-101", ControlPSKey: "secret123"}

	// When the entry is formatted through its logging representation.
	formatted := fmt.Sprint(entry)

	// Then the key value is redacted.
	if strings.Contains(formatted, "secret123") {
		t.Fatalf("formatted registry entry leaked key: %s", formatted)
	}
}
