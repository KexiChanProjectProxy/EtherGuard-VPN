package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const clusterProtoVersion = "eg-cluster/1"

const (
	clusterMessageHello          = "hello"
	clusterMessageFullSync       = "full_sync"
	clusterMessagePeerUpsert     = "peer_upsert"
	clusterMessagePeerAlive      = "peer_alive"
	clusterMessagePeerDelete     = "peer_delete"
	clusterMessageRegistryUpsert = "registry_upsert"
	clusterMessageRegistryDelete = "registry_delete"
	clusterMessageParamsUpdate   = "params_update"
	clusterMessagePing           = "ping"
	clusterMessagePong           = "pong"
)

type clusterPeerRecord struct {
	NodeID      mtypes.Vertex                      `json:"node_id"`
	NodeName    string                             `json:"node_name"`
	PubKey      string                             `json:"pub_key"`
	Candidates  []mtypes.ControlV2Candidate        `json:"candidates,omitempty"`
	RelayCostMS *float64                           `json:"relay_cost_ms,omitempty"`
	LatencyMS   map[mtypes.Vertex]float64          `json:"latency_ms,omitempty"`
	Observed    []mtypes.ControlV2ObservedEndpoint `json:"observed,omitempty"`
	LastSeen    time.Time                          `json:"last_seen"`
	Version     ClusterVersion                     `json:"version"`
	Origin      mtypes.Vertex                      `json:"origin"`
}

type clusterHello struct {
	SuperID mtypes.Vertex `json:"super_id"`
	Proto   string        `json:"proto"`
	HLC     uint64        `json:"hlc"`
}

func (a clusterAlive) MarshalJSON() ([]byte, error) {
	type wire struct {
		NodeID   mtypes.Vertex  `json:"node_id"`
		Version  ClusterVersion `json:"version"`
		LastSeen time.Time      `json:"last_seen"`
	}
	return json.Marshal(wire(a))
}

func (a *clusterAlive) UnmarshalJSON(data []byte) error {
	type wire struct {
		NodeID   mtypes.Vertex  `json:"node_id"`
		Version  ClusterVersion `json:"version"`
		LastSeen time.Time      `json:"last_seen"`
	}
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("cluster protocol: decode peer_alive: %w", err)
	}
	*a = clusterAlive(decoded)
	return nil
}

func (d clusterDelete) MarshalJSON() ([]byte, error) {
	type wire struct {
		NodeID  mtypes.Vertex  `json:"node_id"`
		Version ClusterVersion `json:"version"`
	}
	return json.Marshal(wire(d))
}

func (d *clusterDelete) UnmarshalJSON(data []byte) error {
	type wire struct {
		NodeID  mtypes.Vertex  `json:"node_id"`
		Version ClusterVersion `json:"version"`
	}
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("cluster protocol: decode peer_delete: %w", err)
	}
	*d = clusterDelete(decoded)
	return nil
}

type clusterRegistryEntry struct {
	NodeID         mtypes.Vertex  `json:"node_id"`
	NodeName       string         `json:"node_name"`
	ControlPSKey   string         `json:"control_pskey"`
	AdditionalCost float64        `json:"additional_cost"`
	Version        ClusterVersion `json:"version"`
	Origin         mtypes.Vertex  `json:"origin"`
}

func (e clusterRegistryEntry) String() string {
	return fmt.Sprintf(
		"clusterRegistryEntry{NodeID:%d NodeName:%q ControlPSKey:<redacted> AdditionalCost:%g Version:%v Origin:%d}",
		e.NodeID,
		e.NodeName,
		e.AdditionalCost,
		e.Version,
		e.Origin,
	)
}

func (e clusterRegistryEntry) GoString() string {
	return e.String()
}

type clusterRegistryDelete struct {
	NodeID  mtypes.Vertex  `json:"node_id"`
	Version ClusterVersion `json:"version"`
}

type clusterRegistryTombstone struct {
	NodeID    mtypes.Vertex  `json:"node_id"`
	Version   ClusterVersion `json:"version"`
	Origin    mtypes.Vertex  `json:"origin"`
	DeletedAt time.Time      `json:"deleted_at"`
}

type clusterParams struct {
	Parameters mtypes.ControlV2Parameters `json:"parameters"`
	Version    ClusterVersion             `json:"version"`
}

type clusterFullSync struct {
	Part               int                        `json:"part"`
	Of                 int                        `json:"of"`
	Live               []clusterPeerRecord        `json:"live,omitempty"`
	LiveTombstones     []clusterDelete            `json:"live_tombstones,omitempty"`
	Registry           []clusterRegistryEntry     `json:"registry,omitempty"`
	RegistryTombstones []clusterRegistryTombstone `json:"registry_tombstones,omitempty"`
	Params             *clusterParams             `json:"params,omitempty"`
}

type clusterEnvelope struct {
	T              string                 `json:"t"`
	Hello          *clusterHello          `json:"hello,omitempty"`
	FullSync       *clusterFullSync       `json:"full_sync,omitempty"`
	Peer           *clusterPeerRecord     `json:"peer,omitempty"`
	Alive          *clusterAlive          `json:"alive,omitempty"`
	Delete         *clusterDelete         `json:"delete,omitempty"`
	Registry       *clusterRegistryEntry  `json:"registry,omitempty"`
	RegistryDelete *clusterRegistryDelete `json:"registry_delete,omitempty"`
	Params         *clusterParams         `json:"params,omitempty"`
	HLC            uint64                 `json:"hlc,omitempty"`
}

func encodeClusterEnvelope(e clusterEnvelope) ([]byte, error) {
	encoded, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("cluster protocol: encode envelope: %w", err)
	}
	return encoded, nil
}

func decodeClusterEnvelope(b []byte) (clusterEnvelope, error) {
	var envelope clusterEnvelope
	if err := json.Unmarshal(b, &envelope); err != nil {
		return clusterEnvelope{}, fmt.Errorf("cluster protocol: decode envelope: %w", err)
	}
	if envelope.T == "" {
		return clusterEnvelope{}, errors.New("cluster protocol: missing message type")
	}
	return envelope, nil
}

func splitFullSync(
	live []clusterPeerRecord,
	tombs []clusterDelete,
	registry []clusterRegistryEntry,
	registryTombstones []clusterRegistryTombstone,
	params *clusterParams,
	batch int,
) []clusterFullSync {
	if batch <= 0 {
		batch = 200
	}
	partCount := (len(live) + batch - 1) / batch
	if partCount == 0 {
		partCount = 1
	}

	parts := make([]clusterFullSync, partCount)
	for i := range parts {
		start := i * batch
		end := min(start+batch, len(live))
		parts[i] = clusterFullSync{
			Part: i + 1,
			Of:   partCount,
			Live: live[start:end],
		}
	}
	parts[0].LiveTombstones = tombs
	parts[0].Registry = registry
	parts[0].RegistryTombstones = registryTombstones
	parts[0].Params = params
	return parts
}

func mutationToEnvelope(m clusterMutation) clusterEnvelope {
	envelope := clusterEnvelope{T: m.Kind, HLC: m.Version.HLC}
	switch m.Kind {
	case clusterMessagePeerUpsert:
		envelope.Peer = m.Peer
		if envelope.HLC == 0 && m.Peer != nil {
			envelope.HLC = m.Peer.Version.HLC
		}
	case clusterMessagePeerAlive:
		envelope.Alive = m.Alive
		if envelope.HLC == 0 && m.Alive != nil {
			envelope.HLC = m.Alive.Version.HLC
		}
	case clusterMessagePeerDelete:
		envelope.Delete = &clusterDelete{NodeID: m.NodeID, Version: m.Version}
	case clusterMessageRegistryUpsert:
		envelope.Registry = m.Registry
		if envelope.HLC == 0 && m.Registry != nil {
			envelope.HLC = m.Registry.Version.HLC
		}
	case clusterMessageRegistryDelete:
		envelope.RegistryDelete = &clusterRegistryDelete{NodeID: m.NodeID, Version: m.Version}
	case clusterMessageParamsUpdate:
		envelope.Params = m.Params
		if envelope.HLC == 0 && m.Params != nil {
			envelope.HLC = m.Params.Version.HLC
		}
	}
	return envelope
}
