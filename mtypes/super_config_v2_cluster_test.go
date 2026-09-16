package mtypes

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSuperConfigV2ClusterDefaults(t *testing.T) {
	// Given
	cluster := SuperConfigV2Cluster{}

	// When
	got := cluster.WithDefaults()

	// Then
	if got.HeartbeatSeconds != 10 {
		t.Fatalf("HeartbeatSeconds = %v, want 10", got.HeartbeatSeconds)
	}
	if got.DeadAfterSeconds != 30 {
		t.Fatalf("DeadAfterSeconds = %v, want 30", got.DeadAfterSeconds)
	}
	if got.ReconnectMinSeconds != 1 {
		t.Fatalf("ReconnectMinSeconds = %v, want 1", got.ReconnectMinSeconds)
	}
	if got.ReconnectMaxSeconds != 30 {
		t.Fatalf("ReconnectMaxSeconds = %v, want 30", got.ReconnectMaxSeconds)
	}
	if got.RemoteStaleGraceSeconds != 600 {
		t.Fatalf("RemoteStaleGraceSeconds = %v, want 600", got.RemoteStaleGraceSeconds)
	}
	if got.Compression != "zstd" {
		t.Fatalf("Compression = %q, want zstd", got.Compression)
	}
}

func TestSuperConfigV2ClusterDefaultRemoteStaleGraceUsesPeerAliveTimeout(t *testing.T) {
	// Given
	cluster := validSuperConfigV2Cluster()
	cluster.RemoteStaleGraceSeconds = 0

	// When
	err := cluster.Validate(700)

	// Then
	if err != nil {
		t.Fatalf("Validate() error = %v, want default grace to cover peer timeout", err)
	}
}

func TestSuperConfigV2ClusterRejects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*SuperConfigV2Cluster)
		wantCode string
	}{
		{
			name: "special self ID",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.SelfID = NodeID_SuperNode
			},
			wantCode: ControlV2ErrInvalidNodeID,
		},
		{
			name: "short secret",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.Secret = "short"
			},
			wantCode: ControlV2ErrInvalidCluster,
		},
		{
			name: "duplicate peer SuperID",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.Peers = append(cluster.Peers, cluster.Peers[0])
			},
			wantCode: ControlV2ErrInvalidCluster,
		},
		{
			name: "peer SuperID equals SelfID",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.Peers[0].SuperID = cluster.SelfID
			},
			wantCode: ControlV2ErrInvalidCluster,
		},
		{
			name: "dead after is not greater than heartbeat",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.HeartbeatSeconds = 10
				cluster.DeadAfterSeconds = 10
			},
			wantCode: ControlV2ErrInvalidDuration,
		},
		{
			name: "unsupported compression",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.Compression = "gzip"
			},
			wantCode: ControlV2ErrInvalidCluster,
		},
		{
			name: "non HTTP peer API URL",
			mutate: func(cluster *SuperConfigV2Cluster) {
				cluster.Peers[0].APIUrl = "ftp://x"
			},
			wantCode: ControlV2ErrInvalidURI,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			cluster := validSuperConfigV2Cluster()
			tt.mutate(&cluster)

			// When
			err := cluster.Validate(70)

			// Then
			var controlErr *ControlV2Error
			if !errors.As(err, &controlErr) {
				t.Fatalf("Validate() error = %T %v, want *ControlV2Error", err, err)
			}
			if controlErr.Code != tt.wantCode {
				t.Fatalf("error code = %q, want %q", controlErr.Code, tt.wantCode)
			}
		})
	}
}

func TestSuperConfigV2ClusterSecretRedactedFromJSON(t *testing.T) {
	// Given
	const secret = "super-secret-never-json-9f14"
	config := SuperConfigV2{Cluster: &SuperConfigV2Cluster{Secret: secret}}

	// When
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Then
	if strings.Contains(string(data), "Secret") {
		t.Fatalf("JSON contains Secret field: %s", data)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("JSON contains cluster secret: %s", data)
	}
}

func TestSuperConfigV2ClusterAbsentIsValid(t *testing.T) {
	// Given
	data := []byte(`
NodeName: super-1
APIUrl: https://super.example.com
APIPrefix: /edge/v2
ManagementAuth:
  User: admin
  PasswordHash: hash
STUNServers: []
STUNRequestTimeoutSeconds: 1
STUNRefreshIntervalSeconds: 60
PollIntervalSeconds: 15
ReportIntervalSeconds: 10
HeartbeatIntervalSeconds: 25
PeerAliveTimeoutSeconds: 70
Peers: []
`)
	var config SuperConfigV2
	if err := yamlUnmarshal(data, &config); err != nil {
		t.Fatalf("yamlUnmarshal() error = %v", err)
	}

	// When
	err := config.Validate()

	// Then
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if config.Cluster != nil {
		t.Fatalf("Cluster = %#v, want nil", config.Cluster)
	}
}

func TestSuperConfigV2ClusterYAMLRoundTrip(t *testing.T) {
	// Given
	data := []byte(`
NodeName: super-1
APIUrl: https://super.example.com
APIPrefix: /edge/v2
ManagementAuth:
  User: admin
  PasswordHash: hash
STUNServers: []
STUNRequestTimeoutSeconds: 1
STUNRefreshIntervalSeconds: 60
PollIntervalSeconds: 15
ReportIntervalSeconds: 10
HeartbeatIntervalSeconds: 25
PeerAliveTimeoutSeconds: 70
Peers: []
Cluster:
  SelfID: 1
  Secret: 0123456789abcdef
  Peers:
    - SuperID: 2
      APIUrl: https://super-2.example.com/
  HeartbeatSeconds: 10
  DeadAfterSeconds: 30
  ReconnectMinSeconds: 1
  ReconnectMaxSeconds: 30
  RemoteStaleGraceSeconds: 600
  Compression: zstd
`)
	var config SuperConfigV2

	// When
	err := yamlUnmarshal(data, &config)

	// Then
	if err != nil {
		t.Fatalf("yamlUnmarshal() error = %v", err)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if config.Cluster == nil {
		t.Fatal("Cluster is nil")
	}
	if config.Cluster.SelfID != 1 || len(config.Cluster.Peers) != 1 || config.Cluster.Peers[0].SuperID != 2 {
		t.Fatalf("Cluster decoded incorrectly: %#v", config.Cluster)
	}
}

func validSuperConfigV2Cluster() SuperConfigV2Cluster {
	return SuperConfigV2Cluster{
		SelfID:                  1,
		Secret:                  "0123456789abcdef",
		Peers:                   []SuperConfigV2ClusterPeer{{SuperID: 2, APIUrl: "https://super-2.example.com"}},
		HeartbeatSeconds:        10,
		DeadAfterSeconds:        30,
		ReconnectMinSeconds:     1,
		ReconnectMaxSeconds:     30,
		RemoteStaleGraceSeconds: 600,
		Compression:             "zstd",
	}
}
