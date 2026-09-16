package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	yaml "gopkg.in/yaml.v2"
)

const manageTestSelfID mtypes.Vertex = 7

func TestManageAddPeerPersistsThenCommits(t *testing.T) {
	// Given
	mgr, state, published, dir := newClusterManageV2UnderTest(t, t.TempDir(), validClusterBaseConfig(), nil)
	mgr.pskGen = fixedPSKSource("persist-then-commit-key")

	// When
	result, err := mgr.AddPeer(context.Background(), ManageAddPeerRequest{NodeID: 101, NodeName: "edge-101"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	// Then
	superConfig := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if len(superConfig.Peers) != 1 || superConfig.Peers[0].NodeID != 101 {
		t.Fatalf("super.yaml peers = %#v, want node 101", superConfig.Peers)
	}
	if _, err := os.Stat(filepath.Join(dir, "edge_101.yaml")); err != nil {
		t.Fatalf("edge profile missing: %v", err)
	}
	if key, ok := state.ControlKeyFor(101); !ok || key != result.SuperPeer.ControlPSKey {
		t.Fatalf("ControlKeyFor(101) = (%q, %v), want %q", key, ok, result.SuperPeer.ControlPSKey)
	}
	persisted := readClusterStateYAMLForTest(t, filepath.Join(dir, "cluster_state.yaml"))
	version, ok := persisted.Registry[101]
	if !ok || version.HLC == 0 || version.Origin != manageTestSelfID {
		t.Fatalf("cluster registry version = (%#v, %v), want non-zero version from %d", version, ok, manageTestSelfID)
	}
	mutations, resync := state.DrainOutbox()
	if resync || len(mutations) != 1 || mutations[0].Kind != clusterMessageRegistryUpsert {
		t.Fatalf("outbox = %#v, resync=%v, want one registry_upsert", mutations, resync)
	}
	if published.count() != 0 {
		t.Fatalf("published events = %d, want 0", published.count())
	}
}

func TestManageParametersAllFieldsRoundTrip(t *testing.T) {
	// Given
	mgr, _, _, dir := newClusterManageV2UnderTest(t, t.TempDir(), validClusterBaseConfig(), nil)
	relayCost := 23.75
	port := 51820
	params := validParams()
	params.RelayCostMS = &relayCost
	params.ListenPortPriority = mtypes.ListenPortPriority{
		{Port: &port},
		{Range: &mtypes.ListenPortRange{From: 52000, To: 52002}},
	}
	params.EndpointBlacklist = []string{"192.0.2.10", "2001:db8::/48"}

	// When
	if err := mgr.UpdateParameters(context.Background(), ManageUpdateParametersRequest{Parameters: params}); err != nil {
		t.Fatalf("UpdateParameters: %v", err)
	}

	// Then
	reloaded := readSuperYAML(t, filepath.Join(dir, "super.yaml"))
	if reloaded.RelayCostMS == nil || *reloaded.RelayCostMS != relayCost {
		t.Fatalf("RelayCostMS = %v, want %v", reloaded.RelayCostMS, relayCost)
	}
	if !reflect.DeepEqual(reloaded.ListenPortPriority, params.ListenPortPriority) {
		t.Fatalf("ListenPortPriority = %#v, want %#v", reloaded.ListenPortPriority, params.ListenPortPriority)
	}
	if !reflect.DeepEqual(reloaded.EndpointBlacklist, params.EndpointBlacklist) {
		t.Fatalf("EndpointBlacklist = %#v, want %#v", reloaded.EndpointBlacklist, params.EndpointBlacklist)
	}
}

func TestManageAtomicWriteRestoresOnSecondFileFailure(t *testing.T) {
	// Given
	dir := t.TempDir()
	base := validClusterBaseConfig()
	originalBytes, err := yaml.Marshal(base)
	if err != nil {
		t.Fatalf("marshal base: %v", err)
	}
	superPath := filepath.Join(dir, "super.yaml")
	if err := ioutil.WriteFile(superPath, originalBytes, 0o600); err != nil {
		t.Fatalf("write original super.yaml: %v", err)
	}
	secondEdgePath := filepath.Join(dir, "edge_402.yaml")
	writeHook := func(path string) error {
		if path == secondEdgePath {
			return errors.New("injected second edge write failure")
		}
		return nil
	}
	mgr, _, _, _ := newClusterManageV2UnderTest(t, dir, base, writeHook)
	newBase := cloneSuperConfigV2(base)
	newBase.Peers = []mtypes.SuperConfigV2Peer{
		{NodeID: 401, NodeName: "edge-401", ControlPSKey: "key-401", AdditionalCost: 10},
		{NodeID: 402, NodeName: "edge-402", ControlPSKey: "key-402", AdditionalCost: 10},
	}
	edge401 := mgr.buildEdgeConfigV2(401, "edge-401", "key-401")
	edge402 := mgr.buildEdgeConfigV2(402, "edge-402", "key-402")

	// When
	err = mgr.atomicWriteConfigs(newBase, []*mtypes.EdgeConfigV2{&edge401, &edge402})

	// Then
	if err == nil {
		t.Fatal("atomicWriteConfigs succeeded despite injected failure")
	}
	restored, readErr := ioutil.ReadFile(superPath)
	if readErr != nil {
		t.Fatalf("read restored super.yaml: %v", readErr)
	}
	if !bytes.Equal(restored, originalBytes) {
		t.Fatalf("super.yaml was not restored byte-identically\nwant:\n%s\ngot:\n%s", originalBytes, restored)
	}
	for _, nodeID := range []mtypes.Vertex{401, 402} {
		path := filepath.Join(dir, fmt.Sprintf("edge_%d.yaml", nodeID))
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s survived rollback: %v", path, statErr)
		}
	}
}

func TestClusterStateSeedsUnversionedConfiguredPeer(t *testing.T) {
	// Given
	base := validClusterBaseConfig()
	base.Peers = []mtypes.SuperConfigV2Peer{{
		NodeID:         501,
		NodeName:       "configured-501",
		ControlPSKey:   "configured-key-501",
		AdditionalCost: 10,
	}}

	// When
	_, state, _, _ := newClusterManageV2UnderTest(t, t.TempDir(), base, nil)

	// Then
	wantVersion := ClusterVersion{Origin: manageTestSelfID}
	if got, ok := state.RegistryVersion(501); !ok || got != wantVersion {
		t.Fatalf("RegistryVersion(501) = (%#v, %v), want (%#v, true)", got, ok, wantVersion)
	}
	if key, ok := state.ControlKeyFor(501); !ok || key != "configured-key-501" {
		t.Fatalf("ControlKeyFor(501) = (%q, %v)", key, ok)
	}
	if mutations, resync := state.DrainOutbox(); len(mutations) != 0 || resync {
		t.Fatalf("startup seed produced outbox = %#v, resync=%v", mutations, resync)
	}
}

func validClusterBaseConfig() mtypes.SuperConfigV2 {
	base := validBaseConfig()
	base.Cluster = &mtypes.SuperConfigV2Cluster{
		SelfID: manageTestSelfID,
		Secret: "0123456789abcdef0123456789abcdef",
		Peers: []mtypes.SuperConfigV2ClusterPeer{
			{SuperID: 8, APIUrl: "https://super-8.example"},
		},
	}
	return base
}

func newClusterManageV2UnderTest(
	t *testing.T,
	dir string,
	base mtypes.SuperConfigV2,
	writeHook func(string) error,
) (*ManageV2, *ControlState, *countingPublish, string) {
	t.Helper()
	published := &countingPublish{}
	selfID := mtypes.Vertex(0)
	if base.Cluster != nil {
		selfID = base.Cluster.SelfID
	}
	state := NewControlState(ControlStateConfig{
		Parameters: buildControlV2Parameters(base),
		SelfID:     selfID,
		Publish:    published.hook,
		Now:        time.Now,
	})
	mgr, err := NewManageV2(ManageV2Config{
		State:        state,
		ConfigDir:    dir,
		BaseConfig:   base,
		EdgeTemplate: validEdgeTemplate(),
		WriteHook:    writeHook,
	})
	if err != nil {
		t.Fatalf("NewManageV2: %v", err)
	}
	return mgr, state, published, dir
}

func marshalLocalOnlyConfigForTest(t *testing.T, cfg mtypes.SuperConfigV2) []byte {
	t.Helper()
	local := struct {
		NodeName       string                             `yaml:"NodeName"`
		APIUrl         string                             `yaml:"APIUrl"`
		APIPrefix      string                             `yaml:"APIPrefix"`
		ManagementAuth mtypes.SuperConfigV2ManagementAuth `yaml:"ManagementAuth"`
		Cluster        *mtypes.SuperConfigV2Cluster       `yaml:"Cluster"`
	}{
		NodeName:       cfg.NodeName,
		APIUrl:         cfg.APIUrl,
		APIPrefix:      cfg.APIPrefix,
		ManagementAuth: cfg.ManagementAuth,
		Cluster:        cfg.Cluster,
	}
	data, err := yaml.Marshal(local)
	if err != nil {
		t.Fatalf("marshal local-only config: %v", err)
	}
	return data
}

type clusterStateVersionForTest struct {
	HLC    uint64        `yaml:"HLC"`
	Origin mtypes.Vertex `yaml:"Origin"`
}

type clusterStateFileForTest struct {
	HLCHighWater       uint64                                       `yaml:"HLCHighWater"`
	ParamsVersion      clusterStateVersionForTest                   `yaml:"ParamsVersion"`
	Registry           map[mtypes.Vertex]clusterStateVersionForTest `yaml:"Registry"`
	RegistryTombstones []struct {
		NodeID    mtypes.Vertex `yaml:"NodeID"`
		HLC       uint64        `yaml:"HLC"`
		Origin    mtypes.Vertex `yaml:"Origin"`
		DeletedAt time.Time     `yaml:"DeletedAt"`
	} `yaml:"RegistryTombstones"`
}

func readClusterStateYAMLForTest(t *testing.T, path string) clusterStateFileForTest {
	t.Helper()
	data, err := ioutil.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var state clusterStateFileForTest
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return state
}
