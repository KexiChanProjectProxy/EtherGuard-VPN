package gencfg

import "testing"

func TestGetExampleSuperConfClusterAbsent(t *testing.T) {
	// Given and When
	config, _ := GetExampleSuperConf("", false)

	// Then
	if config.Cluster != nil {
		t.Fatalf("Cluster = %#v, want nil", config.Cluster)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestGetExampleClusterConf(t *testing.T) {
	// Given and When
	configs := GetExampleClusterConf()

	// Then
	for i := range configs {
		if err := configs[i].Validate(); err != nil {
			t.Fatalf("configs[%d].Validate() error = %v", i, err)
		}
		if configs[i].Cluster == nil {
			t.Fatalf("configs[%d].Cluster is nil", i)
		}
	}
	if configs[0].Cluster.SelfID != 1 || configs[1].Cluster.SelfID != 2 {
		t.Fatalf("SelfIDs = %d, %d; want 1, 2", configs[0].Cluster.SelfID, configs[1].Cluster.SelfID)
	}
	if configs[0].Cluster.Secret != configs[1].Cluster.Secret {
		t.Fatal("cluster examples do not share a secret")
	}
	if len(configs[0].Cluster.Peers) != 1 || configs[0].Cluster.Peers[0].SuperID != 2 || configs[0].Cluster.Peers[0].APIUrl != configs[1].APIUrl {
		t.Fatalf("first cluster peers = %#v, want reciprocal peer 2", configs[0].Cluster.Peers)
	}
	if len(configs[1].Cluster.Peers) != 1 || configs[1].Cluster.Peers[0].SuperID != 1 || configs[1].Cluster.Peers[0].APIUrl != configs[0].APIUrl {
		t.Fatalf("second cluster peers = %#v, want reciprocal peer 1", configs[1].Cluster.Peers)
	}
}
