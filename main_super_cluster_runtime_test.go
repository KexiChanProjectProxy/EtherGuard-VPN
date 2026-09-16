package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const superRuntimeClusterTestSecret = "super-runtime-cluster-secret-2026"

type superRuntimeClusterPair struct {
	a          *superRuntime
	b          *superRuntime
	aManageURL string
	apiprefix  string
	password   string
}

func TestSuperRuntimeClusterStartsAndLinks(t *testing.T) {
	// Given two runtimes configured as mutual cluster peers.
	pair := newSuperRuntimeClusterPair(t, 50*time.Millisecond, 300*time.Millisecond)

	// When runtime A's authenticated cluster diagnostics are polled.
	status := waitSuperRuntimeClusterConnected(t, pair.aManageURL, pair.apiprefix, pair.password)

	// Then the real runtime wiring has established its configured link.
	if len(status.Links) != 1 || status.Links[0].State != "connected" {
		t.Fatalf("cluster links = %+v, want one connected link", status.Links)
	}
	code, _ := getSuperRuntimeClusterState(t, pair.aManageURL, pair.apiprefix, "")
	if code != http.StatusUnauthorized {
		t.Fatalf("cluster state without password status = %d, want 401", code)
	}
}

func TestSuperRuntimeClusterAbsent(t *testing.T) {
	// Given a single-Super runtime with no Cluster config or override.
	const password = "single-super-password-hash"
	fx := newRuntimeTestFixture(t, func(cfg *superConfig) {
		cfg.BaseConfig.Cluster = nil
		cfg.BaseConfig.ManagementAuth.PasswordHash = password
	})

	// When the cluster Upgrade and diagnostics routes are requested.
	upgradeCode, _ := getSuperRuntimeURL(t, fx.baseURL+mtypes.ControlV2APIPrefix+"/cluster/link")
	wrongCode, _ := getSuperRuntimeClusterState(t, fx.manageURL, mtypes.ControlV2APIPrefix, "wrong-password")
	stateCode, body := getSuperRuntimeClusterState(t, fx.manageURL, mtypes.ControlV2APIPrefix, password)

	// Then Upgrade remains disabled while diagnostics reports an authenticated disabled state.
	if upgradeCode != http.StatusNotFound {
		t.Fatalf("cluster Upgrade status = %d, want 404", upgradeCode)
	}
	if wrongCode != http.StatusUnauthorized {
		t.Fatalf("disabled cluster state with wrong password status = %d, want 401", wrongCode)
	}
	if stateCode != http.StatusOK || string(body) != `{"enabled":false}` {
		t.Fatalf("disabled cluster state = status %d body %q", stateCode, body)
	}
}

func TestClusterShutdownClosesHijacks(t *testing.T) {
	// Given two linked runtimes whose idle session readers are blocked on the hijacked connections.
	startLocalPprof()
	baseline := runtime.NumGoroutine()
	pair := newSuperRuntimeClusterPair(t, time.Hour, 2*time.Hour)
	waitSuperRuntimeClusterConnected(t, pair.aManageURL, pair.apiprefix, pair.password)

	// When A shuts down through the production runtime lifecycle.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	started := time.Now()
	err := pair.a.Shutdown(ctx)
	cancel()

	// Then its hijacked cluster connection closes before the deadline and reports down.
	if err != nil {
		t.Fatalf("shutdown A: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 3*time.Second {
		t.Fatalf("shutdown A took %v, want under 3s", elapsed)
	}
	status := pair.a.Cluster().Status()
	if len(status.Links) != 1 || status.Links[0].State != "down" {
		t.Fatalf("A cluster status after shutdown = %+v", status.Links)
	}

	shutdownSuperRuntimeForTest(t, pair.b)
	waitSuperRuntimeGoroutines(t, baseline, 3*time.Second)
}

func newSuperRuntimeClusterPair(t *testing.T, heartbeat, deadAfter time.Duration) superRuntimeClusterPair {
	t.Helper()
	edgeA := listenSuperRuntimeTest(t)
	manageA := listenSuperRuntimeTest(t)
	edgeB := listenSuperRuntimeTest(t)
	manageB := listenSuperRuntimeTest(t)
	const password = "cluster-runtime-password-hash"
	apiprefix := mtypes.ControlV2APIPrefix

	start := func(selfID, peerID mtypes.Vertex, edge, manage net.Listener, peerURL string) *superRuntime {
		base := validBaseConfig()
		base.APIUrl = "http://" + edge.Addr().String()
		base.APIPrefix = apiprefix
		base.ManagementAuth.PasswordHash = password
		base.Cluster = nil
		cfg := &superConfig{
			BaseConfig: base, EdgeTemplate: validEdgeTemplate(), ConfigDir: t.TempDir(),
			EdgeListen: edge, ManageListen: manage, ShutdownTimeout: 3 * time.Second, TickInterval: time.Second,
			ClusterOverride: &mtypes.SuperConfigV2Cluster{
				SelfID: selfID, Secret: superRuntimeClusterTestSecret,
				Peers:            []mtypes.SuperConfigV2ClusterPeer{{SuperID: peerID, APIUrl: peerURL}},
				HeartbeatSeconds: heartbeat.Seconds(), DeadAfterSeconds: deadAfter.Seconds(),
				ReconnectMinSeconds: 0.01, ReconnectMaxSeconds: 0.05,
				RemoteStaleGraceSeconds: 600, Compression: "none",
			},
		}
		runtime, err := RunWithListeners(cfg)
		if err != nil {
			t.Fatalf("RunWithListeners(%d): %v", selfID, err)
		}
		return runtime
	}

	a := start(1, 2, edgeA, manageA, "http://"+edgeB.Addr().String())
	b := start(2, 1, edgeB, manageB, "http://"+edgeA.Addr().String())
	t.Cleanup(func() {
		shutdownSuperRuntimeForTest(t, a)
		shutdownSuperRuntimeForTest(t, b)
	})
	return superRuntimeClusterPair{
		a: a, b: b, aManageURL: "http://" + manageA.Addr().String(), apiprefix: apiprefix, password: password,
	}
}

func listenSuperRuntimeTest(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return listener
}

func waitSuperRuntimeClusterConnected(t *testing.T, baseURL, apiprefix, password string) clusterStatus {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		code, body := getSuperRuntimeClusterState(t, baseURL, apiprefix, password)
		if code == http.StatusOK {
			var status clusterStatus
			if err := json.Unmarshal(body, &status); err == nil && len(status.Links) == 1 && status.Links[0].State == "connected" {
				return status
			}
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out waiting for connected cluster link; last status=%d body=%s", code, body)
		case <-ticker.C:
		}
	}
}

func getSuperRuntimeClusterState(t *testing.T, baseURL, apiprefix, password string) (int, []byte) {
	t.Helper()
	return getSuperRuntimeURL(t, baseURL+apiprefix+"/manage/cluster/state?Password="+password)
}

func getSuperRuntimeURL(t *testing.T, url string) (int, []byte) {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read GET %s: %v", url, err)
	}
	return response.StatusCode, body
}

func shutdownSuperRuntimeForTest(t *testing.T, runtime *superRuntime) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Errorf("shutdown runtime: %v", err)
	}
}

func waitSuperRuntimeGoroutines(t *testing.T, baseline int, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		count := runtime.NumGoroutine()
		if count >= baseline-3 && count <= baseline+3 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("goroutine count = %d, baseline = %d", count, baseline)
		case <-ticker.C:
		}
	}
}
