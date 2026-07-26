package device

import (
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func newSuperTrylistForTest() *endpoint_trylist {
	peer := &Peer{device: &Device{}}
	return NewEndpoint_trylist(peer, time.Hour, conn.EnabledAf46)
}

func superCandidates(candidates ...mtypes.APIConnURLCandidate) mtypes.API_connurl {
	return mtypes.API_connurl{Candidates: candidates}
}

func TestEndpointTrylistOrdersSuperCandidatesByClassAndFamilyPreference(t *testing.T) {
	candidates := superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.20:51820", Source: mtypes.APIConnURLSourceLocal},
		mtypes.APIConnURLCandidate{URL: "[2001:db8::20]:51820", Source: mtypes.APIConnURLSourceLocal},
		mtypes.APIConnURLCandidate{URL: "192.0.2.30:51820", Source: mtypes.APIConnURLSourceSTUN},
		mtypes.APIConnURLCandidate{URL: "[2001:db8::30]:51820", Source: mtypes.APIConnURLSourceSTUN},
		mtypes.APIConnURLCandidate{URL: "192.0.2.40:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 16},
		mtypes.APIConnURLCandidate{URL: "[2001:db8::40]:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 16},
	)
	cases := []struct {
		name     string
		afPrefer int
		want     []string
	}{
		{"no family preference", 0, []string{"192.0.2.20:51820", "[2001:db8::20]:51820", "192.0.2.30:51820", "[2001:db8::30]:51820", "192.0.2.40:51820", "[2001:db8::40]:51820"}},
		{"prefer ipv4 within every class", 4, []string{"192.0.2.20:51820", "[2001:db8::20]:51820", "192.0.2.30:51820", "[2001:db8::30]:51820", "192.0.2.40:51820", "[2001:db8::40]:51820"}},
		{"prefer ipv6 within every class", 6, []string{"[2001:db8::20]:51820", "192.0.2.20:51820", "[2001:db8::30]:51820", "192.0.2.30:51820", "[2001:db8::40]:51820", "192.0.2.40:51820"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			trylist := newSuperTrylistForTest()
			trylist.UpdateSuper(candidates, true, tc.afPrefer)

			// When
			got := make([]string, 0, len(tc.want))
			for range tc.want {
				_, url := trylist.GetNextTry()
				got = append(got, url)
			}

			// Then
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("candidate order = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEndpointTrylistRanksObservedCandidatesByReporterCountThenURL(t *testing.T) {
	// Given
	trylist := newSuperTrylistForTest()
	trylist.UpdateSuper(superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.90:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 2},
		mtypes.APIConnURLCandidate{URL: "192.0.2.80:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 16},
		mtypes.APIConnURLCandidate{URL: "192.0.2.70:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 2},
	), true, 0)

	// When
	got := make([]string, 0, 3)
	for range 3 {
		_, url := trylist.GetNextTry()
		got = append(got, url)
	}

	// Then
	want := []string{"192.0.2.80:51820", "192.0.2.70:51820", "192.0.2.90:51820"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("candidate order = %v, want %v", got, want)
	}
}

func TestEndpointTrylistReseedsCandidateWhenObservedVoteCountChanges(t *testing.T) {
	// Given
	trylist := newSuperTrylistForTest()
	trylist.UpdateSuper(superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.10:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 1},
		mtypes.APIConnURLCandidate{URL: "192.0.2.20:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 1},
	), true, 0)
	_, first := trylist.GetNextTry()
	if first != "192.0.2.10:51820" {
		t.Fatalf("first candidate = %q, want lexical first candidate", first)
	}
	trylist.UpdateSuper(superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.10:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 1},
		mtypes.APIConnURLCandidate{URL: "192.0.2.20:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 16},
	), true, 0)

	// When
	_, got := trylist.GetNextTry()

	// Then
	if got != "192.0.2.20:51820" {
		t.Fatalf("reseeded candidate = %q, want higher-vote candidate", got)
	}
}

func TestEndpointTrylistConsumesOneCompletionPerSnapshotGeneration(t *testing.T) {
	// Given
	trylist := newSuperTrylistForTest()
	trylist.UpdateSuper(superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.10:51820", Source: mtypes.APIConnURLSourceLocal},
	), true, 0)
	trylist.GetNextTry()

	// When
	trylist.UpdateSuper(superCandidates(
		mtypes.APIConnURLCandidate{URL: "192.0.2.20:51820", Source: mtypes.APIConnURLSourceLocal},
	), true, 0)

	// Then
	if trylist.ConsumeSuperCycleComplete() {
		t.Fatal("old snapshot completion leaked into replacement generation")
	}
	trylist.GetNextTry()
	if !trylist.ConsumeSuperCycleComplete() {
		t.Fatal("replacement generation completion was not reported")
	}
	if trylist.ConsumeSuperCycleComplete() {
		t.Fatal("snapshot completion was reported more than once")
	}
}

func TestEndpointTrylistSuperSnapshotUpdateIsSafeConcurrentWithRetries(t *testing.T) {
	// Given
	trylist := newSuperTrylistForTest()
	updates := superCandidates(mtypes.APIConnURLCandidate{URL: "192.0.2.10:51820", Source: mtypes.APIConnURLSourceObserved, ReporterCount: 1})
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)

	// When
	go func() {
		defer workers.Done()
		<-start
		for i := range 100 {
			updates.Candidates[0].ReporterCount = uint32(i%16 + 1)
			trylist.UpdateSuper(updates, true, 0)
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for range 100 {
			trylist.GetNextTry()
			trylist.ConsumeSuperCycleComplete()
		}
	}()
	close(start)
	workers.Wait()

	// Then
	if _, url := trylist.GetNextTry(); url == "" {
		t.Fatal("candidate disappeared during concurrent snapshot replacement")
	}
}

func TestEndpointTrylistGetNextTryIsSafeUnderConcurrentAccess(t *testing.T) {
	trylist := endpoint_trylist{
		timeout:      time.Hour,
		trymap_super: make(map[string]*endpoint_tryitem),
		trymap_p2p: map[string]*endpoint_tryitem{
			"127.0.0.1:3001": {URL: "127.0.0.1:3001"},
		},
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(8)
	for range 8 {
		go func() {
			defer workers.Done()
			<-start
			for range 100 {
				trylist.GetNextTry()
			}
		}()
	}
	close(start)
	workers.Wait()
	if _, ok := trylist.trymap_p2p["127.0.0.1:3001"]; !ok {
		t.Fatal("active endpoint unexpectedly removed from retry list")
	}
}

func TestAddEndpointRetryKeepsConfiguredEndpointAvailable(t *testing.T) {
	peer := &Peer{endpoint_trylist: &endpoint_trylist{trymap_super: make(map[string]*endpoint_tryitem), trymap_p2p: make(map[string]*endpoint_tryitem)}}
	endpoint := "[2001:db8::dead]:3002"
	peer.AddEndpointRetry(endpoint, true)
	_, got := peer.endpoint_trylist.GetNextTry()
	if got != endpoint {
		t.Fatalf("configured retry endpoint = %q, want %q", got, endpoint)
	}
}

func TestAddEndpointRetryPreservesStaticPolicyBeforeEndpointExists(t *testing.T) {
	peer := &Peer{endpoint_trylist: &endpoint_trylist{trymap_super: make(map[string]*endpoint_tryitem), trymap_p2p: make(map[string]*endpoint_tryitem)}}
	peer.AddEndpointRetry("[2001:db8::dead]:3002", true)
	static, _, _ := peer.endpointRetryConfig()
	if !static {
		t.Fatal("configured static policy was not preserved for retry")
	}
}

func TestStaticPeerRejectsDiscoveredEndpointCandidates(t *testing.T) {
	peer := &Peer{StaticConn: true}
	if peer.acceptsDiscoveredEndpoints() {
		t.Fatal("static peer accepted a discovered endpoint candidate")
	}
}

func TestAllPeersSnapshotIsSafeDuringConcurrentDiscovery(t *testing.T) {
	device := &Device{}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		for i := range 100 {
			var key NoisePublicKey
			key[0] = byte(i)
			device.peers.Lock()
			device.peers.keyMap[key] = &Peer{}
			delete(device.peers.keyMap, key)
			device.peers.Unlock()
		}
	}()
	go func() {
		defer workers.Done()
		<-start
		for range 100 {
			device.allPeersSnapshot()
		}
	}()
	close(start)
	workers.Wait()
	if got := len(device.allPeersSnapshot()); got != 0 {
		t.Fatalf("peer snapshot retained %d removed peers", got)
	}
}

func TestSignalEndpointRetryReturnsWhenSignalIsAlreadyPending(t *testing.T) {
	device := &Device{event_tryendpoint: make(chan struct{}, 1)}
	device.event_tryendpoint <- struct{}{}
	done := make(chan struct{})
	go func() {
		device.signalEndpointRetry()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("endpoint retry signal blocked while a retry was already pending")
	}
}
