package device

import (
	"sync"
	"testing"
	"time"
)

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
