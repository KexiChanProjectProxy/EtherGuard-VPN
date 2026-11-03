package device

import (
	"context"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

const p2pSTUNTestServer = "203.0.113.80:3478"

func newP2PSTUNTestDevice(t *testing.T) (*Device, *sameBindSTUNFake) {
	t.Helper()
	bind := newSameBindSTUNFake(40100)
	device := &Device{
		log: NewLogger(LogLevelSilent, "p2p-stun-test"),
		EdgeConfig: &mtypes.EdgeConfig{DynamicRoute: mtypes.DynamicRouteInfo{
			P2P: mtypes.P2PInfo{UseP2P: true, STUNServers: []string{"stun:" + p2pSTUNTestServer}},
		}},
	}
	device.net.bind = bind
	device.net.port = bind.port
	device.superSTUN = NewSuperSTUNManager(device)
	device.superSTUN.sources = func() []stunSource { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		bind.Close()
	})
	go receiveSTUNTestPackets(ctx, device.superSTUN, bind.receive)
	return device, bind
}

func containsURL(urls []string, want string) bool {
	for _, url := range urls {
		if url == want {
			return true
		}
	}
	return false
}

func TestP2PSTUNPublishesMappingAndKeepsItAfterFailure(t *testing.T) {
	// Given a STUN server that maps this socket
	device, bind := newP2PSTUNTestDevice(t)
	bind.responses[p2pSTUNTestServer] = net.ParseIP("198.51.100.80")
	servers := device.EdgeConfig.DynamicRoute.P2P.STUNServers
	const mapped = "198.51.100.80:40100"

	// When
	device.refreshP2PSTUN(context.Background(), servers)

	// Then the mapping joins the addresses this edge advertises
	if urls := device.p2pLocalEndpointURLs(); !containsURL(urls, mapped) {
		t.Fatalf("advertised = %v, want %s", urls, mapped)
	}

	// When the next pass fails
	failing, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	delete(bind.responses, p2pSTUNTestServer)
	device.refreshP2PSTUN(failing, servers)

	// Then the mapping is still advertised
	if urls := device.p2pLocalEndpointURLs(); !containsURL(urls, mapped) {
		t.Fatalf("advertised after failure = %v, want %s", urls, mapped)
	}
}

func TestP2PSTUNMappingThroughBlacklistFilterIsNotAdvertised(t *testing.T) {
	// Given a mapping inside the blacklist
	device, _ := newP2PSTUNTestDevice(t)
	device.p2pMapped.addresses = []string{"198.51.100.80:40100"}
	prefixes, err := mtypes.ParseEndpointBlacklist([]string{"198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parse blacklist: %v", err)
	}
	device.setEndpointBlacklist(prefixes)

	// Then
	if urls := device.p2pLocalEndpointURLs(); containsURL(urls, "198.51.100.80:40100") {
		t.Fatalf("advertised = %v, blacklisted mapping included", urls)
	}
}

func TestMergeEndpointURLsDropsMappingEqualToLocalAddress(t *testing.T) {
	got := mergeEndpointURLs([]string{"192.0.2.1:3001", "192.0.2.2:3001"}, []string{"192.0.2.2:3001", "198.51.100.1:40000"})
	want := []string{"192.0.2.1:3001", "192.0.2.2:3001", "198.51.100.1:40000"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}
}

func TestRoutineP2PSTUNDoesNotRunWithoutItsConfig(t *testing.T) {
	cases := map[string]func(config *mtypes.EdgeConfig){
		"empty server list": func(config *mtypes.EdgeConfig) { config.DynamicRoute.P2P.STUNServers = nil },
		"not p2p":           func(config *mtypes.EdgeConfig) { config.DynamicRoute.P2P.UseP2P = false },
		"super mode":        func(config *mtypes.EdgeConfig) { config.SuperNodeV2Enabled = true },
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			// Given
			device, bind := newP2PSTUNTestDevice(t)
			configure(device.EdgeConfig)

			// When
			done := make(chan struct{})
			go func() {
				device.RoutineP2PSTUN()
				close(done)
			}()

			// Then it returns without querying anything
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("RoutineP2PSTUN kept running")
			}
			select {
			case destination := <-bind.sent:
				t.Fatalf("queried %s", destination)
			default:
			}
		})
	}
}

func TestRoutineP2PSTUNStopsWhenDeviceCloses(t *testing.T) {
	// Given a running loop
	device, bind := newP2PSTUNTestDevice(t)
	bind.responses[p2pSTUNTestServer] = net.ParseIP("198.51.100.80")
	device.closed = make(chan int)
	done := make(chan struct{})
	go func() {
		device.RoutineP2PSTUN()
		close(done)
	}()
	select {
	case <-bind.sent:
	case <-time.After(2 * time.Second):
		t.Fatal("no STUN query sent")
	}

	// When
	close(device.closed)

	// Then
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RoutineP2PSTUN did not stop")
	}
}
