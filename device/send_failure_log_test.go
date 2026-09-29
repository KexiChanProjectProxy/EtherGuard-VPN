package device

import (
	"strings"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"golang.org/x/sys/unix"
)

type failingBind struct {
	*pinningSTUNFake
	err error
}

func (b *failingBind) Send([]byte, conn.Endpoint) error { return b.err }

func TestSendTargetDescribesProbeAndCurrentEndpoint(t *testing.T) {
	bind := newPinningSTUNFake(1)
	peer := &Peer{}
	if dst, src, probe := peer.sendTarget(nil); dst != "none" || src != "none" || probe {
		t.Fatalf("no endpoint: dst=%s src=%s probe=%v", dst, src, probe)
	}
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	if dst, _, probe := peer.sendTarget(nil); dst != "203.0.113.20:3001" || probe {
		t.Fatalf("current endpoint: dst=%s probe=%v", dst, probe)
	}
	pinned, _ := bind.ParseEndpointFrom("203.0.113.21:3001", wan2Source.ip, wan2Source.ifindex)
	if dst, src, probe := peer.sendTarget(pinned); dst != "203.0.113.21:3001" || src != "198.51.100.2" || !probe {
		t.Fatalf("probe endpoint: dst=%s src=%s probe=%v", dst, src, probe)
	}
}

func TestSequentialSenderLogsProbeTargetOnFailure(t *testing.T) {
	// Given a bind that fails like a WireGuard tunnel without a matching peer
	bind := &failingBind{pinningSTUNFake: newPinningSTUNFake(1), err: unix.ENOKEY}
	logs := &recordingLogger{}
	device := &Device{log: logs.logger(), EdgeConfig: &mtypes.EdgeConfig{}}
	device.net.bind = bind
	device.state.state = uint32(deviceStateUp)
	device.closed = make(chan int)
	device.PopulatePools()
	peer := &Peer{ID: 2, device: device}
	peer.endpoint, _ = bind.ParseEndpoint("203.0.113.20:3001")
	peer.isRunning.Set(true)
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	probeEndpoint, _ := bind.ParseEndpointFrom("203.0.113.21:3001", wan2Source.ip, wan2Source.ifindex)
	elem := device.NewOutboundElement()
	elem.packet = elem.buffer[:40]
	elem.endpoint = probeEndpoint

	// When the sequential sender transmits it
	peer.stopping.Add(1)
	peer.queue.outbound.c <- elem
	peer.queue.outbound.c <- nil
	peer.RoutineSequentialSender()

	// Then the error names the probe's destination and pinned source
	want := "Failed to send data packet: peer=2 dst=203.0.113.21:3001 src=198.51.100.2 probe=true error=required key not available"
	if got := logs.count(errorLines, want); got != 1 {
		t.Fatalf("want one %q, got %v", want, logs.errors)
	}
	if !strings.Contains(logs.errors[0], "peer(") {
		t.Fatalf("log lost the peer key prefix: %s", logs.errors[0])
	}
}
