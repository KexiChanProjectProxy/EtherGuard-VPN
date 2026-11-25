//go:build linux

package main

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/conn"
	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
)

func loopbackIfindex(t *testing.T) int {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Index
		}
	}
	t.Skip("no loopback interface")
	return 0
}

// TestLegAgentRelaysThroughPinnedKernelSocket runs the agent on a real Linux
// socket bind: datagrams from the controller leave pinned to the leg's
// address, and replies come back framed with that leg.
func TestLegAgentRelaysThroughPinnedKernelSocket(t *testing.T) {
	key, _ := conn.ParseLegKey(e2eLegKey)
	controller, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	farPeer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer farPeer.Close()

	loopback := netip.MustParseAddr("127.0.0.1")
	loIndex := loopbackIfindex(t)
	agent := newLegAgent(mtypes.LegAgentSettings{
		AgentID:          5,
		Listen:           netip.MustParseAddrPort("127.0.0.1:0"),
		Controller:       controller.LocalAddr().(*net.UDPAddr).AddrPort(),
		Key:              key,
		HeartbeatTimeout: conn.DefaultLegHeartbeatTimeout,
	}, legAgentOptions{
		wan: conn.NewDefaultBind(conn.EnabledAf4, "linux", 0),
		uplinks: func() ([]device.Uplink, error) {
			return []device.Uplink{{Addr: loopback, Ifindex: loIndex, Name: "lo"}}, nil
		},
	})
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	defer agent.Close()

	buf := make([]byte, 65536)
	readFrame := func(kind byte) (conn.LegFrame, netip.AddrPort) {
		t.Helper()
		for {
			controller.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, from, err := controller.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatalf("controller read: %v", err)
			}
			frame, err := conn.DecodeLegFrame(&key, buf[:n])
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if frame.Type == kind {
				return frame, from
			}
		}
	}

	// The agent announces its leg with the port of its uplink socket.
	state, agentAddr := readFrame(conn.LegFrameState)
	legs, err := conn.ParseLegState(state.Body)
	if err != nil || len(legs) != 1 || legs[0].Addr != netip.AddrPortFrom(loopback, agent.WANPort()) {
		t.Fatalf("announced legs %+v (%v)", legs, err)
	}

	// Controller -> leg -> far peer.
	farAddr := farPeer.LocalAddr().(*net.UDPAddr).AddrPort()
	out := conn.AppendLegFrame(nil, &key, conn.LegFrame{Type: conn.LegFrameData, AgentID: 5, LegID: legs[0].LegID, Epoch: 1, Counter: 1, Addr: farAddr, Body: []byte("to peer")})
	if _, err := controller.WriteToUDPAddrPort(out, agentAddr); err != nil {
		t.Fatal(err)
	}
	farPeer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := farPeer.ReadFromUDPAddrPort(buf)
	if err != nil || string(buf[:n]) != "to peer" {
		t.Fatalf("far peer got %q, %v", buf[:n], err)
	}
	if from != legs[0].Addr {
		t.Fatalf("far peer saw source %v, want the leg %v", from, legs[0].Addr)
	}

	// Far peer -> leg -> controller, tagged with the leg and the peer.
	if _, err := farPeer.WriteToUDPAddrPort([]byte("to controller"), from); err != nil {
		t.Fatal(err)
	}
	data, _ := readFrame(conn.LegFrameData)
	if data.AgentID != 5 || data.LegID != legs[0].LegID || data.Addr != farAddr || string(data.Body) != "to controller" {
		t.Fatalf("relayed frame %+v", data)
	}
}
