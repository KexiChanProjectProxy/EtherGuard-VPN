package device

import (
	"bytes"
	"sort"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/mtypes"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
	fixed_time_cache "github.com/KusakabeSi/go-cache"
)

// newForwardTestDevice builds node 1 as the hub of a star with leaves 2, 3
// and 4. Every leaf reaches every other leaf through node 1.
func newForwardTestDevice(t *testing.T) (*Device, map[mtypes.Vertex]*Peer) {
	t.Helper()
	graph, err := path.NewGraph(0, false, mtypes.GraphRecalculateSetting{}, mtypes.NTPInfo{}, mtypes.LoggerInfo{})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	graph.SetNHTable(mtypes.NextHopTable{
		1: {2: 2, 3: 3, 4: 4},
		2: {1: 1, 3: 1, 4: 1},
		3: {1: 1, 2: 1, 4: 1},
		4: {1: 1, 2: 1, 3: 1},
	})
	device := &Device{
		ID:    1,
		log:   NewLogger(LogLevelSilent, "forward-test"),
		graph: graph,
		EdgeConfig: &mtypes.EdgeConfig{
			Interface:    mtypes.InterfaceConf{MTU: 1400},
			DefaultTTL:   200,
			DynamicRoute: mtypes.DynamicRouteInfo{PeerAliveTimeout: 60},
		},
		chan_send_packet: make(chan *packet_send_params, 64),
	}
	device.DupData = *fixed_time_cache.NewCache(time.Minute, false, time.Second)
	device.peers.IDMap = make(map[mtypes.Vertex]*Peer)
	device.PopulatePools()
	now := time.Now()
	for _, id := range []mtypes.Vertex{2, 3, 4} {
		peer := &Peer{ID: id, device: device, endpoint: reliabilityTestEndpoint{}}
		peer.SingleWayLatency.device = device
		peer.LastPacketReceivedAdd1Sec.Store(&now)
		device.peers.IDMap[id] = peer
	}
	t.Cleanup(func() { drainSent(device) })
	return device, device.peers.IDMap
}

type sentPacket struct {
	to     mtypes.Vertex
	ttl    uint8
	packet []byte
}

// drainSent empties the dispatch queue without blocking and returns what was
// queued, copied out of the pooled buffers.
func drainSent(device *Device) []sentPacket {
	var sent []sentPacket
	for {
		select {
		case params := <-device.chan_send_packet:
			sent = append(sent, sentPacket{
				to:     params.peer.ID,
				ttl:    params.elem.TTL,
				packet: append([]byte(nil), params.elem.packet...),
			})
			device.PutMessageBuffer(params.elem.buffer)
			device.PutOutboundElement(params.elem)
		default:
			return sent
		}
	}
}

func probePingPacket(t *testing.T, src, dst mtypes.Vertex, requestID uint32) []byte {
	t.Helper()
	body, err := mtypes.GetByte(&mtypes.PingMsg{RequestID: requestID, Src_nodeID: src, Time: time.Unix(1700000000, 0)})
	if err != nil {
		t.Fatalf("encode ping: %v", err)
	}
	packet := make([]byte, path.EgHeaderLen+len(body))
	header, _ := path.NewEgHeader(packet[:path.EgHeaderLen], 1400)
	header.SetSrc(src)
	header.SetDst(dst)
	copy(packet[path.EgHeaderLen:], body)
	return packet
}

func scribble(b []byte) {
	for i := range b {
		b[i] = 0xA5
	}
}

func sentTo(sent []sentPacket) []mtypes.Vertex {
	ids := make([]mtypes.Vertex, 0, len(sent))
	for _, s := range sent {
		ids = append(ids, s.to)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// Every send helper must copy the packet before returning, because the
// receive path hands in a slice of a pooled buffer and recycles it right
// after the call.
func TestFanOutCopiesPacketBeforeReturn(t *testing.T) {
	cases := []struct {
		name string
		send func(d *Device, peers map[mtypes.Vertex]*Peer, packet []byte)
		want []mtypes.Vertex
	}{
		{"SendPacket", func(d *Device, peers map[mtypes.Vertex]*Peer, packet []byte) {
			d.SendPacket(peers[3], path.PingPacket, 7, packet, MessageTransportOffsetContent)
		}, []mtypes.Vertex{3}},
		{"SpreadPacket", func(d *Device, _ map[mtypes.Vertex]*Peer, packet []byte) {
			d.SpreadPacket(map[mtypes.Vertex]bool{2: true}, path.PingPacket, 7, packet, MessageTransportOffsetContent)
		}, []mtypes.Vertex{3, 4}},
		{"BoardcastPacket", func(d *Device, _ map[mtypes.Vertex]*Peer, packet []byte) {
			d.BoardcastPacket(map[mtypes.Vertex]bool{}, path.PingPacket, 7, packet, MessageTransportOffsetContent)
		}, []mtypes.Vertex{2, 3, 4}},
		{"TransitBoardcastPacket", func(d *Device, _ map[mtypes.Vertex]*Peer, packet []byte) {
			d.TransitBoardcastPacket(2, 2, path.PingPacket, 7, packet, MessageTransportOffsetContent)
		}, []mtypes.Vertex{3, 4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			device, peers := newForwardTestDevice(t)
			want := probePingPacket(t, 2, mtypes.NodeID_Broadcast, 42)
			buffer := device.GetMessageBuffer()
			packet := buffer[MessageTransportOffsetContent : MessageTransportOffsetContent+len(want)]
			copy(packet, want)

			tc.send(device, peers, packet)
			scribble(buffer[:])
			device.PutMessageBuffer(buffer)

			sent := drainSent(device)
			if got := sentTo(sent); !equalVertices(got, tc.want) {
				t.Fatalf("queued for %v, want %v", got, tc.want)
			}
			for _, s := range sent {
				if !bytes.Equal(s.packet, want) {
					t.Fatalf("packet queued for %v was modified after the source buffer was reused", s.to)
				}
				if s.ttl != 7 {
					t.Fatalf("packet queued for %v has TTL %v, want 7", s.to, s.ttl)
				}
			}
		})
	}
}

// Drives the real sequential receiver with transit traffic from peer 2 and
// reuses the receive buffer as soon as the receiver has returned it to the
// pool. All forwarded copies must already be queued and intact by then.
//
// Each input gets its own receiver run: within one run a recycled receive
// buffer is legitimately reused as an outbound buffer for the next packet, so
// it is only safe to scribble on it once the receiver has stopped.
func TestReceiveForwardSurvivesBufferRecycle(t *testing.T) {
	inputs := []struct {
		name      string
		dst       mtypes.Vertex
		requestID uint32
		want      []mtypes.Vertex
	}{
		{"unicast", 3, 101, []mtypes.Vertex{3}},
		{"broadcast", mtypes.NodeID_Broadcast, 102, []mtypes.Vertex{3, 4}},
		{"spread", mtypes.NodeID_Spread, 103, []mtypes.Vertex{3, 4}},
	}
	for _, input := range inputs {
		t.Run(input.name, func(t *testing.T) {
			device, peers := newForwardTestDevice(t)
			in := peers[2]
			in.disableRoaming = true
			in.queue.inbound = &autodrainingInboundQueue{c: make(chan *QueueInboundElement, 2)}

			packet := probePingPacket(t, 2, input.dst, input.requestID)
			buffer := device.GetMessageBuffer()
			copy(buffer[MessageTransportOffsetContent:], packet)
			elem := device.GetInboundElement()
			elem.Type = path.PingPacket
			elem.TTL = 5
			elem.buffer = buffer
			elem.packet = buffer[MessageTransportOffsetContent : MessageTransportOffsetContent+len(packet)]
			elem.counter = 1
			elem.keypair = &Keypair{}
			elem.endpoint = reliabilityTestEndpoint{}
			in.queue.inbound.c <- elem
			in.queue.inbound.c <- nil

			in.stopping.Add(1)
			go in.RoutineSequentialReceiver()
			stopped := make(chan struct{})
			go func() {
				in.stopping.Wait()
				close(stopped)
			}()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("sequential receiver did not stop")
			}
			scribble(buffer[:])

			var forwarded []sentPacket
			for _, s := range drainSent(device) {
				header, _ := path.NewEgHeader(s.packet[:path.EgHeaderLen], 1400)
				if header.GetSrc() == device.ID {
					continue // node 1's own probe reply to peer 2
				}
				ping, err := mtypes.ParsePingMsg(s.packet[path.EgHeaderLen:])
				if err != nil {
					t.Fatalf("forwarded packet to %v does not parse: %v", s.to, err)
				}
				if header.GetSrc() != 2 || ping.Src_nodeID != 2 || header.GetDst() != input.dst || ping.RequestID != input.requestID {
					t.Fatalf("forwarded packet to %v is S:%v D:%v body S:%v RequestID:%v, want S:2 D:%v RequestID:%v",
						s.to, header.GetSrc(), header.GetDst(), ping.Src_nodeID, ping.RequestID, input.dst, input.requestID)
				}
				if s.ttl != 4 {
					t.Fatalf("forwarded packet to %v has TTL %v, want 4", s.to, s.ttl)
				}
				forwarded = append(forwarded, s)
			}
			if got := sentTo(forwarded); !equalVertices(got, input.want) {
				t.Fatalf("forwarded to %v, want %v", got, input.want)
			}
		})
	}
}

func equalVertices(a, b []mtypes.Vertex) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
