package device

import (
	"net"
	"testing"
	"time"

	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

type reliabilityTestEndpoint struct{}

func (reliabilityTestEndpoint) ClearSrc()           {}
func (reliabilityTestEndpoint) SrcToString() string { return "" }
func (reliabilityTestEndpoint) DstToString() string { return "127.0.0.1:3001" }
func (reliabilityTestEndpoint) DstToBytes() []byte  { return []byte{127, 0, 0, 1} }
func (reliabilityTestEndpoint) DstIP() net.IP       { return net.IPv4(127, 0, 0, 1) }
func (reliabilityTestEndpoint) SrcIP() net.IP       { return nil }

func TestSendPacketReturnsWhenDispatchQueueIsFull(t *testing.T) {
	device := &Device{chan_send_packet: make(chan *packet_send_params, 1)}
	device.PopulatePools()
	device.chan_send_packet <- &packet_send_params{}
	peer := &Peer{device: device, endpoint: reliabilityTestEndpoint{}}
	done := make(chan struct{})

	go func() {
		device.SendPacket(peer, path.PingPacket, 1, []byte{1}, 0)
		close(done)
	}()

	select {
	case <-done:
		<-device.chan_send_packet
	case <-time.After(time.Second):
		<-device.chan_send_packet
		<-done
		params := <-device.chan_send_packet
		device.PutMessageBuffer(params.elem.buffer)
		device.PutOutboundElement(params.elem)
		t.Fatal("SendPacket blocked while the dispatch queue was full")
	}
}
