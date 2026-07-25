package device

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type endpointSequence struct {
	mu            sync.Mutex
	count         int
	first         chan int
	secondEntered chan struct{}
	releaseSecond chan struct{}
}

type sequencedEndpoint struct {
	id       int
	sequence *endpointSequence
}

func (e *sequencedEndpoint) ClearSrc() {}

func (e *sequencedEndpoint) SrcToString() string { return "127.0.0.1:1000" }

func (e *sequencedEndpoint) DstToString() string {
	e.sequence.mu.Lock()
	e.sequence.count++
	position := e.sequence.count
	e.sequence.mu.Unlock()

	switch position {
	case 1:
		e.sequence.first <- e.id
	case 2:
		close(e.sequence.secondEntered)
		<-e.sequence.releaseSecond
	}
	return "127.0.0.1:1000"
}

func (e *sequencedEndpoint) DstToBytes() []byte { return net.IPv4(127, 0, 0, 1) }

func (e *sequencedEndpoint) DstIP() net.IP { return net.IPv4(127, 0, 0, 1) }

func (e *sequencedEndpoint) SrcIP() net.IP { return net.IPv4(127, 0, 0, 1) }

func TestIpcGetOperation_releasesEachPeerLockAfterSerialization(t *testing.T) {
	// Given
	sequence := &endpointSequence{
		first:         make(chan int, 1),
		secondEntered: make(chan struct{}),
		releaseSecond: make(chan struct{}),
	}
	device := &Device{}
	peers := [2]*Peer{
		{endpoint: &sequencedEndpoint{id: 0, sequence: sequence}},
		{endpoint: &sequencedEndpoint{id: 1, sequence: sequence}},
	}
	device.peers.keyMap = make(map[NoisePublicKey]*Peer, len(peers))
	for id, peer := range peers {
		var key NoisePublicKey
		key[0] = byte(id + 1)
		device.peers.keyMap[key] = peer
	}
	getDone := make(chan error, 1)
	go func() {
		getDone <- device.IpcGetOperation(io.Discard)
	}()
	firstID := <-sequence.first
	<-sequence.secondEntered

	// When
	firstPeerWritable := make(chan struct{})
	go func() {
		peers[firstID].Lock()
		close(firstPeerWritable)
		peers[firstID].Unlock()
	}()

	// Then
	select {
	case <-firstPeerWritable:
	case <-time.After(250 * time.Millisecond):
		close(sequence.releaseSecond)
		if err := <-getDone; err != nil {
			t.Fatalf("finish UAPI get: %v", err)
		}
		t.Fatal("UAPI get retained a previously serialized peer lock")
	}
	close(sequence.releaseSecond)
	if err := <-getDone; err != nil {
		t.Fatalf("UAPI get: %v", err)
	}
}
