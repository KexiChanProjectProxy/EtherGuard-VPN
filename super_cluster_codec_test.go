package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

type clusterCodecTestChunks struct {
	chunks [][]byte
	nextAt int
}

func (c *clusterCodecTestChunks) emit(chunk []byte) error {
	c.chunks = append(c.chunks, bytes.Clone(chunk))
	return nil
}

func (c *clusterCodecTestChunks) next() ([]byte, error) {
	if c.nextAt == len(c.chunks) {
		return nil, io.EOF
	}
	chunk := c.chunks[c.nextAt]
	c.nextAt++
	return chunk, nil
}

func TestClusterCodecRoundTripZstd(t *testing.T) {
	// Given a continuous zstd stream containing several framed messages
	var chunks clusterCodecTestChunks
	encoder, err := NewClusterStreamEncoder("zstd", chunks.emit)
	if err != nil {
		t.Fatalf("new encoder: %v", err)
	}
	messages := [][]byte{
		[]byte(`{"t":"hello","super_id":1}`),
		bytes.Repeat([]byte("repetitive-cluster-state-"), 64),
		{},
	}
	for _, message := range messages {
		if err := encoder.WriteMessage(message); err != nil {
			t.Fatalf("write message: %v", err)
		}
	}
	decoder, err := NewClusterStreamDecoder("zstd", chunks.next)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}

	// When each message is decoded from the same stream
	for i, want := range messages {
		got, err := decoder.ReadMessage()

		// Then framing and payload bytes round-trip exactly
		if err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d = %q, want %q", i, got, want)
		}
	}
	if encoder.Messages() != uint64(len(messages)) || decoder.Messages() != uint64(len(messages)) {
		t.Fatalf("message counters: encoder=%d decoder=%d", encoder.Messages(), decoder.Messages())
	}
}

func TestClusterCodecRoundTripNone(t *testing.T) {
	// Given an uncompressed stream containing framed messages
	var chunks clusterCodecTestChunks
	encoder, err := NewClusterStreamEncoder("none", chunks.emit)
	if err != nil {
		t.Fatalf("new encoder: %v", err)
	}
	messages := [][]byte{[]byte("first"), []byte("second"), {}}
	for _, message := range messages {
		if err := encoder.WriteMessage(message); err != nil {
			t.Fatalf("write message: %v", err)
		}
	}
	decoder, err := NewClusterStreamDecoder("none", chunks.next)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}

	// When the messages are read in order
	for i, want := range messages {
		got, err := decoder.ReadMessage()

		// Then the uncompressed framing preserves each payload
		if err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("message %d = %q, want %q", i, got, want)
		}
	}
	if encoder.CompressedBytes() != encoder.InnerBytes() {
		t.Fatalf("none counters: compressed=%d inner=%d", encoder.CompressedBytes(), encoder.InnerBytes())
	}
}

func TestClusterCodecOneChunkPerMessage(t *testing.T) {
	// Given a zstd encoder whose emit callback counts stream chunks
	emitted := 0
	encoder, err := NewClusterStreamEncoder("zstd", func([]byte) error {
		emitted++
		return nil
	})
	if err != nil {
		t.Fatalf("new encoder: %v", err)
	}

	// When several small messages are written and flushed individually
	for i := range 12 {
		before := emitted
		if err := encoder.WriteMessage([]byte(fmt.Sprintf(`{"t":"ping","hlc":%d}`, i))); err != nil {
			t.Fatalf("write message %d: %v", i, err)
		}

		// Then each WriteMessage produces exactly one emitted chunk
		if emitted != before+1 {
			t.Fatalf("message %d emitted %d chunks, want 1", i, emitted-before)
		}
	}
}

func TestClusterCodecRepetitiveCompresses(t *testing.T) {
	// Given zstd and none encoders receiving the same repetitive workload
	zstdEncoder, err := NewClusterStreamEncoder("zstd", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("new zstd encoder: %v", err)
	}
	noneEncoder, err := NewClusterStreamEncoder("none", func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("new none encoder: %v", err)
	}

	// When 500 JSON messages differ only in a counter
	for i := range 500 {
		message := []byte(fmt.Sprintf(`{"t":"peer_alive","node_id":101,"version":{"hlc":1234567890123,"origin":1},"last_seen":"2026-09-16T12:34:56Z","counter":%d}`, i))
		if err := zstdEncoder.WriteMessage(message); err != nil {
			t.Fatalf("write zstd message %d: %v", i, err)
		}
		if err := noneEncoder.WriteMessage(message); err != nil {
			t.Fatalf("write none message %d: %v", i, err)
		}
	}

	// Then the continuous zstd stream exploits repetition across messages
	if zstdEncoder.CompressedBytes() >= zstdEncoder.InnerBytes()/5 {
		t.Fatalf("zstd compressed=%d inner=%d, want compressed < inner/5", zstdEncoder.CompressedBytes(), zstdEncoder.InnerBytes())
	}
	if noneEncoder.CompressedBytes() != noneEncoder.InnerBytes() {
		t.Fatalf("none compressed=%d inner=%d, want equality", noneEncoder.CompressedBytes(), noneEncoder.InnerBytes())
	}
}

func TestClusterCodecRejectsOversized(t *testing.T) {
	// Given an uncompressed frame declaring a payload one byte over the limit
	var frame []byte
	encoder, err := NewClusterStreamEncoder("none", func(chunk []byte) error {
		frame = chunk
		return nil
	})
	if err != nil {
		t.Fatalf("new encoder: %v", err)
	}
	if err := encoder.WriteMessage(make([]byte, (4<<20)+1)); err != nil {
		t.Fatalf("write oversized message: %v", err)
	}
	delivered := false
	decoder, err := NewClusterStreamDecoder("none", func() ([]byte, error) {
		if delivered {
			return nil, io.EOF
		}
		delivered = true
		return frame, nil
	})
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}

	// When the decoder reads the declared length
	_, err = decoder.ReadMessage()

	// Then it rejects the frame before allocating the oversized payload
	if !errors.Is(err, ErrClusterMessageTooLarge) {
		t.Fatalf("read error = %v, want %v", err, ErrClusterMessageTooLarge)
	}
}

func TestClusterCodecTruncatedChunkErrors(t *testing.T) {
	// Given a zstd stream chunk truncated after encoding
	var chunks clusterCodecTestChunks
	encoder, err := NewClusterStreamEncoder("zstd", chunks.emit)
	if err != nil {
		t.Fatalf("new encoder: %v", err)
	}
	if err := encoder.WriteMessage(bytes.Repeat([]byte("cluster-state-"), 128)); err != nil {
		t.Fatalf("write message: %v", err)
	}
	if len(chunks.chunks) != 1 || len(chunks.chunks[0]) < 2 {
		t.Fatalf("unexpected encoded chunks: count=%d", len(chunks.chunks))
	}
	chunks.chunks[0] = chunks.chunks[0][:len(chunks.chunks[0])/2]
	decoder, err := NewClusterStreamDecoder("zstd", chunks.next)
	if err != nil {
		t.Fatalf("new decoder: %v", err)
	}

	// When the decoder consumes the truncated compressed chunk
	_, err = decoder.ReadMessage()

	// Then it returns an error rather than panicking or returning partial data
	if err == nil {
		t.Fatal("truncated chunk decoded without error")
	}
}
