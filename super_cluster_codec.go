package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync/atomic"

	"github.com/klauspost/compress/zstd"
)

const clusterMaxMessageSize = 4 << 20

var ErrClusterMessageTooLarge = errors.New("cluster codec: message too large")

type clusterChunkWriter struct {
	emit func(chunk []byte) error
}

func (w clusterChunkWriter) Write(p []byte) (int, error) {
	if err := w.emit(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

type clusterStreamEncoder struct {
	mode        string
	emit        func([]byte) error
	zstdEncoder *zstd.Encoder
	noneFrame   []byte
	zstdStarted bool
	zstdHeader  []byte

	innerBytes      atomic.Uint64
	compressedBytes atomic.Uint64
	messages        atomic.Uint64
}

func NewClusterStreamEncoder(mode string, emit func([]byte) error) (*clusterStreamEncoder, error) {
	if emit == nil {
		return nil, errors.New("cluster codec: nil emit callback")
	}

	encoder := &clusterStreamEncoder{mode: mode, emit: emit}
	switch mode {
	case "none":
		return encoder, nil
	case "zstd":
		chunkWriter := clusterChunkWriter{emit: encoder.emitZstdWrite}
		zstdEncoder, err := zstd.NewWriter(
			chunkWriter,
			zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(256<<10),
			zstd.WithLowerEncoderMem(true),
			zstd.WithEncoderLevel(zstd.SpeedDefault),
		)
		if err != nil {
			return nil, fmt.Errorf("cluster codec: create zstd encoder: %w", err)
		}
		encoder.zstdEncoder = zstdEncoder
		return encoder, nil
	default:
		return nil, fmt.Errorf("cluster codec: unsupported compression mode %q", mode)
	}
}

func (e *clusterStreamEncoder) emitZstdWrite(chunk []byte) error {
	if !e.zstdStarted {
		e.zstdStarted = true
		e.zstdHeader = append(e.zstdHeader[:0], chunk...)
		return nil
	}
	if len(e.zstdHeader) > 0 {
		e.zstdHeader = append(e.zstdHeader, chunk...)
		chunk = e.zstdHeader
		e.zstdHeader = e.zstdHeader[:0]
	}
	if err := e.emit(chunk); err != nil {
		return err
	}
	e.compressedBytes.Add(uint64(len(chunk)))
	return nil
}

func (e *clusterStreamEncoder) WriteMessage(msg []byte) error {
	if uint64(len(msg)) > math.MaxUint32 {
		return fmt.Errorf("%w: %d", ErrClusterMessageTooLarge, len(msg))
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(msg)))
	innerSize := uint64(len(header) + len(msg))

	switch e.mode {
	case "none":
		frameSize := len(header) + len(msg)
		if cap(e.noneFrame) < frameSize {
			e.noneFrame = make([]byte, frameSize)
		} else {
			e.noneFrame = e.noneFrame[:frameSize]
		}
		copy(e.noneFrame, header[:])
		copy(e.noneFrame[len(header):], msg)
		if err := e.emit(e.noneFrame); err != nil {
			return fmt.Errorf("cluster codec: emit uncompressed message: %w", err)
		}
		e.compressedBytes.Add(innerSize)
	case "zstd":
		if err := writeClusterStreamPart(e.zstdEncoder, header[:]); err != nil {
			return fmt.Errorf("cluster codec: write message length: %w", err)
		}
		if err := writeClusterStreamPart(e.zstdEncoder, msg); err != nil {
			return fmt.Errorf("cluster codec: write message body: %w", err)
		}
		if err := e.zstdEncoder.Flush(); err != nil {
			return fmt.Errorf("cluster codec: flush message: %w", err)
		}
	default:
		return fmt.Errorf("cluster codec: unsupported compression mode %q", e.mode)
	}

	e.innerBytes.Add(innerSize)
	e.messages.Add(1)
	return nil
}

func (e *clusterStreamEncoder) InnerBytes() uint64 {
	return e.innerBytes.Load()
}

func (e *clusterStreamEncoder) CompressedBytes() uint64 {
	return e.compressedBytes.Load()
}

func (e *clusterStreamEncoder) Messages() uint64 {
	return e.messages.Load()
}

func writeClusterStreamPart(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

type chunkReader struct {
	next       func() ([]byte, error)
	chunk      []byte
	pendingErr error
	bytes      atomic.Uint64
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.chunk) == 0 {
		if r.pendingErr != nil {
			err := r.pendingErr
			r.pendingErr = nil
			return 0, err
		}
		chunk, err := r.next()
		if len(chunk) == 0 {
			if err != nil {
				return 0, err
			}
			return 0, io.ErrNoProgress
		}
		r.chunk = chunk
		r.pendingErr = err
		r.bytes.Add(uint64(len(chunk)))
	}

	n := copy(p, r.chunk)
	r.chunk = r.chunk[n:]
	return n, nil
}

type clusterStreamDecoder struct {
	source      *chunkReader
	reader      io.Reader
	zstdDecoder *zstd.Decoder

	innerBytes atomic.Uint64
	messages   atomic.Uint64
}

func NewClusterStreamDecoder(mode string, next func() ([]byte, error)) (*clusterStreamDecoder, error) {
	if next == nil {
		return nil, errors.New("cluster codec: nil next callback")
	}

	source := &chunkReader{next: next}
	decoder := &clusterStreamDecoder{source: source}
	switch mode {
	case "none":
		decoder.reader = source
		return decoder, nil
	case "zstd":
		zstdDecoder, err := zstd.NewReader(
			source,
			zstd.WithDecoderConcurrency(1),
			zstd.WithDecoderLowmem(true),
			zstd.WithDecoderMaxWindow(1<<20),
			zstd.WithDecoderMaxMemory(8<<20),
		)
		if err != nil {
			return nil, fmt.Errorf("cluster codec: create zstd decoder: %w", err)
		}
		decoder.reader = zstdDecoder
		decoder.zstdDecoder = zstdDecoder
		return decoder, nil
	default:
		return nil, fmt.Errorf("cluster codec: unsupported compression mode %q", mode)
	}
}

func (d *clusterStreamDecoder) ReadMessage() ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(d.reader, header[:]); err != nil {
		return nil, fmt.Errorf("cluster codec: read message length: %w", err)
	}

	messageSize := binary.BigEndian.Uint32(header[:])
	if messageSize > clusterMaxMessageSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrClusterMessageTooLarge, messageSize, clusterMaxMessageSize)
	}
	message := make([]byte, int(messageSize))
	if _, err := io.ReadFull(d.reader, message); err != nil {
		return nil, fmt.Errorf("cluster codec: read message body: %w", err)
	}

	d.innerBytes.Add(uint64(len(header)) + uint64(messageSize))
	d.messages.Add(1)
	return message, nil
}

func (d *clusterStreamDecoder) InnerBytes() uint64 {
	return d.innerBytes.Load()
}

func (d *clusterStreamDecoder) CompressedBytes() uint64 {
	return d.source.bytes.Load()
}

func (d *clusterStreamDecoder) Messages() uint64 {
	return d.messages.Load()
}
