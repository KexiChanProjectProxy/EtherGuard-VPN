package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestClusterCryptoKeysMatchBothSides(t *testing.T) {
	client := mustClusterEphemeral(t)
	server := mustClusterEphemeral(t)
	secret := []byte("shared cluster secret for key agreement")

	clientSend, clientRecv, err := deriveClusterKeys(secret, client.priv, server.pub, client.pub, server.pub, "client-nonce", true)
	if err != nil {
		t.Fatalf("derive client keys: %v", err)
	}
	serverSend, serverRecv, err := deriveClusterKeys(secret, server.priv, client.pub, client.pub, server.pub, "client-nonce", false)
	if err != nil {
		t.Fatalf("derive server keys: %v", err)
	}

	if clientSend != serverRecv {
		t.Fatal("client send key does not match server receive key")
	}
	if clientRecv != serverSend {
		t.Fatal("client receive key does not match server send key")
	}
}

func TestClusterCryptoRecordRoundTrip(t *testing.T) {
	aead := mustClusterAEAD(t)
	writer := &clusterRecordWriter{aead: aead}
	reader := &clusterRecordReader{aead: aead}
	rng := rand.New(rand.NewSource(20260916))

	for record := range 1000 {
		plain := make([]byte, rng.Intn((1<<20)+1))
		if _, err := rng.Read(plain); err != nil {
			t.Fatalf("record %d generate plaintext: %v", record, err)
		}

		wire := writeClusterTestRecord(t, writer, plain)
		reader.r = bufio.NewReader(bytes.NewReader(wire))
		got, err := reader.ReadRecord()
		if err != nil {
			t.Fatalf("record %d read: %v", record, err)
		}
		if !bytes.Equal(got, plain) {
			t.Fatalf("record %d plaintext mismatch", record)
		}
	}
}

func TestClusterCryptoHandshakeSignVerify(t *testing.T) {
	secret := []byte("cluster handshake secret")
	parts := []string{"eg-cluster/1", "GET", "/edge/v2/cluster/link", "nonce"}

	sig := signClusterHandshake(secret, parts...)

	if !verifyClusterHandshake(secret, sig, parts...) {
		t.Fatal("valid handshake signature was rejected")
	}
	if verifyClusterHandshake([]byte("wrong secret"), sig, parts...) {
		t.Fatal("signature verified with the wrong secret")
	}
	if verifyClusterHandshake(secret, sig, append(parts, "extra")...) {
		t.Fatal("signature verified with different canonical parts")
	}
}

func TestClusterCryptoTamperedRecordFails(t *testing.T) {
	aead := mustClusterAEAD(t)
	writer := &clusterRecordWriter{aead: aead}
	wire := writeClusterTestRecord(t, writer, []byte("authenticated record"))
	wire[4] ^= 0x80
	reader := &clusterRecordReader{r: bufio.NewReader(bytes.NewReader(wire)), aead: aead}

	_, err := reader.ReadRecord()

	if !errors.Is(err, ErrClusterAuthFailed) {
		t.Fatalf("tampered record error = %v, want %v", err, ErrClusterAuthFailed)
	}
}

func TestClusterCryptoReplayedRecordFails(t *testing.T) {
	aead := mustClusterAEAD(t)
	writer := &clusterRecordWriter{aead: aead}
	reader := &clusterRecordReader{aead: aead}
	frames := make([][]byte, 4)
	for i := range frames {
		frames[i] = writeClusterTestRecord(t, writer, []byte{byte(i)})
		reader.r = bufio.NewReader(bytes.NewReader(frames[i]))
		if _, err := reader.ReadRecord(); err != nil {
			t.Fatalf("read record %d: %v", i+1, err)
		}
	}
	reader.r = bufio.NewReader(bytes.NewReader(frames[2]))

	_, err := reader.ReadRecord()

	if !errors.Is(err, ErrClusterAuthFailed) {
		t.Fatalf("replayed record error = %v, want %v", err, ErrClusterAuthFailed)
	}
}

func TestClusterCryptoWrongSecretDerivesDifferentKeys(t *testing.T) {
	client := mustClusterEphemeral(t)
	server := mustClusterEphemeral(t)

	sendA, recvA, err := deriveClusterKeys([]byte("secret A"), client.priv, server.pub, client.pub, server.pub, "nonce", true)
	if err != nil {
		t.Fatalf("derive keys with secret A: %v", err)
	}
	sendB, recvB, err := deriveClusterKeys([]byte("secret B"), client.priv, server.pub, client.pub, server.pub, "nonce", true)
	if err != nil {
		t.Fatalf("derive keys with secret B: %v", err)
	}

	if sendA == sendB || recvA == recvB {
		t.Fatal("different cluster secrets derived matching keys")
	}
}

func TestClusterCryptoLowOrderPointRejected(t *testing.T) {
	own := mustClusterEphemeral(t)
	var lowOrderPoint [32]byte

	sendKey, recvKey, err := deriveClusterKeys([]byte("cluster secret"), own.priv, lowOrderPoint, own.pub, lowOrderPoint, "nonce", true)

	if !errors.Is(err, ErrClusterLowOrderPoint) {
		t.Fatalf("low-order point error = %v, want %v", err, ErrClusterLowOrderPoint)
	}
	if sendKey != ([32]byte{}) || recvKey != ([32]byte{}) {
		t.Fatal("low-order point returned non-zero keys")
	}
}

func TestClusterCryptoOversizedRecordRejected(t *testing.T) {
	aead := mustClusterAEAD(t)
	source := &clusterOversizedHeaderReader{}
	binary.BigEndian.PutUint32(source.header[:], (1<<20)+chacha20poly1305.Overhead+1)
	reader := &clusterRecordReader{r: bufio.NewReader(source), aead: aead}

	_, err := reader.ReadRecord()

	if !errors.Is(err, ErrClusterRecordTooLarge) {
		t.Fatalf("oversized record error = %v, want %v", err, ErrClusterRecordTooLarge)
	}
	if source.reads != 1 {
		t.Fatalf("oversized record caused %d underlying reads, want 1 header read", source.reads)
	}
}

func TestClusterCryptoCounterExhausted(t *testing.T) {
	aead := mustClusterAEAD(t)
	var wire bytes.Buffer
	writer := &clusterRecordWriter{w: &wire, aead: aead, counter: 1 << 62}
	reader := &clusterRecordReader{r: bufio.NewReader(bytes.NewReader(nil)), aead: aead, counter: 1 << 62}

	writeErr := writer.WriteRecord(nil)
	_, readErr := reader.ReadRecord()

	if !errors.Is(writeErr, ErrClusterCounterExhausted) {
		t.Fatalf("writer counter error = %v, want %v", writeErr, ErrClusterCounterExhausted)
	}
	if !errors.Is(readErr, ErrClusterCounterExhausted) {
		t.Fatalf("reader counter error = %v, want %v", readErr, ErrClusterCounterExhausted)
	}
	if wire.Len() != 0 {
		t.Fatalf("exhausted writer emitted %d bytes", wire.Len())
	}
}

func TestClusterCryptoOversizedPlaintextRejected(t *testing.T) {
	aead := mustClusterAEAD(t)
	var wire bytes.Buffer
	writer := &clusterRecordWriter{w: &wire, aead: aead}

	err := writer.WriteRecord(make([]byte, (1<<20)+1))

	if !errors.Is(err, ErrClusterRecordTooLarge) {
		t.Fatalf("oversized plaintext error = %v, want %v", err, ErrClusterRecordTooLarge)
	}
	if writer.counter != 0 || wire.Len() != 0 {
		t.Fatalf("oversized plaintext changed writer state: counter=%d wire=%d", writer.counter, wire.Len())
	}
}

func mustClusterEphemeral(t *testing.T) clusterEphemeral {
	t.Helper()
	eph, err := newClusterEphemeral()
	if err != nil {
		t.Fatalf("new cluster ephemeral: %v", err)
	}
	return eph
}

func mustClusterAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	key := sha256.Sum256([]byte("cluster record test key"))
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		t.Fatalf("create test AEAD: %v", err)
	}
	return aead
}

func writeClusterTestRecord(t *testing.T, writer *clusterRecordWriter, plain []byte) []byte {
	t.Helper()
	var wire bytes.Buffer
	writer.w = &wire
	if err := writer.WriteRecord(plain); err != nil {
		t.Fatalf("write record: %v", err)
	}
	return bytes.Clone(wire.Bytes())
}

type clusterOversizedHeaderReader struct {
	header [4]byte
	reads  int
}

func (r *clusterOversizedHeaderReader) Read(p []byte) (int, error) {
	r.reads++
	if r.reads > 1 {
		return 0, errors.New("unexpected oversized record body read")
	}
	return copy(p, r.header[:]), io.EOF
}
