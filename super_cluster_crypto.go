package main

import (
	"bufio"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	clusterMaxPlaintext  = 1 << 20
	clusterMaxCiphertext = clusterMaxPlaintext + chacha20poly1305.Overhead
	clusterCounterLimit  = 1 << 62
)

var (
	ErrClusterLowOrderPoint    = errors.New("cluster crypto: x25519 low-order point")
	ErrClusterRecordTooLarge   = errors.New("cluster crypto: record too large")
	ErrClusterCounterExhausted = errors.New("cluster crypto: record counter exhausted")
	ErrClusterAuthFailed       = errors.New("cluster crypto: record authentication failed")
)

type clusterEphemeral struct {
	priv [32]byte
	pub  [32]byte
}

func newClusterEphemeral() (clusterEphemeral, error) {
	var eph clusterEphemeral
	if _, err := io.ReadFull(rand.Reader, eph.priv[:]); err != nil {
		return clusterEphemeral{}, err
	}
	pub, err := curve25519.X25519(eph.priv[:], curve25519.Basepoint)
	if err != nil {
		return clusterEphemeral{}, err
	}
	copy(eph.pub[:], pub)
	return eph, nil
}

func deriveClusterKeys(
	secret []byte,
	ownPriv [32]byte,
	peerPub [32]byte,
	clientEph [32]byte,
	serverEph [32]byte,
	clientNonce string,
	isClient bool,
) (sendKey, recvKey [32]byte, err error) {
	shared, err := curve25519.X25519(ownPriv[:], peerPub[:])
	if err != nil {
		return sendKey, recvKey, ErrClusterLowOrderPoint
	}
	var zero [32]byte
	if hmac.Equal(shared, zero[:]) {
		return sendKey, recvKey, ErrClusterLowOrderPoint
	}

	ikm := make([]byte, 0, len(shared)+len(secret))
	ikm = append(ikm, shared...)
	ikm = append(ikm, secret...)
	saltInput := make([]byte, 0, len(clientEph)+len(serverEph)+len(clientNonce))
	saltInput = append(saltInput, clientEph[:]...)
	saltInput = append(saltInput, serverEph[:]...)
	saltInput = append(saltInput, clientNonce...)
	salt := sha256.Sum256(saltInput)
	prk := hkdf.Extract(sha256.New, ikm, salt[:])

	var clientToServer [32]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("eg-cluster/1 c2s")), clientToServer[:]); err != nil {
		return sendKey, recvKey, err
	}
	var serverToClient [32]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("eg-cluster/1 s2c")), serverToClient[:]); err != nil {
		return sendKey, recvKey, err
	}

	if isClient {
		return clientToServer, serverToClient, nil
	}
	return serverToClient, clientToServer, nil
}

func signClusterHandshake(secret []byte, parts ...string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifyClusterHandshake(secret []byte, sig string, parts ...string) bool {
	provided, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.Join(parts, "\n")))
	return hmac.Equal(provided, mac.Sum(nil))
}

type clusterRecordWriter struct {
	w       io.Writer
	aead    cipher.AEAD
	counter uint64
	wire    uint64
}

func (w *clusterRecordWriter) WriteRecord(plain []byte) error {
	if len(plain) > clusterMaxPlaintext {
		return ErrClusterRecordTooLarge
	}
	if w.counter >= clusterCounterLimit {
		return ErrClusterCounterExhausted
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(plain)+w.aead.Overhead()))
	nonce := clusterRecordNonce(w.counter)
	ciphertext := w.aead.Seal(nil, nonce[:], plain, header[:])

	n, err := writeClusterBytes(w.w, header[:])
	w.wire += uint64(n)
	if err != nil {
		return err
	}
	n, err = writeClusterBytes(w.w, ciphertext)
	w.wire += uint64(n)
	if err != nil {
		return err
	}
	w.counter++
	return nil
}

type clusterRecordReader struct {
	r       *bufio.Reader
	aead    cipher.AEAD
	counter uint64
	wire    uint64
}

func (r *clusterRecordReader) ReadRecord() ([]byte, error) {
	if r.counter >= clusterCounterLimit {
		return nil, ErrClusterCounterExhausted
	}

	var header [4]byte
	n, err := io.ReadFull(r.r, header[:])
	r.wire += uint64(n)
	if err != nil {
		return nil, err
	}
	ciphertextLen := binary.BigEndian.Uint32(header[:])
	if ciphertextLen > clusterMaxCiphertext {
		return nil, ErrClusterRecordTooLarge
	}

	ciphertext := make([]byte, int(ciphertextLen))
	n, err = io.ReadFull(r.r, ciphertext)
	r.wire += uint64(n)
	if err != nil {
		return nil, err
	}
	nonce := clusterRecordNonce(r.counter)
	plain, err := r.aead.Open(nil, nonce[:], ciphertext, header[:])
	if err != nil {
		return nil, ErrClusterAuthFailed
	}
	r.counter++
	return plain, nil
}

func clusterRecordNonce(counter uint64) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func writeClusterBytes(w io.Writer, p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := w.Write(p[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
