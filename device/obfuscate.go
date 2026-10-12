package device

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"

	"github.com/KusakabeSi/EtherGuard-VPN/path"
	"golang.org/x/crypto/chacha20poly1305"
)

// ObfuscationKeyBase64 is the base64 encoding of the 32-byte key that
// obfuscates every WireGuard datagram. It is injected at build time:
//
//	go build -ldflags "-X github.com/KusakabeSi/EtherGuard-VPN/device.ObfuscationKeyBase64=<key>"
//
// All nodes that talk to each other must be built with the same key.
var ObfuscationKeyBase64 string

const (
	obfuscationKeySize = 32
	// obfuscationMaxPacketSize bounds padded handshake datagrams. It stays
	// below the 1232-byte IPv6 minimum-MTU UDP payload so they never fragment.
	obfuscationMaxPacketSize     = 1200
	obfuscationHandshakeOverhead = 2 + chacha20poly1305.Overhead + chacha20poly1305.NonceSizeX
	obfuscationMaxHandshakeSize  = obfuscationMaxPacketSize - obfuscationHandshakeOverhead
)

// packetObfuscator is a port of swgp-go's legacy zero-overhead handler,
// adapted to EtherGuard's message types.
//
//	data:      aes(pkt[:16]) + pkt[16:]
//	handshake: aes(pkt[:16]) + XChaCha20-Poly1305(pkt[16:] + padding + u16be len(pkt[16:])) + 24B nonce
//
// Datagrams shorter than one AES block pass through unchanged.
type packetObfuscator struct {
	cb   cipher.Block
	aead cipher.AEAD
}

var errObfuscatedPacketInvalid = errors.New("invalid obfuscated handshake packet")

func newPacketObfuscator(key []byte) (*packetObfuscator, error) {
	if len(key) != obfuscationKeySize {
		return nil, fmt.Errorf("obfuscation key must be %d bytes, got %d", obfuscationKeySize, len(key))
	}
	cb, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &packetObfuscator{cb: cb, aead: aead}, nil
}

func newPacketObfuscatorFromBase64(encoded string) (*packetObfuscator, error) {
	if encoded == "" {
		return nil, errors.New("obfuscation key was not set at build time")
	}
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode obfuscation key: %w", err)
	}
	return newPacketObfuscator(key)
}

var buildObfuscator = sync.OnceValues(func() (*packetObfuscator, error) {
	return newPacketObfuscatorFromBase64(ObfuscationKeyBase64)
})

// ObfuscationKeyError reports whether the build-time obfuscation key is
// missing or malformed. Edge startup refuses to run when it returns non-nil.
func ObfuscationKeyError() error {
	_, err := buildObfuscator()
	return err
}

func isObfuscatedHandshakeType(t byte) bool {
	switch path.Usage(t) {
	case path.MessageInitiationType, path.MessageResponseType, path.MessageCookieReplyType:
		return true
	}
	return false
}

// Encrypt obfuscates pkt and appends the result to dst. The spare capacity of
// dst must not overlap pkt.
func (o *packetObfuscator) Encrypt(dst, pkt []byte) ([]byte, error) {
	if len(pkt) < aes.BlockSize {
		return append(dst, pkt...), nil
	}
	messageType := pkt[0]
	plaintextStart := len(dst) + aes.BlockSize
	dst = append(dst, pkt...)
	o.cb.Encrypt(dst[plaintextStart-aes.BlockSize:plaintextStart], pkt[:aes.BlockSize])
	if !isObfuscatedHandshakeType(messageType) {
		return dst, nil
	}

	remaining := len(pkt) - aes.BlockSize
	headroom := obfuscationMaxHandshakeSize - len(pkt)
	if headroom < 0 {
		return nil, fmt.Errorf("handshake packet (type %d) is too large (%d bytes)", messageType, len(pkt))
	}
	paddingLen := 0
	if headroom > 0 {
		paddingLen = 1 + mrand.IntN(headroom)
	}
	// Padding content is encrypted, so its value does not matter.
	dst = append(dst, make([]byte, paddingLen)...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(remaining))

	var nonce [chacha20poly1305.NonceSizeX]byte
	rand.Read(nonce[:])
	dst = o.aead.Seal(dst[:plaintextStart], nonce[:], dst[plaintextStart:], nil)
	return append(dst, nonce[:]...), nil
}

// EncryptDataInPlace obfuscates a non-handshake packet without copying.
func (o *packetObfuscator) EncryptDataInPlace(pkt []byte) {
	if len(pkt) < aes.BlockSize {
		return
	}
	o.cb.Encrypt(pkt[:aes.BlockSize], pkt[:aes.BlockSize])
}

// DecryptInPlace reverses Encrypt inside pkt's memory and returns the
// recovered WireGuard packet, which is a prefix of pkt.
func (o *packetObfuscator) DecryptInPlace(pkt []byte) ([]byte, error) {
	if len(pkt) < aes.BlockSize {
		return pkt, nil
	}
	var header [aes.BlockSize]byte
	o.cb.Decrypt(header[:], pkt[:aes.BlockSize])
	if !isObfuscatedHandshakeType(header[0]) {
		copy(pkt, header[:])
		return pkt, nil
	}
	if len(pkt) < aes.BlockSize+obfuscationHandshakeOverhead {
		return nil, errObfuscatedPacketInvalid
	}
	nonceStart := len(pkt) - chacha20poly1305.NonceSizeX
	var nonce [chacha20poly1305.NonceSizeX]byte
	copy(nonce[:], pkt[nonceStart:])
	plaintext, err := o.aead.Open(pkt[aes.BlockSize:aes.BlockSize], nonce[:], pkt[aes.BlockSize:nonceStart], nil)
	if err != nil {
		return nil, err
	}
	paddingEnd := len(plaintext) - 2
	remaining := int(binary.BigEndian.Uint16(plaintext[paddingEnd:]))
	if remaining > paddingEnd {
		return nil, errObfuscatedPacketInvalid
	}
	copy(pkt, header[:])
	return pkt[:aes.BlockSize+remaining], nil
}
