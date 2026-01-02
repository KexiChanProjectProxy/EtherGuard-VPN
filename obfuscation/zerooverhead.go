package obfuscation

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"math/rand"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Control message types for EtherGuard protocol
	// These are the packet types that should get padding and full encryption
	MessageTypeRegister       = 1
	MessageTypeServerUpdate   = 2
	MessageTypePing           = 3
	MessageTypePong           = 4
	MessageTypeQueryPeer      = 5
	MessageTypeBroadcastPeer  = 6
)

// ZeroOverheadHandler encrypts packets using zero-overhead mode:
// - Encrypts first 16 bytes with AES block cipher
// - For control packets: adds random padding and encrypts remainder with XChaCha20-Poly1305
// - For data packets: leaves remainder unchanged (zero overhead)
type ZeroOverheadHandler struct {
	cb                     cipher.Block
	aead                   cipher.AEAD
	maxPacketSize          int
	maxControlPacketSize   int
	enabled                bool
}

// NewZeroOverheadHandler creates a new handler with the given PSK
func NewZeroOverheadHandler(psk []byte, maxPacketSize int, enabled bool) (*ZeroOverheadHandler, error) {
	if !enabled {
		return &ZeroOverheadHandler{enabled: false}, nil
	}

	if len(psk) != 32 {
		return nil, errors.New("PSK must be 32 bytes")
	}

	cb, err := aes.NewCipher(psk)
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(psk)
	if err != nil {
		return nil, err
	}

	maxControlPacketSize := maxPacketSize - 2 - chacha20poly1305.Overhead - chacha20poly1305.NonceSizeX

	return &ZeroOverheadHandler{
		cb:                   cb,
		aead:                 aead,
		maxPacketSize:        maxPacketSize,
		maxControlPacketSize: maxControlPacketSize,
		enabled:              true,
	}, nil
}

// Enabled returns whether obfuscation is enabled
func (h *ZeroOverheadHandler) Enabled() bool {
	return h.enabled
}

// Overhead returns the overhead added by this handler (0 for data packets)
func (h *ZeroOverheadHandler) Overhead() int {
	return 0
}

// Encrypt encrypts a packet using zero-overhead mode
func (h *ZeroOverheadHandler) Encrypt(packet []byte) ([]byte, error) {
	if !h.enabled {
		return packet, nil
	}

	// Return packets smaller than AES block size unmodified
	if len(packet) < aes.BlockSize {
		return packet, nil
	}

	// Save message type before encryption
	messageType := packet[0]

	// Calculate capacity needed
	capacity := len(packet) + 2 + chacha20poly1305.Overhead + chacha20poly1305.NonceSizeX
	dst := make([]byte, aes.BlockSize, capacity)

	// Encrypt first AES block
	h.cb.Encrypt(dst[:aes.BlockSize], packet[:aes.BlockSize])

	// Append remaining payload
	remainingPayload := packet[aes.BlockSize:]
	plaintextStart := len(dst)
	dst = append(dst, remainingPayload...)

	// Check if this is a control packet that needs full encryption
	isControlPacket := false
	switch messageType {
	case MessageTypeRegister, MessageTypeServerUpdate, MessageTypePing,
		MessageTypePong, MessageTypeQueryPeer, MessageTypeBroadcastPeer:
		isControlPacket = true
	}

	if !isControlPacket {
		// Data packet - we're done
		return dst, nil
	}

	// Control packet - add padding and encrypt
	paddingHeadroom := h.maxControlPacketSize - len(packet)
	if paddingHeadroom < 0 || len(remainingPayload) > 65535 {
		return nil, errors.New("control packet is too large")
	}

	var paddingLen int
	if paddingHeadroom > 0 {
		paddingLen = 1 + rand.Intn(paddingHeadroom)
	}

	// Add random padding
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		cryptorand.Read(padding)
		dst = append(dst, padding...)
	}

	// Append payload length
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(remainingPayload)))

	// Generate nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	cryptorand.Read(nonce)

	// Seal the remainder (from plaintextStart to current end) in-place
	plaintext := dst[plaintextStart:]
	dst = h.aead.Seal(dst[:plaintextStart], nonce, plaintext, nil)

	// Append nonce at the end
	dst = append(dst, nonce...)

	return dst, nil
}

// Decrypt decrypts a packet using zero-overhead mode
func (h *ZeroOverheadHandler) Decrypt(packet []byte) ([]byte, error) {
	if !h.enabled {
		return packet, nil
	}

	// Return packets smaller than AES block size unmodified
	if len(packet) < aes.BlockSize {
		return packet, nil
	}

	dst := make([]byte, aes.BlockSize)

	// Decrypt first AES block
	h.cb.Decrypt(dst, packet[:aes.BlockSize])

	// Check message type
	messageType := dst[0]

	// Check if this is a control packet
	isControlPacket := false
	switch messageType {
	case MessageTypeRegister, MessageTypeServerUpdate, MessageTypePing,
		MessageTypePong, MessageTypeQueryPeer, MessageTypeBroadcastPeer:
		isControlPacket = true
	}

	if !isControlPacket {
		// Data packet - just append remainder
		return append(dst, packet[aes.BlockSize:]...), nil
	}

	// Control packet - need to decrypt remainder
	minControlPacketLen := aes.BlockSize + 2 + chacha20poly1305.Overhead + chacha20poly1305.NonceSizeX
	if len(packet) < minControlPacketLen {
		return nil, errors.New("invalid control packet length")
	}

	dstLen := len(dst)

	// Extract nonce from end
	nonceStart := len(packet) - chacha20poly1305.NonceSizeX
	nonce := packet[nonceStart:]
	ciphertext := packet[aes.BlockSize:nonceStart]

	// Open the ciphertext
	plaintext, err := h.aead.Open(dst, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Read and validate payload length
	if len(plaintext) < 2 {
		return nil, errors.New("decrypted packet too small")
	}

	paddingEnd := len(plaintext) - 2
	remainingPayloadSize := int(binary.BigEndian.Uint16(plaintext[paddingEnd:]))
	dstLen += remainingPayloadSize

	if dstLen > paddingEnd {
		return nil, errors.New("invalid control packet payload length")
	}

	return plaintext[:dstLen], nil
}
