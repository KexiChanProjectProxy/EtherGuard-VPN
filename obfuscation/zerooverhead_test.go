package obfuscation

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestZeroOverheadHandler_DataPacket(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, err := NewZeroOverheadHandler(psk, 1452, true)
	if err != nil {
		t.Fatalf("NewZeroOverheadHandler failed: %v", err)
	}

	// Test data packet (type 0, not a control packet)
	originalPacket := make([]byte, 128)
	originalPacket[0] = 0 // Data packet type
	rand.Read(originalPacket[1:])

	// Encrypt
	encrypted, err := handler.Encrypt(originalPacket)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// For data packets, only first 16 bytes should be encrypted
	if bytes.Equal(originalPacket[:16], encrypted[:16]) {
		t.Error("First 16 bytes should be encrypted")
	}

	if !bytes.Equal(originalPacket[16:], encrypted[16:]) {
		t.Error("Bytes after 16 should be unchanged for data packets")
	}

	// Decrypt
	decrypted, err := handler.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// Should match original
	if !bytes.Equal(originalPacket, decrypted) {
		t.Error("Decrypted packet doesn't match original")
	}
}

func TestZeroOverheadHandler_ControlPacket(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, err := NewZeroOverheadHandler(psk, 1452, true)
	if err != nil {
		t.Fatalf("NewZeroOverheadHandler failed: %v", err)
	}

	// Test control packet types
	controlTypes := []byte{
		MessageTypeRegister,
		MessageTypeServerUpdate,
		MessageTypePing,
		MessageTypePong,
		MessageTypeQueryPeer,
		MessageTypeBroadcastPeer,
	}

	for _, msgType := range controlTypes {
		t.Run(string(rune(msgType)), func(t *testing.T) {
			originalPacket := make([]byte, 128)
			originalPacket[0] = msgType
			rand.Read(originalPacket[1:])

			// Encrypt
			encrypted, err := handler.Encrypt(originalPacket)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			// Control packets should be longer due to padding
			if len(encrypted) < len(originalPacket) {
				t.Error("Encrypted control packet should not be shorter")
			}

			// First 16 bytes should be encrypted
			if bytes.Equal(originalPacket[:16], encrypted[:16]) {
				t.Error("First 16 bytes should be encrypted")
			}

			// Rest should also be encrypted (different from original)
			if len(originalPacket) > 16 && bytes.Equal(originalPacket[16:], encrypted[16:len(originalPacket)]) {
				t.Error("Control packet remainder should be encrypted")
			}

			// Decrypt
			decrypted, err := handler.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Should match original
			if !bytes.Equal(originalPacket, decrypted) {
				t.Errorf("Decrypted packet doesn't match original.\nOriginal: %x\nDecrypted: %x", originalPacket, decrypted)
			}
		})
	}
}

func TestZeroOverheadHandler_SmallPacket(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, err := NewZeroOverheadHandler(psk, 1452, true)
	if err != nil {
		t.Fatalf("NewZeroOverheadHandler failed: %v", err)
	}

	// Test packet smaller than AES block size
	smallPacket := []byte{1, 2, 3, 4}

	encrypted, err := handler.Encrypt(smallPacket)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Should be unchanged
	if !bytes.Equal(smallPacket, encrypted) {
		t.Error("Small packet should be unchanged")
	}

	decrypted, err := handler.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(smallPacket, decrypted) {
		t.Error("Decrypted small packet doesn't match")
	}
}

func TestZeroOverheadHandler_Disabled(t *testing.T) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, err := NewZeroOverheadHandler(psk, 1452, false)
	if err != nil {
		t.Fatalf("NewZeroOverheadHandler failed: %v", err)
	}

	if handler.Enabled() {
		t.Error("Handler should be disabled")
	}

	packet := make([]byte, 128)
	rand.Read(packet)

	encrypted, err := handler.Encrypt(packet)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Should be unchanged when disabled
	if !bytes.Equal(packet, encrypted) {
		t.Error("Packet should be unchanged when handler is disabled")
	}

	decrypted, err := handler.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(packet, decrypted) {
		t.Error("Decrypted packet doesn't match when disabled")
	}
}

func BenchmarkEncrypt_DataPacket(b *testing.B) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, _ := NewZeroOverheadHandler(psk, 1452, true)

	packet := make([]byte, 1420)
	packet[0] = 0 // Data packet
	rand.Read(packet[1:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Encrypt(packet)
	}
}

func BenchmarkEncrypt_ControlPacket(b *testing.B) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, _ := NewZeroOverheadHandler(psk, 1452, true)

	packet := make([]byte, 128)
	packet[0] = MessageTypePing
	rand.Read(packet[1:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Encrypt(packet)
	}
}

func BenchmarkDecrypt_DataPacket(b *testing.B) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, _ := NewZeroOverheadHandler(psk, 1452, true)

	packet := make([]byte, 1420)
	packet[0] = 0 // Data packet
	rand.Read(packet[1:])

	encrypted, _ := handler.Encrypt(packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Decrypt(encrypted)
	}
}

func BenchmarkDecrypt_ControlPacket(b *testing.B) {
	psk := make([]byte, 32)
	rand.Read(psk)

	handler, _ := NewZeroOverheadHandler(psk, 1452, true)

	packet := make([]byte, 128)
	packet[0] = MessageTypePing
	rand.Read(packet[1:])

	encrypted, _ := handler.Encrypt(packet)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = handler.Decrypt(encrypted)
	}
}
