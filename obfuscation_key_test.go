package main

import (
	"crypto/aes"
	"encoding/base64"

	"github.com/KusakabeSi/EtherGuard-VPN/device"
	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

// testObfuscationKeyBase64 stands in for the build-time key, since tests run
// without -ldflags.
const testObfuscationKeyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func init() {
	if device.ObfuscationKeyBase64 == "" {
		device.ObfuscationKeyBase64 = testObfuscationKeyBase64
	}
}

// wireMessageType recovers the EtherGuard message type of an obfuscated
// datagram by decrypting its first AES block, as a fake network would need to.
func wireMessageType(packet []byte) (byte, bool) {
	if len(packet) == 0 {
		return 0, false
	}
	if len(packet) < aes.BlockSize {
		return packet[0], true
	}
	key, err := base64.StdEncoding.DecodeString(device.ObfuscationKeyBase64)
	if err != nil {
		return 0, false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, false
	}
	var header [aes.BlockSize]byte
	block.Decrypt(header[:], packet[:aes.BlockSize])
	return header[0], true
}

func isWireInitiation(packet []byte) bool {
	msgType, ok := wireMessageType(packet)
	return ok && msgType == uint8(path.MessageInitiationType)
}
