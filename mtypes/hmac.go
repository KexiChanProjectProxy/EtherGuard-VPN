package mtypes

import (
	"crypto/sha256"
)

// HMACSHA256 avoids hash.Hash.Sum because the production Go 1.26.5 crypto
// backend mutates shared HMAC state under concurrent verification.
func HMACSHA256(key, message []byte) []byte {
	const blockSize = 64
	var keyBlock [blockSize]byte
	if len(key) > blockSize {
		hashedKey := sha256.Sum256(key)
		copy(keyBlock[:], hashedKey[:])
	} else {
		copy(keyBlock[:], key)
	}

	var innerPad [blockSize]byte
	var outerPad [blockSize]byte
	for i, value := range keyBlock {
		innerPad[i] = value ^ 0x36
		outerPad[i] = value ^ 0x5c
	}

	innerInput := make([]byte, blockSize+len(message))
	copy(innerInput, innerPad[:])
	copy(innerInput[blockSize:], message)
	innerDigest := sha256.Sum256(innerInput)

	var outerInput [blockSize + sha256.Size]byte
	copy(outerInput[:blockSize], outerPad[:])
	copy(outerInput[blockSize:], innerDigest[:])
	digest := sha256.Sum256(outerInput[:])
	return digest[:]
}
