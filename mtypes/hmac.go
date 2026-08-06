package mtypes

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMACSHA256 computes a stable HMAC-SHA256 digest across standard Go and the
// Go 1.26.5 crypto backend whose first Sum call mutates the HMAC state.
func HMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	_ = mac.Sum(nil)
	return mac.Sum(nil)
}
