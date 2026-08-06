package mtypes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHMACSHA256MatchesRFC4231(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	want, err := hex.DecodeString("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	if err != nil {
		t.Fatalf("decode expected digest: %v", err)
	}

	for i := 0; i < 2; i++ {
		if got := HMACSHA256(key, []byte("Hi There")); !bytes.Equal(got, want) {
			t.Fatalf("digest %d = %x, want %x", i+1, got, want)
		}
	}
}
