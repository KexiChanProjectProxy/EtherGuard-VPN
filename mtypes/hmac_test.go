package mtypes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHMACSHA256MatchesRFC4231(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		message string
		digest  string
	}{
		{
			name:    "short key",
			key:     bytes.Repeat([]byte{0x0b}, 20),
			message: "Hi There",
			digest:  "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			name:    "long key",
			key:     bytes.Repeat([]byte{0xaa}, 131),
			message: "Test Using Larger Than Block-Size Key - Hash Key First",
			digest:  "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			want, err := hex.DecodeString(test.digest)
			if err != nil {
				t.Fatalf("decode expected digest: %v", err)
			}
			for i := 0; i < 2; i++ {
				if got := HMACSHA256(test.key, []byte(test.message)); !bytes.Equal(got, want) {
					t.Fatalf("digest %d = %x, want %x", i+1, got, want)
				}
			}
		})
	}
}
