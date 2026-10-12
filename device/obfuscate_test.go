package device

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/KusakabeSi/EtherGuard-VPN/path"
)

// testObfuscationKeyBase64 stands in for the build-time key in tests.
const testObfuscationKeyBase64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

func init() {
	if ObfuscationKeyBase64 == "" {
		ObfuscationKeyBase64 = testObfuscationKeyBase64
	}
}

func newTestObfuscator(t *testing.T) *packetObfuscator {
	t.Helper()
	o, err := newPacketObfuscatorFromBase64(testObfuscationKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func randomPacket(t *testing.T, msgType path.Usage, size int) []byte {
	t.Helper()
	pkt := make([]byte, size)
	rand.Read(pkt)
	pkt[0] = byte(msgType)
	return pkt
}

func TestObfuscatorHandshakeRoundTrip(t *testing.T) {
	o := newTestObfuscator(t)
	cases := []struct {
		msgType path.Usage
		size    int
	}{
		{path.MessageInitiationType, MessageInitiationSize},
		{path.MessageResponseType, MessageResponseSize},
		{path.MessageCookieReplyType, MessageCookieReplySize},
	}
	for _, tc := range cases {
		pkt := randomPacket(t, tc.msgType, tc.size)
		first, err := o.Encrypt(nil, pkt)
		if err != nil {
			t.Fatalf("type %d: encrypt: %v", tc.msgType, err)
		}
		if len(first) < tc.size+1+obfuscationHandshakeOverhead || len(first) > obfuscationMaxPacketSize {
			t.Fatalf("type %d: wire length %d outside [%d, %d]", tc.msgType, len(first), tc.size+1+obfuscationHandshakeOverhead, obfuscationMaxPacketSize)
		}
		if first[0] == byte(tc.msgType) && bytes.Equal(first[1:16], pkt[1:16]) {
			t.Fatalf("type %d: header was not obfuscated", tc.msgType)
		}
		second, err := o.Encrypt(nil, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first, second) {
			t.Fatalf("type %d: two encryptions are identical", tc.msgType)
		}
		got, err := o.DecryptInPlace(first)
		if err != nil {
			t.Fatalf("type %d: decrypt: %v", tc.msgType, err)
		}
		if !bytes.Equal(got, pkt) {
			t.Fatalf("type %d: round trip mismatch", tc.msgType)
		}
	}
}

func TestObfuscatorDataZeroOverhead(t *testing.T) {
	o := newTestObfuscator(t)
	for msgType := path.MessageTransportType; msgType <= path.BroadcastPeer; msgType++ {
		pkt := randomPacket(t, msgType, 200)
		orig := append([]byte(nil), pkt...)
		o.EncryptDataInPlace(pkt)
		if len(pkt) != len(orig) || !bytes.Equal(pkt[16:], orig[16:]) || bytes.Equal(pkt[:16], orig[:16]) {
			t.Fatalf("type %d: only the first block must change", msgType)
		}
		appended, err := o.Encrypt(nil, orig)
		if err != nil || !bytes.Equal(appended, pkt) {
			t.Fatalf("type %d: Encrypt and EncryptDataInPlace disagree: %v", msgType, err)
		}
		got, err := o.DecryptInPlace(pkt)
		if err != nil || !bytes.Equal(got, orig) {
			t.Fatalf("type %d: round trip failed: %v", msgType, err)
		}
	}
}

func TestObfuscatorShortPacketPassthrough(t *testing.T) {
	o := newTestObfuscator(t)
	pkt := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	enc, err := o.Encrypt(nil, pkt)
	if err != nil || !bytes.Equal(enc, pkt) {
		t.Fatalf("short packet changed: %v", err)
	}
	if got, err := o.DecryptInPlace(enc); err != nil || !bytes.Equal(got, pkt) {
		t.Fatalf("short packet decrypt: %v", err)
	}
}

func TestObfuscatorRejectsForgedHandshake(t *testing.T) {
	o := newTestObfuscator(t)
	pkt := randomPacket(t, path.MessageInitiationType, MessageInitiationSize)
	wire, err := o.Encrypt(nil, pkt)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), wire...)
	tampered[40] ^= 1
	if _, err := o.DecryptInPlace(tampered); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	if !bytes.Equal(tampered[:16], wire[:16]) {
		t.Fatal("failed decrypt modified the header")
	}

	truncated := append([]byte(nil), wire[:len(wire)-1]...)
	if _, err := o.DecryptInPlace(truncated); err == nil {
		t.Fatal("truncated packet accepted")
	}

	short := append([]byte(nil), wire[:16+obfuscationHandshakeOverhead-1]...)
	if _, err := o.DecryptInPlace(short); err == nil {
		t.Fatal("packet shorter than handshake overhead accepted")
	}

	other, err := newPacketObfuscator(bytes.Repeat([]byte{7}, obfuscationKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := other.DecryptInPlace(append([]byte(nil), wire...)); err == nil && bytes.Equal(got, pkt) {
		t.Fatal("packet decrypted with the wrong key")
	}
}

func TestObfuscatorRejectsBadLengthField(t *testing.T) {
	o := newTestObfuscator(t)
	// A sealed payload whose length field exceeds the padded plaintext.
	header := randomPacket(t, path.MessageResponseType, 16)
	plaintext := []byte{0xaa, 0xbb, 0xff, 0xff}
	var nonce [24]byte
	rand.Read(nonce[:])
	wire := make([]byte, 16)
	o.cb.Encrypt(wire, header)
	wire = o.aead.Seal(wire, nonce[:], plaintext, nil)
	wire = append(wire, nonce[:]...)
	if _, err := o.DecryptInPlace(wire); err == nil {
		t.Fatal("oversized length field accepted")
	}
}

func TestObfuscatorRejectsOversizedHandshake(t *testing.T) {
	o := newTestObfuscator(t)
	pkt := randomPacket(t, path.MessageInitiationType, obfuscationMaxHandshakeSize+1)
	if _, err := o.Encrypt(nil, pkt); err == nil {
		t.Fatal("oversized handshake accepted")
	}
	pkt = randomPacket(t, path.MessageInitiationType, obfuscationMaxHandshakeSize)
	wire, err := o.Encrypt(nil, pkt)
	if err != nil || len(wire) != obfuscationMaxPacketSize {
		t.Fatalf("max-size handshake: len=%d err=%v", len(wire), err)
	}
}

func TestObfuscationKeyValidation(t *testing.T) {
	for _, key := range []string{
		"",
		"not base64!",
		base64.StdEncoding.EncodeToString(make([]byte, 16)),
		base64.StdEncoding.EncodeToString(make([]byte, 33)),
	} {
		if _, err := newPacketObfuscatorFromBase64(key); err == nil {
			t.Fatalf("key %q accepted", key)
		}
	}
	if err := ObfuscationKeyError(); err != nil {
		t.Fatalf("test build key rejected: %v", err)
	}
}

func BenchmarkObfuscatorData(b *testing.B) {
	o, _ := newPacketObfuscatorFromBase64(testObfuscationKeyBase64)
	pkt := make([]byte, 1420)
	pkt[0] = byte(path.MessageTransportType)
	b.SetBytes(int64(len(pkt)))
	for b.Loop() {
		o.EncryptDataInPlace(pkt)
		if _, err := o.DecryptInPlace(pkt); err != nil {
			b.Fatal(err)
		}
	}
}
