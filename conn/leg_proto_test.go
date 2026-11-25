package conn

import (
	"bytes"
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"
)

func testLegKey(b byte) *LegKey {
	var key LegKey
	for i := range key {
		key[i] = b + byte(i)
	}
	return &key
}

func TestLegFrameRoundTrip(t *testing.T) {
	key := testLegKey(1)
	for _, addr := range []netip.AddrPort{
		netip.MustParseAddrPort("203.0.113.9:51820"),
		netip.MustParseAddrPort("[2001:db8::9]:443"),
	} {
		in := LegFrame{Type: LegFrameData, AgentID: 7, LegID: 3, Epoch: 99, Counter: 1 << 40, Addr: addr, Body: []byte("payload")}
		buf := AppendLegFrame([]byte("prefix"), key, in)
		if len(buf) != len("prefix")+len(in.Body)+LegFrameOverhead {
			t.Fatalf("frame size %d", len(buf))
		}
		out, err := DecodeLegFrame(key, buf[len("prefix"):])
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.Type != in.Type || out.AgentID != 7 || out.LegID != 3 || out.Epoch != 99 || out.Counter != 1<<40 || out.Addr != addr || !bytes.Equal(out.Body, in.Body) {
			t.Fatalf("round trip mismatch: %+v", out)
		}
	}
}

func TestLegFrameWithoutAddress(t *testing.T) {
	key := testLegKey(1)
	out, err := DecodeLegFrame(key, AppendLegFrame(nil, key, LegFrame{Type: LegFrameState}))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Addr.IsValid() {
		t.Fatalf("state frame has address %v", out.Addr)
	}
}

func TestLegFrameRejectsTamperingAndWrongKey(t *testing.T) {
	key := testLegKey(1)
	frame := AppendLegFrame(nil, key, LegFrame{Type: LegFrameData, AgentID: 1, Addr: netip.MustParseAddrPort("192.0.2.1:1"), Body: []byte("x")})
	for i := range frame {
		tampered := append([]byte(nil), frame...)
		tampered[i] ^= 0x40
		if _, err := DecodeLegFrame(key, tampered); err == nil {
			t.Fatalf("byte %d tampered but accepted", i)
		}
	}
	if _, err := DecodeLegFrame(testLegKey(2), frame); !errors.Is(err, ErrLegFrameMAC) {
		t.Fatalf("wrong key: got %v", err)
	}
	if _, err := DecodeLegFrame(key, frame[:LegFrameOverhead-1]); !errors.Is(err, ErrLegFrameShort) {
		t.Fatalf("short frame: got %v", err)
	}
}

func TestLegStateRoundTrip(t *testing.T) {
	in := LegState{Nonce: 11, Echo: 22, Legs: []LegInfo{
		{LegID: 0, Name: "eth0", Addr: netip.MustParseAddrPort("198.51.100.4:16386")},
		{LegID: 5, Name: "wwan0", Addr: netip.MustParseAddrPort("[2001:db8:1::5]:16386")},
	}}
	out, err := ParseLegState(AppendLegState(nil, in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Nonce != 11 || out.Echo != 22 || len(out.Legs) != 2 || out.Legs[0] != in.Legs[0] || out.Legs[1] != in.Legs[1] {
		t.Fatalf("got %+v", out)
	}
	empty, err := ParseLegState(AppendLegState(nil, LegState{}))
	if err != nil || len(empty.Legs) != 0 {
		t.Fatalf("empty state: %v %v", empty, err)
	}
}

func TestLegStateRejectsMalformedBodies(t *testing.T) {
	good := AppendLegState(nil, LegState{Legs: []LegInfo{{LegID: 1, Name: "eth0", Addr: netip.MustParseAddrPort("198.51.100.4:1")}}})
	tooMany := append(make([]byte, 16), MaxLegsPerAgent+1)
	for name, body := range map[string][]byte{
		"empty":     nil,
		"no legs":   make([]byte, 16),
		"truncated": good[:len(good)-1],
		"trailing":  append(append([]byte(nil), good...), 0),
		"too many":  tooMany,
	} {
		if _, err := ParseLegState(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLegFrameCarriesDirectionFlag(t *testing.T) {
	key := testLegKey(1)
	out, err := DecodeLegFrame(key, AppendLegFrame(nil, key, LegFrame{Type: LegFrameData, Flags: LegFlagFromController}))
	if err != nil || out.Flags&LegFlagFromController == 0 {
		t.Fatalf("flags %x, %v", out.Flags, err)
	}
}

var (
	sessionHome  = netip.MustParseAddrPort("192.168.1.21:16400")
	sessionOther = netip.MustParseAddrPort("192.168.1.66:4000")
)

func TestLegSessionNeedsEchoBeforeTrustingAnAddress(t *testing.T) {
	var s LegSession
	now := time.Unix(1000, 0)
	timeout := 6 * time.Second
	challenge, _ := s.Nonces()

	// A first frame from anywhere is answered with a challenge.
	if accepted, reply := s.Observe(1, 1, LegState{Nonce: 77}, sessionHome, now, timeout); accepted || !reply {
		t.Fatalf("first frame: accepted=%v reply=%v", accepted, reply)
	}
	if _, echo := s.Nonces(); echo != 77 {
		t.Fatalf("does not echo the sender's nonce: %d", echo)
	}
	// Echoing the challenge proves freshness.
	if accepted, reply := s.Observe(1, 2, LegState{Nonce: 77, Echo: challenge}, sessionHome, now, timeout); !accepted || !reply {
		t.Fatalf("echo: accepted=%v reply=%v", accepted, reply)
	}
	if next, _ := s.Nonces(); next == challenge {
		t.Fatal("challenge not rotated after use")
	}
	// Newer frames from the same address are trusted while live.
	if accepted, reply := s.Observe(1, 3, LegState{Nonce: 77}, sessionHome, now.Add(time.Second), timeout); !accepted || reply {
		t.Fatalf("live frame: accepted=%v reply=%v", accepted, reply)
	}
	// The echo frame replayed, from anywhere, is not.
	for _, from := range []netip.AddrPort{sessionHome, sessionOther} {
		if accepted, _ := s.Observe(1, 2, LegState{Nonce: 77, Echo: challenge}, from, now.Add(2*time.Second), timeout); accepted {
			t.Fatalf("replayed echo frame from %v accepted", from)
		}
	}
	// A trusted frame that echoes the current challenge uses it up, so the
	// frame replayed from another address is refused.
	current, _ := s.Nonces()
	if accepted, _ := s.Observe(1, 4, LegState{Nonce: 77, Echo: current}, sessionHome, now.Add(time.Second), timeout); !accepted {
		t.Fatal("live echo frame refused")
	}
	if accepted, _ := s.Observe(1, 4, LegState{Nonce: 77, Echo: current}, sessionOther, now.Add(2*time.Second), timeout); accepted {
		t.Fatal("replayed live frame accepted from another address")
	}
	// A newer frame from another address still needs the echo.
	if accepted, _ := s.Observe(1, 9, LegState{Nonce: 77}, sessionOther, now.Add(3*time.Second), timeout); accepted {
		t.Fatal("new address trusted without echo")
	}
	if addr, _ := s.Addr(); addr != sessionHome {
		t.Fatalf("session moved to %v", addr)
	}
}

func TestLegSessionNeedsEchoAfterTimeoutAndForOlderEpochs(t *testing.T) {
	var s LegSession
	now := time.Unix(1000, 0)
	timeout := 6 * time.Second
	challenge, _ := s.Nonces()
	s.Observe(5, 1, LegState{Echo: challenge}, sessionHome, now, timeout)
	if !s.Live(now, timeout) {
		t.Fatal("not live after echo")
	}

	// After a timeout even a newer frame from the same address needs the echo,
	// so a replay cannot revive a dead side.
	later := now.Add(10 * time.Second)
	if s.Live(later, timeout) {
		t.Fatal("still live after timeout")
	}
	if accepted, reply := s.Observe(5, 2, LegState{}, sessionHome, later, timeout); accepted || !reply {
		t.Fatalf("stale frame: accepted=%v reply=%v", accepted, reply)
	}
	// A sender whose clock went backwards gets back in with the echo.
	current, _ := s.Nonces()
	if accepted, _ := s.Observe(1, 1, LegState{Echo: current}, sessionHome, later, timeout); !accepted {
		t.Fatal("older epoch with echo refused")
	}
}

func TestLegSessionRateLimitsChallenges(t *testing.T) {
	var s LegSession
	now := time.Unix(1000, 0)
	if _, reply := s.Observe(1, 1, LegState{}, sessionOther, now, time.Second); !reply {
		t.Fatal("first untrusted frame not answered")
	}
	if _, reply := s.Observe(1, 1, LegState{}, sessionOther, now.Add(time.Millisecond), time.Second); reply {
		t.Fatal("second untrusted frame answered at once")
	}
	if _, reply := s.Observe(1, 1, LegState{}, sessionOther, now.Add(time.Second), time.Second); !reply {
		t.Fatal("untrusted frame not answered after the interval")
	}
}

func TestLegSessionBootstrapChallenge(t *testing.T) {
	var s LegSession
	s.Bootstrap(42)
	if accepted, _ := s.Observe(1, 1, LegState{Echo: 42}, sessionHome, time.Unix(1, 0), time.Second); !accepted {
		t.Fatal("bootstrap echo refused")
	}
	s.Bootstrap(43)
	if nonce, _ := s.Nonces(); nonce == 43 {
		t.Fatal("bootstrap replaced a live challenge")
	}
}

func TestLegIfindexRange(t *testing.T) {
	for _, c := range []struct {
		agent uint16
		leg   uint8
	}{{1, 0}, {65535, 255}, {300, 7}} {
		ifindex := LegIfindex(c.agent, c.leg)
		if !IsLegIfindex(ifindex) || ifindex > math.MaxInt32 {
			t.Fatalf("ifindex %d out of range", ifindex)
		}
		agent, leg := splitLegIfindex(ifindex)
		if agent != c.agent || leg != c.leg {
			t.Fatalf("split %d: got %d/%d", ifindex, agent, leg)
		}
	}
	if IsLegIfindex(2) || IsLegIfindex(0) {
		t.Fatal("kernel ifindex taken for a leg")
	}
}

func TestParseLegKey(t *testing.T) {
	if _, err := ParseLegKey("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="); err != nil {
		t.Fatalf("valid key: %v", err)
	}
	for _, bad := range []string{"", "not base64!", "AAEC"} {
		if _, err := ParseLegKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
