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
	legs := []LegInfo{
		{LegID: 0, Name: "eth0", Addr: netip.MustParseAddrPort("198.51.100.4:16386")},
		{LegID: 5, Name: "wwan0", Addr: netip.MustParseAddrPort("[2001:db8:1::5]:16386")},
	}
	out, err := ParseLegState(AppendLegState(nil, legs))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 2 || out[0] != legs[0] || out[1] != legs[1] {
		t.Fatalf("got %+v", out)
	}
	empty, err := ParseLegState(AppendLegState(nil, nil))
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty state: %v %v", empty, err)
	}
}

func TestLegStateRejectsMalformedBodies(t *testing.T) {
	good := AppendLegState(nil, []LegInfo{{LegID: 1, Name: "eth0", Addr: netip.MustParseAddrPort("198.51.100.4:1")}})
	for name, body := range map[string][]byte{
		"empty":     nil,
		"truncated": good[:len(good)-1],
		"trailing":  append(append([]byte(nil), good...), 0),
		"too many":  {MaxLegsPerAgent + 1},
	} {
		if _, err := ParseLegState(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLegReplayGuard(t *testing.T) {
	var guard LegReplayGuard
	now := time.Unix(1000, 0)
	timeout := 6 * time.Second
	steps := []struct {
		epoch   uint64
		counter uint64
		at      time.Duration
		want    bool
	}{
		{10, 5, 0, true},
		{10, 5, time.Second, false},      // replay
		{10, 4, time.Second, false},      // older
		{10, 6, time.Second, true},       // newer
		{9, 100, 2 * time.Second, false}, // older epoch
		{11, 1, 3 * time.Second, true},   // restart
		{1, 1, 20 * time.Second, true},   // silent past the timeout: any epoch
	}
	for i, step := range steps {
		if got := guard.Accept(step.epoch, step.counter, now.Add(step.at), timeout); got != step.want {
			t.Fatalf("step %d: got %v want %v", i, got, step.want)
		}
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
