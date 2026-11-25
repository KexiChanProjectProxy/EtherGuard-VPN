/* SPDX-License-Identifier: MIT */

package conn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
)

// Remote legs let one edge (the controller) send and receive its WireGuard
// datagrams through the uplinks of other machines on the same site. A leg
// agent on each of those machines owns a UDP socket on its uplinks and relays
// datagrams between that socket and the controller over the site network. It
// holds no WireGuard keys: every payload is already encrypted and obfuscated.
//
// Both sides speak the same framed protocol over UDP. A frame is
//
//	magic "EL" | version | type | agentID u16 | legID u8 | flags u8 |
//	epoch u64 | counter u64 | addr [16] | port u16 | body | tag [16]
//
// tag is a keyed BLAKE2s-128 MAC over everything before it, under the
// site-wide leg key. All integers are big endian. addr/port is the far peer
// of a data frame (IPv4 in mapped form) and zero in control frames.
//
// flags carries LegFlagFromController on every frame the controller sends,
// and each side drops frames in its own direction, so a frame can never be
// reflected back to the side that built it.
//
// State frames are the only control message. Their body is
//
//	nonce u64 | echo u64 | count u8 | legs
//
// An agent lists its uplinks; the controller (agentID 0) sends none. Each side
// sends them every LegHeartbeatInterval to every address it knows for the
// other side, so either side alone may know the other's address. A receiver
// trusts a state frame when it is newer than the last one (epoch, then
// counter) from the address it already uses for that side, while that side is
// live. Any other frame (a new address, a restarted sender, a side back after
// a timeout) is trusted only when its echo carries the receiver's current
// challenge, which the receiver sends as its own nonce in reply. A recorded
// frame therefore cannot move a side to another address, and a sender whose
// clock went backwards recovers in one round trip. That tolerates one-way
// reachability through NAT or firewalls on the site network, and the
// heartbeats keep such mappings open.

const (
	LegFrameVersion      = 1
	LegFrameData    byte = 1
	LegFrameState   byte = 2

	// LegFlagFromController marks frames the controller sends.
	LegFlagFromController byte = 1 << 0

	legMagic0 = 'E'
	legMagic1 = 'L'

	LegHeaderSize = 2 + 1 + 1 + 2 + 1 + 1 + 8 + 8 + 16 + 2
	LegTagSize    = 16
	// LegFrameOverhead is the bytes a frame adds to its payload.
	LegFrameOverhead = LegHeaderSize + LegTagSize
	LegKeySize       = 32

	// LegHeartbeatInterval is how often both sides send state frames.
	LegHeartbeatInterval = 2 * time.Second
	// DefaultLegHeartbeatTimeout is how long a side stays up without state
	// frames.
	DefaultLegHeartbeatTimeout = 6 * time.Second

	// LegControllerID is the agentID the controller puts in its frames.
	LegControllerID uint16 = 0

	// MaxLegsPerAgent bounds the uplinks one agent may announce.
	MaxLegsPerAgent = 16
	maxLegNameLen   = 32

	// legIfindexBase marks synthetic interface indexes of remote legs. Real
	// kernel ifindexes are far smaller, and the result stays below MaxInt32.
	legIfindexBase = 1 << 30
)

var (
	ErrLegFrameShort    = errors.New("leg frame too short")
	ErrLegFrameMagic    = errors.New("not a leg frame")
	ErrLegFrameVersion  = errors.New("unsupported leg frame version")
	ErrLegFrameMAC      = errors.New("leg frame authentication failed")
	ErrLegFrameBody     = errors.New("malformed leg state body")
	ErrLegUnavailable   = errors.New("remote leg is not available")
	ErrLegPayloadTooBig = errors.New("leg payload too large")
)

// LegKey is the site-wide key that authenticates leg frames.
type LegKey [LegKeySize]byte

// ParseLegKey decodes a base64 leg key of exactly LegKeySize bytes.
func ParseLegKey(s string) (LegKey, error) {
	var key LegKey
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("leg key is not base64: %w", err)
	}
	if len(raw) != LegKeySize {
		return key, fmt.Errorf("leg key must be %d bytes, got %d", LegKeySize, len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// LegIfindex is the synthetic interface index of a remote leg. Remote leg
// endpoints carry it so they never match a local uplink.
func LegIfindex(agentID uint16, legID uint8) int {
	return legIfindexBase | int(agentID)<<8 | int(legID)
}

// IsLegIfindex reports whether ifindex is a synthetic remote leg index.
func IsLegIfindex(ifindex int) bool {
	return ifindex >= legIfindexBase && ifindex < legIfindexBase<<1
}

func splitLegIfindex(ifindex int) (agentID uint16, legID uint8) {
	return uint16(ifindex >> 8), uint8(ifindex)
}

// LegFrame is a decoded frame. Body aliases the buffer it was decoded from.
type LegFrame struct {
	Type    byte
	Flags   byte
	AgentID uint16
	LegID   uint8
	Epoch   uint64
	Counter uint64
	Addr    netip.AddrPort
	Body    []byte
}

func legMAC(key *LegKey, data []byte) [LegTagSize]byte {
	h, err := blake2s.New128(key[:])
	if err != nil {
		panic(err) // only fails for keys longer than 32 bytes
	}
	h.Write(data)
	var tag [LegTagSize]byte
	copy(tag[:], h.Sum(nil))
	return tag
}

// AppendLegFrame appends the encoded frame to dst and returns the result.
func AppendLegFrame(dst []byte, key *LegKey, frame LegFrame) []byte {
	start := len(dst)
	var header [LegHeaderSize]byte
	header[0], header[1] = legMagic0, legMagic1
	header[2] = LegFrameVersion
	header[3] = frame.Type
	binary.BigEndian.PutUint16(header[4:6], frame.AgentID)
	header[6] = frame.LegID
	header[7] = frame.Flags
	binary.BigEndian.PutUint64(header[8:16], frame.Epoch)
	binary.BigEndian.PutUint64(header[16:24], frame.Counter)
	if frame.Addr.IsValid() {
		addr := frame.Addr.Addr().As16()
		copy(header[24:40], addr[:])
		binary.BigEndian.PutUint16(header[40:42], frame.Addr.Port())
	}
	dst = append(dst, header[:]...)
	dst = append(dst, frame.Body...)
	tag := legMAC(key, dst[start:])
	return append(dst, tag[:]...)
}

// DecodeLegFrame authenticates and decodes buf.
func DecodeLegFrame(key *LegKey, buf []byte) (LegFrame, error) {
	var frame LegFrame
	if len(buf) < LegFrameOverhead {
		return frame, ErrLegFrameShort
	}
	if buf[0] != legMagic0 || buf[1] != legMagic1 {
		return frame, ErrLegFrameMagic
	}
	if buf[2] != LegFrameVersion {
		return frame, ErrLegFrameVersion
	}
	signed := buf[:len(buf)-LegTagSize]
	tag := legMAC(key, signed)
	if subtle.ConstantTimeCompare(tag[:], buf[len(buf)-LegTagSize:]) != 1 {
		return frame, ErrLegFrameMAC
	}
	frame.Type = buf[3]
	frame.AgentID = binary.BigEndian.Uint16(buf[4:6])
	frame.LegID = buf[6]
	frame.Flags = buf[7]
	frame.Epoch = binary.BigEndian.Uint64(buf[8:16])
	frame.Counter = binary.BigEndian.Uint64(buf[16:24])
	var addr [16]byte
	copy(addr[:], buf[24:40])
	if port := binary.BigEndian.Uint16(buf[40:42]); port != 0 || addr != [16]byte{} {
		frame.Addr = netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), port)
	}
	frame.Body = signed[LegHeaderSize:]
	return frame, nil
}

// LegInfo is one uplink an agent announces in its state frames.
type LegInfo struct {
	LegID uint8
	Name  string
	Addr  netip.AddrPort // the uplink address and the agent's socket port
}

// LegState is the body of a state frame.
type LegState struct {
	// Nonce is the sender's current challenge for the receiver; Echo is the
	// receiver's challenge the sender last saw.
	Nonce, Echo uint64
	Legs        []LegInfo
}

// AppendLegState encodes state as a state frame body.
func AppendLegState(dst []byte, state LegState) []byte {
	legs := state.Legs
	if len(legs) > MaxLegsPerAgent {
		legs = legs[:MaxLegsPerAgent]
	}
	dst = binary.BigEndian.AppendUint64(dst, state.Nonce)
	dst = binary.BigEndian.AppendUint64(dst, state.Echo)
	dst = append(dst, byte(len(legs)))
	for _, leg := range legs {
		name := leg.Name
		if len(name) > maxLegNameLen {
			name = name[:maxLegNameLen]
		}
		addr := leg.Addr.Addr().As16()
		dst = append(dst, leg.LegID)
		dst = append(dst, addr[:]...)
		dst = binary.BigEndian.AppendUint16(dst, leg.Addr.Port())
		dst = append(dst, byte(len(name)))
		dst = append(dst, name...)
	}
	return dst
}

// ParseLegState decodes a state frame body.
func ParseLegState(body []byte) (LegState, error) {
	var state LegState
	if len(body) < 8+8+1 {
		return state, ErrLegFrameBody
	}
	state.Nonce = binary.BigEndian.Uint64(body[0:8])
	state.Echo = binary.BigEndian.Uint64(body[8:16])
	count := int(body[16])
	if count > MaxLegsPerAgent {
		return state, ErrLegFrameBody
	}
	body = body[17:]
	state.Legs = make([]LegInfo, 0, count)
	for i := 0; i < count; i++ {
		if len(body) < 1+16+2+1 {
			return state, ErrLegFrameBody
		}
		var addr [16]byte
		copy(addr[:], body[1:17])
		port := binary.BigEndian.Uint16(body[17:19])
		nameLen := int(body[19])
		if nameLen > maxLegNameLen || len(body) < 20+nameLen {
			return state, ErrLegFrameBody
		}
		state.Legs = append(state.Legs, LegInfo{
			LegID: body[0],
			Name:  string(body[20 : 20+nameLen]),
			Addr:  netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), port),
		})
		body = body[20+nameLen:]
	}
	if len(body) != 0 {
		return state, ErrLegFrameBody
	}
	return state, nil
}

// LegSequence numbers the frames one side sends. The epoch is the start time
// in nanoseconds, so a restarted sender is newer than its previous run as long
// as its clock moves forward.
type LegSequence struct {
	mu      sync.Mutex
	epoch   uint64
	counter uint64
}

func NewLegSequence() *LegSequence {
	return &LegSequence{epoch: uint64(time.Now().UnixNano())}
}

// Next returns the epoch and the next counter.
func (s *LegSequence) Next() (uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter++
	return s.epoch, s.counter
}

// NewLegNonce returns a random non-zero challenge.
func NewLegNonce() uint64 {
	var b [8]byte
	for {
		if _, err := rand.Read(b[:]); err != nil {
			panic(err)
		}
		if n := binary.BigEndian.Uint64(b[:]); n != 0 {
			return n
		}
	}
}

// legChallengeReplyInterval limits how often a session answers frames it did
// not trust, which bounds what replayed frames can make it send.
const legChallengeReplyInterval = 250 * time.Millisecond

// LegSession is one side's view of the other side of a leg link: where it
// is, the last frame trusted from it, and the challenges in both directions.
// The zero value is ready to use. It is not safe for concurrent use.
type LegSession struct {
	addr      netip.AddrPort
	epoch     uint64
	counter   uint64
	lastSeen  time.Time
	valid     bool
	challenge uint64
	peerNonce uint64
	lastReply time.Time
}

// Bootstrap sets the challenge of a session that has seen no frame yet, so a
// side that sent a shared bootstrap challenge before it knew the other side
// can trust the echo.
func (s *LegSession) Bootstrap(challenge uint64) {
	if s.challenge == 0 {
		s.challenge = challenge
	}
}

// Nonces returns the nonce and echo for the next state frame to this side.
func (s *LegSession) Nonces() (nonce, echo uint64) {
	if s.challenge == 0 {
		s.challenge = NewLegNonce()
	}
	return s.challenge, s.peerNonce
}

// Observe handles an authenticated state frame from from. accepted reports
// that the frame is trusted and the session now points at from. reply asks
// the caller to answer at once: with a challenge when the frame was not
// trusted, or with the echo of the other side's nonce when the frame just
// admitted it, since it may be waiting to admit this side too.
//
// The challenge changes whenever a trusted frame echoes it, so no frame that
// was ever trusted carries the current challenge: replayed from anywhere, it
// is refused.
func (s *LegSession) Observe(epoch, counter uint64, state LegState, from netip.AddrPort, now time.Time, timeout time.Duration) (accepted, reply bool) {
	if s.challenge == 0 {
		s.challenge = NewLegNonce()
	}
	s.peerNonce = state.Nonce
	live := s.valid && now.Sub(s.lastSeen) <= timeout
	newer := epoch > s.epoch || (epoch == s.epoch && counter > s.counter)
	echoed := state.Echo != 0 && state.Echo == s.challenge
	switch {
	case live && from == s.addr && newer:
	case echoed:
		reply = true
	default:
		if now.Sub(s.lastReply) < legChallengeReplyInterval {
			return false, false
		}
		s.lastReply = now
		return false, true
	}
	if echoed {
		s.challenge = NewLegNonce()
	}
	s.addr, s.epoch, s.counter, s.lastSeen, s.valid = from, epoch, counter, now, true
	return true, reply
}

// Live reports whether a trusted frame arrived within timeout of now.
func (s *LegSession) Live(now time.Time, timeout time.Duration) bool {
	return s.valid && now.Sub(s.lastSeen) <= timeout
}

// Addr returns the address of the last trusted frame.
func (s *LegSession) Addr() (netip.AddrPort, bool) {
	return s.addr, s.valid
}

// LastSeen returns when the last trusted frame arrived.
func (s *LegSession) LastSeen() time.Time {
	return s.lastSeen
}
