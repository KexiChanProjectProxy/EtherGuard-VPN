/* SPDX-License-Identifier: MIT */

package conn

import (
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
// State frames are the only control message. An agent sends its uplink list
// in every state frame; the controller (agentID 0) sends an empty one. Each
// side sends them every LegHeartbeatInterval to every address it knows for the
// other side, so either side alone may know the other's address: the receiver
// learns the sender's address from authenticated state frames that are newer
// than the last one it accepted (epoch, then counter). That tolerates one-way
// reachability through NAT or firewalls on the site network, and keeps such
// mappings open.

const (
	LegFrameVersion      = 1
	LegFrameData    byte = 1
	LegFrameState   byte = 2

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

// AppendLegState encodes legs as a state frame body.
func AppendLegState(dst []byte, legs []LegInfo) []byte {
	if len(legs) > MaxLegsPerAgent {
		legs = legs[:MaxLegsPerAgent]
	}
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
func ParseLegState(body []byte) ([]LegInfo, error) {
	if len(body) < 1 {
		return nil, ErrLegFrameBody
	}
	count := int(body[0])
	if count > MaxLegsPerAgent {
		return nil, ErrLegFrameBody
	}
	body = body[1:]
	legs := make([]LegInfo, 0, count)
	for i := 0; i < count; i++ {
		if len(body) < 1+16+2+1 {
			return nil, ErrLegFrameBody
		}
		var addr [16]byte
		copy(addr[:], body[1:17])
		port := binary.BigEndian.Uint16(body[17:19])
		nameLen := int(body[19])
		if nameLen > maxLegNameLen || len(body) < 20+nameLen {
			return nil, ErrLegFrameBody
		}
		legs = append(legs, LegInfo{
			LegID: body[0],
			Name:  string(body[20 : 20+nameLen]),
			Addr:  netip.AddrPortFrom(netip.AddrFrom16(addr).Unmap(), port),
		})
		body = body[20+nameLen:]
	}
	if len(body) != 0 {
		return nil, ErrLegFrameBody
	}
	return legs, nil
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

// LegReplayGuard accepts state frames only in increasing (epoch, counter)
// order. A side that has been silent for longer than the timeout may come
// back with any epoch, so a sender whose clock went backwards recovers after
// one timeout.
type LegReplayGuard struct {
	epoch    uint64
	counter  uint64
	lastSeen time.Time
	valid    bool
}

// Accept reports whether a frame numbered (epoch, counter) is fresh at now
// and, if so, records it.
func (g *LegReplayGuard) Accept(epoch uint64, counter uint64, now time.Time, timeout time.Duration) bool {
	stale := !g.valid || now.Sub(g.lastSeen) > timeout
	if !stale && (epoch < g.epoch || (epoch == g.epoch && counter <= g.counter)) {
		return false
	}
	g.epoch, g.counter, g.lastSeen, g.valid = epoch, counter, now, true
	return true
}

// LastSeen returns when the last fresh frame arrived.
func (g *LegReplayGuard) LastSeen() (time.Time, bool) {
	return g.lastSeen, g.valid
}
