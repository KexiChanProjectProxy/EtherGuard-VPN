// SPDX-License-Identifier: MIT
package faketcp

import (
	"encoding/binary"
	"net"
)

const (
	IPv4HeaderLen = 20
	IPv6HeaderLen = 40
	TCPHeaderLen  = 20
	MaxPacketLen  = 1500
)

// TCP flags
const (
	FIN uint8 = 1 << 0
	SYN uint8 = 1 << 1
	RST uint8 = 1 << 2
	PSH uint8 = 1 << 3
	ACK uint8 = 1 << 4
	URG uint8 = 1 << 5
)

// TCPPacket represents a parsed TCP packet
type TCPPacket struct {
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Seq         uint32
	Ack         uint32
	Flags       uint8
	Window      uint16
	Payload     []byte
	IsIPv6      bool
}

// BuildTCPPacket builds a complete TCP/IP packet
func BuildTCPPacket(localAddr, remoteAddr *net.UDPAddr, seq, ack uint32, flags uint8, payload []byte) []byte {
	isIPv6 := localAddr.IP.To4() == nil

	var ipHeaderLen int
	if isIPv6 {
		ipHeaderLen = IPv6HeaderLen
	} else {
		ipHeaderLen = IPv4HeaderLen
	}

	// Determine if we need TCP options (window scale for SYN packets)
	wscale := (flags & SYN) != 0
	tcpHeaderLen := TCPHeaderLen
	if wscale {
		tcpHeaderLen += 4 // NOP + WScale option
	}

	tcpTotalLen := tcpHeaderLen + len(payload)
	totalLen := ipHeaderLen + tcpTotalLen
	buf := make([]byte, totalLen)

	ipBuf := buf[:ipHeaderLen]
	tcpBuf := buf[ipHeaderLen:]

	// Build IP header
	if isIPv6 {
		buildIPv6Header(ipBuf, localAddr.IP, remoteAddr.IP, tcpTotalLen)
	} else {
		buildIPv4Header(ipBuf, localAddr.IP, remoteAddr.IP, totalLen)
	}

	// Build TCP header
	buildTCPHeader(tcpBuf, localAddr.Port, remoteAddr.Port, seq, ack, flags, tcpHeaderLen, payload, wscale)

	// Calculate TCP checksum
	pseudoHeader := buildPseudoHeader(localAddr.IP, remoteAddr.IP, tcpTotalLen)
	checksum := calculateChecksum(pseudoHeader, tcpBuf)
	binary.BigEndian.PutUint16(tcpBuf[16:18], checksum)

	return buf
}

// ParseTCPPacket parses a TCP/IP packet from the TUN device
func ParseTCPPacket(buf []byte) *TCPPacket {
	if len(buf) < IPv4HeaderLen {
		return nil
	}

	version := buf[0] >> 4
	var pkt TCPPacket

	var tcpStart int
	var proto uint8

	if version == 4 {
		if len(buf) < IPv4HeaderLen {
			return nil
		}
		pkt.IsIPv6 = false
		pkt.SrcIP = net.IP(buf[12:16])
		pkt.DstIP = net.IP(buf[16:20])
		proto = buf[9]
		tcpStart = IPv4HeaderLen
	} else if version == 6 {
		if len(buf) < IPv6HeaderLen {
			return nil
		}
		pkt.IsIPv6 = true
		pkt.SrcIP = net.IP(buf[8:24])
		pkt.DstIP = net.IP(buf[24:40])
		proto = buf[6]
		tcpStart = IPv6HeaderLen
	} else {
		return nil
	}

	// Check if it's TCP
	if proto != 6 { // 6 = TCP
		return nil
	}

	if len(buf) < tcpStart+TCPHeaderLen {
		return nil
	}

	tcpBuf := buf[tcpStart:]
	pkt.SrcPort = binary.BigEndian.Uint16(tcpBuf[0:2])
	pkt.DstPort = binary.BigEndian.Uint16(tcpBuf[2:4])
	pkt.Seq = binary.BigEndian.Uint32(tcpBuf[4:8])
	pkt.Ack = binary.BigEndian.Uint32(tcpBuf[8:12])

	dataOffset := (tcpBuf[12] >> 4) * 4
	pkt.Flags = tcpBuf[13]
	pkt.Window = binary.BigEndian.Uint16(tcpBuf[14:16])

	if int(dataOffset) < len(tcpBuf) {
		pkt.Payload = tcpBuf[dataOffset:]
	}

	return &pkt
}

// buildIPv4Header builds an IPv4 header
func buildIPv4Header(buf []byte, srcIP, dstIP net.IP, totalLen int) {
	srcIP4 := srcIP.To4()
	dstIP4 := dstIP.To4()

	buf[0] = 0x45 // Version 4, header length 5 (20 bytes)
	buf[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], 0) // ID
	binary.BigEndian.PutUint16(buf[6:8], 0x4000) // Flags: Don't Fragment
	buf[8] = 64   // TTL
	buf[9] = 6    // Protocol: TCP
	binary.BigEndian.PutUint16(buf[10:12], 0) // Checksum (calculated later)
	copy(buf[12:16], srcIP4)
	copy(buf[16:20], dstIP4)

	// Calculate IPv4 header checksum
	checksum := calculateChecksumSimple(buf[:IPv4HeaderLen])
	binary.BigEndian.PutUint16(buf[10:12], checksum)
}

// buildIPv6Header builds an IPv6 header
func buildIPv6Header(buf []byte, srcIP, dstIP net.IP, payloadLen int) {
	buf[0] = 0x60 // Version 6
	buf[1] = 0    // Traffic class
	buf[2] = 0    // Flow label
	buf[3] = 0    // Flow label
	binary.BigEndian.PutUint16(buf[4:6], uint16(payloadLen))
	buf[6] = 6    // Next header: TCP
	buf[7] = 64   // Hop limit
	copy(buf[8:24], srcIP.To16())
	copy(buf[24:40], dstIP.To16())
}

// buildTCPHeader builds a TCP header
func buildTCPHeader(buf []byte, srcPort, dstPort int, seq, ack uint32, flags uint8, headerLen int, payload []byte, wscale bool) {
	binary.BigEndian.PutUint16(buf[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(buf[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ack)
	buf[12] = uint8(headerLen / 4) << 4 // Data offset
	buf[13] = flags
	binary.BigEndian.PutUint16(buf[14:16], 0xffff) // Window size
	binary.BigEndian.PutUint16(buf[16:18], 0)      // Checksum (calculated later)
	binary.BigEndian.PutUint16(buf[18:20], 0)      // Urgent pointer

	// Add TCP options if needed
	if wscale {
		buf[20] = 1  // NOP
		buf[21] = 3  // Window Scale option kind
		buf[22] = 3  // Window Scale option length
		buf[23] = 14 // Window Scale value (14)
	}

	// Copy payload
	if len(payload) > 0 {
		copy(buf[headerLen:], payload)
	}
}

// buildPseudoHeader builds the pseudo header for TCP checksum calculation
func buildPseudoHeader(srcIP, dstIP net.IP, tcpLen int) []byte {
	if srcIP.To4() != nil {
		// IPv4 pseudo header
		pseudo := make([]byte, 12)
		copy(pseudo[0:4], srcIP.To4())
		copy(pseudo[4:8], dstIP.To4())
		pseudo[8] = 0
		pseudo[9] = 6 // TCP protocol
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen))
		return pseudo
	} else {
		// IPv6 pseudo header
		pseudo := make([]byte, 40)
		copy(pseudo[0:16], srcIP.To16())
		copy(pseudo[16:32], dstIP.To16())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(tcpLen))
		pseudo[36] = 0
		pseudo[37] = 0
		pseudo[38] = 0
		pseudo[39] = 6 // TCP protocol
		return pseudo
	}
}

// calculateChecksum calculates the TCP checksum with pseudo header
func calculateChecksum(pseudoHeader, tcpSegment []byte) uint16 {
	sum := uint32(0)

	// Add pseudo header
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}

	// Add TCP segment (excluding checksum field which is already 0)
	for i := 0; i < len(tcpSegment)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSegment[i : i+2]))
	}

	// Handle odd length
	if len(tcpSegment)%2 == 1 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// calculateChecksumSimple calculates a simple checksum (for IP header)
func calculateChecksumSimple(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
