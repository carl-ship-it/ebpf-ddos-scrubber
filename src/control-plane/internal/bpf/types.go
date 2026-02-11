// Package bpf provides Go equivalents of the BPF C types defined in types.h.
package bpf

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Verdict constants (matching types.h)
const (
	VerdictPass  = 0
	VerdictDrop  = 1
	VerdictTX    = 2
	VerdictRedir = 3
)

// Attack type IDs (matching types.h)
const (
	AttackNone         = 0
	AttackSYNFlood     = 1
	AttackUDPFlood     = 2
	AttackICMPFlood    = 3
	AttackACKFlood     = 4
	AttackDNSAmp       = 5
	AttackNTPAmp       = 6
	AttackSSDPAmp      = 7
	AttackMemcachedAmp = 8
	AttackFragment     = 9
	AttackRSTFlood     = 10
)

// Drop reason codes (matching types.h)
const (
	DropBlacklist   = 1
	DropRateLimit   = 2
	DropSYNFlood    = 3
	DropUDPFlood    = 4
	DropICMPFlood   = 5
	DropACKInvalid  = 6
	DropDNSAmp      = 7
	DropNTPAmp      = 8
	DropFragment    = 9
	DropParseError  = 10
	DropFingerprint = 11
)

// Config keys (matching types.h CFG_* constants)
const (
	CfgEnabled          = 0
	CfgSYNRatePPS       = 1
	CfgUDPRatePPS       = 2
	CfgICMPRatePPS      = 3
	CfgGlobalPPSLimit   = 4
	CfgGlobalBPSLimit   = 5
	CfgSYNCookieEnable  = 6
	CfgConntrackEnable  = 7
	CfgBaselinePPS      = 8
	CfgBaselineBPS      = 9
	CfgAttackThreshold  = 10
	CfgGeoIPEnable      = 11
	CfgReputationEnable = 12
	CfgReputationThresh = 13
	CfgProtoValidEnable = 14
	CfgPayloadMatchEn   = 15
	CfgEscalationLevel  = 16
	CfgThreatIntelEn    = 17
	CfgDNSValidMode     = 18
	CfgTCPStateEnable   = 19
	CfgAdaptiveRate     = 20
	CfgMax              = 64
)

// ConntrackKey matches struct conntrack_key in types.h.
type ConntrackKey struct {
	SrcIP    uint32 // __be32
	DstIP    uint32 // __be32
	SrcPort  uint16 // __be16
	DstPort  uint16 // __be16
	Protocol uint8
	Pad      [3]uint8
}

// ConntrackEntry matches struct conntrack_entry in types.h.
type ConntrackEntry struct {
	LastSeenNS uint64
	PacketsFwd uint32
	PacketsRev uint32
	BytesFwd   uint64
	BytesRev   uint64
	State      uint8
	Flags      uint8
	Pad        [6]uint8
}

// GlobalStats matches struct global_stats in types.h (per-CPU).
type GlobalStats struct {
	RxPackets            uint64
	RxBytes              uint64
	TxPackets            uint64
	TxBytes              uint64
	DroppedPackets       uint64
	DroppedBytes         uint64
	SYNFloodDropped      uint64
	UDPFloodDropped      uint64
	ICMPFloodDropped     uint64
	ACKFloodDropped      uint64
	DNSAmpDropped        uint64
	NTPAmpDropped        uint64
	FragmentDropped      uint64
	ACLDropped           uint64
	RateLimited          uint64
	ConntrackNew         uint64
	ConntrackEstablished uint64
	SYNCookiesSent       uint64
	SYNCookiesValidated  uint64
	SYNCookiesFailed     uint64
}

// Event matches struct event in types.h (ring buffer events).
type Event struct {
	TimestampNS uint64
	SrcIP       uint32 // __be32
	DstIP       uint32 // __be32
	SrcPort     uint16 // __be16
	DstPort     uint16 // __be16
	Protocol    uint8
	AttackType  uint8
	Action      uint8
	DropReason  uint8
	PPSEstimate uint64
	BPSEstimate uint64
}

// LPMKeyV4 matches struct lpm_key_v4 in types.h.
type LPMKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // __be32
}

// SYNCookieCtx matches struct syn_cookie_ctx in types.h.
type SYNCookieCtx struct {
	SeedCurrent  uint32
	SeedPrevious uint32
	SeedUpdateNS uint64
}

// AttackSig matches struct attack_sig in types.h.
type AttackSig struct {
	Protocol    uint8
	FlagsMask   uint8
	FlagsMatch  uint8
	Pad         uint8
	SrcPortMin  uint16 // __be16
	SrcPortMax  uint16 // __be16
	DstPortMin  uint16 // __be16
	DstPortMax  uint16 // __be16
	PktLenMin   uint16
	PktLenMax   uint16
	PayloadHash uint32
}

// RateLimiter matches struct rate_limiter in types.h.
type RateLimiter struct {
	Tokens         uint64
	LastRefillNS   uint64
	RatePPS        uint64
	BurstSize      uint64
	TotalPackets   uint64
	DroppedPackets uint64
}

// Helper functions

// IPToU32BE converts a net.IP to big-endian uint32.
func IPToU32BE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// U32BEToIP converts a big-endian uint32 to net.IP.
func U32BEToIP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

// FormatEvent returns a human-readable string for an Event.
func FormatEvent(e *Event) string {
	srcIP := U32BEToIP(e.SrcIP)
	dstIP := U32BEToIP(e.DstIP)
	srcPort := (e.SrcPort>>8) | (e.SrcPort<<8)
	dstPort := (e.DstPort>>8) | (e.DstPort<<8)

	action := "PASS"
	if e.Action == 1 {
		action = "DROP"
	}

	return fmt.Sprintf("[%s] %s:%d → %s:%d proto=%d attack=%d reason=%d",
		action, srcIP, srcPort, dstIP, dstPort,
		e.Protocol, e.AttackType, e.DropReason)
}

// AttackTypeName returns the human-readable name of an attack type.
func AttackTypeName(t uint8) string {
	switch t {
	case AttackNone:
		return "none"
	case AttackSYNFlood:
		return "syn_flood"
	case AttackUDPFlood:
		return "udp_flood"
	case AttackICMPFlood:
		return "icmp_flood"
	case AttackACKFlood:
		return "ack_flood"
	case AttackDNSAmp:
		return "dns_amplification"
	case AttackNTPAmp:
		return "ntp_amplification"
	case AttackSSDPAmp:
		return "ssdp_amplification"
	case AttackMemcachedAmp:
		return "memcached_amplification"
	case AttackFragment:
		return "fragment"
	case AttackRSTFlood:
		return "rst_flood"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// DropReasonName returns the human-readable name of a drop reason.
func DropReasonName(r uint8) string {
	switch r {
	case DropBlacklist:
		return "blacklist"
	case DropRateLimit:
		return "rate_limit"
	case DropSYNFlood:
		return "syn_flood"
	case DropUDPFlood:
		return "udp_flood"
	case DropICMPFlood:
		return "icmp_flood"
	case DropACKInvalid:
		return "ack_invalid"
	case DropDNSAmp:
		return "dns_amp"
	case DropNTPAmp:
		return "ntp_amp"
	case DropFragment:
		return "fragment"
	case DropParseError:
		return "parse_error"
	case DropFingerprint:
		return "fingerprint"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}
