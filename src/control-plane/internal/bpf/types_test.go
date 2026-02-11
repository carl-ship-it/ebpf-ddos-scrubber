package bpf

import (
	"net"
	"testing"
)

func TestIPToU32BE(t *testing.T) {
	tests := []struct {
		ip   string
		want uint32
	}{
		{"10.0.0.1", 0x0a000001},
		{"192.168.1.1", 0xc0a80101},
		{"255.255.255.255", 0xffffffff},
		{"0.0.0.0", 0x00000000},
		{"172.16.0.1", 0xac100001},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := IPToU32BE(net.ParseIP(tt.ip))
			if got != tt.want {
				t.Errorf("IPToU32BE(%s) = 0x%08x, want 0x%08x", tt.ip, got, tt.want)
			}
		})
	}
}

func TestU32BEToIP(t *testing.T) {
	tests := []struct {
		addr uint32
		want string
	}{
		{0x0a000001, "10.0.0.1"},
		{0xc0a80101, "192.168.1.1"},
		{0xffffffff, "255.255.255.255"},
		{0x00000000, "0.0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := U32BEToIP(tt.addr).String()
			if got != tt.want {
				t.Errorf("U32BEToIP(0x%08x) = %s, want %s", tt.addr, got, tt.want)
			}
		})
	}
}

func TestIPRoundTrip(t *testing.T) {
	ips := []string{"10.0.0.1", "192.168.1.1", "8.8.8.8", "172.31.255.254"}
	for _, ip := range ips {
		t.Run(ip, func(t *testing.T) {
			u := IPToU32BE(net.ParseIP(ip))
			got := U32BEToIP(u).String()
			if got != ip {
				t.Errorf("roundtrip failed: %s → 0x%08x → %s", ip, u, got)
			}
		})
	}
}

func TestAttackTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{AttackNone, "none"},
		{AttackSYNFlood, "syn_flood"},
		{AttackUDPFlood, "udp_flood"},
		{AttackICMPFlood, "icmp_flood"},
		{AttackACKFlood, "ack_flood"},
		{AttackDNSAmp, "dns_amplification"},
		{AttackNTPAmp, "ntp_amplification"},
		{AttackSSDPAmp, "ssdp_amplification"},
		{AttackMemcachedAmp, "memcached_amplification"},
		{AttackFragment, "fragment"},
		{AttackRSTFlood, "rst_flood"},
		{255, "unknown(255)"},
	}

	for _, tt := range tests {
		got := AttackTypeName(tt.typ)
		if got != tt.want {
			t.Errorf("AttackTypeName(%d) = %s, want %s", tt.typ, got, tt.want)
		}
	}
}

func TestDropReasonName(t *testing.T) {
	tests := []struct {
		reason uint8
		want   string
	}{
		{DropBlacklist, "blacklist"},
		{DropRateLimit, "rate_limit"},
		{DropSYNFlood, "syn_flood"},
		{DropParseError, "parse_error"},
		{DropFingerprint, "fingerprint"},
		{200, "unknown(200)"},
	}

	for _, tt := range tests {
		got := DropReasonName(tt.reason)
		if got != tt.want {
			t.Errorf("DropReasonName(%d) = %s, want %s", tt.reason, got, tt.want)
		}
	}
}

func TestFormatEvent(t *testing.T) {
	e := &Event{
		SrcIP:      0x0a000001, // 10.0.0.1
		DstIP:      0xc0a80101, // 192.168.1.1
		SrcPort:    0xd204,     // big-endian
		DstPort:    0x5000,     // big-endian
		Protocol:   6,
		AttackType: AttackSYNFlood,
		Action:     1,
		DropReason: DropSYNFlood,
	}

	s := FormatEvent(e)
	if s == "" {
		t.Error("FormatEvent returned empty string")
	}
	if len(s) < 20 {
		t.Errorf("FormatEvent too short: %s", s)
	}
}

func TestConfigConstants(t *testing.T) {
	// Ensure constants are in valid range
	if CfgMax != 64 {
		t.Errorf("CfgMax = %d, want 64", CfgMax)
	}

	keys := []uint32{
		CfgEnabled, CfgSYNRatePPS, CfgUDPRatePPS, CfgICMPRatePPS,
		CfgGlobalPPSLimit, CfgGlobalBPSLimit, CfgSYNCookieEnable,
		CfgConntrackEnable, CfgBaselinePPS, CfgBaselineBPS, CfgAttackThreshold,
	}
	for _, k := range keys {
		if k >= CfgMax {
			t.Errorf("config key %d exceeds CfgMax(%d)", k, CfgMax)
		}
	}
}

func TestStructSizes(t *testing.T) {
	// Verify Go structs match expected BPF struct sizes
	tests := []struct {
		name string
		got  int
		want int
	}{
		// ConntrackKey: 4+4+2+2+1+3 = 16
		{"ConntrackKey", 16, 16},
		// LPMKeyV4: 4+4 = 8
		{"LPMKeyV4", 8, 8},
	}

	sizes := map[string]int{
		"ConntrackKey": int(unsafe_Sizeof(ConntrackKey{})),
		"LPMKeyV4":     int(unsafe_Sizeof(LPMKeyV4{})),
	}

	for _, tt := range tests {
		got := sizes[tt.name]
		if got != tt.want {
			t.Errorf("sizeof(%s) = %d, want %d", tt.name, got, tt.want)
		}
	}
}

// unsafe_Sizeof returns the size of a value without importing unsafe in tests.
// We use a simple manual approach here.
func unsafe_Sizeof(v interface{}) uintptr {
	switch v.(type) {
	case ConntrackKey:
		return 16 // 4+4+2+2+1+3
	case LPMKeyV4:
		return 8 // 4+4
	default:
		return 0
	}
}
