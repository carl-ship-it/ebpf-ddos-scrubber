// Go control plane benchmark tests.
// Run: go test -bench=. -benchmem ./tests/performance/

package performance

import (
	"net"
	"testing"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
)

// Benchmark IP conversion functions.

func BenchmarkIPToU32BE(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bpf.IPToU32BE(ip)
	}
}

func BenchmarkU32BEToIP(b *testing.B) {
	addr := uint32(0xc0a80101)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bpf.U32BEToIP(addr)
	}
}

func BenchmarkIPRoundTrip(b *testing.B) {
	ip := net.ParseIP("10.0.0.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u := bpf.IPToU32BE(ip)
		_ = bpf.U32BEToIP(u)
	}
}

// Benchmark name lookups.

func BenchmarkAttackTypeName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = bpf.AttackTypeName(uint8(i % 11))
	}
}

func BenchmarkDropReasonName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = bpf.DropReasonName(uint8(i%11 + 1))
	}
}

// Benchmark event formatting.

func BenchmarkFormatEvent(b *testing.B) {
	event := &bpf.Event{
		SrcIP:      0x0a000001,
		DstIP:      0xc0a80101,
		SrcPort:    0x3930,
		DstPort:    0x5000,
		Protocol:   6,
		AttackType: bpf.AttackSYNFlood,
		Action:     1,
		DropReason: bpf.DropSYNFlood,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bpf.FormatEvent(event)
	}
}

// Benchmark event parsing (simulating ring buffer read).

func BenchmarkParseEventData(b *testing.B) {
	// 40-byte event payload
	data := make([]byte, 40)
	data[20] = 6 // protocol
	data[21] = 1 // attack type
	data[22] = 1 // action

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate minimal event parsing
		_ = bpf.Event{
			Protocol:   data[20],
			AttackType: data[21],
			Action:     data[22],
		}
	}
}
