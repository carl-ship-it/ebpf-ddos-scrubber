package events

import (
	"encoding/binary"
	"testing"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
)

func TestParseEvent(t *testing.T) {
	// Build a 40-byte event matching struct event layout
	data := make([]byte, 40)

	// timestamp_ns = 1000000000 (1 second)
	binary.LittleEndian.PutUint64(data[0:8], 1000000000)
	// src_ip = 10.0.0.1 (0x0a000001 in little-endian memory)
	binary.LittleEndian.PutUint32(data[8:12], 0x0100000a)
	// dst_ip = 192.168.1.1
	binary.LittleEndian.PutUint32(data[12:16], 0x0101a8c0)
	// src_port = 12345
	binary.LittleEndian.PutUint16(data[16:18], 12345)
	// dst_port = 80
	binary.LittleEndian.PutUint16(data[18:20], 80)
	// protocol = 6 (TCP)
	data[20] = 6
	// attack_type = 1 (SYN flood)
	data[21] = 1
	// action = 1 (drop)
	data[22] = 1
	// drop_reason = 3 (SYN flood)
	data[23] = 3
	// pps_estimate
	binary.LittleEndian.PutUint64(data[24:32], 50000)
	// bps_estimate
	binary.LittleEndian.PutUint64(data[32:40], 100000000)

	event, err := parseEvent(data)
	if err != nil {
		t.Fatalf("parseEvent() error: %v", err)
	}

	if event.TimestampNS != 1000000000 {
		t.Errorf("TimestampNS = %d, want 1000000000", event.TimestampNS)
	}
	if event.Protocol != 6 {
		t.Errorf("Protocol = %d, want 6", event.Protocol)
	}
	if event.AttackType != bpf.AttackSYNFlood {
		t.Errorf("AttackType = %d, want %d", event.AttackType, bpf.AttackSYNFlood)
	}
	if event.Action != 1 {
		t.Errorf("Action = %d, want 1", event.Action)
	}
	if event.DropReason != bpf.DropSYNFlood {
		t.Errorf("DropReason = %d, want %d", event.DropReason, bpf.DropSYNFlood)
	}
	if event.PPSEstimate != 50000 {
		t.Errorf("PPSEstimate = %d, want 50000", event.PPSEstimate)
	}
	if event.BPSEstimate != 100000000 {
		t.Errorf("BPSEstimate = %d, want 100000000", event.BPSEstimate)
	}
}

func TestParseEventTooShort(t *testing.T) {
	data := make([]byte, 10)
	_, err := parseEvent(data)
	if err == nil {
		t.Error("expected error for short data")
	}
}

func TestParseEventExactSize(t *testing.T) {
	data := make([]byte, 40)
	event, err := parseEvent(data)
	if err != nil {
		t.Fatalf("parseEvent() error: %v", err)
	}
	if event.TimestampNS != 0 {
		t.Errorf("zero data: TimestampNS = %d, want 0", event.TimestampNS)
	}
}

func TestHandlerDispatch(t *testing.T) {
	r := &Reader{}

	var received *bpf.Event
	r.OnEvent(func(e *bpf.Event) {
		received = e
	})

	event := &bpf.Event{
		Protocol:   17,
		AttackType: bpf.AttackUDPFlood,
		Action:     1,
	}

	r.dispatch(event)

	if received == nil {
		t.Fatal("handler was not called")
	}
	if received.Protocol != 17 {
		t.Errorf("Protocol = %d, want 17", received.Protocol)
	}
	if received.AttackType != bpf.AttackUDPFlood {
		t.Errorf("AttackType = %d, want %d", received.AttackType, bpf.AttackUDPFlood)
	}
}

func TestMultipleHandlers(t *testing.T) {
	r := &Reader{}

	count := 0
	for i := 0; i < 5; i++ {
		r.OnEvent(func(e *bpf.Event) {
			count++
		})
	}

	r.dispatch(&bpf.Event{})

	if count != 5 {
		t.Errorf("handler call count = %d, want 5", count)
	}
}
