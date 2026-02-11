package stats

import (
	"testing"
	"time"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
)

func TestSnapshotRateCalculation(t *testing.T) {
	// Simulate two snapshots 1 second apart
	prev := &Snapshot{
		Timestamp: time.Now(),
		Stats: bpf.GlobalStats{
			RxPackets:      1000,
			RxBytes:        1500000,
			TxPackets:      900,
			TxBytes:        1350000,
			DroppedPackets: 100,
			DroppedBytes:   150000,
		},
	}

	curr := &Snapshot{
		Timestamp: prev.Timestamp.Add(time.Second),
		Stats: bpf.GlobalStats{
			RxPackets:      2000,
			RxBytes:        3000000,
			TxPackets:      1800,
			TxBytes:        2700000,
			DroppedPackets: 200,
			DroppedBytes:   300000,
		},
	}

	// Calculate rates
	dt := curr.Timestamp.Sub(prev.Timestamp).Seconds()
	curr.RxPPS = float64(curr.Stats.RxPackets-prev.Stats.RxPackets) / dt
	curr.RxBPS = float64(curr.Stats.RxBytes-prev.Stats.RxBytes) * 8 / dt
	curr.TxPPS = float64(curr.Stats.TxPackets-prev.Stats.TxPackets) / dt
	curr.TxBPS = float64(curr.Stats.TxBytes-prev.Stats.TxBytes) * 8 / dt
	curr.DropPPS = float64(curr.Stats.DroppedPackets-prev.Stats.DroppedPackets) / dt
	curr.DropBPS = float64(curr.Stats.DroppedBytes-prev.Stats.DroppedBytes) * 8 / dt

	// Verify
	assertFloat(t, "RxPPS", curr.RxPPS, 1000.0)
	assertFloat(t, "RxBPS", curr.RxBPS, 12000000.0) // 1.5MB * 8
	assertFloat(t, "TxPPS", curr.TxPPS, 900.0)
	assertFloat(t, "DropPPS", curr.DropPPS, 100.0)
}

func TestSnapshotZeroDelta(t *testing.T) {
	now := time.Now()
	prev := &Snapshot{Timestamp: now, Stats: bpf.GlobalStats{RxPackets: 100}}
	curr := &Snapshot{Timestamp: now, Stats: bpf.GlobalStats{RxPackets: 200}}

	dt := curr.Timestamp.Sub(prev.Timestamp).Seconds()
	if dt != 0 {
		t.Errorf("expected zero delta, got %f", dt)
	}
	// Rates should remain zero when dt=0
	if curr.RxPPS != 0 {
		t.Errorf("RxPPS should be 0 when dt=0, got %f", curr.RxPPS)
	}
}

func TestSubscriberChannel(t *testing.T) {
	c := &Collector{
		subs: make([]chan<- *Snapshot, 0),
	}

	ch := c.Subscribe(10)

	snap := &Snapshot{
		Timestamp: time.Now(),
		RxPPS:     5000,
	}

	// Simulate notify
	c.subsMu.RLock()
	for _, sub := range c.subs {
		select {
		case sub <- snap:
		default:
		}
	}
	c.subsMu.RUnlock()

	select {
	case got := <-ch:
		if got.RxPPS != 5000 {
			t.Errorf("subscriber got RxPPS=%f, want 5000", got.RxPPS)
		}
	case <-time.After(time.Second):
		t.Error("subscriber did not receive snapshot")
	}
}

func TestCurrentReturnsLatest(t *testing.T) {
	c := &Collector{}

	if c.Current() != nil {
		t.Error("Current() should be nil before any collection")
	}

	s1 := &Snapshot{RxPPS: 100}
	s2 := &Snapshot{RxPPS: 200}

	c.mu.Lock()
	c.current = s1
	c.mu.Unlock()

	if c.Current().RxPPS != 100 {
		t.Error("Current() should return s1")
	}

	c.mu.Lock()
	c.previous = s1
	c.current = s2
	c.mu.Unlock()

	if c.Current().RxPPS != 200 {
		t.Error("Current() should return s2")
	}
	if c.Previous().RxPPS != 100 {
		t.Error("Previous() should return s1")
	}
}

func assertFloat(t *testing.T, name string, got, want float64) {
	t.Helper()
	epsilon := want * 0.001 // 0.1% tolerance
	if epsilon < 0.01 {
		epsilon = 0.01
	}
	diff := got - want
	if diff < 0 {
		diff = -diff
	}
	if diff > epsilon {
		t.Errorf("%s = %f, want %f (diff=%f)", name, got, want, diff)
	}
}
