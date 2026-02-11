// Package stats collects and exposes BPF statistics.
package stats

import (
	"context"
	"sync"
	"time"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
	"go.uber.org/zap"
)

// Snapshot represents a point-in-time statistics snapshot with computed rates.
type Snapshot struct {
	Timestamp time.Time

	// Counters (cumulative)
	Stats bpf.GlobalStats

	// Rates (computed from delta between snapshots)
	RxPPS      float64
	RxBPS      float64
	TxPPS      float64
	TxBPS      float64
	DropPPS    float64
	DropBPS    float64

	// Attack rates
	SYNFloodPPS  float64
	UDPFloodPPS  float64
	ICMPFloodPPS float64
	ACKFloodPPS  float64
}

// Collector periodically reads BPF stats and computes rates.
type Collector struct {
	log      *zap.Logger
	maps     *bpf.MapManager
	interval time.Duration

	mu       sync.RWMutex
	current  *Snapshot
	previous *Snapshot

	// Subscribers receive snapshot updates
	subs   []chan<- *Snapshot
	subsMu sync.RWMutex
}

// NewCollector creates a stats collector with the given poll interval.
func NewCollector(log *zap.Logger, maps *bpf.MapManager, interval time.Duration) *Collector {
	return &Collector{
		log:      log,
		maps:     maps,
		interval: interval,
	}
}

// Subscribe returns a channel that receives stats snapshots.
func (c *Collector) Subscribe(bufSize int) <-chan *Snapshot {
	ch := make(chan *Snapshot, bufSize)
	c.subsMu.Lock()
	c.subs = append(c.subs, ch)
	c.subsMu.Unlock()
	return ch
}

// Run starts the collection loop. Blocks until context is cancelled.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.log.Info("stats collector started", zap.Duration("interval", c.interval))

	for {
		select {
		case <-ctx.Done():
			c.log.Info("stats collector stopped")
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) collect() {
	raw, err := c.maps.ReadStats()
	if err != nil {
		c.log.Warn("failed to read stats", zap.Error(err))
		return
	}

	now := time.Now()
	snap := &Snapshot{
		Timestamp: now,
		Stats:     *raw,
	}

	c.mu.Lock()
	prev := c.current
	c.previous = prev
	c.current = snap
	c.mu.Unlock()

	// Compute rates if we have a previous snapshot
	if prev != nil {
		dt := snap.Timestamp.Sub(prev.Timestamp).Seconds()
		if dt > 0 {
			snap.RxPPS = float64(snap.Stats.RxPackets-prev.Stats.RxPackets) / dt
			snap.RxBPS = float64(snap.Stats.RxBytes-prev.Stats.RxBytes) * 8 / dt
			snap.TxPPS = float64(snap.Stats.TxPackets-prev.Stats.TxPackets) / dt
			snap.TxBPS = float64(snap.Stats.TxBytes-prev.Stats.TxBytes) * 8 / dt
			snap.DropPPS = float64(snap.Stats.DroppedPackets-prev.Stats.DroppedPackets) / dt
			snap.DropBPS = float64(snap.Stats.DroppedBytes-prev.Stats.DroppedBytes) * 8 / dt
			snap.SYNFloodPPS = float64(snap.Stats.SYNFloodDropped-prev.Stats.SYNFloodDropped) / dt
			snap.UDPFloodPPS = float64(snap.Stats.UDPFloodDropped-prev.Stats.UDPFloodDropped) / dt
			snap.ICMPFloodPPS = float64(snap.Stats.ICMPFloodDropped-prev.Stats.ICMPFloodDropped) / dt
			snap.ACKFloodPPS = float64(snap.Stats.ACKFloodDropped-prev.Stats.ACKFloodDropped) / dt
		}
	}

	// Notify subscribers
	c.subsMu.RLock()
	for _, ch := range c.subs {
		select {
		case ch <- snap:
		default:
			// Drop if subscriber is slow
		}
	}
	c.subsMu.RUnlock()
}

// Current returns the most recent stats snapshot.
func (c *Collector) Current() *Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}

// Previous returns the previous stats snapshot (for delta calculations).
func (c *Collector) Previous() *Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.previous
}
