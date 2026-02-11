// Package reputation provides an IP reputation engine that reads the BPF
// reputation_map periodically, applies time-based decay, auto-blocks IPs
// exceeding the configured threshold, and auto-unblocks decayed IPs.
package reputation

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Default tuning parameters.
const (
	defaultPollInterval = 5 * time.Second
	defaultDecayRate    = uint32(5)  // Score points to decay per poll interval.
	defaultThreshold    = uint32(500) // Score at which auto-block triggers.
	unblockRatio        = 2           // Unblock when score < threshold / unblockRatio.
)

// ipReputation matches struct ip_reputation in types.h (BPF map value).
type ipReputation struct {
	Score          uint32
	TotalPackets   uint32
	DroppedPackets uint32
	ViolationCount uint32
	FirstSeenNS    uint64
	LastSeenNS     uint64
	LastDecayNS    uint64
	DistinctPorts  uint16
	Blocked        uint8
	Flags          uint8
}

// lpmKeyV4 matches struct lpm_key_v4 in the BPF program.
type lpmKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // __be32
}

// IPReputation is the userspace representation of an IP's reputation state.
type IPReputation struct {
	IP          string
	Score       uint32
	TotalPkts   uint32
	DroppedPkts uint32
	Blocked     bool
	FirstSeen   time.Time
	LastSeen    time.Time
}

// Engine manages IP reputation scoring from userspace.
// It reads reputation_map from BPF periodically, handles decay, and auto-blocks.
type Engine struct {
	log            *zap.Logger
	reputationMap  *ebpf.Map
	blacklistMap   *ebpf.Map
	configMap      *ebpf.Map

	mu             sync.RWMutex
	threshold      uint32
	decayRate      uint32
	reputations    map[uint32]*IPReputation // key: __be32 IP
	blocked        map[uint32]bool          // IPs currently auto-blocked
	manualBlocked  map[uint32]bool          // IPs manually blocked (never auto-unblocked)
}

// NewEngine creates a new reputation engine.
func NewEngine(log *zap.Logger, reputationMap, blacklistMap, configMap *ebpf.Map) *Engine {
	return &Engine{
		log:           log,
		reputationMap: reputationMap,
		blacklistMap:  blacklistMap,
		configMap:     configMap,
		threshold:     defaultThreshold,
		decayRate:     defaultDecayRate,
		reputations:   make(map[uint32]*IPReputation),
		blocked:       make(map[uint32]bool),
		manualBlocked: make(map[uint32]bool),
	}
}

// Start begins the background reputation management loop.
// It runs every 5 seconds until the context is cancelled.
func (e *Engine) Start(ctx context.Context) error {
	// Read threshold from config map if available.
	e.loadThresholdFromConfig()

	go e.run(ctx)

	e.log.Info("reputation engine started",
		zap.Uint32("threshold", e.threshold),
		zap.Uint32("decay_rate", e.decayRate),
	)
	return nil
}

func (e *Engine) run(ctx context.Context) {
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.log.Info("reputation engine stopped")
			return
		case <-ticker.C:
			e.poll()
		}
	}
}

// poll reads the reputation_map, applies decay, and manages auto-block/unblock.
func (e *Engine) poll() {
	var (
		key   uint32 // __be32 source IP
		value ipReputation
	)

	now := time.Now()
	nowNS := uint64(now.UnixNano())

	e.mu.Lock()
	defer e.mu.Unlock()

	iter := e.reputationMap.Iterate()
	for iter.Next(&key, &value) {
		ipStr := u32BEToIP(key).String()

		// Apply time-based decay.
		if value.Score > 0 && value.Score > e.decayRate {
			value.Score -= e.decayRate
		} else if value.Score > 0 {
			value.Score = 0
		}
		value.LastDecayNS = nowNS

		// Write decayed score back to BPF map.
		// We update in place; failures are non-fatal.
		decayed := value
		_ = e.reputationMap.Update(key, decayed, ebpf.UpdateExist)

		// Track in userspace.
		rep, exists := e.reputations[key]
		if !exists {
			rep = &IPReputation{
				IP:        ipStr,
				FirstSeen: nsToTime(value.FirstSeenNS),
			}
			e.reputations[key] = rep
		}
		rep.Score = value.Score
		rep.TotalPkts = value.TotalPackets
		rep.DroppedPkts = value.DroppedPackets
		rep.LastSeen = nsToTime(value.LastSeenNS)
		rep.Blocked = value.Blocked != 0

		// Auto-block: score exceeds threshold and not already blocked.
		if value.Score >= e.threshold && !e.blocked[key] {
			if err := e.addToBlacklist(key); err != nil {
				e.log.Warn("auto-block failed",
					zap.String("ip", ipStr),
					zap.Uint32("score", value.Score),
					zap.Error(err),
				)
			} else {
				e.blocked[key] = true
				rep.Blocked = true

				// Mark as blocked in BPF reputation entry.
				value.Blocked = 1
				_ = e.reputationMap.Update(key, value, ebpf.UpdateExist)

				e.log.Info("ip auto-blocked by reputation",
					zap.String("ip", ipStr),
					zap.Uint32("score", value.Score),
					zap.Uint32("threshold", e.threshold),
				)
			}
		}

		// Auto-unblock: score decayed below threshold/2, was auto-blocked (not manual).
		unblockThreshold := e.threshold / uint32(unblockRatio)
		if value.Score < unblockThreshold && e.blocked[key] && !e.manualBlocked[key] {
			if err := e.removeFromBlacklist(key); err != nil {
				e.log.Warn("auto-unblock failed",
					zap.String("ip", ipStr),
					zap.Uint32("score", value.Score),
					zap.Error(err),
				)
			} else {
				delete(e.blocked, key)
				rep.Blocked = false

				value.Blocked = 0
				_ = e.reputationMap.Update(key, value, ebpf.UpdateExist)

				e.log.Info("ip auto-unblocked by reputation decay",
					zap.String("ip", ipStr),
					zap.Uint32("score", value.Score),
					zap.Uint32("unblock_threshold", unblockThreshold),
				)
			}
		}
	}

	if err := iter.Err(); err != nil {
		e.log.Debug("reputation map iteration error", zap.Error(err))
	}
}

// GetTopOffenders returns the top N IPs by reputation score.
func (e *Engine) GetTopOffenders(n int) []IPReputation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	all := make([]IPReputation, 0, len(e.reputations))
	for _, rep := range e.reputations {
		all = append(all, *rep)
	}

	sort.Slice(all, func(i, j int) bool {
		return all[i].Score > all[j].Score
	})

	if n > len(all) {
		n = len(all)
	}
	return all[:n]
}

// BlockIP manually blocks an IP address. Manual blocks are never auto-unblocked.
func (e *Engine) BlockIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	parsed = parsed.To4()
	if parsed == nil {
		return fmt.Errorf("IPv6 not supported: %s", ip)
	}

	key := binary.BigEndian.Uint32(parsed)

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.addToBlacklist(key); err != nil {
		return fmt.Errorf("blocking %s: %w", ip, err)
	}

	e.blocked[key] = true
	e.manualBlocked[key] = true

	// Update userspace tracking.
	rep, exists := e.reputations[key]
	if !exists {
		rep = &IPReputation{
			IP:        ip,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		e.reputations[key] = rep
	}
	rep.Blocked = true

	e.log.Info("ip manually blocked", zap.String("ip", ip))
	return nil
}

// UnblockIP manually unblocks an IP address.
func (e *Engine) UnblockIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	parsed = parsed.To4()
	if parsed == nil {
		return fmt.Errorf("IPv6 not supported: %s", ip)
	}

	key := binary.BigEndian.Uint32(parsed)

	e.mu.Lock()
	defer e.mu.Unlock()

	if err := e.removeFromBlacklist(key); err != nil {
		return fmt.Errorf("unblocking %s: %w", ip, err)
	}

	delete(e.blocked, key)
	delete(e.manualBlocked, key)

	if rep, exists := e.reputations[key]; exists {
		rep.Blocked = false
	}

	e.log.Info("ip manually unblocked", zap.String("ip", ip))
	return nil
}

// GetBlocked returns all currently blocked IPs (auto + manual).
func (e *Engine) GetBlocked() []IPReputation {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]IPReputation, 0, len(e.blocked))
	for key := range e.blocked {
		if rep, exists := e.reputations[key]; exists {
			result = append(result, *rep)
		} else {
			result = append(result, IPReputation{
				IP:      u32BEToIP(key).String(),
				Blocked: true,
			})
		}
	}
	return result
}

// SetThreshold changes the auto-block threshold. Also updates the BPF config map.
func (e *Engine) SetThreshold(threshold uint32) error {
	e.mu.Lock()
	e.threshold = threshold
	e.mu.Unlock()

	// CFG_REPUTATION_THRESH = 13
	const cfgReputationThresh uint32 = 13
	if err := e.configMap.Update(cfgReputationThresh, uint64(threshold), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating reputation threshold in config map: %w", err)
	}

	e.log.Info("reputation threshold updated", zap.Uint32("threshold", threshold))
	return nil
}

// GetThreshold returns the current auto-block threshold.
func (e *Engine) GetThreshold() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.threshold
}

// GetTrackedCount returns the number of IPs currently tracked.
func (e *Engine) GetTrackedCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.reputations)
}

// --- Internal helpers ---

func (e *Engine) loadThresholdFromConfig() {
	const cfgReputationThresh uint32 = 13
	var val uint64
	if err := e.configMap.Lookup(cfgReputationThresh, &val); err == nil && val > 0 {
		e.mu.Lock()
		e.threshold = uint32(val)
		e.mu.Unlock()
	}
}

func (e *Engine) addToBlacklist(ipBE uint32) error {
	key := lpmKeyV4{
		PrefixLen: 32,
		Addr:      ipBE,
	}
	// Drop reason = DROP_REPUTATION (13 from types.h).
	var reason uint32 = 13
	return e.blacklistMap.Update(key, reason, ebpf.UpdateAny)
}

func (e *Engine) removeFromBlacklist(ipBE uint32) error {
	key := lpmKeyV4{
		PrefixLen: 32,
		Addr:      ipBE,
	}
	return e.blacklistMap.Delete(key)
}

func u32BEToIP(addr uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}

func nsToTime(ns uint64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns))
}

// Compile-time size checks.
var _ [8]byte = [unsafe.Sizeof(lpmKeyV4{})]byte{}
