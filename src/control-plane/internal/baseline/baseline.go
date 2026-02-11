// Package baseline implements EWMA-based traffic baseline learning and
// anomaly detection for the DDoS scrubber control plane.
package baseline

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// EWMA tuning parameters.
const (
	// alpha controls how quickly the EWMA adapts to new values.
	// 0.01 provides a slow-learning ~100 sample effective window.
	alpha = 0.01

	// anomalyZThreshold is the Z-score above which traffic is flagged as anomalous.
	// Z > 3.0 corresponds to 99.7% confidence.
	anomalyZThreshold = 3.0

	// learningPeriod is the number of samples before the baseline becomes operational.
	// At 1s poll interval, 300 samples = 5 minutes of learning.
	learningPeriod = 300

	// pushInterval determines how often adaptive thresholds are pushed to the BPF config map.
	pushInterval = 10 * time.Second

	// Adaptive rate safety margins.
	adaptiveSYNMultiplier  = 3.0
	adaptiveUDPMultiplier  = 2.0
	adaptiveICMPMultiplier = 5.0
	adaptiveGlobalMargin   = 2.0
)

// Config map keys matching types.h CFG_* constants.
const (
	cfgBaselinePPS    uint32 = 8
	cfgBaselineBPS    uint32 = 9
	cfgSYNRatePPS     uint32 = 1
	cfgUDPRatePPS     uint32 = 2
	cfgICMPRatePPS    uint32 = 3
	cfgGlobalPPSLimit uint32 = 4
)

// Metrics holds the current baseline state and anomaly detection results.
type Metrics struct {
	BaselinePPS  float64
	BaselineBPS  float64
	CurrentPPS   float64
	CurrentBPS   float64
	StdDevPPS    float64
	StdDevBPS    float64
	ZScorePPS    float64
	ZScoreBPS    float64
	IsAnomaly    bool
	AnomalyScore float64
}

// AdaptiveRates holds recommended rate limits derived from the baseline.
type AdaptiveRates struct {
	SynPPS    uint64
	UdpPPS    uint64
	IcmpPPS   uint64
	GlobalPPS uint64
}

// Baseline provides EWMA-based traffic baseline learning and anomaly detection.
type Baseline struct {
	log       *zap.Logger
	configMap *ebpf.Map

	mu sync.RWMutex

	// EWMA state for PPS.
	meanPPS     float64
	variancePPS float64 // EWMA of (x - mean)^2

	// EWMA state for BPS.
	meanBPS     float64
	varianceBPS float64

	// EWMA state for drop PPS.
	meanDropPPS     float64
	varianceDropPPS float64

	// Current values (most recent feed).
	currentPPS     float64
	currentBPS     float64
	currentDropPPS float64

	// Sample count for learning period tracking.
	sampleCount int

	// Last push time.
	lastPush time.Time
}

// NewBaseline creates a new traffic baseline tracker.
func NewBaseline(log *zap.Logger, configMap *ebpf.Map) *Baseline {
	return &Baseline{
		log:       log,
		configMap: configMap,
	}
}

// Start begins the baseline management loop. It periodically pushes
// learned baseline values to the BPF config map.
func (b *Baseline) Start(ctx context.Context) error {
	go b.run(ctx)
	b.log.Info("baseline engine started",
		zap.Float64("alpha", alpha),
		zap.Float64("anomaly_z_threshold", anomalyZThreshold),
		zap.Int("learning_samples", learningPeriod),
	)
	return nil
}

func (b *Baseline) run(ctx context.Context) {
	ticker := time.NewTicker(pushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			b.log.Info("baseline engine stopped")
			return
		case <-ticker.C:
			b.mu.RLock()
			operational := b.sampleCount >= learningPeriod
			b.mu.RUnlock()

			if operational {
				if err := b.UpdateBPFConfig(); err != nil {
					b.log.Warn("failed to push baseline to BPF", zap.Error(err))
				}
			}
		}
	}
}

// Feed pushes a new stats snapshot for baseline calculation.
// Should be called approximately every 1 second.
func (b *Baseline) Feed(rxPps, rxBps, dropPps float64) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.currentPPS = rxPps
	b.currentBPS = rxBps
	b.currentDropPPS = dropPps
	b.sampleCount++

	if b.sampleCount == 1 {
		// Initialize EWMA with first sample.
		b.meanPPS = rxPps
		b.meanBPS = rxBps
		b.meanDropPPS = dropPps
		b.variancePPS = 0
		b.varianceBPS = 0
		b.varianceDropPPS = 0
		return
	}

	// Update EWMA for PPS.
	b.meanPPS, b.variancePPS = updateEWMA(b.meanPPS, b.variancePPS, rxPps)

	// Update EWMA for BPS.
	b.meanBPS, b.varianceBPS = updateEWMA(b.meanBPS, b.varianceBPS, rxBps)

	// Update EWMA for drop PPS.
	b.meanDropPPS, b.varianceDropPPS = updateEWMA(b.meanDropPPS, b.varianceDropPPS, dropPps)
}

// GetMetrics returns the current baseline state and anomaly detection results.
func (b *Baseline) GetMetrics() Metrics {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stdPPS := math.Sqrt(b.variancePPS)
	stdBPS := math.Sqrt(b.varianceBPS)

	zPPS := zScore(b.currentPPS, b.meanPPS, stdPPS)
	zBPS := zScore(b.currentBPS, b.meanBPS, stdBPS)

	isLearning := b.sampleCount < learningPeriod
	isAnomaly := false
	anomalyScore := math.Max(zPPS, zBPS)

	if !isLearning {
		isAnomaly = zPPS > anomalyZThreshold || zBPS > anomalyZThreshold
	}

	return Metrics{
		BaselinePPS:  b.meanPPS,
		BaselineBPS:  b.meanBPS,
		CurrentPPS:   b.currentPPS,
		CurrentBPS:   b.currentBPS,
		StdDevPPS:    stdPPS,
		StdDevBPS:    stdBPS,
		ZScorePPS:    zPPS,
		ZScoreBPS:    zBPS,
		IsAnomaly:    isAnomaly,
		AnomalyScore: anomalyScore,
	}
}

// GetAdaptiveRates returns recommended rate limits based on the learned baseline.
func (b *Baseline) GetAdaptiveRates() AdaptiveRates {
	b.mu.RLock()
	defer b.mu.RUnlock()

	basePPS := b.meanPPS
	if basePPS < 100 {
		basePPS = 100 // Minimum floor to avoid zero-rate lockout.
	}

	return AdaptiveRates{
		SynPPS:    uint64(basePPS * adaptiveSYNMultiplier),
		UdpPPS:    uint64(basePPS * adaptiveUDPMultiplier),
		IcmpPPS:   uint64(math.Max(basePPS*0.1*adaptiveICMPMultiplier, 100)),
		GlobalPPS: uint64(basePPS * adaptiveGlobalMargin),
	}
}

// UpdateBPFConfig pushes the learned baseline PPS and BPS to the BPF config map.
func (b *Baseline) UpdateBPFConfig() error {
	b.mu.RLock()
	meanPPS := b.meanPPS
	meanBPS := b.meanBPS
	b.mu.RUnlock()

	if err := b.configMap.Update(cfgBaselinePPS, uint64(meanPPS), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating CFG_BASELINE_PPS: %w", err)
	}

	if err := b.configMap.Update(cfgBaselineBPS, uint64(meanBPS), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating CFG_BASELINE_BPS: %w", err)
	}

	b.mu.Lock()
	b.lastPush = time.Now()
	b.mu.Unlock()

	b.log.Debug("baseline pushed to BPF config",
		zap.Float64("baseline_pps", meanPPS),
		zap.Float64("baseline_bps", meanBPS),
	)

	return nil
}

// IsOperational returns true if the baseline has completed the learning period.
func (b *Baseline) IsOperational() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sampleCount >= learningPeriod
}

// SampleCount returns the number of samples fed so far.
func (b *Baseline) SampleCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sampleCount
}

// Reset clears the baseline state, restarting the learning period.
func (b *Baseline) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.meanPPS = 0
	b.variancePPS = 0
	b.meanBPS = 0
	b.varianceBPS = 0
	b.meanDropPPS = 0
	b.varianceDropPPS = 0
	b.currentPPS = 0
	b.currentBPS = 0
	b.currentDropPPS = 0
	b.sampleCount = 0

	b.log.Info("baseline reset, re-entering learning period")
}

// --- Internal helpers ---

// updateEWMA computes the next EWMA mean and variance.
//
//	newMean = alpha * x + (1 - alpha) * oldMean
//	newVariance = alpha * (x - newMean)^2 + (1 - alpha) * oldVariance
func updateEWMA(oldMean, oldVariance, x float64) (float64, float64) {
	newMean := alpha*x + (1-alpha)*oldMean
	diff := x - newMean
	newVariance := alpha*(diff*diff) + (1-alpha)*oldVariance
	return newMean, newVariance
}

// zScore computes (value - mean) / stddev. Returns 0 if stddev is near zero.
func zScore(value, mean, stddev float64) float64 {
	if stddev < 1e-9 {
		return 0
	}
	return (value - mean) / stddev
}
