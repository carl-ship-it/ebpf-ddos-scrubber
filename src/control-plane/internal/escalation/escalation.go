// Package escalation implements a multi-level auto-escalation engine that
// adjusts DDoS defense posture based on threat indicators.
package escalation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Config map key for escalation level, matching types.h CFG_ESCALATION_LEVEL.
const cfgEscalationLevel uint32 = 16

// Evaluation interval for the escalation loop.
const evalInterval = 5 * time.Second

// Maximum history entries to retain.
const maxHistory = 1000

// Level represents the current escalation level.
type Level int

const (
	Low      Level = iota // Normal operation.
	Medium                // Elevated: activate rate limiting.
	High                  // Attack: aggressive filtering.
	Critical              // Major attack: full scrub + BGP signaling.
)

// String returns the human-readable name of the escalation level.
func (l Level) String() string {
	switch l {
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int(l))
	}
}

// Trigger represents a single trigger condition for escalation decisions.
type Trigger struct {
	Name      string
	Current   float64
	Threshold float64
	Active    bool
}

// EscalationEvent records a transition between escalation levels.
type EscalationEvent struct {
	Timestamp time.Time
	FromLevel Level
	ToLevel   Level
	Reason    string
	Triggers  []Trigger
}

// Escalation thresholds for upgrading levels.
var escalateThresholds = map[Level]struct {
	dropRatio          float64
	zScore             float64
	reputationBlocked  int
	dropPps            float64
}{
	Medium:   {dropRatio: 0.10, zScore: 2.0, reputationBlocked: 0, dropPps: 0},
	High:     {dropRatio: 0.30, zScore: 3.0, reputationBlocked: 100, dropPps: 0},
	Critical: {dropRatio: 0.50, zScore: 5.0, reputationBlocked: 0, dropPps: 500000},
}

// De-escalation thresholds: must be below these for 3 consecutive evaluations.
var deescalateThresholds = map[Level]struct {
	dropRatio float64
	zScore    float64
}{
	Low:    {dropRatio: 0.05, zScore: 1.0},
	Medium: {dropRatio: 0.15, zScore: 1.5},
	High:   {dropRatio: 0.25, zScore: 2.5},
}

// hysteresisCount is the number of consecutive evaluations below threshold
// required before de-escalation occurs.
const hysteresisCount = 3

// Engine manages escalation levels based on threat indicators.
type Engine struct {
	log       *zap.Logger
	configMap *ebpf.Map

	mu               sync.RWMutex
	level            Level
	history          []EscalationEvent
	triggers         []Trigger
	deescalateStreak int // Consecutive evaluations meeting de-escalation criteria.

	// Callbacks for external actions.
	onCritical   func()
	onDeescalate func(Level)
}

// NewEngine creates a new escalation engine.
func NewEngine(log *zap.Logger, configMap *ebpf.Map) *Engine {
	return &Engine{
		log:       log,
		configMap: configMap,
		level:     Low,
		history:   make([]EscalationEvent, 0, 64),
	}
}

// Start begins the escalation evaluation loop (every 5 seconds).
// The actual evaluation must be driven by calling Evaluate() with current metrics;
// Start only handles pushing the level to BPF config on changes.
func (e *Engine) Start(ctx context.Context) error {
	// Push initial level to BPF config map.
	if err := e.pushLevel(); err != nil {
		return fmt.Errorf("pushing initial escalation level: %w", err)
	}

	e.log.Info("escalation engine started", zap.String("level", e.level.String()))
	return nil
}

// Evaluate checks trigger conditions and adjusts the escalation level.
// Parameters:
//   - rxPps: current receive packets per second
//   - dropPps: current drop packets per second
//   - dropRatio: dropPps / rxPps (0.0 - 1.0)
//   - zScore: anomaly Z-score from baseline engine
//   - reputationBlocked: number of IPs currently auto-blocked by reputation
//
// Returns the new escalation level after evaluation.
func (e *Engine) Evaluate(rxPps, dropPps, dropRatio float64, zScore float64, reputationBlocked int) Level {
	e.mu.Lock()
	defer e.mu.Unlock()

	oldLevel := e.level

	// Build current trigger states.
	e.triggers = []Trigger{
		{Name: "drop_ratio", Current: dropRatio, Threshold: 0, Active: false},
		{Name: "z_score", Current: zScore, Threshold: 0, Active: false},
		{Name: "reputation_blocked", Current: float64(reputationBlocked), Threshold: 0, Active: false},
		{Name: "drop_pps", Current: dropPps, Threshold: 0, Active: false},
	}

	// Check for escalation: try to escalate from current level upward.
	newLevel := e.level
	for targetLevel := e.level + 1; targetLevel <= Critical; targetLevel++ {
		thresh, ok := escalateThresholds[targetLevel]
		if !ok {
			continue
		}

		triggered := false
		reason := ""

		if dropRatio > thresh.dropRatio && thresh.dropRatio > 0 {
			triggered = true
			reason = fmt.Sprintf("drop_ratio=%.2f > %.2f", dropRatio, thresh.dropRatio)
			e.setTriggerActive("drop_ratio", thresh.dropRatio)
		}
		if zScore > thresh.zScore && thresh.zScore > 0 {
			triggered = true
			if reason != "" {
				reason += " OR "
			}
			reason += fmt.Sprintf("z_score=%.2f > %.2f", zScore, thresh.zScore)
			e.setTriggerActive("z_score", thresh.zScore)
		}
		if thresh.reputationBlocked > 0 && reputationBlocked > thresh.reputationBlocked {
			triggered = true
			if reason != "" {
				reason += " OR "
			}
			reason += fmt.Sprintf("reputation_blocked=%d > %d", reputationBlocked, thresh.reputationBlocked)
			e.setTriggerActive("reputation_blocked", float64(thresh.reputationBlocked))
		}
		if thresh.dropPps > 0 && dropPps > thresh.dropPps {
			triggered = true
			if reason != "" {
				reason += " OR "
			}
			reason += fmt.Sprintf("drop_pps=%.0f > %.0f", dropPps, thresh.dropPps)
			e.setTriggerActive("drop_pps", thresh.dropPps)
		}

		if triggered {
			newLevel = targetLevel
		}
	}

	// If we escalated, apply the change.
	if newLevel > e.level {
		e.deescalateStreak = 0
		e.level = newLevel

		event := EscalationEvent{
			Timestamp: time.Now(),
			FromLevel: oldLevel,
			ToLevel:   newLevel,
			Reason:    fmt.Sprintf("escalate: %s", e.buildReason()),
			Triggers:  copyTriggers(e.triggers),
		}
		e.appendHistory(event)

		e.log.Warn("escalation level increased",
			zap.String("from", oldLevel.String()),
			zap.String("to", newLevel.String()),
			zap.String("reason", event.Reason),
		)

		if err := e.pushLevelLocked(); err != nil {
			e.log.Error("failed to push escalation level to BPF", zap.Error(err))
		}

		// Fire critical callback.
		if newLevel == Critical && e.onCritical != nil {
			go e.onCritical()
		}

		return e.level
	}

	// Check for de-escalation.
	if e.level > Low {
		targetLevel := e.level - 1
		deThresh, ok := deescalateThresholds[targetLevel]
		if ok && dropRatio < deThresh.dropRatio && zScore < deThresh.zScore {
			e.deescalateStreak++
		} else {
			e.deescalateStreak = 0
		}

		if e.deescalateStreak >= hysteresisCount {
			e.level = targetLevel
			e.deescalateStreak = 0

			event := EscalationEvent{
				Timestamp: time.Now(),
				FromLevel: oldLevel,
				ToLevel:   targetLevel,
				Reason:    fmt.Sprintf("de-escalate: %d consecutive evals below threshold", hysteresisCount),
				Triggers:  copyTriggers(e.triggers),
			}
			e.appendHistory(event)

			e.log.Info("escalation level decreased",
				zap.String("from", oldLevel.String()),
				zap.String("to", targetLevel.String()),
				zap.Int("consecutive_below", hysteresisCount),
			)

			if err := e.pushLevelLocked(); err != nil {
				e.log.Error("failed to push escalation level to BPF", zap.Error(err))
			}

			if e.onDeescalate != nil {
				go e.onDeescalate(targetLevel)
			}
		}
	}

	return e.level
}

// GetLevel returns the current escalation level.
func (e *Engine) GetLevel() Level {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.level
}

// GetHistory returns the escalation event history.
func (e *Engine) GetHistory() []EscalationEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]EscalationEvent, len(e.history))
	copy(result, e.history)
	return result
}

// GetTriggers returns the current trigger states from the most recent evaluation.
func (e *Engine) GetTriggers() []Trigger {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make([]Trigger, len(e.triggers))
	copy(result, e.triggers)
	return result
}

// OnCritical sets a callback that fires when escalation reaches CRITICAL level.
// Typically used to trigger BGP/RTBH signaling.
func (e *Engine) OnCritical(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onCritical = fn
}

// OnDeescalate sets a callback that fires when the escalation level decreases.
func (e *Engine) OnDeescalate(fn func(Level)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onDeescalate = fn
}

// SetLevel manually overrides the escalation level. Use with caution.
func (e *Engine) SetLevel(level Level) error {
	if level < Low || level > Critical {
		return fmt.Errorf("invalid level %d: must be 0-3", level)
	}

	e.mu.Lock()
	oldLevel := e.level
	e.level = level
	e.deescalateStreak = 0

	event := EscalationEvent{
		Timestamp: time.Now(),
		FromLevel: oldLevel,
		ToLevel:   level,
		Reason:    "manual override",
	}
	e.appendHistory(event)
	e.mu.Unlock()

	if err := e.pushLevel(); err != nil {
		return fmt.Errorf("pushing manual level override: %w", err)
	}

	e.log.Info("escalation level manually set",
		zap.String("from", oldLevel.String()),
		zap.String("to", level.String()),
	)

	return nil
}

// --- Internal helpers ---

func (e *Engine) pushLevel() error {
	e.mu.RLock()
	level := e.level
	e.mu.RUnlock()

	return e.configMap.Update(cfgEscalationLevel, uint64(level), ebpf.UpdateAny)
}

// pushLevelLocked pushes the level while the mutex is already held.
func (e *Engine) pushLevelLocked() error {
	return e.configMap.Update(cfgEscalationLevel, uint64(e.level), ebpf.UpdateAny)
}

func (e *Engine) appendHistory(event EscalationEvent) {
	e.history = append(e.history, event)
	// Trim history if it exceeds the maximum.
	if len(e.history) > maxHistory {
		e.history = e.history[len(e.history)-maxHistory:]
	}
}

func (e *Engine) setTriggerActive(name string, threshold float64) {
	for i := range e.triggers {
		if e.triggers[i].Name == name {
			e.triggers[i].Active = true
			e.triggers[i].Threshold = threshold
		}
	}
}

func (e *Engine) buildReason() string {
	reasons := ""
	for _, t := range e.triggers {
		if t.Active {
			if reasons != "" {
				reasons += ", "
			}
			reasons += fmt.Sprintf("%s=%.2f>%.2f", t.Name, t.Current, t.Threshold)
		}
	}
	return reasons
}

func copyTriggers(triggers []Trigger) []Trigger {
	result := make([]Trigger, len(triggers))
	copy(result, triggers)
	return result
}
