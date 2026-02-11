// Package engine orchestrates all scrubber components.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/api"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/bpf"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/config"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/events"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/stats"
	"go.uber.org/zap"
)

// Engine is the main control plane orchestrator.
type Engine struct {
	log  *zap.Logger
	cfg  *config.Config

	loader *bpf.Loader
	maps   *bpf.MapManager

	statsCollector *stats.Collector
	eventReader    *events.Reader
	apiServer      *api.Server

	cancel context.CancelFunc
}

// New creates a new Engine with the given configuration.
func New(log *zap.Logger, cfg *config.Config) *Engine {
	return &Engine{
		log: log,
		cfg: cfg,
	}
}

// Start initializes and starts all components.
func (e *Engine) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	// Step 1: Load BPF program (maps are created but XDP is NOT yet attached)
	e.log.Info("=== Starting DDoS Scrubber Engine ===")

	e.loader = bpf.NewLoader(e.log, e.cfg.BPFObject)
	if err := e.loader.Load(); err != nil {
		return fmt.Errorf("loading BPF program: %w", err)
	}

	// Step 2: Initialize map manager
	e.maps = bpf.NewMapManager(e.log, e.loader.Objects())

	// Step 3: Apply initial configuration to BPF maps BEFORE attaching XDP.
	// This ensures whitelist, rate limits, and other settings are in place
	// before the program starts processing packets — preventing lockout.
	if err := e.applyConfig(); err != nil {
		e.loader.Close()
		return fmt.Errorf("applying config: %w", err)
	}

	// Step 4: NOW attach to interface (safe — maps are populated)
	flags := xdpFlags(e.cfg.XDPMode)
	if err := e.loader.Attach(e.cfg.Interface, flags); err != nil {
		e.loader.Close()
		return fmt.Errorf("attaching XDP: %w", err)
	}

	// Step 5: Start stats collector
	e.statsCollector = stats.NewCollector(e.log, e.maps, time.Second)
	go e.statsCollector.Run(ctx)

	// Step 6: Start event reader
	e.eventReader = events.NewReader(e.log, e.loader.Objects().Events)
	e.eventReader.OnEvent(func(ev *bpf.Event) {
		e.log.Debug("event",
			zap.String("detail", bpf.FormatEvent(ev)),
			zap.String("attack", bpf.AttackTypeName(ev.AttackType)),
		)
	})
	go func() {
		if err := e.eventReader.Run(ctx); err != nil {
			e.log.Error("event reader error", zap.Error(err))
		}
	}()

	// Step 7: Start SYN cookie seed rotation
	go e.rotateSYNCookieSeeds(ctx)

	// Step 8: Start gRPC API server
	e.apiServer = api.NewServer(e.log, e.cfg, e.maps, e.statsCollector, e.eventReader)
	if err := e.apiServer.Start(); err != nil {
		e.loader.Close()
		return fmt.Errorf("starting API server: %w", err)
	}

	e.log.Info("=== DDoS Scrubber Engine Started ===",
		zap.String("interface", e.cfg.Interface),
		zap.String("mode", e.cfg.XDPMode),
		zap.String("api", e.cfg.API.Listen),
	)

	return nil
}

// Stop gracefully shuts down all components.
func (e *Engine) Stop() {
	e.log.Info("=== Stopping DDoS Scrubber Engine ===")

	if e.cancel != nil {
		e.cancel()
	}

	if e.apiServer != nil {
		e.apiServer.Stop()
	}

	if e.loader != nil {
		e.loader.Close()
	}

	e.log.Info("=== DDoS Scrubber Engine Stopped ===")
}

// applyConfig pushes the YAML configuration into BPF maps.
func (e *Engine) applyConfig() error {
	m := e.maps

	// Enabled state
	var enabled uint64
	if e.cfg.Scrubber.Enabled {
		enabled = 1
	}
	if err := m.SetConfig(bpf.CfgEnabled, enabled); err != nil {
		return err
	}

	// Conntrack
	var ctEnabled uint64
	if e.cfg.Scrubber.ConntrackEnabled {
		ctEnabled = 1
	}
	if err := m.SetConfig(bpf.CfgConntrackEnable, ctEnabled); err != nil {
		return err
	}

	// SYN Cookie
	var scEnabled uint64
	if e.cfg.SYNCookie.Enabled {
		scEnabled = 1
	}
	if err := m.SetConfig(bpf.CfgSYNCookieEnable, scEnabled); err != nil {
		return err
	}

	// Rate limits
	rl := e.cfg.RateLimit
	rateCfgs := map[uint32]uint64{
		bpf.CfgSYNRatePPS:     rl.SYNRatePPS,
		bpf.CfgUDPRatePPS:     rl.UDPRatePPS,
		bpf.CfgICMPRatePPS:    rl.ICMPRatePPS,
		bpf.CfgGlobalPPSLimit: rl.GlobalPPS,
		bpf.CfgGlobalBPSLimit: rl.GlobalBPS,
	}
	for key, val := range rateCfgs {
		if err := m.SetConfig(key, val); err != nil {
			return err
		}
	}

	// Baseline & threshold
	if err := m.SetConfig(bpf.CfgBaselinePPS, e.cfg.Scrubber.BaselinePPS); err != nil {
		return err
	}
	if err := m.SetConfig(bpf.CfgBaselineBPS, e.cfg.Scrubber.BaselineBPS); err != nil {
		return err
	}
	if err := m.SetConfig(bpf.CfgAttackThreshold, e.cfg.Scrubber.AttackThreshold); err != nil {
		return err
	}

	// Blacklist
	for _, cidr := range e.cfg.Blacklist {
		if err := m.AddBlacklistCIDR(cidr, bpf.DropBlacklist); err != nil {
			e.log.Warn("failed to add blacklist entry", zap.String("cidr", cidr), zap.Error(err))
		}
	}

	// Whitelist
	for _, cidr := range e.cfg.Whitelist {
		if err := m.AddWhitelistCIDR(cidr); err != nil {
			e.log.Warn("failed to add whitelist entry", zap.String("cidr", cidr), zap.Error(err))
		}
	}

	// Amplification-sensitive ports
	for _, ap := range e.cfg.AmpPorts {
		if err := m.SetPortProtocol(ap.Port, ap.Flags); err != nil {
			e.log.Warn("failed to set amp port", zap.Uint16("port", ap.Port), zap.Error(err))
		}
	}

	// Initial SYN cookie seeds
	seed1, seed2 := randomSeed(), randomSeed()
	if err := m.UpdateSYNCookieSeeds(seed1, seed2, uint64(time.Now().UnixNano())); err != nil {
		return err
	}

	e.log.Info("configuration applied to BPF maps")
	return nil
}

// rotateSYNCookieSeeds periodically rotates the SYN cookie seeds.
func (e *Engine) rotateSYNCookieSeeds(ctx context.Context) {
	interval := time.Duration(e.cfg.SYNCookie.SeedRotationSec) * time.Second
	if interval == 0 {
		interval = 60 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	e.log.Info("SYN cookie seed rotation started", zap.Duration("interval", interval))

	var currentSeed uint32 = randomSeed()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			previousSeed := currentSeed
			currentSeed = randomSeed()

			if err := e.maps.UpdateSYNCookieSeeds(
				currentSeed, previousSeed,
				uint64(time.Now().UnixNano()),
			); err != nil {
				e.log.Warn("failed to rotate SYN cookie seeds", zap.Error(err))
			} else {
				e.log.Debug("SYN cookie seeds rotated")
			}
		}
	}
}

func xdpFlags(mode string) link.XDPAttachFlags {
	switch mode {
	case "offload":
		return link.XDPOffloadMode
	case "skb":
		return link.XDPGenericMode
	default:
		return link.XDPDriverMode
	}
}

func randomSeed() uint32 {
	var buf [4]byte
	rand.Read(buf[:])
	return binary.LittleEndian.Uint32(buf[:])
}
