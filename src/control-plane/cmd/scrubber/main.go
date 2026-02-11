// Command scrubber is the main entry point for the DDoS scrubber control plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ebpf-ddos-scrubber/control-plane/internal/config"
	"github.com/ebpf-ddos-scrubber/control-plane/internal/engine"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	var (
		configPath = flag.String("config", "/etc/ddos-scrubber/config.yaml", "Path to configuration file")
		iface      = flag.String("interface", "", "Override network interface")
		mode       = flag.String("mode", "", "Override XDP mode (native/skb/offload)")
		listen     = flag.String("listen", "", "Override gRPC API listen address")
		logLevel   = flag.String("log-level", "", "Override log level (debug/info/warn/error)")
		showVer    = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("ddos-scrubber %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Apply CLI overrides
	if *iface != "" {
		cfg.Interface = *iface
	}
	if *mode != "" {
		cfg.XDPMode = *mode
	}
	if *listen != "" {
		cfg.API.Listen = *listen
	}
	if *logLevel != "" {
		cfg.LogLevel = *logLevel
	}

	// Initialize logger
	log, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
		os.Exit(1)
	}
	defer log.Sync()

	log.Info("DDoS Scrubber starting",
		zap.String("version", version),
		zap.String("interface", cfg.Interface),
		zap.String("xdp_mode", cfg.XDPMode),
		zap.String("api_listen", cfg.API.Listen),
	)

	// Create and start engine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eng := engine.New(log, cfg)
	if err := eng.Start(ctx); err != nil {
		log.Fatal("failed to start engine", zap.Error(err))
	}

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigCh
	log.Info("received signal, shutting down...", zap.String("signal", sig.String()))

	cancel()
	eng.Stop()

	log.Info("DDoS Scrubber stopped")
}

func loadConfig(path string) (*config.Config, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Config file not found — use defaults
		return config.DefaultConfig(), nil
	}
	return config.LoadFromFile(path)
}

func newLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Level:       zap.NewAtomicLevelAt(zapLevel),
		Development: false,
		Encoding:    "json",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:        "ts",
			LevelKey:       "level",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "msg",
			StacktraceKey:  "stacktrace",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return cfg.Build()
}
