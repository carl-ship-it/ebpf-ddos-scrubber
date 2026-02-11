// Package config handles configuration loading and runtime updates.
package config

import (
	"fmt"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Config is the top-level scrubber configuration.
type Config struct {
	mu sync.RWMutex

	// General
	Interface string `yaml:"interface"`
	XDPMode   string `yaml:"xdp_mode"` // "native", "skb", "offload"
	BPFObject string `yaml:"bpf_object"`
	LogLevel  string `yaml:"log_level"` // "debug", "info", "warn", "error"

	// Scrubber settings
	Scrubber ScrubberConfig `yaml:"scrubber"`

	// gRPC API
	API APIConfig `yaml:"api"`

	// SYN Cookie
	SYNCookie SYNCookieConfig `yaml:"syn_cookie"`

	// Rate limits
	RateLimit RateLimitConfig `yaml:"rate_limit"`

	// ACL
	Blacklist []string `yaml:"blacklist"` // CIDR list
	Whitelist []string `yaml:"whitelist"` // CIDR list

	// Amplification ports
	AmpPorts []AmpPortConfig `yaml:"amp_ports"`
}

// ScrubberConfig controls the scrubber engine behavior.
type ScrubberConfig struct {
	Enabled            bool   `yaml:"enabled"`
	ConntrackEnabled   bool   `yaml:"conntrack_enabled"`
	BaselinePPS        uint64 `yaml:"baseline_pps"`
	BaselineBPS        uint64 `yaml:"baseline_bps"`
	AttackThreshold    uint64 `yaml:"attack_threshold"` // Multiplier x100 (e.g. 300 = 3x)
}

// APIConfig controls the gRPC API server.
type APIConfig struct {
	Listen string `yaml:"listen"` // e.g. "0.0.0.0:9090"
	TLS    bool   `yaml:"tls"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
}

// SYNCookieConfig controls SYN cookie behavior.
type SYNCookieConfig struct {
	Enabled         bool   `yaml:"enabled"`
	SeedRotationSec uint64 `yaml:"seed_rotation_sec"` // Seed rotation interval
}

// RateLimitConfig controls rate limiting thresholds.
type RateLimitConfig struct {
	SYNRatePPS    uint64 `yaml:"syn_rate_pps"`    // Per-source SYN rate
	UDPRatePPS    uint64 `yaml:"udp_rate_pps"`    // Per-source UDP rate
	ICMPRatePPS   uint64 `yaml:"icmp_rate_pps"`   // Per-source ICMP rate
	GlobalPPS     uint64 `yaml:"global_pps"`       // Global PPS limit
	GlobalBPS     uint64 `yaml:"global_bps"`       // Global BPS limit
}

// AmpPortConfig defines an amplification-sensitive port.
type AmpPortConfig struct {
	Port  uint16 `yaml:"port"`
	Flags uint32 `yaml:"flags"` // Protocol type flags
}

// DefaultConfig returns a configuration with reasonable defaults.
func DefaultConfig() *Config {
	return &Config{
		Interface: "eth0",
		XDPMode:   "native",
		BPFObject: "build/obj/xdp_ddos_scrubber.o",
		LogLevel:  "info",
		Scrubber: ScrubberConfig{
			Enabled:          true,
			ConntrackEnabled: true,
			BaselinePPS:      100000,
			BaselineBPS:      1000000000, // 1 Gbps
			AttackThreshold:  300,         // 3x
		},
		API: APIConfig{
			Listen: "0.0.0.0:9090",
		},
		SYNCookie: SYNCookieConfig{
			Enabled:         true,
			SeedRotationSec: 60,
		},
		RateLimit: RateLimitConfig{
			SYNRatePPS:  1000,
			UDPRatePPS:  10000,
			ICMPRatePPS: 100,
			GlobalPPS:   0, // 0 = disabled
			GlobalBPS:   0,
		},
		AmpPorts: []AmpPortConfig{
			{Port: 53, Flags: 1},    // DNS
			{Port: 123, Flags: 2},   // NTP
			{Port: 1900, Flags: 4},  // SSDP
			{Port: 11211, Flags: 8}, // Memcached
			{Port: 19, Flags: 16},   // Chargen
		},
	}
}

// LoadFromFile loads configuration from a YAML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for consistency.
func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface is required")
	}

	switch c.XDPMode {
	case "native", "skb", "offload":
		// ok
	default:
		return fmt.Errorf("invalid xdp_mode: %s (must be native, skb, or offload)", c.XDPMode)
	}

	if c.BPFObject == "" {
		return fmt.Errorf("bpf_object path is required")
	}

	if c.API.Listen == "" {
		return fmt.Errorf("api.listen is required")
	}

	return nil
}

// SaveToFile writes the current configuration to a YAML file.
func (c *Config) SaveToFile(path string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// GetRateLimit returns the current rate limit config (thread-safe).
func (c *Config) GetRateLimit() RateLimitConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.RateLimit
}

// SetRateLimit updates the rate limit config (thread-safe).
func (c *Config) SetRateLimit(rl RateLimitConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.RateLimit = rl
}
