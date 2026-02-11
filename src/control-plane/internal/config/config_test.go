package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Interface != "eth0" {
		t.Errorf("default interface = %s, want eth0", cfg.Interface)
	}
	if cfg.XDPMode != "native" {
		t.Errorf("default xdp_mode = %s, want native", cfg.XDPMode)
	}
	if !cfg.Scrubber.Enabled {
		t.Error("default scrubber.enabled should be true")
	}
	if !cfg.Scrubber.ConntrackEnabled {
		t.Error("default conntrack_enabled should be true")
	}
	if !cfg.SYNCookie.Enabled {
		t.Error("default syn_cookie.enabled should be true")
	}
	if cfg.RateLimit.SYNRatePPS != 1000 {
		t.Errorf("default syn_rate_pps = %d, want 1000", cfg.RateLimit.SYNRatePPS)
	}
	if cfg.RateLimit.UDPRatePPS != 10000 {
		t.Errorf("default udp_rate_pps = %d, want 10000", cfg.RateLimit.UDPRatePPS)
	}
	if cfg.RateLimit.ICMPRatePPS != 100 {
		t.Errorf("default icmp_rate_pps = %d, want 100", cfg.RateLimit.ICMPRatePPS)
	}
	if cfg.API.Listen != "0.0.0.0:9090" {
		t.Errorf("default api.listen = %s, want 0.0.0.0:9090", cfg.API.Listen)
	}
	if len(cfg.AmpPorts) < 5 {
		t.Errorf("default amp_ports count = %d, want >= 5", len(cfg.AmpPorts))
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "empty interface",
			modify:  func(c *Config) { c.Interface = "" },
			wantErr: true,
		},
		{
			name:    "invalid xdp_mode",
			modify:  func(c *Config) { c.XDPMode = "turbo" },
			wantErr: true,
		},
		{
			name:    "empty bpf_object",
			modify:  func(c *Config) { c.BPFObject = "" },
			wantErr: true,
		},
		{
			name:    "empty api listen",
			modify:  func(c *Config) { c.API.Listen = "" },
			wantErr: true,
		},
		{
			name:    "offload mode valid",
			modify:  func(c *Config) { c.XDPMode = "offload" },
			wantErr: false,
		},
		{
			name:    "skb mode valid",
			modify:  func(c *Config) { c.XDPMode = "skb" },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	yaml := `
interface: ens3f0
xdp_mode: skb
bpf_object: /opt/bpf/xdp.o
log_level: debug
scrubber:
  enabled: true
  conntrack_enabled: false
  baseline_pps: 500000
api:
  listen: "127.0.0.1:8080"
rate_limit:
  syn_rate_pps: 2000
  udp_rate_pps: 50000
  icmp_rate_pps: 200
blacklist:
  - "10.0.0.0/8"
  - "192.168.100.0/24"
whitelist:
  - "172.16.0.0/12"
`

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if cfg.Interface != "ens3f0" {
		t.Errorf("interface = %s, want ens3f0", cfg.Interface)
	}
	if cfg.XDPMode != "skb" {
		t.Errorf("xdp_mode = %s, want skb", cfg.XDPMode)
	}
	if cfg.Scrubber.ConntrackEnabled {
		t.Error("conntrack_enabled should be false")
	}
	if cfg.Scrubber.BaselinePPS != 500000 {
		t.Errorf("baseline_pps = %d, want 500000", cfg.Scrubber.BaselinePPS)
	}
	if cfg.RateLimit.SYNRatePPS != 2000 {
		t.Errorf("syn_rate_pps = %d, want 2000", cfg.RateLimit.SYNRatePPS)
	}
	if len(cfg.Blacklist) != 2 {
		t.Errorf("blacklist count = %d, want 2", len(cfg.Blacklist))
	}
	if len(cfg.Whitelist) != 1 {
		t.Errorf("whitelist count = %d, want 1", len(cfg.Whitelist))
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("{{{{invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestSaveToFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Interface = "ens4f1"

	dir := t.TempDir()
	path := filepath.Join(dir, "out.yaml")

	if err := cfg.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}

	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	if loaded.Interface != "ens4f1" {
		t.Errorf("reloaded interface = %s, want ens4f1", loaded.Interface)
	}
}

func TestRateLimitThreadSafe(t *testing.T) {
	cfg := DefaultConfig()

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			cfg.SetRateLimit(RateLimitConfig{SYNRatePPS: uint64(i)})
		}
		close(done)
	}()

	for i := 0; i < 1000; i++ {
		_ = cfg.GetRateLimit()
	}
	<-done
}
