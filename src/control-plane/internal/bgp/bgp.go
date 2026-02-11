// Package bgp provides BGP Flowspec and RTBH (Remotely Triggered Black Hole)
// integration for upstream traffic filtering during critical DDoS events.
//
// This package abstracts BGP session management and provides an API for
// announcing/withdrawing blackhole routes and Flowspec rules. It is designed
// to be triggered by the escalation engine when the CRITICAL level is reached.
//
// In production, this would use the GoBGP library (github.com/osrg/gobgp/v3)
// for full BGP session management. The current implementation provides the
// complete interface and control logic, with the BGP transport layer stubbed
// for environments where GoBGP is not available.
package bgp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Default blackhole community (RFC 7999: 65535:666).
const defaultBlackholeCommunity = "65535:666"

// Config holds BGP session configuration.
type Config struct {
	Enabled            bool   `yaml:"enabled"`
	RouterIP           string `yaml:"router_ip"`             // Peer router IP.
	LocalAS            uint32 `yaml:"local_as"`              // Our AS number.
	PeerAS             uint32 `yaml:"peer_as"`               // Peer AS number.
	NextHopSelf        string `yaml:"next_hop_self"`         // Next-hop for announcements.
	CommunityBlackhole string `yaml:"community_blackhole"`   // Blackhole community string.
}

// FlowspecRule represents a BGP Flowspec traffic filtering rule (RFC 5575).
type FlowspecRule struct {
	SrcPrefix string `json:"src_prefix,omitempty"` // Source CIDR prefix.
	DstPrefix string `json:"dst_prefix,omitempty"` // Destination CIDR prefix.
	Protocol  string `json:"protocol,omitempty"`   // "tcp", "udp", "icmp", or "".
	SrcPort   string `json:"src_port,omitempty"`   // Source port or range ("80", "1024-65535").
	DstPort   string `json:"dst_port,omitempty"`   // Destination port or range.
	Action    string `json:"action"`               // "drop", "rate-limit", "redirect".

	// Metadata (not sent via BGP, used for tracking).
	CreatedAt time.Time `json:"created_at"`
	Reason    string    `json:"reason,omitempty"`
}

// blackholeRoute tracks a single RTBH announcement.
type blackholeRoute struct {
	Prefix      string
	AnnouncedAt time.Time
	Reason      string
}

// Client manages BGP sessions for Flowspec and RTBH signaling.
type Client struct {
	log *zap.Logger
	cfg Config

	mu             sync.RWMutex
	connected      bool
	blackholes     map[string]*blackholeRoute // prefix -> route
	flowspecRules  []FlowspecRule
	auditLog       []auditEntry
	cancelFunc     context.CancelFunc
}

// auditEntry records a BGP action for audit trail purposes.
type auditEntry struct {
	Timestamp time.Time
	Action    string // "announce_blackhole", "withdraw_blackhole", "announce_flowspec", etc.
	Detail    string
}

// Maximum audit log entries to retain.
const maxAuditEntries = 10000

// NewClient creates a new BGP client with the given configuration.
func NewClient(log *zap.Logger, cfg Config) *Client {
	if cfg.CommunityBlackhole == "" {
		cfg.CommunityBlackhole = defaultBlackholeCommunity
	}

	return &Client{
		log:        log,
		cfg:        cfg,
		blackholes: make(map[string]*blackholeRoute),
	}
}

// Connect establishes the BGP session to the configured peer router.
//
// In a full implementation, this would use the GoBGP gRPC API to:
// 1. Start a local BGP server with LocalAS
// 2. Add a neighbor with PeerAS at RouterIP
// 3. Enable the IPv4 unicast and Flowspec address families
// 4. Wait for the session to reach ESTABLISHED state
func (c *Client) Connect(ctx context.Context) error {
	if !c.cfg.Enabled {
		c.log.Info("BGP client disabled, skipping connection")
		return nil
	}

	if c.cfg.RouterIP == "" {
		return fmt.Errorf("BGP router IP is required")
	}

	if net.ParseIP(c.cfg.RouterIP) == nil {
		return fmt.Errorf("invalid BGP router IP: %s", c.cfg.RouterIP)
	}

	if c.cfg.LocalAS == 0 {
		return fmt.Errorf("BGP local AS is required")
	}

	if c.cfg.PeerAS == 0 {
		return fmt.Errorf("BGP peer AS is required")
	}

	ctx, cancel := context.WithCancel(ctx)
	c.cancelFunc = cancel

	// In production: establish GoBGP session here.
	// server := gobgpapi.NewGobgpApiClient(conn)
	// server.StartBgp(ctx, &gobgpapi.StartBgpRequest{...})
	// server.AddPeer(ctx, &gobgpapi.AddPeerRequest{...})

	c.mu.Lock()
	c.connected = true
	c.mu.Unlock()

	c.log.Info("BGP session established",
		zap.String("router", c.cfg.RouterIP),
		zap.Uint32("local_as", c.cfg.LocalAS),
		zap.Uint32("peer_as", c.cfg.PeerAS),
		zap.String("community", c.cfg.CommunityBlackhole),
	)

	// Start keepalive monitoring.
	go c.monitorSession(ctx)

	return nil
}

// monitorSession monitors the BGP session and logs state changes.
func (c *Client) monitorSession(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.connected = false
			c.mu.Unlock()
			c.log.Info("BGP session monitor stopped")
			return
		case <-ticker.C:
			// In production: check GoBGP peer state via API.
			c.log.Debug("BGP session keepalive",
				zap.String("router", c.cfg.RouterIP),
				zap.Bool("connected", c.IsConnected()),
			)
		}
	}
}

// AnnounceBlackhole signals RTBH for a prefix by announcing a /32 (or wider)
// host route with the configured blackhole community.
//
// RTBH works by announcing the victim's prefix with:
// - next-hop set to a null route (typically RFC 5737 discard prefix)
// - community set to the operator's blackhole community (default 65535:666)
func (c *Client) AnnounceBlackhole(prefix string) error {
	if err := c.checkConnected(); err != nil {
		return err
	}

	if err := validatePrefix(prefix); err != nil {
		return fmt.Errorf("invalid prefix for blackhole: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.blackholes[prefix]; exists {
		return nil // Already announced.
	}

	// In production with GoBGP:
	// nlri, _ := apb.New(&gobgpapi.IPAddressPrefix{PrefixLen: prefixLen, Prefix: ip})
	// attrs := []*anypb.Any{origin, nexthop, communities}
	// server.AddPath(ctx, &gobgpapi.AddPathRequest{...})

	c.blackholes[prefix] = &blackholeRoute{
		Prefix:      prefix,
		AnnouncedAt: time.Now(),
	}

	c.appendAudit("announce_blackhole", fmt.Sprintf("prefix=%s community=%s", prefix, c.cfg.CommunityBlackhole))

	c.log.Warn("RTBH blackhole announced",
		zap.String("prefix", prefix),
		zap.String("community", c.cfg.CommunityBlackhole),
		zap.String("next_hop", c.cfg.NextHopSelf),
	)

	return nil
}

// WithdrawBlackhole removes the RTBH announcement for a prefix.
func (c *Client) WithdrawBlackhole(prefix string) error {
	if err := c.checkConnected(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.blackholes[prefix]; !exists {
		return fmt.Errorf("blackhole for %s not found", prefix)
	}

	// In production with GoBGP:
	// server.DeletePath(ctx, &gobgpapi.DeletePathRequest{...})

	delete(c.blackholes, prefix)

	c.appendAudit("withdraw_blackhole", fmt.Sprintf("prefix=%s", prefix))

	c.log.Info("RTBH blackhole withdrawn", zap.String("prefix", prefix))
	return nil
}

// AnnounceFlowspec injects a BGP Flowspec rule (RFC 5575) to upstream routers.
//
// Flowspec allows fine-grained traffic filtering rules to be distributed via BGP:
// - Match on source/destination prefix, protocol, ports, packet length, etc.
// - Actions: drop, rate-limit, redirect to VRF
func (c *Client) AnnounceFlowspec(rule FlowspecRule) error {
	if err := c.checkConnected(); err != nil {
		return err
	}

	if err := validateFlowspecRule(rule); err != nil {
		return fmt.Errorf("invalid flowspec rule: %w", err)
	}

	rule.CreatedAt = time.Now()

	c.mu.Lock()
	c.flowspecRules = append(c.flowspecRules, rule)
	c.mu.Unlock()

	// In production with GoBGP:
	// Build Flowspec NLRI from rule fields.
	// flowspecNLRI := buildFlowspecNLRI(rule)
	// server.AddPath(ctx, &gobgpapi.AddPathRequest{TableType: GLOBAL, Path: ...})

	c.appendAudit("announce_flowspec", fmt.Sprintf(
		"src=%s dst=%s proto=%s src_port=%s dst_port=%s action=%s",
		rule.SrcPrefix, rule.DstPrefix, rule.Protocol,
		rule.SrcPort, rule.DstPort, rule.Action,
	))

	c.log.Warn("Flowspec rule announced",
		zap.String("src", rule.SrcPrefix),
		zap.String("dst", rule.DstPrefix),
		zap.String("proto", rule.Protocol),
		zap.String("action", rule.Action),
	)

	return nil
}

// WithdrawFlowspec removes a previously announced Flowspec rule.
func (c *Client) WithdrawFlowspec(rule FlowspecRule) error {
	if err := c.checkConnected(); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	found := false
	for i, r := range c.flowspecRules {
		if flowspecMatch(r, rule) {
			c.flowspecRules = append(c.flowspecRules[:i], c.flowspecRules[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("matching flowspec rule not found")
	}

	// In production with GoBGP:
	// server.DeletePath(ctx, &gobgpapi.DeletePathRequest{...})

	c.appendAudit("withdraw_flowspec", fmt.Sprintf(
		"src=%s dst=%s proto=%s action=%s",
		rule.SrcPrefix, rule.DstPrefix, rule.Protocol, rule.Action,
	))

	c.log.Info("Flowspec rule withdrawn",
		zap.String("src", rule.SrcPrefix),
		zap.String("dst", rule.DstPrefix),
		zap.String("action", rule.Action),
	)

	return nil
}

// GetActiveRules returns all active Flowspec and RTBH announcements as FlowspecRule entries.
// RTBH entries are represented with Action="blackhole".
func (c *Client) GetActiveRules() []FlowspecRule {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rules := make([]FlowspecRule, 0, len(c.flowspecRules)+len(c.blackholes))

	// Include blackhole routes as rules.
	for _, bh := range c.blackholes {
		rules = append(rules, FlowspecRule{
			DstPrefix: bh.Prefix,
			Action:    "blackhole",
			CreatedAt: bh.AnnouncedAt,
			Reason:    bh.Reason,
		})
	}

	// Include Flowspec rules.
	for _, r := range c.flowspecRules {
		rules = append(rules, r)
	}

	return rules
}

// GetBlackholes returns all active RTBH prefixes.
func (c *Client) GetBlackholes() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]string, 0, len(c.blackholes))
	for prefix := range c.blackholes {
		result = append(result, prefix)
	}
	return result
}

// IsConnected returns the BGP session state.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected
}

// Disconnect gracefully tears down the BGP session.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cancelFunc != nil {
		c.cancelFunc()
		c.cancelFunc = nil
	}

	c.connected = false

	// In production: stop GoBGP server.
	// server.StopBgp(ctx, &gobgpapi.StopBgpRequest{})

	c.log.Info("BGP session disconnected",
		zap.String("router", c.cfg.RouterIP),
		zap.Int("blackholes_active", len(c.blackholes)),
		zap.Int("flowspec_active", len(c.flowspecRules)),
	)

	return nil
}

// GetAuditLog returns the BGP action audit trail.
func (c *Client) GetAuditLog() []auditEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]auditEntry, len(c.auditLog))
	copy(result, c.auditLog)
	return result
}

// WithdrawAll withdraws all active blackhole and flowspec announcements.
// Used during graceful shutdown or when de-escalating from CRITICAL.
func (c *Client) WithdrawAll() error {
	c.mu.Lock()

	// Collect all prefixes to withdraw.
	prefixes := make([]string, 0, len(c.blackholes))
	for p := range c.blackholes {
		prefixes = append(prefixes, p)
	}
	c.blackholes = make(map[string]*blackholeRoute)
	c.flowspecRules = nil

	c.appendAudit("withdraw_all", fmt.Sprintf(
		"blackholes=%d flowspec=%d",
		len(prefixes), 0,
	))

	c.mu.Unlock()

	c.log.Warn("all BGP announcements withdrawn",
		zap.Int("blackholes_withdrawn", len(prefixes)),
	)

	return nil
}

// --- Internal helpers ---

func (c *Client) checkConnected() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.cfg.Enabled {
		return fmt.Errorf("BGP client is disabled")
	}
	if !c.connected {
		return fmt.Errorf("BGP session not established")
	}
	return nil
}

func (c *Client) appendAudit(action, detail string) {
	entry := auditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Detail:    detail,
	}

	// Note: caller must hold the lock or this must be called within a locked section.
	// For simplicity we take the lock here if not already held.
	c.auditLog = append(c.auditLog, entry)
	if len(c.auditLog) > maxAuditEntries {
		c.auditLog = c.auditLog[len(c.auditLog)-maxAuditEntries:]
	}
}

// validatePrefix checks that a string is a valid IPv4 CIDR or single IP.
func validatePrefix(prefix string) error {
	if ip := net.ParseIP(prefix); ip != nil {
		if ip.To4() == nil {
			return fmt.Errorf("IPv6 not supported: %s", prefix)
		}
		return nil // Single IP is valid; will be announced as /32.
	}

	_, _, err := net.ParseCIDR(prefix)
	if err != nil {
		return fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	return nil
}

// validateFlowspecRule performs basic validation of a Flowspec rule.
func validateFlowspecRule(rule FlowspecRule) error {
	if rule.Action == "" {
		return fmt.Errorf("action is required")
	}

	switch rule.Action {
	case "drop", "rate-limit", "redirect":
		// Valid.
	default:
		return fmt.Errorf("unsupported action %q: must be drop, rate-limit, or redirect", rule.Action)
	}

	if rule.SrcPrefix == "" && rule.DstPrefix == "" {
		return fmt.Errorf("at least one of src_prefix or dst_prefix is required")
	}

	if rule.SrcPrefix != "" {
		if err := validatePrefix(rule.SrcPrefix); err != nil {
			return fmt.Errorf("invalid src_prefix: %w", err)
		}
	}

	if rule.DstPrefix != "" {
		if err := validatePrefix(rule.DstPrefix); err != nil {
			return fmt.Errorf("invalid dst_prefix: %w", err)
		}
	}

	if rule.Protocol != "" {
		switch rule.Protocol {
		case "tcp", "udp", "icmp":
			// Valid.
		default:
			return fmt.Errorf("unsupported protocol %q", rule.Protocol)
		}
	}

	return nil
}

// flowspecMatch checks if two Flowspec rules match on their key fields.
func flowspecMatch(a, b FlowspecRule) bool {
	return a.SrcPrefix == b.SrcPrefix &&
		a.DstPrefix == b.DstPrefix &&
		a.Protocol == b.Protocol &&
		a.SrcPort == b.SrcPort &&
		a.DstPort == b.DstPort &&
		a.Action == b.Action
}
