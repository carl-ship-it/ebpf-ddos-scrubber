// Package threatintel fetches and syncs external threat intelligence feeds
// to BPF maps for real-time IP blocking and rate limiting.
package threatintel

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Default sync interval for periodic feed updates.
const defaultSyncInterval = 1 * time.Hour

// HTTP client timeout for feed fetches.
const httpTimeout = 60 * time.Second

// lpmKeyV4 matches struct lpm_key_v4 in the BPF program.
type lpmKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // __be32
}

// threatIntelEntry matches struct threat_intel_entry in types.h.
type threatIntelEntry struct {
	SourceID    uint8  // Feed source identifier.
	ThreatType  uint8  // 0=botnet, 1=scanner, 2=tor_exit, 3=proxy, 4=malware.
	Confidence  uint8  // 0-100 confidence score.
	Action      uint8  // 0=drop, 1=rate-limit, 2=monitor.
	LastUpdated uint32 // Unix timestamp.
}

// Feed represents a configured threat intelligence feed.
type Feed struct {
	Name       string
	URL        string
	Type       string // "plaintext", "csv", "json"
	Enabled    bool
	LastSync   time.Time
	EntryCount int
	Error      string

	// CSV-specific configuration.
	CSVColumn int // Column index containing IP/CIDR (0-based).

	// Feed metadata for BPF entries.
	SourceID   uint8
	ThreatType uint8
	Confidence uint8
	Action     uint8 // Default action: 0=drop, 1=rate-limit, 2=monitor.
}

// Stats holds aggregate threat intelligence statistics.
type Stats struct {
	TotalEntries int
	LastSync     time.Time
	FeedCount    int
}

// Manager fetches and syncs external threat intelligence feeds to BPF maps.
type Manager struct {
	log          *zap.Logger
	threatMap    *ebpf.Map // threat_intel_map (LPM trie)
	blacklistMap *ebpf.Map // blacklist_v4 (LPM trie, for high-confidence direct blocks)
	httpClient   *http.Client

	mu           sync.RWMutex
	feeds        map[string]*Feed
	nextSourceID uint8
	totalEntries int
	lastSync     time.Time
	syncInterval time.Duration
}

// NewManager creates a new threat intelligence manager.
func NewManager(log *zap.Logger, threatMap, blacklistMap *ebpf.Map) *Manager {
	m := &Manager{
		log:          log,
		threatMap:    threatMap,
		blacklistMap: blacklistMap,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		feeds:        make(map[string]*Feed),
		nextSourceID: 0,
		syncInterval: defaultSyncInterval,
	}

	// Register built-in feeds (disabled by default until explicitly enabled).
	m.registerBuiltinFeeds()

	return m
}

// registerBuiltinFeeds adds the preconfigured Spamhaus feeds.
func (m *Manager) registerBuiltinFeeds() {
	m.feeds["spamhaus-drop"] = &Feed{
		Name:       "spamhaus-drop",
		URL:        "https://www.spamhaus.org/drop/drop.txt",
		Type:       "plaintext",
		Enabled:    false,
		SourceID:   0,
		ThreatType: 0, // botnet
		Confidence: 100,
		Action:     0, // drop
	}
	m.nextSourceID++

	m.feeds["spamhaus-edrop"] = &Feed{
		Name:       "spamhaus-edrop",
		URL:        "https://www.spamhaus.org/drop/edrop.txt",
		Type:       "plaintext",
		Enabled:    false,
		SourceID:   1,
		ThreatType: 0, // botnet
		Confidence: 100,
		Action:     0, // drop
	}
	m.nextSourceID++
}

// AddFeed registers a new threat feed.
func (m *Manager) AddFeed(name, url, feedType string) error {
	if name == "" {
		return fmt.Errorf("feed name is required")
	}
	if url == "" {
		return fmt.Errorf("feed URL is required")
	}

	switch feedType {
	case "plaintext", "csv", "json":
		// Valid.
	default:
		return fmt.Errorf("unsupported feed type %q: must be plaintext, csv, or json", feedType)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.feeds[name]; exists {
		return fmt.Errorf("feed %q already exists", name)
	}

	m.feeds[name] = &Feed{
		Name:       name,
		URL:        url,
		Type:       feedType,
		Enabled:    true,
		SourceID:   m.nextSourceID,
		ThreatType: 0,  // Default: botnet.
		Confidence: 80, // Default confidence.
		Action:     0,  // Default: drop.
	}
	m.nextSourceID++

	m.log.Info("threat feed added",
		zap.String("name", name),
		zap.String("url", url),
		zap.String("type", feedType),
	)

	return nil
}

// RemoveFeed removes a feed and optionally clears its entries.
func (m *Manager) RemoveFeed(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.feeds[name]; !exists {
		return fmt.Errorf("feed %q not found", name)
	}

	delete(m.feeds, name)

	m.log.Info("threat feed removed", zap.String("name", name))
	return nil
}

// Start begins periodic sync of all enabled feeds.
func (m *Manager) Start(ctx context.Context) error {
	// Perform initial sync.
	m.SyncNow()

	go m.run(ctx)

	m.log.Info("threat intel manager started",
		zap.Duration("sync_interval", m.syncInterval),
		zap.Int("feeds", len(m.feeds)),
	)
	return nil
}

func (m *Manager) run(ctx context.Context) {
	ticker := time.NewTicker(m.syncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.log.Info("threat intel manager stopped")
			return
		case <-ticker.C:
			m.SyncNow()
		}
	}
}

// SyncNow forces immediate sync of all enabled feeds.
func (m *Manager) SyncNow() error {
	m.mu.RLock()
	feeds := make([]*Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		if f.Enabled {
			feeds = append(feeds, f)
		}
	}
	m.mu.RUnlock()

	totalEntries := 0
	var lastErr error

	for _, feed := range feeds {
		count, err := m.syncFeed(feed)
		if err != nil {
			m.mu.Lock()
			feed.Error = err.Error()
			m.mu.Unlock()

			m.log.Warn("feed sync failed",
				zap.String("feed", feed.Name),
				zap.Error(err),
			)
			lastErr = err
			continue
		}

		m.mu.Lock()
		feed.LastSync = time.Now()
		feed.EntryCount = count
		feed.Error = ""
		m.mu.Unlock()

		totalEntries += count

		m.log.Info("feed synced",
			zap.String("feed", feed.Name),
			zap.Int("entries", count),
		)
	}

	m.mu.Lock()
	m.totalEntries = totalEntries
	m.lastSync = time.Now()
	m.mu.Unlock()

	return lastErr
}

// syncFeed fetches a single feed and inserts entries into the BPF map.
func (m *Manager) syncFeed(feed *Feed) (int, error) {
	resp, err := m.httpClient.Get(feed.URL)
	if err != nil {
		return 0, fmt.Errorf("fetching %s: %w", feed.URL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d from %s", resp.StatusCode, feed.URL)
	}

	switch feed.Type {
	case "plaintext":
		return m.parsePlaintext(resp.Body, feed)
	case "csv":
		return m.parseCSV(resp.Body, feed)
	case "json":
		return m.parseJSON(resp.Body, feed)
	default:
		return 0, fmt.Errorf("unsupported feed type: %s", feed.Type)
	}
}

// parsePlaintext parses one IP/CIDR per line (Spamhaus DROP format).
// Lines starting with ';' or '#' are treated as comments.
func (m *Manager) parsePlaintext(r io.Reader, feed *Feed) (int, error) {
	scanner := bufio.NewScanner(r)
	count := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments.
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}

		// Spamhaus DROP format: "1.2.3.0/24 ; SBLxxxxxx"
		// Take only the CIDR part.
		if idx := strings.IndexAny(line, " \t;"); idx > 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if err := m.insertEntry(line, feed); err != nil {
			continue
		}
		count++
	}

	if err := scanner.Err(); err != nil {
		return count, fmt.Errorf("reading plaintext feed: %w", err)
	}

	return count, nil
}

// parseCSV parses a CSV feed with an IP column at the configured index.
func (m *Manager) parseCSV(r io.Reader, feed *Feed) (int, error) {
	reader := csv.NewReader(r)
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	// Skip header row.
	if _, err := reader.Read(); err != nil {
		return 0, fmt.Errorf("reading CSV header: %w", err)
	}

	colIdx := feed.CSVColumn
	count := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if colIdx >= len(record) {
			continue
		}

		ipStr := strings.TrimSpace(record[colIdx])
		if ipStr == "" {
			continue
		}

		if err := m.insertEntry(ipStr, feed); err != nil {
			continue
		}
		count++
	}

	return count, nil
}

// parseJSON parses a JSON array of IP strings.
func (m *Manager) parseJSON(r io.Reader, feed *Feed) (int, error) {
	var ips []string
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&ips); err != nil {
		return 0, fmt.Errorf("decoding JSON feed: %w", err)
	}

	count := 0
	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}
		if err := m.insertEntry(ipStr, feed); err != nil {
			continue
		}
		count++
	}

	return count, nil
}

// insertEntry parses an IP or CIDR string and inserts it into the threat_intel_map.
func (m *Manager) insertEntry(ipOrCIDR string, feed *Feed) error {
	key, err := parseLPMKey(ipOrCIDR)
	if err != nil {
		return err
	}

	entry := threatIntelEntry{
		SourceID:    feed.SourceID,
		ThreatType:  feed.ThreatType,
		Confidence:  feed.Confidence,
		Action:      feed.Action,
		LastUpdated: uint32(time.Now().Unix()),
	}

	if err := m.threatMap.Update(key, entry, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("inserting threat entry for %s: %w", ipOrCIDR, err)
	}

	return nil
}

// GetFeeds returns all configured feeds with their current status.
func (m *Manager) GetFeeds() []Feed {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Feed, 0, len(m.feeds))
	for _, f := range m.feeds {
		result = append(result, *f)
	}
	return result
}

// GetStats returns aggregate threat intelligence statistics.
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return Stats{
		TotalEntries: m.totalEntries,
		LastSync:     m.lastSync,
		FeedCount:    len(m.feeds),
	}
}

// SetSyncInterval changes the periodic sync interval.
func (m *Manager) SetSyncInterval(interval time.Duration) {
	m.mu.Lock()
	m.syncInterval = interval
	m.mu.Unlock()
}

// EnableFeed enables a feed by name.
func (m *Manager) EnableFeed(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	feed, exists := m.feeds[name]
	if !exists {
		return fmt.Errorf("feed %q not found", name)
	}
	feed.Enabled = true
	return nil
}

// DisableFeed disables a feed by name.
func (m *Manager) DisableFeed(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	feed, exists := m.feeds[name]
	if !exists {
		return fmt.Errorf("feed %q not found", name)
	}
	feed.Enabled = false
	return nil
}

// --- Helpers ---

// parseLPMKey converts an IP address or CIDR string to an LPM trie key.
func parseLPMKey(s string) (lpmKeyV4, error) {
	// Try as CIDR first.
	if strings.Contains(s, "/") {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return lpmKeyV4{}, fmt.Errorf("invalid CIDR: %s", s)
		}
		ones, _ := ipNet.Mask.Size()
		return lpmKeyV4{
			PrefixLen: uint32(ones),
			Addr:      ipToU32BE(ipNet.IP),
		}, nil
	}

	// Try as single IP.
	ip := net.ParseIP(s)
	if ip == nil {
		return lpmKeyV4{}, fmt.Errorf("invalid IP: %s", s)
	}
	ip = ip.To4()
	if ip == nil {
		return lpmKeyV4{}, fmt.Errorf("IPv6 not supported: %s", s)
	}
	return lpmKeyV4{
		PrefixLen: 32,
		Addr:      ipToU32BE(ip),
	}, nil
}

func ipToU32BE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Compile-time size checks.
var _ [8]byte = [unsafe.Sizeof(lpmKeyV4{})]byte{}
var _ [8]byte = [unsafe.Sizeof(threatIntelEntry{})]byte{}
