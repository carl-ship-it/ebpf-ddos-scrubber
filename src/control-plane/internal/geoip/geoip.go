// Package geoip loads MaxMind GeoLite2 CSV data and populates BPF geoip_map
// and geoip_policy maps for country-level traffic filtering.
package geoip

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// Supported GeoIP actions matching types.h GEOIP_ACTION_* constants.
const (
	ActionPass      uint8 = 0
	ActionDrop      uint8 = 1
	ActionRateLimit uint8 = 2
	ActionMonitor   uint8 = 3
)

// lpmKeyV4 matches struct lpm_key_v4 in the BPF program.
type lpmKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // __be32
}

// geoipEntry matches struct geoip_entry in types.h.
type geoipEntry struct {
	CountryCode uint16 // 2-byte country code packed: 'C'<<8|'N'
	Action      uint8
	Pad         uint8
}

// CountryStats holds drop statistics per country.
type CountryStats struct {
	Country     string
	Drops       uint64
	RateLimited uint64
	Monitored   uint64
}

// Manager loads MaxMind GeoLite2 CSV data and populates BPF geoip_map + geoip_policy.
type Manager struct {
	log          *zap.Logger
	geoipMap     *ebpf.Map
	policyMap    *ebpf.Map

	mu           sync.RWMutex
	policies     map[string]uint8          // country code → action
	geonameToCC  map[int]string            // geoname_id → country code (e.g. "US")
	loadedPrefixes int
	countryStats map[string]*CountryStats  // country code → stats
}

// NewManager creates a geoip manager that operates on the given BPF maps.
func NewManager(log *zap.Logger, geoipMap, policyMap *ebpf.Map) *Manager {
	return &Manager{
		log:          log,
		geoipMap:     geoipMap,
		policyMap:    policyMap,
		policies:     make(map[string]uint8),
		geonameToCC:  make(map[int]string),
		countryStats: make(map[string]*CountryStats),
	}
}

// LoadCSV loads GeoLite2-Country-Blocks-IPv4.csv and GeoLite2-Country-Locations-en.csv.
//
// The locations file maps geoname_id to country_iso_code.
// The blocks file maps CIDR → geoname_id.
//
// For each network block, an LPM trie entry is created in geoip_map mapping
// the CIDR prefix to the packed country code.
func (m *Manager) LoadCSV(blocksPath, locationsPath string) error {
	// Step 1: Load locations to build geoname_id → country_code mapping.
	if err := m.loadLocations(locationsPath); err != nil {
		return fmt.Errorf("loading locations: %w", err)
	}

	// Step 2: Load blocks and populate BPF map.
	loaded, err := m.loadBlocks(blocksPath)
	if err != nil {
		return fmt.Errorf("loading blocks: %w", err)
	}

	m.mu.Lock()
	m.loadedPrefixes = loaded
	m.mu.Unlock()

	m.log.Info("geoip data loaded",
		zap.Int("prefixes", loaded),
		zap.Int("countries", len(m.geonameToCC)),
		zap.String("blocks_file", blocksPath),
		zap.String("locations_file", locationsPath),
	)

	return nil
}

// loadLocations parses GeoLite2-Country-Locations-en.csv.
// Expected columns: geoname_id, locale_code, continent_code, continent_name,
//
//	country_iso_code, country_name, is_in_european_union
func (m *Manager) loadLocations(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening locations file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	// Read and validate header.
	header, err := reader.Read()
	if err != nil {
		return fmt.Errorf("reading locations header: %w", err)
	}

	geonameIdx := -1
	countryIdx := -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case "geoname_id":
			geonameIdx = i
		case "country_iso_code":
			countryIdx = i
		}
	}

	if geonameIdx < 0 || countryIdx < 0 {
		return fmt.Errorf("locations CSV missing required columns (geoname_id, country_iso_code)")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading locations record: %w", err)
		}

		if geonameIdx >= len(record) || countryIdx >= len(record) {
			continue
		}

		geonameID, err := strconv.Atoi(strings.TrimSpace(record[geonameIdx]))
		if err != nil {
			continue
		}

		cc := strings.TrimSpace(record[countryIdx])
		if len(cc) != 2 {
			continue
		}

		m.geonameToCC[geonameID] = strings.ToUpper(cc)
	}

	return nil
}

// loadBlocks parses GeoLite2-Country-Blocks-IPv4.csv and inserts entries into geoip_map.
// Expected columns: network, geoname_id, registered_country_geoname_id, ...
func (m *Manager) loadBlocks(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening blocks file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	header, err := reader.Read()
	if err != nil {
		return 0, fmt.Errorf("reading blocks header: %w", err)
	}

	networkIdx := -1
	geonameIdx := -1
	regGeonameIdx := -1
	for i, col := range header {
		switch strings.TrimSpace(col) {
		case "network":
			networkIdx = i
		case "geoname_id":
			geonameIdx = i
		case "registered_country_geoname_id":
			regGeonameIdx = i
		}
	}

	if networkIdx < 0 {
		return 0, fmt.Errorf("blocks CSV missing 'network' column")
	}

	m.mu.RLock()
	geonameToCC := m.geonameToCC
	m.mu.RUnlock()

	loaded := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if networkIdx >= len(record) {
			continue
		}

		cidr := strings.TrimSpace(record[networkIdx])
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		// Resolve geoname_id to country code; fall back to registered_country_geoname_id.
		cc := ""
		if geonameIdx >= 0 && geonameIdx < len(record) {
			if gid, err := strconv.Atoi(strings.TrimSpace(record[geonameIdx])); err == nil {
				cc = geonameToCC[gid]
			}
		}
		if cc == "" && regGeonameIdx >= 0 && regGeonameIdx < len(record) {
			if gid, err := strconv.Atoi(strings.TrimSpace(record[regGeonameIdx])); err == nil {
				cc = geonameToCC[gid]
			}
		}
		if cc == "" || len(cc) != 2 {
			continue
		}

		ones, _ := ipNet.Mask.Size()
		key := lpmKeyV4{
			PrefixLen: uint32(ones),
			Addr:      ipToU32BE(ipNet.IP),
		}

		entry := geoipEntry{
			CountryCode: packCountryCode(cc),
			Action:      ActionPass, // Default action; policy map overrides per-country.
		}

		if err := m.geoipMap.Update(key, entry, ebpf.UpdateAny); err != nil {
			// Log at debug level since individual failures are common for large datasets.
			m.log.Debug("failed to insert geoip entry",
				zap.String("cidr", cidr),
				zap.String("country", cc),
				zap.Error(err),
			)
			continue
		}

		loaded++
	}

	return loaded, nil
}

// SetCountryPolicy sets the action for a country code (e.g., "CN" -> DROP).
// Supported actions: 0=pass, 1=drop, 2=rate-limit, 3=monitor.
func (m *Manager) SetCountryPolicy(country string, action uint8) error {
	if len(country) != 2 {
		return fmt.Errorf("country code must be exactly 2 characters, got %q", country)
	}
	if action > ActionMonitor {
		return fmt.Errorf("invalid action %d: must be 0-3", action)
	}

	cc := strings.ToUpper(country)
	packed := packCountryCode(cc)

	if err := m.policyMap.Update(packed, action, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("updating geoip policy for %s: %w", cc, err)
	}

	m.mu.Lock()
	m.policies[cc] = action
	m.mu.Unlock()

	m.log.Info("geoip policy set",
		zap.String("country", cc),
		zap.Uint8("action", action),
	)

	return nil
}

// GetCountryPolicy returns the current policy for all configured countries.
func (m *Manager) GetCountryPolicy() map[string]uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]uint8, len(m.policies))
	for cc, action := range m.policies {
		result[cc] = action
	}
	return result
}

// GetCountryStats returns drop statistics per country.
func (m *Manager) GetCountryStats() []CountryStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]CountryStats, 0, len(m.countryStats))
	for _, cs := range m.countryStats {
		result = append(result, *cs)
	}
	return result
}

// RecordDrop records a drop event for the given country code for stats tracking.
func (m *Manager) RecordDrop(country string, action uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cs, ok := m.countryStats[country]
	if !ok {
		cs = &CountryStats{Country: country}
		m.countryStats[country] = cs
	}

	switch action {
	case ActionDrop:
		cs.Drops++
	case ActionRateLimit:
		cs.RateLimited++
	case ActionMonitor:
		cs.Monitored++
	}
}

// GetLoadedPrefixes returns the number of loaded CIDR prefixes.
func (m *Manager) GetLoadedPrefixes() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loadedPrefixes
}

// --- Helpers ---

// packCountryCode packs a 2-letter country code into a uint16: cc[0]<<8 | cc[1].
func packCountryCode(cc string) uint16 {
	if len(cc) < 2 {
		return 0
	}
	return uint16(cc[0])<<8 | uint16(cc[1])
}

// unpackCountryCode unpacks a uint16 country code back to a 2-letter string.
func unpackCountryCode(packed uint16) string {
	if packed == 0 {
		return ""
	}
	return string([]byte{byte(packed >> 8), byte(packed & 0xFF)})
}

// ipToU32BE converts a net.IP (IPv4) to a big-endian uint32.
func ipToU32BE(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// Compile-time size checks to ensure struct layout matches BPF expectations.
var _ [8]byte = [unsafe.Sizeof(lpmKeyV4{})]byte{}
var _ [4]byte = [unsafe.Sizeof(geoipEntry{})]byte{}
