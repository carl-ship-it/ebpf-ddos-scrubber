package bpf

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"go.uber.org/zap"
)

// MapManager provides high-level operations on BPF maps.
type MapManager struct {
	log  *zap.Logger
	objs *Objects
}

// NewMapManager creates a new map manager.
func NewMapManager(log *zap.Logger, objs *Objects) *MapManager {
	return &MapManager{log: log, objs: objs}
}

// --- Config Map ---

// SetConfig sets a configuration value in the config map.
func (m *MapManager) SetConfig(key uint32, value uint64) error {
	if key >= CfgMax {
		return fmt.Errorf("config key %d out of range (max %d)", key, CfgMax)
	}
	return m.objs.ConfigMap.Update(key, value, ebpf.UpdateAny)
}

// GetConfig reads a configuration value from the config map.
func (m *MapManager) GetConfig(key uint32) (uint64, error) {
	var value uint64
	if err := m.objs.ConfigMap.Lookup(key, &value); err != nil {
		return 0, fmt.Errorf("reading config key %d: %w", key, err)
	}
	return value, nil
}

// --- Blacklist/Whitelist ---

// AddBlacklistCIDR adds a CIDR prefix to the blacklist.
func (m *MapManager) AddBlacklistCIDR(cidr string, reason uint32) error {
	key, err := cidrToLPMKey(cidr)
	if err != nil {
		return err
	}
	if err := m.objs.BlacklistV4.Update(key, reason, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("adding blacklist entry %s: %w", cidr, err)
	}
	m.log.Debug("blacklist entry added", zap.String("cidr", cidr), zap.Uint32("reason", reason))
	return nil
}

// RemoveBlacklistCIDR removes a CIDR prefix from the blacklist.
func (m *MapManager) RemoveBlacklistCIDR(cidr string) error {
	key, err := cidrToLPMKey(cidr)
	if err != nil {
		return err
	}
	if err := m.objs.BlacklistV4.Delete(key); err != nil {
		return fmt.Errorf("removing blacklist entry %s: %w", cidr, err)
	}
	m.log.Debug("blacklist entry removed", zap.String("cidr", cidr))
	return nil
}

// AddWhitelistCIDR adds a CIDR prefix to the whitelist.
func (m *MapManager) AddWhitelistCIDR(cidr string) error {
	key, err := cidrToLPMKey(cidr)
	if err != nil {
		return err
	}
	var value uint32 = 1
	if err := m.objs.WhitelistV4.Update(key, value, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("adding whitelist entry %s: %w", cidr, err)
	}
	m.log.Debug("whitelist entry added", zap.String("cidr", cidr))
	return nil
}

// RemoveWhitelistCIDR removes a CIDR prefix from the whitelist.
func (m *MapManager) RemoveWhitelistCIDR(cidr string) error {
	key, err := cidrToLPMKey(cidr)
	if err != nil {
		return err
	}
	if err := m.objs.WhitelistV4.Delete(key); err != nil {
		return fmt.Errorf("removing whitelist entry %s: %w", cidr, err)
	}
	m.log.Debug("whitelist entry removed", zap.String("cidr", cidr))
	return nil
}

// --- Attack Signatures ---

// SetAttackSignature sets an attack signature at the given index.
func (m *MapManager) SetAttackSignature(index uint32, sig AttackSig) error {
	if index >= 256 {
		return fmt.Errorf("signature index %d out of range (max 255)", index)
	}
	return m.objs.AttackSigMap.Update(index, sig, ebpf.UpdateAny)
}

// SetAttackSignatureCount updates the number of active signatures.
func (m *MapManager) SetAttackSignatureCount(count uint32) error {
	var key uint32 = 0
	return m.objs.AttackSigCnt.Update(key, count, ebpf.UpdateAny)
}

// --- SYN Cookie ---

// UpdateSYNCookieSeeds sets new SYN cookie seeds.
func (m *MapManager) UpdateSYNCookieSeeds(current, previous uint32, updateNS uint64) error {
	var key uint32 = 0
	ctx := SYNCookieCtx{
		SeedCurrent:  current,
		SeedPrevious: previous,
		SeedUpdateNS: updateNS,
	}
	return m.objs.SYNCookieMap.Update(key, ctx, ebpf.UpdateAny)
}

// --- Statistics ---

// ReadStats reads and aggregates per-CPU global statistics.
func (m *MapManager) ReadStats() (*GlobalStats, error) {
	var key uint32 = 0
	var perCPU []GlobalStats

	if err := m.objs.StatsMap.Lookup(key, &perCPU); err != nil {
		return nil, fmt.Errorf("reading stats: %w", err)
	}

	// Aggregate across all CPUs
	agg := &GlobalStats{}
	for i := range perCPU {
		agg.RxPackets += perCPU[i].RxPackets
		agg.RxBytes += perCPU[i].RxBytes
		agg.TxPackets += perCPU[i].TxPackets
		agg.TxBytes += perCPU[i].TxBytes
		agg.DroppedPackets += perCPU[i].DroppedPackets
		agg.DroppedBytes += perCPU[i].DroppedBytes
		agg.SYNFloodDropped += perCPU[i].SYNFloodDropped
		agg.UDPFloodDropped += perCPU[i].UDPFloodDropped
		agg.ICMPFloodDropped += perCPU[i].ICMPFloodDropped
		agg.ACKFloodDropped += perCPU[i].ACKFloodDropped
		agg.DNSAmpDropped += perCPU[i].DNSAmpDropped
		agg.NTPAmpDropped += perCPU[i].NTPAmpDropped
		agg.FragmentDropped += perCPU[i].FragmentDropped
		agg.ACLDropped += perCPU[i].ACLDropped
		agg.RateLimited += perCPU[i].RateLimited
		agg.ConntrackNew += perCPU[i].ConntrackNew
		agg.ConntrackEstablished += perCPU[i].ConntrackEstablished
		agg.SYNCookiesSent += perCPU[i].SYNCookiesSent
		agg.SYNCookiesValidated += perCPU[i].SYNCookiesValidated
		agg.SYNCookiesFailed += perCPU[i].SYNCookiesFailed
		agg.GeoIPDropped += perCPU[i].GeoIPDropped
		agg.ReputationDropped += perCPU[i].ReputationDropped
		agg.ProtoViolationDropped += perCPU[i].ProtoViolationDropped
		agg.PayloadMatchDropped += perCPU[i].PayloadMatchDropped
		agg.TCPStateDropped += perCPU[i].TCPStateDropped
		agg.SSDPAmpDropped += perCPU[i].SSDPAmpDropped
		agg.MemcachedAmpDropped += perCPU[i].MemcachedAmpDropped
		agg.ThreatIntelDropped += perCPU[i].ThreatIntelDropped
		agg.ReputationAutoBlocked += perCPU[i].ReputationAutoBlocked
		agg.EscalationUpgrades += perCPU[i].EscalationUpgrades
		agg.DNSQueriesValidated += perCPU[i].DNSQueriesValidated
		agg.DNSQueriesBlocked += perCPU[i].DNSQueriesBlocked
		agg.NTPMonlistBlocked += perCPU[i].NTPMonlistBlocked
		agg.TCPStateViolations += perCPU[i].TCPStateViolations
		agg.PortScanDetected += perCPU[i].PortScanDetected
	}

	return agg, nil
}

// --- Port Protocol Map ---

// SetPortProtocol marks a port as an amplification-sensitive protocol.
func (m *MapManager) SetPortProtocol(port uint16, flags uint32) error {
	bePort := hostToBE16(port)
	return m.objs.PortProtoMap.Update(bePort, flags, ebpf.UpdateAny)
}

// --- GRE Tunnels ---

// AddGRETunnel maps a destination prefix to a GRE tunnel endpoint.
func (m *MapManager) AddGRETunnel(cidr string, tunnelEndpoint net.IP) error {
	key, err := cidrToLPMKey(cidr)
	if err != nil {
		return err
	}
	endpointBE := IPToU32BE(tunnelEndpoint)
	return m.objs.GREtunnels.Update(key, endpointBE, ebpf.UpdateAny)
}

// --- Conntrack ---

// ConntrackCount returns the approximate number of conntrack entries.
func (m *MapManager) ConntrackCount() (int, error) {
	var (
		key   ConntrackKey
		value []ConntrackEntry // per-CPU slice
		count int
	)
	iter := m.objs.ConntrackMap.Iterate()
	for iter.Next(&key, &value) {
		count++
	}
	return count, iter.Err()
}

// FlushConntrack removes all entries from the conntrack map.
func (m *MapManager) FlushConntrack() error {
	var key ConntrackKey
	var value []ConntrackEntry // per-CPU slice required for LRU_PERCPU_HASH
	var keys []ConntrackKey

	iter := m.objs.ConntrackMap.Iterate()
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterating conntrack: %w", err)
	}

	for _, k := range keys {
		m.objs.ConntrackMap.Delete(k)
	}

	m.log.Info("conntrack flushed", zap.Int("entries_removed", len(keys)))
	return nil
}

// --- Helpers ---

func cidrToLPMKey(cidr string) (LPMKeyV4, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as a single IP
		ip := net.ParseIP(cidr)
		if ip == nil {
			return LPMKeyV4{}, fmt.Errorf("invalid CIDR or IP: %s", cidr)
		}
		return LPMKeyV4{
			PrefixLen: 32,
			Addr:      IPToU32BE(ip),
		}, nil
	}

	ones, _ := ipNet.Mask.Size()
	return LPMKeyV4{
		PrefixLen: uint32(ones),
		Addr:      IPToU32BE(ipNet.IP),
	}, nil
}

func hostToBE16(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return binary.LittleEndian.Uint16(buf[:])
}
