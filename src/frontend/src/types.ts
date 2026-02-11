// Shared type definitions matching the backend gRPC proto / BPF types.

export interface StatsSnapshot {
  timestampNs: number;

  // Counters
  rxPackets: number;
  rxBytes: number;
  txPackets: number;
  txBytes: number;
  droppedPackets: number;
  droppedBytes: number;

  // Per-attack
  synFloodDropped: number;
  udpFloodDropped: number;
  icmpFloodDropped: number;
  ackFloodDropped: number;
  dnsAmpDropped: number;
  ntpAmpDropped: number;
  fragmentDropped: number;
  aclDropped: number;
  rateLimited: number;

  // Conntrack
  conntrackNew: number;
  conntrackEstablished: number;

  // SYN Cookie
  synCookiesSent: number;
  synCookiesValidated: number;
  synCookiesFailed: number;

  // === New advanced counters ===
  geoipDropped: number;
  reputationDropped: number;
  protoViolationDropped: number;
  payloadMatchDropped: number;
  tcpStateDropped: number;
  ssdpAmpDropped: number;
  memcachedAmpDropped: number;
  threatIntelDropped: number;
  reputationAutoBlocked: number;
  dnsQueriesValidated: number;
  dnsQueriesBlocked: number;
  ntpMonlistBlocked: number;
  tcpStateViolations: number;
  portScanDetected: number;

  // Rates (computed)
  rxPps: number;
  rxBps: number;
  txPps: number;
  txBps: number;
  dropPps: number;
  dropBps: number;
}

export interface ScrubberEvent {
  timestampNs: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: number;
  attackType: string;
  action: string;
  dropReason: string;
  ppsEstimate: number;
  bpsEstimate: number;
  reputationScore?: number;
  countryCode?: string;
  escalationLevel?: number;
}

export interface ScrubberStatus {
  enabled: boolean;
  interfaceName: string;
  xdpMode: string;
  programId: number;
  uptimeSeconds: number;
  version: string;
  escalationLevel?: number;
  pipelineStages?: number;
}

export interface RateConfig {
  synRatePps: number;
  udpRatePps: number;
  icmpRatePps: number;
  globalPpsLimit: number;
  globalBpsLimit: number;
  adaptiveEnabled?: boolean;
}

export interface ACLEntry {
  cidr: string;
  reason?: number;
  addedAt?: string;
}

export interface ConntrackInfo {
  activeConnections: number;
  enabled: boolean;
}

export interface AttackSignature {
  index: number;
  protocol: number;
  flagsMask: number;
  flagsMatch: number;
  srcPortMin: number;
  srcPortMax: number;
  dstPortMin: number;
  dstPortMax: number;
  pktLenMin: number;
  pktLenMax: number;
  payloadHash: number;
}

export type AttackType =
  | 'none'
  | 'syn_flood'
  | 'udp_flood'
  | 'icmp_flood'
  | 'ack_flood'
  | 'dns_amplification'
  | 'ntp_amplification'
  | 'ssdp_amplification'
  | 'memcached_amplification'
  | 'fragment'
  | 'rst_flood'
  | 'geoip_block'
  | 'reputation'
  | 'proto_violation'
  | 'payload_match'
  | 'threat_intel';

export const PROTOCOL_NAMES: Record<number, string> = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
};

// === New types for advanced defense ===

export type EscalationLevel = 0 | 1 | 2 | 3;

export const ESCALATION_NAMES: Record<EscalationLevel, string> = {
  0: 'LOW',
  1: 'MEDIUM',
  2: 'HIGH',
  3: 'CRITICAL',
};

export const ESCALATION_COLORS: Record<EscalationLevel, string> = {
  0: '#52c41a',
  1: '#fadb14',
  2: '#fa8c16',
  3: '#f5222d',
};

export interface GeoIPPolicy {
  countryActions: Record<string, number>; // country_code → action
  enabled: boolean;
  totalEntries: number;
}

export interface IPReputationEntry {
  ip: string;
  score: number;
  totalPackets: number;
  droppedPackets: number;
  violationCount: number;
  blocked: boolean;
  firstSeen: number;
  lastSeen: number;
}

export interface EscalationTrigger {
  name: string;
  currentValue: number;
  threshold: number;
  active: boolean;
}

export interface EscalationEvent {
  timestampNs: number;
  fromLevel: EscalationLevel;
  toLevel: EscalationLevel;
  reason: string;
  triggers: EscalationTrigger[];
}

export interface BaselineMetrics {
  baselinePps: number;
  baselineBps: number;
  currentPps: number;
  currentBps: number;
  stdDevPps: number;
  stdDevBps: number;
  zScorePps: number;
  zScoreBps: number;
  isAnomaly: boolean;
  anomalyScore: number;
  learningComplete: boolean;
  samplesCollected: number;
}

export interface ThreatFeed {
  name: string;
  url: string;
  feedType: string;
  enabled: boolean;
  lastSync: number;
  entryCount: number;
  error: string;
}

export interface BGPStatus {
  connected: boolean;
  routerIp: string;
  localAs: number;
  peerAs: number;
  sessionState: string;
  activeBlackholes: number;
  activeFlowspec: number;
}

export interface PayloadRule {
  ruleId: number;
  pattern: string;
  mask: string;
  patternLen: number;
  offset: number;
  protocol: number;
  action: number;
  dstPort: number;
  hitCount: number;
  description: string;
}
