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
}

export interface ScrubberStatus {
  enabled: boolean;
  interfaceName: string;
  xdpMode: string;
  programId: number;
  uptimeSeconds: number;
  version: string;
}

export interface RateConfig {
  synRatePps: number;
  udpRatePps: number;
  icmpRatePps: number;
  globalPpsLimit: number;
  globalBpsLimit: number;
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
  | 'rst_flood';

export const PROTOCOL_NAMES: Record<number, string> = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
};
