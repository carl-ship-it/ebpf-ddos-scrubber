/**
 * Realistic mock data generator for demo / development.
 * Simulates traffic patterns, attack spikes, and events.
 */

import type { StatsSnapshot, ScrubberEvent, ScrubberStatus } from '../types';

let tick = 0;
let baseRxPps = 85000;
let attackActive = false;
let attackType = '';
let attackStartTick = 0;

// Simulate attack every ~60 ticks, lasting 15-30 ticks
function maybeToggleAttack() {
  if (!attackActive && tick > 0 && tick % 60 < 2 && Math.random() > 0.5) {
    attackActive = true;
    attackStartTick = tick;
    const types = ['syn_flood', 'udp_flood', 'dns_amplification', 'ntp_amplification', 'icmp_flood'];
    attackType = types[Math.floor(Math.random() * types.length)];
  }
  if (attackActive && tick - attackStartTick > 15 + Math.random() * 15) {
    attackActive = false;
  }
}

function noise(base: number, pct: number): number {
  return base * (1 + (Math.random() - 0.5) * 2 * pct);
}

export function generateStats(): StatsSnapshot {
  tick++;
  maybeToggleAttack();

  const attackMultiplier = attackActive ? 3 + Math.random() * 8 : 1;
  const rxPps = noise(baseRxPps * attackMultiplier, 0.08);
  const rxBps = rxPps * (200 + Math.random() * 800) * 8;

  const dropRatio = attackActive ? 0.55 + Math.random() * 0.3 : 0.005 + Math.random() * 0.01;
  const dropPps = rxPps * dropRatio;
  const dropBps = rxBps * dropRatio;
  const txPps = rxPps - dropPps;
  const txBps = rxBps - dropBps;

  const synDropped = attackActive && attackType === 'syn_flood' ? noise(dropPps * 0.7, 0.1) : noise(12, 0.5);
  const udpDropped = attackActive && attackType === 'udp_flood' ? noise(dropPps * 0.6, 0.1) : noise(25, 0.5);
  const icmpDropped = attackActive && attackType === 'icmp_flood' ? noise(dropPps * 0.8, 0.1) : noise(3, 0.8);
  const dnsDropped = attackActive && attackType === 'dns_amplification' ? noise(dropPps * 0.65, 0.1) : noise(8, 0.5);
  const ntpDropped = attackActive && attackType === 'ntp_amplification' ? noise(dropPps * 0.6, 0.1) : noise(2, 0.8);

  return {
    timestampNs: Date.now() * 1e6,
    rxPackets: Math.floor(rxPps * tick),
    rxBytes: Math.floor(rxBps * tick / 8),
    txPackets: Math.floor(txPps * tick),
    txBytes: Math.floor(txBps * tick / 8),
    droppedPackets: Math.floor(dropPps * tick),
    droppedBytes: Math.floor(dropBps * tick / 8),
    synFloodDropped: Math.floor(synDropped),
    udpFloodDropped: Math.floor(udpDropped),
    icmpFloodDropped: Math.floor(icmpDropped),
    ackFloodDropped: Math.floor(noise(5, 0.6)),
    dnsAmpDropped: Math.floor(dnsDropped),
    ntpAmpDropped: Math.floor(ntpDropped),
    fragmentDropped: Math.floor(noise(1, 0.9)),
    aclDropped: Math.floor(noise(18, 0.4)),
    rateLimited: Math.floor(noise(attackActive ? dropPps * 0.15 : 30, 0.3)),
    conntrackNew: Math.floor(noise(1200, 0.2)),
    conntrackEstablished: Math.floor(noise(45000, 0.05)),
    synCookiesSent: Math.floor(noise(attackActive && attackType === 'syn_flood' ? 8000 : 50, 0.3)),
    synCookiesValidated: Math.floor(noise(attackActive && attackType === 'syn_flood' ? 1200 : 45, 0.3)),
    synCookiesFailed: Math.floor(noise(attackActive && attackType === 'syn_flood' ? 6800 : 5, 0.5)),
    // New advanced counters
    geoipDropped: Math.floor(noise(attackActive ? 2500 : 15, 0.5)),
    reputationDropped: Math.floor(noise(attackActive ? 4200 : 8, 0.6)),
    protoViolationDropped: Math.floor(noise(attackActive ? 1800 : 5, 0.5)),
    payloadMatchDropped: Math.floor(noise(attackActive ? 900 : 2, 0.7)),
    tcpStateDropped: Math.floor(noise(attackActive ? 600 : 3, 0.6)),
    ssdpAmpDropped: Math.floor(noise(attackActive ? 300 : 1, 0.8)),
    memcachedAmpDropped: Math.floor(noise(attackActive ? 150 : 0, 0.9)),
    threatIntelDropped: Math.floor(noise(attackActive ? 3500 : 20, 0.4)),
    reputationAutoBlocked: Math.floor(noise(attackActive ? 85 : 3, 0.5)),
    dnsQueriesValidated: Math.floor(noise(2500, 0.2)),
    dnsQueriesBlocked: Math.floor(noise(attackActive ? 1200 : 8, 0.5)),
    ntpMonlistBlocked: Math.floor(noise(attackActive ? 400 : 2, 0.6)),
    tcpStateViolations: Math.floor(noise(attackActive ? 800 : 5, 0.5)),
    portScanDetected: Math.floor(noise(attackActive ? 25 : 1, 0.7)),
    rxPps,
    rxBps,
    txPps,
    txBps,
    dropPps,
    dropBps,
  };
}

const randomIp = () =>
  `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;

const attackTypes = ['syn_flood', 'udp_flood', 'dns_amplification', 'ntp_amplification', 'icmp_flood', 'ack_flood', 'fragment', 'geoip_block', 'reputation', 'proto_violation', 'payload_match', 'threat_intel'];
const dropReasons = ['blacklist', 'rate_limit', 'syn_flood', 'udp_flood', 'icmp_flood', 'ack_invalid', 'dns_amp', 'ntp_amp', 'fragment', 'fingerprint', 'geoip', 'reputation', 'proto_invalid', 'payload_match', 'threat_intel', 'tcp_state'];
const protocols = [6, 17, 1];
const countries = ['CN', 'RU', 'US', 'BR', 'IN', 'VN', 'KR', 'DE', 'UA', 'ID', 'IR', 'PK', 'NG', 'TH', 'TR'];

export function generateEvent(): ScrubberEvent {
  const proto = protocols[Math.floor(Math.random() * protocols.length)];
  return {
    timestampNs: Date.now() * 1e6,
    srcIp: randomIp(),
    dstIp: '192.168.1.' + Math.floor(Math.random() * 10 + 100),
    srcPort: Math.floor(Math.random() * 64000) + 1024,
    dstPort: [80, 443, 53, 8080, 3306][Math.floor(Math.random() * 5)],
    protocol: proto,
    attackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
    action: Math.random() > 0.15 ? 'DROP' : 'PASS',
    dropReason: dropReasons[Math.floor(Math.random() * dropReasons.length)],
    ppsEstimate: Math.floor(noise(50000, 0.5)),
    bpsEstimate: Math.floor(noise(800000000, 0.5)),
    reputationScore: Math.floor(Math.random() * 1000),
    countryCode: countries[Math.floor(Math.random() * countries.length)],
    escalationLevel: attackActive ? (Math.random() > 0.5 ? 2 : 3) : (Math.random() > 0.7 ? 1 : 0),
  };
}

export function generateStatus(): ScrubberStatus {
  return {
    enabled: true,
    interfaceName: 'eth0',
    xdpMode: 'native',
    programId: 42,
    uptimeSeconds: tick,
    version: '2.0.0',
    escalationLevel: attackActive ? 2 : 0,
    pipelineStages: 18,
  };
}

export function isAttackActive(): boolean {
  return attackActive;
}

export function currentAttackType(): string {
  return attackActive ? attackType : '';
}

// Top attacker source IPs (simulated)
const topAttackerPool = Array.from({ length: 20 }, () => ({
  ip: randomIp(),
  country: ['CN', 'RU', 'US', 'BR', 'IN', 'VN', 'KR', 'DE', 'UA', 'ID'][Math.floor(Math.random() * 10)],
  asn: `AS${Math.floor(Math.random() * 60000 + 1000)}`,
}));

export function getTopAttackers() {
  return topAttackerPool
    .map((a) => ({
      ...a,
      pps: Math.floor(noise(attackActive ? 15000 : 200, 0.8)),
      bps: Math.floor(noise(attackActive ? 120000000 : 1600000, 0.8)),
      packets: Math.floor(noise(attackActive ? 500000 : 8000, 0.3) * tick),
      blocked: Math.floor(noise(attackActive ? 480000 : 200, 0.3) * tick),
    }))
    .sort((a, b) => b.pps - a.pps)
    .slice(0, 10);
}
