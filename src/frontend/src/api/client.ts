// REST API client for the scrubber control plane.
// Wraps fetch calls to the Go backend (which proxies to gRPC internally).

import type {
  ScrubberStatus,
  StatsSnapshot,
  RateConfig,
  ConntrackInfo,
  ACLEntry,
  AttackSignature,
} from '../types';

const BASE = '/api/v1';

async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API error ${res.status}: ${body}`);
  }
  return res.json();
}

// --- Status ---

export async function getStatus(): Promise<ScrubberStatus> {
  return request('/status');
}

export async function setEnabled(enabled: boolean): Promise<void> {
  await request('/status/enabled', {
    method: 'PUT',
    body: JSON.stringify({ enabled }),
  });
}

// --- Stats ---

export async function getStats(): Promise<StatsSnapshot> {
  return request('/stats');
}

// --- ACL ---

export async function getBlacklist(): Promise<ACLEntry[]> {
  return request('/acl/blacklist');
}

export async function addBlacklist(cidr: string, reason?: number): Promise<void> {
  await request('/acl/blacklist', {
    method: 'POST',
    body: JSON.stringify({ cidr, reason: reason ?? 1 }),
  });
}

export async function removeBlacklist(cidr: string): Promise<void> {
  await request('/acl/blacklist', {
    method: 'DELETE',
    body: JSON.stringify({ cidr }),
  });
}

export async function getWhitelist(): Promise<ACLEntry[]> {
  return request('/acl/whitelist');
}

export async function addWhitelist(cidr: string): Promise<void> {
  await request('/acl/whitelist', {
    method: 'POST',
    body: JSON.stringify({ cidr }),
  });
}

export async function removeWhitelist(cidr: string): Promise<void> {
  await request('/acl/whitelist', {
    method: 'DELETE',
    body: JSON.stringify({ cidr }),
  });
}

// --- Rate Limit ---

export async function getRateConfig(): Promise<RateConfig> {
  return request('/config/rate');
}

export async function setRateConfig(config: RateConfig): Promise<void> {
  await request('/config/rate', {
    method: 'PUT',
    body: JSON.stringify(config),
  });
}

// --- Conntrack ---

export async function getConntrackInfo(): Promise<ConntrackInfo> {
  return request('/conntrack');
}

export async function flushConntrack(): Promise<{ entriesRemoved: number }> {
  return request('/conntrack/flush', { method: 'POST' });
}

// --- Attack Signatures ---

export async function setAttackSignature(sig: AttackSignature): Promise<void> {
  await request('/signatures', {
    method: 'POST',
    body: JSON.stringify(sig),
  });
}

export async function clearAttackSignatures(): Promise<void> {
  await request('/signatures', { method: 'DELETE' });
}
