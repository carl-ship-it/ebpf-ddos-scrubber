import numeral from 'numeral';

/** Format packets-per-second with SI suffix. */
export function formatPPS(pps: number): string {
  if (pps < 1000) return `${Math.round(pps)} pps`;
  return `${numeral(pps).format('0.0a')}pps`;
}

/** Format bits-per-second with SI suffix. */
export function formatBPS(bps: number): string {
  if (bps < 1000) return `${Math.round(bps)} bps`;
  if (bps < 1e6) return `${numeral(bps / 1e3).format('0.0')} Kbps`;
  if (bps < 1e9) return `${numeral(bps / 1e6).format('0.0')} Mbps`;
  return `${numeral(bps / 1e9).format('0.00')} Gbps`;
}

/** Format byte count with SI suffix. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${numeral(bytes / 1024).format('0.0')} KB`;
  if (bytes < 1073741824) return `${numeral(bytes / 1048576).format('0.0')} MB`;
  return `${numeral(bytes / 1073741824).format('0.00')} GB`;
}

/** Format large packet counts. */
export function formatCount(n: number): string {
  if (n < 1000) return String(n);
  return numeral(n).format('0.0a');
}

/** Format uptime seconds to human-readable. */
export function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  parts.push(`${s}s`);
  return parts.join(' ');
}

/** Protocol number to name. */
export function protoName(proto: number): string {
  switch (proto) {
    case 1: return 'ICMP';
    case 6: return 'TCP';
    case 17: return 'UDP';
    case 47: return 'GRE';
    default: return `Proto(${proto})`;
  }
}
