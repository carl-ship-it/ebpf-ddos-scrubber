// SPDX-License-Identifier: GPL-2.0
#ifndef __MAPS_H__
#define __MAPS_H__

#include "types.h"

/* ===== Configuration Map =====
 * Array map holding runtime configuration values.
 * Indexed by CFG_* constants from types.h.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CFG_MAX);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");

/* ===== Blacklist (IPv4 CIDR) =====
 * LPM trie for source IP blacklisting.
 * Value: drop reason / attack type hint.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __u32);
} blacklist_v4 SEC(".maps");

/* ===== Whitelist (IPv4 CIDR) =====
 * LPM trie for source IP whitelisting.
 * Value: 1 = pass unconditionally.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 100000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __u32);
} whitelist_v4 SEC(".maps");

/* ===== Per-Source Rate Limiter =====
 * LRU hash keyed by source IP, per-CPU for lock-free operation.
 * Each entry is a token bucket.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 1000000);
    __type(key, __be32);
    __type(value, struct rate_limiter);
} rate_limit_map SEC(".maps");

/* ===== Connection Tracking =====
 * LRU hash keyed by 5-tuple, per-CPU for lock-free operation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __uint(max_entries, 2000000);
    __type(key, struct conntrack_key);
    __type(value, struct conntrack_entry);
} conntrack_map SEC(".maps");

/* ===== SYN Cookie Context =====
 * Array map with single entry holding seed data.
 * Updated periodically by control plane.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct syn_cookie_ctx);
} syn_cookie_map SEC(".maps");

/* ===== Attack Signatures =====
 * Array of up to 256 attack fingerprint rules.
 * Control plane populates from threat intel feeds.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct attack_sig);
} attack_sig_map SEC(".maps");

/* ===== Attack Signature Count =====
 * Single-entry array holding count of active signatures.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} attack_sig_count SEC(".maps");

/* ===== Global Statistics (per-CPU) =====
 * Single-entry per-CPU array for lock-free stats aggregation.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_stats);
} stats_map SEC(".maps");

/* ===== Event Ring Buffer =====
 * Ring buffer for sending events to userspace (drops, attacks, etc.)
 * 16 MB default, tunable via control plane.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

/* ===== Global Rate Limiter =====
 * Per-CPU array for aggregate PPS/BPS tracking.
 * Index 0: PPS counter, Index 1: BPS counter.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct rate_limiter);
} global_rate_map SEC(".maps");

/* ===== GRE Tunnel Endpoints =====
 * Maps destination IP prefix → GRE tunnel endpoint IP.
 * Used for traffic re-injection after scrubbing.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key_v4);
    __type(value, __be32);
} gre_tunnels SEC(".maps");

/* ===== Port Protocol Map =====
 * Hash map: dst_port → expected protocol behavior.
 * Used by amplification detection (DNS=53, NTP=123, etc.)
 * Value bits: [0]=dns, [1]=ntp, [2]=ssdp, [3]=memcached, [4]=chargen
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be16);
    __type(value, __u32);
} port_proto_map SEC(".maps");

#endif /* __MAPS_H__ */
