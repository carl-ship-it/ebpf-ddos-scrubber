// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_RATE_LIMITER_H__
#define __MOD_RATE_LIMITER_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== Per-Source Rate Limiter Module =====
 * Token bucket rate limiter per source IP.
 * Limits are configured per protocol via config map.
 *
 * Returns:
 *   VERDICT_PASS - Within rate limit
 *   VERDICT_DROP - Rate exceeded
 */

static __always_inline int rate_limit_check(struct packet_ctx *pkt,
                                             struct global_stats *stats,
                                             __u64 now_ns)
{
    __u64 rate_pps;
    __u32 cfg_key;

    switch (pkt->ip_proto) {
    case IPPROTO_TCP:
        cfg_key = CFG_SYN_RATE_PPS;
        break;
    case IPPROTO_UDP:
        cfg_key = CFG_UDP_RATE_PPS;
        break;
    case IPPROTO_ICMP:
        cfg_key = CFG_ICMP_RATE_PPS;
        break;
    default:
        return VERDICT_PASS;
    }

    rate_pps = get_config(cfg_key);
    if (rate_pps == 0)
        return VERDICT_PASS; /* Not configured = no limit */

    /* Lookup or create per-source rate limiter */
    struct rate_limiter *rl;
    rl = bpf_map_lookup_elem(&rate_limit_map, &pkt->src_ip);

    if (!rl) {
        /* First packet from this source — initialize */
        struct rate_limiter new_rl = {
            .tokens = rate_pps,         /* Start with full bucket */
            .last_refill_ns = now_ns,
            .rate_pps = rate_pps,
            .burst_size = rate_pps * 2, /* Allow 2x burst */
            .total_packets = 0,
            .dropped_packets = 0,
        };
        bpf_map_update_elem(&rate_limit_map, &pkt->src_ip, &new_rl, BPF_NOEXIST);
        return VERDICT_PASS;
    }

    /* Update rate config in case it changed */
    rl->rate_pps = rate_pps;
    rl->burst_size = rate_pps * 2;

    if (token_bucket_consume(rl, now_ns, 1))
        return VERDICT_PASS;

    /* Rate exceeded */
    if (stats)
        stats->rate_limited++;

    emit_event(pkt, ATTACK_NONE, 1, DROP_RATE_LIMIT, 0, 0);
    return VERDICT_DROP;
}

/* ===== Global Rate Limiter =====
 * Checks aggregate PPS and BPS across all sources.
 */

static __always_inline int global_rate_check(struct packet_ctx *pkt,
                                              struct global_stats *stats,
                                              __u64 now_ns)
{
    __u64 pps_limit = get_config(CFG_GLOBAL_PPS_LIMIT);
    __u64 bps_limit = get_config(CFG_GLOBAL_BPS_LIMIT);

    if (pps_limit == 0 && bps_limit == 0)
        return VERDICT_PASS;

    /* PPS check */
    if (pps_limit > 0) {
        __u32 pps_key = 0;
        struct rate_limiter *pps_rl;
        pps_rl = bpf_map_lookup_elem(&global_rate_map, &pps_key);
        if (pps_rl) {
            pps_rl->rate_pps = pps_limit;
            pps_rl->burst_size = pps_limit * 2;
            if (!token_bucket_consume(pps_rl, now_ns, 1)) {
                if (stats)
                    stats->rate_limited++;
                return VERDICT_DROP;
            }
        }
    }

    /* BPS check */
    if (bps_limit > 0) {
        __u32 bps_key = 1;
        struct rate_limiter *bps_rl;
        bps_rl = bpf_map_lookup_elem(&global_rate_map, &bps_key);
        if (bps_rl) {
            bps_rl->rate_pps = bps_limit / 8; /* Convert bits to bytes/sec as rate */
            bps_rl->burst_size = (bps_limit / 8) * 2;
            if (!token_bucket_consume(bps_rl, now_ns, pkt->pkt_len)) {
                if (stats)
                    stats->rate_limited++;
                return VERDICT_DROP;
            }
        }
    }

    return VERDICT_PASS;
}

#endif /* __MOD_RATE_LIMITER_H__ */
