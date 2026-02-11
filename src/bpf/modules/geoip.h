// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_GEOIP_H__
#define __MOD_GEOIP_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== GeoIP Blocking Module =====
 * Looks up the source IP in the GeoIP LPM trie to obtain a country code,
 * then checks the per-country policy map for the configured action.
 *
 * Actions:
 *   GEOIP_ACTION_PASS       - Allow traffic (default)
 *   GEOIP_ACTION_DROP       - Drop traffic from this country
 *   GEOIP_ACTION_RATE_LIMIT - Apply 50% stricter rate via adaptive_rate_map
 *   GEOIP_ACTION_MONITOR    - Pass but emit event for monitoring
 *
 * At ESCALATION_CRITICAL, IPs with no country mapping are treated as DROP.
 *
 * Returns:
 *   VERDICT_PASS - Allowed
 *   VERDICT_DROP - Blocked by GeoIP policy
 */

/* Default adaptive rate divisor: 50% stricter means rate = current / 2 */
#define GEOIP_RATE_LIMIT_DIVISOR 2

static __always_inline int geoip_check(struct packet_ctx *pkt,
                                        struct global_stats *stats)
{
    /* Check if GeoIP module is enabled */
    if (!get_config(CFG_GEOIP_ENABLE))
        return VERDICT_PASS;

    __u64 escalation = get_config(CFG_ESCALATION_LEVEL);

    /* Build LPM trie key for source IP lookup */
    struct lpm_key_v4 lpm_key = {
        .prefixlen = 32,
        .addr = pkt->src_ip,
    };

    struct geoip_entry *geo;
    geo = bpf_map_lookup_elem(&geoip_map, &lpm_key);

    if (!geo) {
        /*
         * No GeoIP entry for this IP prefix.
         * At ESCALATION_CRITICAL, treat unknown origins as hostile.
         */
        if (escalation >= ESCALATION_CRITICAL) {
            if (stats) {
                stats->geoip_dropped++;
                stats_drop(stats, pkt->pkt_len);
            }
            emit_event(pkt, ATTACK_GEOIP_BLOCK, 1, DROP_GEOIP, 0, 0);
            return VERDICT_DROP;
        }
        return VERDICT_PASS;
    }

    __u16 country = geo->country_code;

    /* Look up per-country policy */
    __u8 *policy;
    policy = bpf_map_lookup_elem(&geoip_policy, &country);

    __u8 action;
    if (policy) {
        action = *policy;
    } else {
        /*
         * No explicit policy for this country.
         * At ESCALATION_CRITICAL, drop countries with no explicit allow.
         */
        if (escalation >= ESCALATION_CRITICAL) {
            if (stats) {
                stats->geoip_dropped++;
                stats_drop(stats, pkt->pkt_len);
            }
            emit_event(pkt, ATTACK_GEOIP_BLOCK, 1, DROP_GEOIP, 0, 0);
            return VERDICT_DROP;
        }
        return VERDICT_PASS;
    }

    switch (action) {
    case GEOIP_ACTION_DROP:
        if (stats) {
            stats->geoip_dropped++;
            stats_drop(stats, pkt->pkt_len);
        }
        emit_event(pkt, ATTACK_GEOIP_BLOCK, 1, DROP_GEOIP, 0, 0);
        return VERDICT_DROP;

    case GEOIP_ACTION_RATE_LIMIT: {
        /*
         * Apply 50% stricter rate limit for this source IP.
         * Look up the current adaptive rate; if none exists, read the
         * protocol-default from config and halve it.
         */
        __u64 *existing_rate;
        existing_rate = bpf_map_lookup_elem(&adaptive_rate_map, &pkt->src_ip);

        if (!existing_rate) {
            /* Determine base rate from protocol config */
            __u64 base_rate;
            switch (pkt->ip_proto) {
            case IPPROTO_TCP:
                base_rate = get_config(CFG_SYN_RATE_PPS);
                break;
            case IPPROTO_UDP:
                base_rate = get_config(CFG_UDP_RATE_PPS);
                break;
            case IPPROTO_ICMP:
                base_rate = get_config(CFG_ICMP_RATE_PPS);
                break;
            default:
                base_rate = get_config(CFG_GLOBAL_PPS_LIMIT);
                break;
            }

            if (base_rate > 0) {
                __u64 stricter_rate = base_rate / GEOIP_RATE_LIMIT_DIVISOR;
                if (stricter_rate == 0)
                    stricter_rate = 1;
                bpf_map_update_elem(&adaptive_rate_map, &pkt->src_ip,
                                    &stricter_rate, BPF_NOEXIST);
            }
        }
        /* Pass the packet; rate_limiter module will enforce the override */
        return VERDICT_PASS;
    }

    case GEOIP_ACTION_MONITOR:
        /* Pass traffic but emit an event so userspace can track it */
        emit_event(pkt, ATTACK_GEOIP_BLOCK, 0, 0, 0, 0);
        return VERDICT_PASS;

    default:
        /* GEOIP_ACTION_PASS or unknown action — allow */
        break;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_GEOIP_H__ */
