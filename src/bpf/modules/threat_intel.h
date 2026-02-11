// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_THREAT_INTEL_H__
#define __MOD_THREAT_INTEL_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== Threat Intelligence Feed Module =====
 *
 * Checks source IPs against external threat intelligence feeds loaded
 * into an LPM trie by the control plane. Supports feeds from Spamhaus,
 * AbuseIPDB, Emerging Threats, and custom operator lists.
 *
 * Each entry carries:
 *   - source_id:  Feed origin identifier
 *   - threat_type: Classification (botnet, scanner, tor_exit, proxy, malware)
 *   - confidence: 0-100 confidence score from the feed
 *   - action:     0=drop, 1=rate-limit, 2=monitor
 *
 * Confidence thresholds are adjusted by escalation level:
 *   ESCALATION_LOW/MEDIUM:  drop >= 80, rate-limit >= 50
 *   ESCALATION_HIGH:        drop >= 50, rate-limit >= 30
 *   ESCALATION_CRITICAL:    drop >= 30, rate-limit >= 10
 *
 * The LPM trie supports both /32 exact matches and CIDR prefixes for
 * blocking entire ranges published by threat feeds.
 *
 * Returns:
 *   VERDICT_PASS - Not in threat intel, or below confidence threshold
 *   VERDICT_DROP - Known-bad IP above confidence threshold with action=drop
 */

/* Rate-limit divisor for threat-intel flagged sources */
#define THREAT_INTEL_RATE_LIMIT_DIVISOR 4

static __always_inline int threat_intel_check(struct packet_ctx *pkt,
                                               struct global_stats *stats)
{
    /* Check if threat intel module is enabled */
    if (!get_config(CFG_THREAT_INTEL_EN))
        return VERDICT_PASS;

    __u64 escalation = get_config(CFG_ESCALATION_LEVEL);

    /* Build LPM trie key for source IP lookup */
    struct lpm_key_v4 lpm_key = {
        .prefixlen = 32,
        .addr = pkt->src_ip,
    };

    struct threat_intel_entry *entry;
    entry = bpf_map_lookup_elem(&threat_intel_map, &lpm_key);

    if (!entry)
        return VERDICT_PASS;

    /*
     * Determine confidence thresholds based on escalation level.
     * Higher escalation means we act on lower confidence scores,
     * catching more potential threats at the cost of more false positives.
     */
    __u8 drop_threshold;
    __u8 rate_limit_threshold;

    if (escalation >= ESCALATION_CRITICAL) {
        drop_threshold = 30;
        rate_limit_threshold = 10;
    } else if (escalation >= ESCALATION_HIGH) {
        drop_threshold = 50;
        rate_limit_threshold = 30;
    } else {
        /* ESCALATION_LOW and ESCALATION_MEDIUM */
        drop_threshold = 80;
        rate_limit_threshold = 50;
    }

    __u8 confidence = entry->confidence;
    __u8 action = entry->action;

    switch (action) {
    case 0: /* Drop */
        if (confidence >= drop_threshold) {
            if (stats) {
                stats->threat_intel_dropped++;
                stats_drop(stats, pkt->pkt_len);
            }
            emit_event(pkt, ATTACK_THREAT_INTEL, 1, DROP_THREAT_INTEL, 0, 0);
            return VERDICT_DROP;
        }
        break;

    case 1: {
        /* Rate-limit: mark source IP for stricter rate limiting */
        if (confidence >= rate_limit_threshold) {
            __u64 *existing_rate;
            existing_rate = bpf_map_lookup_elem(&adaptive_rate_map, &pkt->src_ip);

            if (!existing_rate) {
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
                    __u64 stricter = base_rate / THREAT_INTEL_RATE_LIMIT_DIVISOR;
                    if (stricter == 0)
                        stricter = 1;
                    bpf_map_update_elem(&adaptive_rate_map, &pkt->src_ip,
                                        &stricter, BPF_NOEXIST);
                }
            }
        }
        /* Pass the packet; rate_limiter module enforces the override */
        return VERDICT_PASS;
    }

    case 2:
        /* Monitor: log the match for visibility but allow the packet */
        emit_event(pkt, ATTACK_THREAT_INTEL, 0, 0, 0, 0);
        return VERDICT_PASS;

    default:
        break;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_THREAT_INTEL_H__ */
