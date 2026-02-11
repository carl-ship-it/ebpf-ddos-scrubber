// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_PAYLOAD_MATCH_H__
#define __MOD_PAYLOAD_MATCH_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== Payload Pattern Matching Module =====
 *
 * Deep payload inspection engine that matches L4 payload content against
 * configurable pattern rules loaded by the control plane.
 *
 * Each rule specifies:
 *   - A byte pattern and mask (up to 64 bytes)
 *   - An offset from L4 payload start
 *   - Optional protocol and destination port filters
 *   - An action: 0=drop, 1=rate-limit, 2=monitor
 *
 * The mask field allows wildcard bytes (0x00 = don't care, 0xFF = must match).
 * Rules are stored in the payload_rules array map, with the active count
 * in payload_rule_count.
 *
 * Returns:
 *   VERDICT_PASS - No matching rule, or rule action is monitor/rate-limit
 *   VERDICT_DROP - Matched a rule with action=drop
 */

/* Maximum rules to check per packet (BPF verifier loop bound) */
#define PAYLOAD_MAX_CHECK  16

/* Rate-limit divisor for payload-flagged sources */
#define PAYLOAD_RATE_LIMIT_DIVISOR 4

static __always_inline int payload_match_check(struct packet_ctx *pkt,
                                                struct global_stats *stats)
{
    /* Check if payload match module is enabled */
    if (!get_config(CFG_PAYLOAD_MATCH_EN))
        return VERDICT_PASS;

    /* No payload to inspect */
    if (!pkt->payload || pkt->l4_payload_len == 0)
        return VERDICT_PASS;

    /* Read the active rule count */
    __u32 zero = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&payload_rule_count, &zero);
    if (!count_ptr || *count_ptr == 0)
        return VERDICT_PASS;

    __u32 rule_count = *count_ptr;
    if (rule_count > PAYLOAD_MAX_CHECK)
        rule_count = PAYLOAD_MAX_CHECK;

    #pragma unroll
    for (__u32 i = 0; i < PAYLOAD_MAX_CHECK; i++) {
        if (i >= rule_count)
            break;

        struct payload_rule *rule = bpf_map_lookup_elem(&payload_rules, &i);
        if (!rule)
            continue;

        /* Protocol filter: 0 means any protocol matches */
        if (rule->protocol != 0 && rule->protocol != pkt->ip_proto)
            continue;

        /* Destination port filter: 0 means any port matches */
        if (rule->dst_port != 0 && rule->dst_port != pkt->dst_port)
            continue;

        /* Validate pattern length */
        __u16 pat_len = rule->pattern_len;
        if (pat_len == 0 || pat_len > PAYLOAD_PATTERN_MAX_LEN)
            continue;

        /* Bounds check: ensure payload region is within packet */
        __u16 offset = rule->offset;
        void *match_start = pkt->payload + offset;
        void *match_end = match_start + pat_len;

        if (match_end > pkt->data_end)
            continue;

        if (match_start >= pkt->data_end)
            continue;

        /* Check that offset + pattern_len doesn't exceed actual payload */
        if ((__u32)offset + (__u32)pat_len > (__u32)pkt->l4_payload_len)
            continue;

        /* Byte-by-byte masked pattern comparison.
         * The inner loop is bounded to PAYLOAD_PATTERN_MAX_LEN for
         * the BPF verifier. Each byte read is individually bounds-checked.
         */
        int matched = 1;

        #pragma unroll
        for (__u32 j = 0; j < PAYLOAD_PATTERN_MAX_LEN; j++) {
            if (j >= pat_len)
                break;

            /* Bounds check each individual byte access */
            __u8 *byte_ptr = (__u8 *)match_start + j;
            if ((__u8 *)byte_ptr + 1 > (__u8 *)pkt->data_end) {
                matched = 0;
                break;
            }

            __u8 payload_byte = *byte_ptr;
            __u8 mask_byte = rule->mask[j];
            __u8 pattern_byte = rule->pattern[j];

            if ((payload_byte & mask_byte) != (pattern_byte & mask_byte)) {
                matched = 0;
                break;
            }
        }

        if (!matched)
            continue;

        /* Pattern matched - take configured action */
        switch (rule->action) {
        case 0: /* Drop */
            /* Atomically increment hit_count via direct map value update */
            __sync_fetch_and_add(&rule->hit_count, 1);

            if (stats) {
                stats->payload_match_dropped++;
                stats_drop(stats, pkt->pkt_len);
            }
            emit_event(pkt, ATTACK_PAYLOAD_MATCH, 1, DROP_PAYLOAD_MATCH, 0, 0);
            return VERDICT_DROP;

        case 1: {
            /* Rate-limit: mark this source IP for stricter rate limiting */
            __sync_fetch_and_add(&rule->hit_count, 1);

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
                default:
                    base_rate = get_config(CFG_GLOBAL_PPS_LIMIT);
                    break;
                }

                if (base_rate > 0) {
                    __u64 stricter = base_rate / PAYLOAD_RATE_LIMIT_DIVISOR;
                    if (stricter == 0)
                        stricter = 1;
                    bpf_map_update_elem(&adaptive_rate_map, &pkt->src_ip,
                                        &stricter, BPF_NOEXIST);
                }
            }
            /* Pass the packet; rate_limiter module enforces the override */
            return VERDICT_PASS;
        }

        case 2:
            /* Monitor: log the match but allow the packet through */
            __sync_fetch_and_add(&rule->hit_count, 1);
            emit_event(pkt, ATTACK_PAYLOAD_MATCH, 0, 0, 0, 0);
            return VERDICT_PASS;

        default:
            break;
        }
    }

    return VERDICT_PASS;
}

#endif /* __MOD_PAYLOAD_MATCH_H__ */
