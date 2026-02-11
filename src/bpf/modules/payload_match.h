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
 * Uses manual unrolling (macros) to avoid BPF verifier "infinite loop"
 * rejection on kernel 5.14 where #pragma unroll fails for complex bodies.
 *
 * Returns:
 *   VERDICT_PASS - No matching rule, or rule action is monitor/rate-limit
 *   VERDICT_DROP - Matched a rule with action=drop
 */

/* Maximum rules to check per packet */
#define PAYLOAD_MAX_CHECK  8

/* Rate-limit divisor for payload-flagged sources */
#define PAYLOAD_RATE_LIMIT_DIVISOR 4

/* Inline byte-by-byte masked comparison for up to 16 bytes (no loop) */
static __always_inline int pattern_cmp_16(void *start, void *data_end,
                                           __u8 *pattern, __u8 *mask,
                                           __u16 len)
{
    __u8 *p = (__u8 *)start;

    if (p + 16 > (__u8 *)data_end)
        return 0;

#define _CMP_BYTE(n) \
    if ((n) < len && ((p[n] & mask[n]) != (pattern[n] & mask[n]))) return 0

    _CMP_BYTE(0);  _CMP_BYTE(1);  _CMP_BYTE(2);  _CMP_BYTE(3);
    _CMP_BYTE(4);  _CMP_BYTE(5);  _CMP_BYTE(6);  _CMP_BYTE(7);
    _CMP_BYTE(8);  _CMP_BYTE(9);  _CMP_BYTE(10); _CMP_BYTE(11);
    _CMP_BYTE(12); _CMP_BYTE(13); _CMP_BYTE(14); _CMP_BYTE(15);

#undef _CMP_BYTE

    return 1;
}

/* Handle the action for a matched payload rule. Returns verdict. */
static __always_inline int payload_handle_action(struct payload_rule *rule,
                                                  struct packet_ctx *pkt,
                                                  struct global_stats *stats)
{
    switch (rule->action) {
    case 0: /* Drop */
        __sync_fetch_and_add(&rule->hit_count, 1);
        if (stats) {
            stats->payload_match_dropped++;
            stats_drop(stats, pkt->pkt_len);
        }
        emit_event(pkt, ATTACK_PAYLOAD_MATCH, 1, DROP_PAYLOAD_MATCH, 0, 0);
        return VERDICT_DROP;

    case 1: {
        /* Rate-limit: mark source IP for stricter rate limiting */
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
        return VERDICT_PASS;
    }

    case 2:
        /* Monitor: log the match but allow the packet through */
        __sync_fetch_and_add(&rule->hit_count, 1);
        emit_event(pkt, ATTACK_PAYLOAD_MATCH, 0, 0, 0, 0);
        return VERDICT_PASS;

    default:
        return VERDICT_PASS;
    }
}

/* Check a single payload rule. Returns -1 if no match, else verdict. */
static __always_inline int check_one_rule(struct packet_ctx *pkt,
                                           struct global_stats *stats,
                                           __u32 idx)
{
    struct payload_rule *rule = bpf_map_lookup_elem(&payload_rules, &idx);
    if (!rule)
        return -1;

    /* Protocol filter */
    if (rule->protocol != 0 && rule->protocol != pkt->ip_proto)
        return -1;

    /* Destination port filter */
    if (rule->dst_port != 0 && rule->dst_port != pkt->dst_port)
        return -1;

    /* Validate pattern length */
    __u16 pat_len = rule->pattern_len;
    if (pat_len == 0 || pat_len > PAYLOAD_PATTERN_MAX_LEN)
        return -1;

    /* Bounds check */
    __u16 offset = rule->offset;
    void *match_start = pkt->payload + offset;

    if (match_start + pat_len > pkt->data_end)
        return -1;

    if (match_start >= pkt->data_end)
        return -1;

    if ((__u32)offset + (__u32)pat_len > (__u32)pkt->l4_payload_len)
        return -1;

    /* Manually unrolled 16-byte comparison (no inner loop) */
    if (!pattern_cmp_16(match_start, pkt->data_end,
                        rule->pattern, rule->mask, pat_len))
        return -1;

    /* Matched — handle action */
    return payload_handle_action(rule, pkt, stats);
}

/* Macro for manual unroll: check one rule index */
#define _CHECK_RULE(idx) do {                   \
    if ((idx) < rule_count) {                   \
        __u32 _k = (idx);                       \
        int _v = check_one_rule(pkt, stats, _k);\
        if (_v >= 0)                            \
            return _v;                          \
    }                                           \
} while(0)

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

    /* Manually unrolled — no for-loop back-edge for the verifier */
    _CHECK_RULE(0);
    _CHECK_RULE(1);
    _CHECK_RULE(2);
    _CHECK_RULE(3);
    _CHECK_RULE(4);
    _CHECK_RULE(5);
    _CHECK_RULE(6);
    _CHECK_RULE(7);

    return VERDICT_PASS;
}

#undef _CHECK_RULE

#endif /* __MOD_PAYLOAD_MATCH_H__ */
