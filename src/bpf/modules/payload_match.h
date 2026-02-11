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
 * Takes struct xdp_md *ctx to re-derive fresh packet pointers that the
 * BPF verifier can track (stack-stored pointers lose their type).
 *
 * Returns:
 *   VERDICT_PASS - No matching rule, or rule action is monitor/rate-limit
 *   VERDICT_DROP - Matched a rule with action=drop
 */

/* Maximum rules to check per packet */
#define PAYLOAD_MAX_CHECK  8

/* Rate-limit divisor for payload-flagged sources */
#define PAYLOAD_RATE_LIMIT_DIVISOR 4

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

/* Check a single payload rule using fresh data/data_end from ctx.
 * Returns -1 if no match, else verdict. */
static __always_inline int check_payload_rule(struct xdp_md *ctx,
                                               struct packet_ctx *pkt,
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

    /* Payload offset from packet start (pre-computed in parser) */
    __u16 poff = pkt->payload_offset;
    if (poff == 0)
        return -1;

    __u16 rule_offset = rule->offset;
    __u32 total_offset = (__u32)poff + (__u32)rule_offset;

    /* Clamp to prevent verifier complaints about unbounded offset */
    if (total_offset > 1500)
        return -1;

    /* Re-derive fresh data/data_end from ctx (verifier trusts these) */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u8 *match_start = (__u8 *)data + total_offset;

    /* Bounds check: ensure all pat_len bytes are within packet */
    if ((__u8 *)match_start + pat_len > (__u8 *)data_end)
        return -1;

    /* Also verify against declared payload length */
    if ((__u32)rule_offset + (__u32)pat_len > (__u32)pkt->l4_payload_len)
        return -1;

    /* Byte-by-byte masked comparison (manually unrolled, no loop) */
    __u8 *pattern = rule->pattern;
    __u8 *mask = rule->mask;

#define _PM_CMP(n) \
    if ((n) < pat_len && ((match_start[n] & mask[n]) != (pattern[n] & mask[n]))) \
        return -1

    _PM_CMP(0);  _PM_CMP(1);  _PM_CMP(2);  _PM_CMP(3);
    _PM_CMP(4);  _PM_CMP(5);  _PM_CMP(6);  _PM_CMP(7);
    _PM_CMP(8);  _PM_CMP(9);  _PM_CMP(10); _PM_CMP(11);
    _PM_CMP(12); _PM_CMP(13); _PM_CMP(14); _PM_CMP(15);

#undef _PM_CMP

    /* Matched — handle action */
    return payload_handle_action(rule, pkt, stats);
}

/* Macro for manual unroll */
#define _CHECK_PRULE(idx) do {                              \
    if ((idx) < rule_count) {                               \
        __u32 _k = (idx);                                   \
        int _v = check_payload_rule(ctx, pkt, stats, _k);   \
        if (_v >= 0)                                        \
            return _v;                                      \
    }                                                       \
} while(0)

static __always_inline int payload_match_check(struct xdp_md *ctx,
                                                struct packet_ctx *pkt,
                                                struct global_stats *stats)
{
    /* Check if payload match module is enabled */
    if (!get_config(CFG_PAYLOAD_MATCH_EN))
        return VERDICT_PASS;

    /* No payload to inspect */
    if (pkt->payload_offset == 0 || pkt->l4_payload_len == 0)
        return VERDICT_PASS;

    /* Read the active rule count */
    __u32 zero = 0;
    __u32 *count_ptr = bpf_map_lookup_elem(&payload_rule_count, &zero);
    if (!count_ptr || *count_ptr == 0)
        return VERDICT_PASS;

    __u32 rule_count = *count_ptr;
    if (rule_count > PAYLOAD_MAX_CHECK)
        rule_count = PAYLOAD_MAX_CHECK;

    /* Manually unrolled — no for-loop back-edge */
    _CHECK_PRULE(0);
    _CHECK_PRULE(1);
    _CHECK_PRULE(2);
    _CHECK_PRULE(3);
    _CHECK_PRULE(4);
    _CHECK_PRULE(5);
    _CHECK_PRULE(6);
    _CHECK_PRULE(7);

    return VERDICT_PASS;
}

#undef _CHECK_PRULE

#endif /* __MOD_PAYLOAD_MATCH_H__ */
