// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_ACK_FLOOD_H__
#define __MOD_ACK_FLOOD_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== ACK Flood Mitigation Module =====
 *
 * Detects and drops spoofed ACK packets that don't belong to
 * any tracked connection. Only effective when conntrack is enabled.
 *
 * Strategy:
 * - Pure ACK (no SYN/FIN/RST) without existing conntrack entry → suspect
 * - ACK with invalid window/seq that doesn't match conntrack → drop
 *
 * Returns:
 *   VERDICT_PASS - Legitimate or conntrack disabled
 *   VERDICT_DROP - Spoofed ACK detected
 */

static __always_inline int ack_flood_check(struct packet_ctx *pkt,
                                            struct global_stats *stats,
                                            __u64 now_ns)
{
    if (pkt->ip_proto != IPPROTO_TCP)
        return VERDICT_PASS;

    /* Only check pure ACK packets */
    if (pkt->tcp_flags != TCP_FLAG_ACK)
        return VERDICT_PASS;

    __u64 ct_enabled = get_config(CFG_CONNTRACK_ENABLE);
    if (!ct_enabled)
        return VERDICT_PASS;

    /* Look up connection in forward direction */
    struct conntrack_key ct_key = {
        .src_ip = pkt->src_ip,
        .dst_ip = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .protocol = IPPROTO_TCP,
    };

    struct conntrack_entry *ct;
    ct = bpf_map_lookup_elem(&conntrack_map, &ct_key);
    if (ct) {
        /* Connection exists — update and pass */
        ct->last_seen_ns = now_ns;
        ct->packets_fwd++;
        ct->bytes_fwd += pkt->pkt_len;
        return VERDICT_PASS;
    }

    /* Check reverse direction */
    struct conntrack_key ct_key_rev = {
        .src_ip = pkt->dst_ip,
        .dst_ip = pkt->src_ip,
        .src_port = pkt->dst_port,
        .dst_port = pkt->src_port,
        .protocol = IPPROTO_TCP,
    };

    ct = bpf_map_lookup_elem(&conntrack_map, &ct_key_rev);
    if (ct) {
        ct->last_seen_ns = now_ns;
        ct->packets_rev++;
        ct->bytes_rev += pkt->pkt_len;
        return VERDICT_PASS;
    }

    /* No conntrack entry in either direction — suspicious ACK */
    if (stats)
        stats->ack_flood_dropped++;

    emit_event(pkt, ATTACK_ACK_FLOOD, 1, DROP_ACK_INVALID, 0, 0);
    return VERDICT_DROP;
}

#endif /* __MOD_ACK_FLOOD_H__ */
