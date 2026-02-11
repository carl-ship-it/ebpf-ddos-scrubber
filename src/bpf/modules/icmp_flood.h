// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_ICMP_FLOOD_H__
#define __MOD_ICMP_FLOOD_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== ICMP Flood Mitigation Module =====
 *
 * Policies:
 * 1. Drop ICMP packets larger than threshold (Ping of Death / smurf)
 * 2. Only allow Echo Request/Reply, Dest Unreachable, Time Exceeded
 * 3. Rate limit ICMP per source (handled by rate_limiter module)
 *
 * Returns:
 *   VERDICT_PASS - Legitimate ICMP
 *   VERDICT_DROP - Suspicious ICMP
 */

/* Maximum allowed ICMP packet size (bytes, IP payload) */
#define ICMP_MAX_SIZE   1024

/* Allowed ICMP types */
#define ICMP_ECHO_REPLY          0
#define ICMP_DEST_UNREACHABLE    3
#define ICMP_ECHO_REQUEST        8
#define ICMP_TIME_EXCEEDED      11

static __always_inline int icmp_flood_check(struct packet_ctx *pkt,
                                             struct global_stats *stats)
{
    if (pkt->ip_proto != IPPROTO_ICMP)
        return VERDICT_PASS;

    if (!pkt->icmp)
        return VERDICT_PASS;

    struct icmphdr *icmp = pkt->icmp;
    if ((void *)(icmp + 1) > pkt->data_end)
        return VERDICT_PASS;

    __u8 type = icmp->type;

    /* ---- Size check: drop oversized ICMP ---- */
    if (pkt->l4_payload_len + sizeof(struct icmphdr) > ICMP_MAX_SIZE) {
        if (stats)
            stats->icmp_flood_dropped++;
        emit_event(pkt, ATTACK_ICMP_FLOOD, 1, DROP_ICMP_FLOOD, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- Type filter: only allow specific ICMP types ---- */
    if (type != ICMP_ECHO_REPLY &&
        type != ICMP_DEST_UNREACHABLE &&
        type != ICMP_ECHO_REQUEST &&
        type != ICMP_TIME_EXCEEDED) {
        if (stats)
            stats->icmp_flood_dropped++;
        emit_event(pkt, ATTACK_ICMP_FLOOD, 1, DROP_ICMP_FLOOD, 0, 0);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_ICMP_FLOOD_H__ */
