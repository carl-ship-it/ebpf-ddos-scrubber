// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_CONNTRACK_H__
#define __MOD_CONNTRACK_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== Connection Tracking Module =====
 *
 * Lightweight connection tracking for TCP, UDP, and ICMP.
 * Creates and updates connection state entries.
 *
 * TCP state machine:
 *   NEW → SYN_SENT → SYN_RECV → ESTABLISHED → FIN_WAIT → CLOSED
 *
 * UDP/ICMP: Simplified NEW → ESTABLISHED (based on bidirectional traffic)
 *
 * Returns:
 *   VERDICT_PASS  - Always (conntrack is informational, doesn't drop)
 */

/* Connection timeout values (nanoseconds) */
#define CT_TIMEOUT_TCP_EST    (300ULL * 1000000000ULL)  /* 5 minutes */
#define CT_TIMEOUT_TCP_NEW    (30ULL * 1000000000ULL)   /* 30 seconds */
#define CT_TIMEOUT_UDP        (60ULL * 1000000000ULL)   /* 1 minute */
#define CT_TIMEOUT_ICMP       (30ULL * 1000000000ULL)   /* 30 seconds */

static __always_inline void conntrack_tcp_state_update(
    struct conntrack_entry *ct, __u8 tcp_flags, int is_fwd)
{
    switch (ct->state) {
    case CT_STATE_NEW:
        if (tcp_flags & TCP_FLAG_SYN) {
            ct->state = CT_STATE_SYN_SENT;
        }
        break;

    case CT_STATE_SYN_SENT:
        if ((tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
            (TCP_FLAG_SYN | TCP_FLAG_ACK) && !is_fwd) {
            ct->state = CT_STATE_SYN_RECV;
        }
        break;

    case CT_STATE_SYN_RECV:
        if ((tcp_flags & TCP_FLAG_ACK) && is_fwd) {
            ct->state = CT_STATE_ESTABLISHED;
        }
        break;

    case CT_STATE_ESTABLISHED:
        if (tcp_flags & TCP_FLAG_FIN) {
            ct->state = CT_STATE_FIN_WAIT;
        }
        if (tcp_flags & TCP_FLAG_RST) {
            ct->state = CT_STATE_CLOSED;
        }
        break;

    case CT_STATE_FIN_WAIT:
        if ((tcp_flags & TCP_FLAG_FIN) && !is_fwd) {
            ct->state = CT_STATE_CLOSED;
        }
        if (tcp_flags & TCP_FLAG_RST) {
            ct->state = CT_STATE_CLOSED;
        }
        break;
    }
}

static __always_inline int conntrack_update(struct packet_ctx *pkt,
                                             struct global_stats *stats,
                                             __u64 now_ns)
{
    __u64 ct_enabled = get_config(CFG_CONNTRACK_ENABLE);
    if (!ct_enabled)
        return VERDICT_PASS;

    /* Build conntrack key (forward direction) */
    struct conntrack_key ct_key = {
        .src_ip = pkt->src_ip,
        .dst_ip = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .protocol = pkt->ip_proto,
    };

    /* Try forward lookup */
    struct conntrack_entry *ct;
    ct = bpf_map_lookup_elem(&conntrack_map, &ct_key);

    if (ct) {
        /* Forward direction match */
        ct->last_seen_ns = now_ns;
        ct->packets_fwd++;
        ct->bytes_fwd += pkt->pkt_len;

        if (pkt->ip_proto == IPPROTO_TCP)
            conntrack_tcp_state_update(ct, pkt->tcp_flags, 1);

        return VERDICT_PASS;
    }

    /* Try reverse lookup */
    struct conntrack_key ct_key_rev = {
        .src_ip = pkt->dst_ip,
        .dst_ip = pkt->src_ip,
        .src_port = pkt->dst_port,
        .dst_port = pkt->src_port,
        .protocol = pkt->ip_proto,
    };

    ct = bpf_map_lookup_elem(&conntrack_map, &ct_key_rev);
    if (ct) {
        /* Reverse direction match */
        ct->last_seen_ns = now_ns;
        ct->packets_rev++;
        ct->bytes_rev += pkt->pkt_len;

        if (pkt->ip_proto == IPPROTO_TCP)
            conntrack_tcp_state_update(ct, pkt->tcp_flags, 0);

        /* Promote UDP/ICMP to established on bidirectional traffic */
        if (pkt->ip_proto != IPPROTO_TCP &&
            ct->state == CT_STATE_NEW) {
            ct->state = CT_STATE_ESTABLISHED;
            if (stats)
                stats->conntrack_established++;
        }

        return VERDICT_PASS;
    }

    /* ---- New connection ---- */
    struct conntrack_entry new_ct = {
        .last_seen_ns = now_ns,
        .packets_fwd = 1,
        .packets_rev = 0,
        .bytes_fwd = pkt->pkt_len,
        .bytes_rev = 0,
        .state = CT_STATE_NEW,
        .flags = 0,
    };

    bpf_map_update_elem(&conntrack_map, &ct_key, &new_ct, BPF_NOEXIST);

    if (stats)
        stats->conntrack_new++;

    return VERDICT_PASS;
}

#endif /* __MOD_CONNTRACK_H__ */
