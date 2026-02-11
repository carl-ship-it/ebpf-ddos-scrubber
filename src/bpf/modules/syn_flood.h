// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_SYN_FLOOD_H__
#define __MOD_SYN_FLOOD_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== SYN Flood Mitigation Module =====
 *
 * Strategy:
 * 1. SYN Cookie: When enabled, responds to SYN with a crafted SYN-ACK.
 *    The ISN encodes source info via SipHash. On ACK return, we validate
 *    the cookie and create a conntrack entry.
 *
 * 2. SYN Rate Limiting: Per-source SYN rate check (handled by rate_limiter).
 *
 * This module handles the SYN Cookie challenge-response mechanism.
 */

/* Encode MSS option into 2 bits for SYN cookie */
static __always_inline __u8 mss_to_index(__u16 mss)
{
    if (mss >= 1460) return 3;
    if (mss >= 1220) return 2;
    if (mss >= 536)  return 1;
    return 0;
}

static __always_inline __u16 index_to_mss(__u8 idx)
{
    switch (idx & 0x3) {
    case 3: return 1460;
    case 2: return 1220;
    case 1: return 536;
    default: return 256;
    }
}

/* Generate SYN cookie value */
static __always_inline __u32 syn_cookie_generate(struct packet_ctx *pkt,
                                                   __u32 seed,
                                                   __u8 mss_idx)
{
    __u64 hash = siphash_2_4(
        (__u64)seed | ((__u64)seed << 32),
        0x0123456789abcdefULL,
        pkt->src_ip, pkt->dst_ip,
        bpf_ntohs(pkt->src_port), bpf_ntohs(pkt->dst_port)
    );

    /* Cookie format: [hash:30][mss_idx:2] */
    return ((__u32)(hash >> 2) << 2) | (mss_idx & 0x3);
}

/* Validate SYN cookie from ACK */
static __always_inline int syn_cookie_validate(struct packet_ctx *pkt,
                                                __u32 ack_seq)
{
    __u32 zero = 0;
    struct syn_cookie_ctx *sc;

    sc = bpf_map_lookup_elem(&syn_cookie_map, &zero);
    if (!sc)
        return 0;

    /* The client's ACK seq = our ISN + 1, so cookie = ack_seq - 1 */
    __u32 cookie = ack_seq - 1;
    __u8 mss_idx = cookie & 0x3;

    /* Try current seed */
    __u32 expected = syn_cookie_generate(pkt, sc->seed_current, mss_idx);
    if (cookie == expected)
        return 1;

    /* Try previous seed (for seed rotation window) */
    expected = syn_cookie_generate(pkt, sc->seed_previous, mss_idx);
    if (cookie == expected)
        return 1;

    return 0;
}

/* ===== SYN Flood check and response =====
 *
 * Returns:
 *   VERDICT_PASS - Not a SYN, or SYN Cookie disabled, or valid ACK
 *   VERDICT_TX   - SYN-ACK sent back (XDP_TX)
 *   VERDICT_DROP - Invalid ACK / failed cookie validation
 */
static __always_inline int syn_flood_check(struct packet_ctx *pkt,
                                            struct global_stats *stats,
                                            __u64 now_ns)
{
    if (pkt->ip_proto != IPPROTO_TCP)
        return VERDICT_PASS;

    if (!pkt->tcp)
        return VERDICT_PASS;

    __u64 syn_cookie_enabled = get_config(CFG_SYN_COOKIE_ENABLE);
    if (!syn_cookie_enabled)
        return VERDICT_PASS;

    /* ---- Handle incoming SYN ---- */
    if ((pkt->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN) {
        __u32 zero = 0;
        struct syn_cookie_ctx *sc;

        sc = bpf_map_lookup_elem(&syn_cookie_map, &zero);
        if (!sc)
            return VERDICT_PASS;

        /* Generate cookie ISN */
        __u8 mss_idx = mss_to_index(1460); /* Default MSS */
        __u32 cookie = syn_cookie_generate(pkt, sc->seed_current, mss_idx);

        /* Bounds check for header modification */
        struct ethhdr *eth = pkt->eth;
        struct iphdr *iph = pkt->iph;
        struct tcphdr *tcp = pkt->tcp;

        if ((void *)(tcp + 1) > pkt->data_end)
            return VERDICT_PASS;

        /* Swap Ethernet addresses */
        __u8 tmp_mac[6];
        __builtin_memcpy(tmp_mac, eth->h_dest, 6);
        __builtin_memcpy(eth->h_dest, eth->h_source, 6);
        __builtin_memcpy(eth->h_source, tmp_mac, 6);

        /* Swap IP addresses */
        __be32 tmp_ip = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = tmp_ip;
        iph->ttl = 64;
        iph->id = 0;

        /* Build SYN-ACK */
        __be16 tmp_port = tcp->source;
        tcp->source = tcp->dest;
        tcp->dest = tmp_port;

        tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
        tcp->seq = bpf_htonl(cookie);

        tcp->syn = 1;
        tcp->ack = 1;
        tcp->fin = 0;
        tcp->rst = 0;
        tcp->psh = 0;
        tcp->urg = 0;
        tcp->window = bpf_htons(65535);

        /* Recalculate IP checksum */
        iph->check = 0;
        /* Simple IP checksum - use bpf_csum_diff if available */
        __u32 csum = 0;
        __u16 *p = (__u16 *)iph;
        #pragma unroll
        for (int i = 0; i < 10; i++) {
            if ((void *)(p + 1) > pkt->data_end)
                break;
            csum += *p;
            p++;
        }
        iph->check = csum_fold(csum);

        /* Recalculate TCP checksum (simplified - zero and let NIC offload) */
        tcp->check = 0;

        if (stats)
            stats->syn_cookies_sent++;

        return VERDICT_TX;
    }

    /* ---- Handle ACK (cookie validation) ---- */
    if ((pkt->tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_ACK) {
        /* Only validate if no existing conntrack entry */
        struct conntrack_key ct_key = {
            .src_ip = pkt->src_ip,
            .dst_ip = pkt->dst_ip,
            .src_port = pkt->src_port,
            .dst_port = pkt->dst_port,
            .protocol = IPPROTO_TCP,
        };

        struct conntrack_entry *ct;
        ct = bpf_map_lookup_elem(&conntrack_map, &ct_key);

        /* Already tracked — pass through */
        if (ct && ct->state >= CT_STATE_ESTABLISHED)
            return VERDICT_PASS;

        /* Validate SYN cookie (use pre-extracted ack_seq from parser) */
        __u32 ack_seq = pkt->tcp_ack_seq;
        if (syn_cookie_validate(pkt, ack_seq)) {
            /* Valid cookie — create conntrack entry */
            struct conntrack_entry new_ct = {
                .last_seen_ns = now_ns,
                .packets_fwd = 1,
                .packets_rev = 0,
                .bytes_fwd = pkt->pkt_len,
                .bytes_rev = 0,
                .state = CT_STATE_ESTABLISHED,
                .flags = CT_FLAG_SYN_COOKIE_VERIFIED,
            };
            bpf_map_update_elem(&conntrack_map, &ct_key, &new_ct, BPF_ANY);

            if (stats)
                stats->syn_cookies_validated++;

            return VERDICT_PASS;
        }

        /* Invalid cookie — might be legitimate non-cookie ACK */
        if (!ct) {
            /* No conntrack and failed cookie = suspicious */
            if (stats)
                stats->syn_cookies_failed++;

            emit_event(pkt, ATTACK_SYN_FLOOD, 1, DROP_SYN_FLOOD, 0, 0);
            return VERDICT_DROP;
        }
    }

    return VERDICT_PASS;
}

#endif /* __MOD_SYN_FLOOD_H__ */
