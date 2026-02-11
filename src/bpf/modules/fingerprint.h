// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_FINGERPRINT_H__
#define __MOD_FINGERPRINT_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== Attack Signature Fingerprint Module =====
 *
 * Matches packets against known attack signatures loaded by control plane.
 * Each signature specifies protocol, TCP flags, port ranges, size ranges,
 * and optional payload hash.
 *
 * Uses manual unrolling (macro) to avoid BPF verifier "infinite loop"
 * rejection on kernel 5.14 where #pragma unroll fails for complex bodies.
 *
 * Returns:
 *   VERDICT_PASS - No matching signature
 *   VERDICT_DROP - Matched attack signature
 */

/* Maximum signatures to check per packet */
#define MAX_SIG_CHECK  8

static __always_inline __u32 payload_hash_4bytes(struct packet_ctx *pkt)
{
    void *payload;

    if (pkt->ip_proto == IPPROTO_TCP && pkt->tcp) {
        __u8 tcp_hdr_len = pkt->tcp->doff * 4;
        payload = (void *)pkt->tcp + tcp_hdr_len;
    } else if (pkt->ip_proto == IPPROTO_UDP && pkt->udp) {
        payload = (void *)(pkt->udp + 1);
    } else {
        return 0;
    }

    if (payload + 4 > pkt->data_end)
        return 0;

    return *(__u32 *)payload;
}

/* Single signature match check — inlined into unrolled macro calls */
static __always_inline int sig_matches(struct attack_sig *sig,
                                        struct packet_ctx *pkt,
                                        __u16 src_port_h, __u16 dst_port_h,
                                        __u32 *phash, int *phash_computed)
{
    /* Protocol match */
    if (sig->protocol != 0 && sig->protocol != pkt->ip_proto)
        return 0;

    /* TCP flags match (mask-based) */
    if (sig->flags_mask != 0) {
        if ((pkt->tcp_flags & sig->flags_mask) != sig->flags_match)
            return 0;
    }

    /* Source port range */
    __u16 sp_min = bpf_ntohs(sig->src_port_min);
    __u16 sp_max = bpf_ntohs(sig->src_port_max);
    if (sp_min != 0 || sp_max != 0) {
        if (src_port_h < sp_min || src_port_h > sp_max)
            return 0;
    }

    /* Destination port range */
    __u16 dp_min = bpf_ntohs(sig->dst_port_min);
    __u16 dp_max = bpf_ntohs(sig->dst_port_max);
    if (dp_min != 0 || dp_max != 0) {
        if (dst_port_h < dp_min || dst_port_h > dp_max)
            return 0;
    }

    /* Packet length range */
    if (sig->pkt_len_min != 0 || sig->pkt_len_max != 0) {
        if (pkt->pkt_len < sig->pkt_len_min ||
            pkt->pkt_len > sig->pkt_len_max)
            return 0;
    }

    /* Payload hash (lazy compute) */
    if (sig->payload_hash != 0) {
        if (!*phash_computed) {
            *phash = payload_hash_4bytes(pkt);
            *phash_computed = 1;
        }
        if (*phash != sig->payload_hash)
            return 0;
    }

    return 1;
}

/* Macro for manual unroll: check one signature index */
#define _CHECK_SIG(idx) do {                                                \
    if ((idx) < count) {                                                    \
        __u32 _k = (idx);                                                   \
        struct attack_sig *_sig = bpf_map_lookup_elem(&attack_sig_map, &_k);\
        if (_sig && sig_matches(_sig, pkt, src_port_h, dst_port_h,          \
                                &phash, &phash_computed)) {                 \
            if (stats) stats->acl_dropped++;                                \
            emit_event(pkt, ATTACK_NONE, 1, DROP_FINGERPRINT, 0, 0);       \
            return VERDICT_DROP;                                            \
        }                                                                   \
    }                                                                       \
} while(0)

static __always_inline int fingerprint_check(struct packet_ctx *pkt,
                                              struct global_stats *stats)
{
    __u32 zero = 0;
    __u32 *sig_count = bpf_map_lookup_elem(&attack_sig_count, &zero);
    if (!sig_count || *sig_count == 0)
        return VERDICT_PASS;

    __u32 count = *sig_count;
    if (count > MAX_SIG_CHECK)
        count = MAX_SIG_CHECK;

    __u16 src_port_h = bpf_ntohs(pkt->src_port);
    __u16 dst_port_h = bpf_ntohs(pkt->dst_port);
    __u32 phash = 0;
    int phash_computed = 0;

    /* Manually unrolled — no for-loop back-edge for the verifier */
    _CHECK_SIG(0);
    _CHECK_SIG(1);
    _CHECK_SIG(2);
    _CHECK_SIG(3);
    _CHECK_SIG(4);
    _CHECK_SIG(5);
    _CHECK_SIG(6);
    _CHECK_SIG(7);

    return VERDICT_PASS;
}

#undef _CHECK_SIG

#endif /* __MOD_FINGERPRINT_H__ */
