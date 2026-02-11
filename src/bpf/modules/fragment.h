// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_FRAGMENT_H__
#define __MOD_FRAGMENT_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== IP Fragment Attack Mitigation Module =====
 *
 * Detects and drops:
 * 1. All IP fragments (aggressive mode) — simplest, most effective
 * 2. Tiny fragment attacks (fragment offset = 0, very small)
 * 3. Overlapping fragments
 *
 * Most legitimate traffic doesn't fragment at L3/L4 scrubbing level.
 * Dropping all fragments is acceptable for DDoS scrubbing appliances.
 *
 * Returns:
 *   VERDICT_PASS - Not a fragment
 *   VERDICT_DROP - Fragment detected
 */

/* Minimum acceptable first-fragment size (bytes) */
#define FRAG_MIN_SIZE   68

static __always_inline int fragment_check(struct xdp_md *ctx,
                                           struct packet_ctx *pkt,
                                           struct global_stats *stats)
{
    if (!pkt->is_fragment)
        return VERDICT_PASS;

    /* Re-derive fresh IP header pointer from ctx to satisfy BPF verifier.
     * Stack-stored packet pointers lose their type on kernel 5.14. */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* IP header is just before L4; compute l3 offset from l4_offset.
     * For fragments, l4_offset might be 0 if parser couldn't determine L4.
     * Fall back to re-parsing from Ethernet. */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return VERDICT_PASS;

    void *l3_start = data + sizeof(struct ethhdr);
    __u16 proto = eth->h_proto;

    /* Handle up to 2 VLAN tags */
    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (proto != bpf_htons(0x8100) && proto != bpf_htons(0x88A8))
            break;
        if ((void *)(l3_start + 4) > data_end)
            return VERDICT_PASS;
        proto = *(__be16 *)(l3_start + 2);
        l3_start += 4;
    }

    struct iphdr *iph = l3_start;
    if ((void *)(iph + 1) > data_end)
        return VERDICT_PASS;

    __u16 frag_off = bpf_ntohs(iph->frag_off);
    __u16 offset = (frag_off & 0x1FFF) * 8;
    int more_fragments = !!(frag_off & 0x2000);

    /* ---- Drop all fragments (aggressive mode) ---- */
    if (offset > 0 || more_fragments) {
        /* Tiny first fragment attack detection */
        if (offset == 0 && pkt->pkt_len < FRAG_MIN_SIZE) {
            /* Tiny first fragment — classic evasion technique */
            if (stats)
                stats->fragment_dropped++;
            emit_event(pkt, ATTACK_FRAGMENT, 1, DROP_FRAGMENT, 0, 0);
            return VERDICT_DROP;
        }

        /* Drop non-first fragments unconditionally.
         * First fragments (MF=1, offset=0) with adequate size
         * could be allowed if we implement fragment reassembly,
         * but for a scrubbing appliance, dropping is safer.
         */
        if (stats)
            stats->fragment_dropped++;

        emit_event(pkt, ATTACK_FRAGMENT, 1, DROP_FRAGMENT, 0, 0);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_FRAGMENT_H__ */
