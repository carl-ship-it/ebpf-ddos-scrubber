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

static __always_inline int fragment_check(struct packet_ctx *pkt,
                                           struct global_stats *stats)
{
    if (!pkt->is_fragment)
        return VERDICT_PASS;

    struct iphdr *iph = pkt->iph;
    if (!iph)
        return VERDICT_PASS;

    if ((void *)(iph + 1) > pkt->data_end)
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
