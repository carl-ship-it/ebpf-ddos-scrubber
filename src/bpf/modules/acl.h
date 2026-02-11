// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_ACL_H__
#define __MOD_ACL_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== ACL Module =====
 * Checks source IP against whitelist/blacklist LPM tries.
 * Whitelist takes priority over blacklist.
 *
 * Returns:
 *   VERDICT_PASS  - Whitelisted or not in blacklist
 *   VERDICT_DROP  - Blacklisted
 */

static __always_inline int acl_check(struct packet_ctx *pkt,
                                      struct global_stats *stats)
{
    struct lpm_key_v4 key = {
        .prefixlen = 32,
        .addr = pkt->src_ip,
    };

    /* Whitelist check first — always takes priority */
    __u32 *wl = bpf_map_lookup_elem(&whitelist_v4, &key);
    if (wl)
        return VERDICT_PASS;

    /* Blacklist check */
    __u32 *bl = bpf_map_lookup_elem(&blacklist_v4, &key);
    if (bl) {
        if (stats)
            stats->acl_dropped++;

        emit_event(pkt, ATTACK_NONE, 1, DROP_BLACKLIST, 0, 0);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_ACL_H__ */
