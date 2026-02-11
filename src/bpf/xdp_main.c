// SPDX-License-Identifier: GPL-2.0
/*
 * XDP DDoS Scrubber — Main Entry Point
 *
 * Processing pipeline:
 *   1. Parse packet (Ethernet → IPv4 → L4)
 *   2. Whitelist/Blacklist ACL check
 *   3. IP Fragment detection
 *   4. Attack signature fingerprint matching
 *   5. SYN Flood mitigation (SYN Cookie)
 *   6. ACK Flood detection (requires conntrack)
 *   7. UDP Flood & Amplification detection
 *   8. ICMP Flood mitigation
 *   9. Per-source rate limiting
 *  10. Global rate limiting
 *  11. Connection tracking update
 *  12. Statistics update → XDP_PASS
 */

#include "common/types.h"
#include "common/maps.h"
#include "common/helpers.h"
#include "common/parser.h"

#include "modules/acl.h"
#include "modules/fragment.h"
#include "modules/fingerprint.h"
#include "modules/syn_flood.h"
#include "modules/ack_flood.h"
#include "modules/udp_flood.h"
#include "modules/icmp_flood.h"
#include "modules/rate_limiter.h"
#include "modules/conntrack.h"

char _license[] SEC("license") = "GPL";

SEC("xdp")
int xdp_ddos_scrubber(struct xdp_md *ctx)
{
    struct packet_ctx pkt = {};
    struct global_stats *stats;
    int verdict;
    __u64 now_ns = bpf_ktime_get_ns();

    /* ---- Check if scrubber is enabled ---- */
    __u64 enabled = get_config(CFG_ENABLED);
    if (!enabled)
        return XDP_PASS;

    /* ---- Get per-CPU stats ---- */
    stats = get_stats();

    /* ---- Stage 1: Parse packet ---- */
    if (parse_packet(ctx, &pkt) < 0) {
        /* Malformed packet — count and drop */
        stats_drop(stats, 0);
        emit_event(&pkt, ATTACK_NONE, 1, DROP_PARSE_ERROR, 0, 0);
        return XDP_DROP;
    }

    /* Record RX stats */
    stats_rx(stats, pkt.pkt_len);

    /* ---- Stage 2: ACL (Whitelist/Blacklist) ---- */
    verdict = acl_check(&pkt, stats);
    if (verdict == VERDICT_DROP)
        return XDP_DROP;

    /* ---- Stage 3: Fragment detection ---- */
    verdict = fragment_check(&pkt, stats);
    if (verdict == VERDICT_DROP)
        return XDP_DROP;

    /* ---- Stage 4: Attack signature fingerprint ---- */
    verdict = fingerprint_check(&pkt, stats);
    if (verdict == VERDICT_DROP)
        return XDP_DROP;

    /* ---- Stage 5: SYN Flood (SYN Cookie) ---- */
    verdict = syn_flood_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_TX) {
        stats_tx(stats, pkt.pkt_len);
        return XDP_TX;
    }
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 6: ACK Flood ---- */
    verdict = ack_flood_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 7: UDP Flood & Amplification ---- */
    verdict = udp_flood_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 8: ICMP Flood ---- */
    verdict = icmp_flood_check(&pkt, stats);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 9: Per-Source Rate Limiting ---- */
    verdict = rate_limit_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 10: Global Rate Limiting ---- */
    verdict = global_rate_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 11: Connection Tracking ---- */
    conntrack_update(&pkt, stats, now_ns);

    /* ---- Stage 12: Pass ---- */
    stats_tx(stats, pkt.pkt_len);
    return XDP_PASS;
}
