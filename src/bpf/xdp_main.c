// SPDX-License-Identifier: GPL-2.0
/*
 * XDP DDoS Scrubber — Main Entry Point (v2: Advanced Defense)
 *
 * 18-stage processing pipeline:
 *   1.  Parse packet (Ethernet → IPv4 → L4 → Payload)
 *   2.  Whitelist/Blacklist ACL check
 *   3.  Threat intelligence feed check
 *   4.  GeoIP country-based filtering
 *   5.  IP Reputation score check
 *   6.  IP Fragment detection
 *   7.  Attack signature fingerprint matching
 *   8.  Payload pattern matching
 *   9.  Deep protocol validation (DNS/NTP/SSDP/Memcached)
 *  10.  TCP state machine validation
 *  11.  SYN Flood mitigation (SYN Cookie)
 *  12.  ACK Flood detection (requires conntrack)
 *  13.  UDP Flood & Amplification detection
 *  14.  ICMP Flood mitigation
 *  15.  Per-source rate limiting (adaptive)
 *  16.  Global rate limiting
 *  17.  Connection tracking update
 *  18.  Statistics update → XDP_PASS
 */

#include "common/types.h"
#include "common/maps.h"
#include "common/helpers.h"
#include "common/parser.h"

#include "modules/acl.h"
#include "modules/threat_intel.h"
#include "modules/geoip.h"
#include "modules/reputation.h"
#include "modules/fragment.h"
#include "modules/fingerprint.h"
#include "modules/payload_match.h"
#include "modules/proto_validator.h"
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

    /* ---- Stage 3: Threat Intelligence Feed ---- */
    verdict = threat_intel_check(&pkt, stats);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 4: GeoIP Country Filtering ---- */
    verdict = geoip_check(&pkt, stats);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 5: IP Reputation Check ---- */
    verdict = reputation_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 6: Fragment detection ---- */
    verdict = fragment_check(&pkt, stats);
    if (verdict == VERDICT_DROP)
        return XDP_DROP;

    /* ---- Stage 7: Attack signature fingerprint ---- */
    verdict = fingerprint_check(&pkt, stats);
    if (verdict == VERDICT_DROP)
        return XDP_DROP;

    /* ---- Stage 8: Payload Pattern Matching ---- */
    verdict = payload_match_check(ctx, &pkt, stats);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 9-10: Deep Protocol Validation + TCP State ---- */
    verdict = proto_validate(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 11: SYN Flood (SYN Cookie) ---- */
    verdict = syn_flood_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_TX) {
        stats_tx(stats, pkt.pkt_len);
        return XDP_TX;
    }
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 12: ACK Flood ---- */
    verdict = ack_flood_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 13: UDP Flood & Amplification ---- */
    verdict = udp_flood_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 14: ICMP Flood ---- */
    verdict = icmp_flood_check(&pkt, stats);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 15: Per-Source Rate Limiting (Adaptive) ---- */
    verdict = rate_limit_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 16: Global Rate Limiting ---- */
    verdict = global_rate_check(&pkt, stats, now_ns);
    if (verdict == VERDICT_DROP) {
        stats_drop(stats, pkt.pkt_len);
        return XDP_DROP;
    }

    /* ---- Stage 17: Connection Tracking ---- */
    conntrack_update(&pkt, stats, now_ns);

    /* ---- Stage 18: Pass ---- */
    stats_tx(stats, pkt.pkt_len);
    return XDP_PASS;
}
