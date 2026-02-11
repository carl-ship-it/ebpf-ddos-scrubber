// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_REPUTATION_H__
#define __MOD_REPUTATION_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== IP Reputation Scoring Module =====
 * Maintains a per-source-IP reputation score that increases on violations
 * and decays over time. When the score exceeds a configurable threshold
 * the IP is auto-blocked.
 *
 * Includes port scan detection: if a source IP touches > 20 distinct
 * destination ports within a 10-second window, a REP_WEIGHT_PORT_SCAN
 * penalty is applied.
 *
 * Functions:
 *   reputation_check()    - Main verdict function (called from pipeline)
 *   reputation_penalize() - Add penalty points (called from other modules)
 *
 * Returns:
 *   VERDICT_PASS - Score below threshold
 *   VERDICT_DROP - Score at/above threshold or already blocked
 */

/* Port scan detection parameters */
#define PORT_SCAN_WINDOW_NS   10000000000ULL  /* 10 seconds in nanoseconds */
#define PORT_SCAN_THRESHOLD   20              /* Distinct ports before penalty */

/* Score decay interval: 1 second in nanoseconds */
#define REP_DECAY_INTERVAL_NS 1000000000ULL

/* ===== Port scan tracking =====
 * Track distinct destination ports per source IP.
 * Uses a 64-bit bitmap for ports 0-63 and a counter for higher ports.
 *
 * Returns the penalty weight to apply (0 if no scan detected).
 */
static __always_inline __u32 port_scan_detect(__be32 src_ip,
                                               __be16 dst_port,
                                               __u64 now_ns,
                                               struct global_stats *stats)
{
    struct port_scan_entry *ps;
    ps = bpf_map_lookup_elem(&port_scan_map, &src_ip);

    __u16 port = bpf_ntohs(dst_port);

    if (!ps) {
        /* First packet from this source — create entry */
        struct port_scan_entry new_ps = {};
        new_ps.window_start_ns = now_ns;
        new_ps.distinct_ports = 1;

        /* Set bit in bitmap for ports 0-63 */
        if (port < 32)
            new_ps.port_bitmap[0] = 1U << port;
        else if (port < 64)
            new_ps.port_bitmap[1] = 1U << (port - 32);

        bpf_map_update_elem(&port_scan_map, &src_ip, &new_ps, BPF_NOEXIST);
        return 0;
    }

    /* Check if window has expired — reset tracking */
    if (now_ns - ps->window_start_ns > PORT_SCAN_WINDOW_NS) {
        ps->window_start_ns = now_ns;
        ps->distinct_ports = 1;
        ps->port_bitmap[0] = 0;
        ps->port_bitmap[1] = 0;

        if (port < 32)
            ps->port_bitmap[0] = 1U << port;
        else if (port < 64)
            ps->port_bitmap[1] = 1U << (port - 32);

        return 0;
    }

    /* Check if this port was already seen (bitmap for 0-63) */
    int already_seen = 0;
    if (port < 32) {
        __u32 bit = 1U << port;
        if (ps->port_bitmap[0] & bit)
            already_seen = 1;
        else
            ps->port_bitmap[0] |= bit;
    } else if (port < 64) {
        __u32 bit = 1U << (port - 32);
        if (ps->port_bitmap[1] & bit)
            already_seen = 1;
        else
            ps->port_bitmap[1] |= bit;
    }
    /* For ports >= 64 we cannot use bitmap; count as new */

    if (!already_seen)
        ps->distinct_ports++;

    /* Trigger penalty once threshold is crossed */
    if (ps->distinct_ports > PORT_SCAN_THRESHOLD) {
        if (stats)
            stats->port_scan_detected++;
        return REP_WEIGHT_PORT_SCAN;
    }

    return 0;
}

/* ===== Penalise an IP =====
 * Called by other modules (syn_flood, fragment, etc.) when a violation
 * is detected. Adds the given weight to the reputation score.
 */
static __always_inline void reputation_penalize(__be32 src_ip,
                                                 __u32 weight,
                                                 __u64 now_ns)
{
    if (!get_config(CFG_REPUTATION_ENABLE))
        return;

    struct ip_reputation *rep;
    rep = bpf_map_lookup_elem(&reputation_map, &src_ip);

    if (!rep) {
        /* Create a new entry with the initial penalty */
        struct ip_reputation new_rep = {};
        new_rep.score = weight;
        new_rep.total_packets = 0;
        new_rep.dropped_packets = 0;
        new_rep.violation_count = 1;
        new_rep.first_seen_ns = now_ns;
        new_rep.last_seen_ns = now_ns;
        new_rep.last_decay_ns = now_ns;
        new_rep.distinct_ports = 0;
        new_rep.blocked = 0;
        new_rep.flags = 0;

        bpf_map_update_elem(&reputation_map, &src_ip, &new_rep, BPF_NOEXIST);
        return;
    }

    rep->score += weight;
    rep->violation_count++;
    rep->last_seen_ns = now_ns;

    /* Cap score at 1000 to avoid overflow issues */
    if (rep->score > 1000)
        rep->score = 1000;
}

/* ===== Main reputation verdict =====
 *
 * Returns:
 *   VERDICT_PASS - Reputation score below threshold
 *   VERDICT_DROP - Score at/above threshold or already auto-blocked
 */
static __always_inline int reputation_check(struct packet_ctx *pkt,
                                             struct global_stats *stats,
                                             __u64 now_ns)
{
    /* Check if reputation module is enabled */
    if (!get_config(CFG_REPUTATION_ENABLE))
        return VERDICT_PASS;

    __u64 threshold = get_config(CFG_REPUTATION_THRESH);
    if (threshold == 0)
        threshold = 500; /* Sensible default if not configured */

    /* Lookup or create reputation entry for source IP */
    struct ip_reputation *rep;
    rep = bpf_map_lookup_elem(&reputation_map, &pkt->src_ip);

    if (!rep) {
        /* First time seeing this IP — create entry */
        struct ip_reputation new_rep = {};
        new_rep.score = 0;
        new_rep.total_packets = 1;
        new_rep.dropped_packets = 0;
        new_rep.violation_count = 0;
        new_rep.first_seen_ns = now_ns;
        new_rep.last_seen_ns = now_ns;
        new_rep.last_decay_ns = now_ns;
        new_rep.distinct_ports = 0;
        new_rep.blocked = 0;
        new_rep.flags = 0;

        bpf_map_update_elem(&reputation_map, &pkt->src_ip, &new_rep, BPF_NOEXIST);

        /* Run port scan detection for the new IP */
        port_scan_detect(pkt->src_ip, pkt->dst_port, now_ns, stats);

        return VERDICT_PASS;
    }

    /* ---- Fast path: already blocked ---- */
    if (rep->blocked) {
        rep->total_packets++;
        rep->dropped_packets++;
        rep->last_seen_ns = now_ns;

        if (stats) {
            stats->reputation_dropped++;
            stats_drop(stats, pkt->pkt_len);
        }
        emit_event(pkt, ATTACK_REPUTATION, 1, DROP_REPUTATION, 0, 0);
        return VERDICT_DROP;
    }

    /* Update packet counters and timestamps */
    rep->total_packets++;
    rep->last_seen_ns = now_ns;

    /* ---- Score decay ----
     * Every second, decay the score by REP_WEIGHT_DECAY_TICK to allow
     * legitimate hosts to recover from transient violations.
     */
    if (now_ns - rep->last_decay_ns > REP_DECAY_INTERVAL_NS) {
        __u64 elapsed_intervals = (now_ns - rep->last_decay_ns) / REP_DECAY_INTERVAL_NS;

        /* Cap iterations to avoid BPF verifier loop issues */
        if (elapsed_intervals > 60)
            elapsed_intervals = 60;

        __u32 total_decay = (__u32)elapsed_intervals * REP_WEIGHT_DECAY_TICK;
        if (rep->score > total_decay)
            rep->score -= total_decay;
        else
            rep->score = 0;

        rep->last_decay_ns = now_ns;
    }

    /* ---- Port scan detection ---- */
    __u32 scan_penalty = port_scan_detect(pkt->src_ip, pkt->dst_port,
                                           now_ns, stats);
    if (scan_penalty > 0) {
        rep->score += scan_penalty;
        rep->violation_count++;
        if (rep->score > 1000)
            rep->score = 1000;
    }

    /* ---- Threshold check ---- */
    if (rep->score >= (__u32)threshold) {
        rep->blocked = 1;
        rep->dropped_packets++;

        if (stats) {
            stats->reputation_dropped++;
            stats->reputation_auto_blocked++;
            stats_drop(stats, pkt->pkt_len);
        }
        emit_event(pkt, ATTACK_REPUTATION, 1, DROP_REPUTATION, 0, 0);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_REPUTATION_H__ */
