// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_UDP_FLOOD_H__
#define __MOD_UDP_FLOOD_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== UDP Flood & Amplification Detection Module =====
 *
 * Detects:
 * 1. Generic UDP flood — high PPS from single source
 * 2. DNS amplification — large responses from port 53
 * 3. NTP amplification — monlist responses from port 123
 * 4. SSDP amplification — responses from port 1900
 * 5. Memcached amplification — responses from port 11211
 *
 * Known amplification source ports and their response patterns.
 */

/* Well-known amplification ports */
#define PORT_DNS        53
#define PORT_NTP        123
#define PORT_SSDP       1900
#define PORT_MEMCACHED  11211
#define PORT_CHARGEN    19
#define PORT_CLDAP      389
#define PORT_SNMP       161

/* Amplification response size thresholds (bytes) */
#define DNS_AMP_THRESHOLD       512
#define NTP_AMP_THRESHOLD       468   /* NTP monlist response */
#define SSDP_AMP_THRESHOLD      256
#define MEMCACHED_AMP_THRESHOLD 1400

static __always_inline int udp_flood_check(struct packet_ctx *pkt,
                                            struct global_stats *stats,
                                            __u64 now_ns)
{
    if (pkt->ip_proto != IPPROTO_UDP)
        return VERDICT_PASS;

    __u16 src_port = bpf_ntohs(pkt->src_port);
    __u16 payload_len = pkt->l4_payload_len;

    /* ---- DNS Amplification ---- */
    if (src_port == PORT_DNS && payload_len > DNS_AMP_THRESHOLD) {
        if (stats)
            stats->dns_amp_dropped++;
        emit_event(pkt, ATTACK_DNS_AMP, 1, DROP_DNS_AMP, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- NTP Amplification ---- */
    if (src_port == PORT_NTP && payload_len > NTP_AMP_THRESHOLD) {
        if (stats)
            stats->ntp_amp_dropped++;
        emit_event(pkt, ATTACK_NTP_AMP, 1, DROP_NTP_AMP, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- SSDP Amplification ---- */
    if (src_port == PORT_SSDP && payload_len > SSDP_AMP_THRESHOLD) {
        if (stats)
            stats->udp_flood_dropped++;
        emit_event(pkt, ATTACK_SSDP_AMP, 1, DROP_UDP_FLOOD, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- Memcached Amplification ---- */
    if (src_port == PORT_MEMCACHED && payload_len > MEMCACHED_AMP_THRESHOLD) {
        if (stats)
            stats->udp_flood_dropped++;
        emit_event(pkt, ATTACK_MEMCACHED_AMP, 1, DROP_UDP_FLOOD, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- CHARGEN / CLDAP / SNMP (generic amp check) ---- */
    if ((src_port == PORT_CHARGEN || src_port == PORT_CLDAP ||
         src_port == PORT_SNMP) && payload_len > 256) {
        if (stats)
            stats->udp_flood_dropped++;
        emit_event(pkt, ATTACK_UDP_FLOOD, 1, DROP_UDP_FLOOD, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- Port Protocol Map check ----
     * For ports registered as amplification-sensitive,
     * drop large unsolicited responses.
     */
    __u32 *proto_flags = bpf_map_lookup_elem(&port_proto_map, &pkt->src_port);
    if (proto_flags && *proto_flags != 0 && payload_len > 512) {
        if (stats)
            stats->udp_flood_dropped++;
        emit_event(pkt, ATTACK_UDP_FLOOD, 1, DROP_UDP_FLOOD, 0, 0);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

#endif /* __MOD_UDP_FLOOD_H__ */
