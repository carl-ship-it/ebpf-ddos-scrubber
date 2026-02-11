// SPDX-License-Identifier: GPL-2.0
#ifndef __PARSER_H__
#define __PARSER_H__

#include "types.h"
#include "helpers.h"

/* ===== Packet parser =====
 * Parses Ethernet → IPv4 → TCP/UDP/ICMP
 * Populates struct packet_ctx for downstream modules.
 *
 * Returns:
 *   0 = Successfully parsed
 *  -1 = Parse error (malformed, unsupported)
 */

static __always_inline int parse_packet(struct xdp_md *ctx,
                                         struct packet_ctx *pkt)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    pkt->data = data;
    pkt->data_end = data_end;
    pkt->is_fragment = 0;
    pkt->tcp_flags = 0;
    pkt->src_port = 0;
    pkt->dst_port = 0;
    pkt->l4_payload_len = 0;
    pkt->l4_hdr = NULL;
    pkt->tcp_seq = 0;
    pkt->tcp_ack_seq = 0;
    pkt->l4_payload_hash4 = 0;
    pkt->payload = NULL;

    /* ---- L2: Ethernet ---- */
    struct ethhdr *eth = data;
    if (!bounds_check(eth, sizeof(*eth), data_end))
        return -1;

    pkt->eth = eth;
    pkt->eth_proto = bpf_ntohs(eth->h_proto);

    /* Handle VLAN (802.1Q) - skip up to 2 tags */
    void *l3_hdr = (void *)(eth + 1);
    __u16 eth_proto = pkt->eth_proto;

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (eth_proto != 0x8100 && eth_proto != 0x88A8)
            break;
        /* VLAN header: 4 bytes (TPID + TCI) */
        if (!bounds_check(l3_hdr, 4, data_end))
            return -1;
        eth_proto = bpf_ntohs(*(__be16 *)(l3_hdr + 2));
        l3_hdr += 4;
    }
    pkt->eth_proto = eth_proto;

    /* Only IPv4 supported in this version */
    if (eth_proto != 0x0800)
        return -1;

    /* ---- L3: IPv4 ---- */
    struct iphdr *iph = l3_hdr;
    if (!bounds_check(iph, sizeof(*iph), data_end))
        return -1;

    /* Validate minimum header length */
    __u8 ihl = iph->ihl;
    if (ihl < 5)
        return -1;

    __u32 ip_hdr_len = ihl * 4;
    if (!bounds_check(iph, ip_hdr_len, data_end))
        return -1;

    pkt->iph = iph;
    pkt->ip_proto = iph->protocol;
    pkt->src_ip = iph->saddr;
    pkt->dst_ip = iph->daddr;
    pkt->pkt_len = bpf_ntohs(iph->tot_len);
    pkt->ttl = iph->ttl;

    /* Check for IP fragments */
    __u16 frag_off = bpf_ntohs(iph->frag_off);
    if ((frag_off & 0x1FFF) != 0 || (frag_off & 0x2000)) {
        pkt->is_fragment = 1;
        /* For non-first fragments, we can't parse L4 */
        if ((frag_off & 0x1FFF) != 0)
            return 0; /* Valid but fragmented, no L4 */
    }

    /* ---- L4 ---- */
    void *l4_hdr = (void *)iph + ip_hdr_len;
    __u16 l4_len = pkt->pkt_len > ip_hdr_len ? pkt->pkt_len - ip_hdr_len : 0;

    switch (iph->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4_hdr;
        if (!bounds_check(tcp, sizeof(*tcp), data_end))
            return -1;

        pkt->tcp = tcp;
        pkt->src_port = tcp->source;
        pkt->dst_port = tcp->dest;
        pkt->tcp_flags = extract_tcp_flags(tcp);
        pkt->tcp_seq = bpf_ntohl(tcp->seq);
        pkt->tcp_ack_seq = bpf_ntohl(tcp->ack_seq);

        __u8 tcp_hdr_len = tcp->doff * 4;
        if (tcp_hdr_len < 20)
            return -1;

        pkt->l4_payload_len = l4_len > tcp_hdr_len ? l4_len - tcp_hdr_len : 0;

        /* Set payload pointer and compute payload hash */
        {
            void *p = (void *)tcp + tcp_hdr_len;
            if (p + 4 <= data_end) {
                pkt->payload = p;
                pkt->l4_payload_hash4 = *(__u32 *)p;
            } else if (p < data_end) {
                pkt->payload = p;
            }
        }
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = l4_hdr;
        if (!bounds_check(udp, sizeof(*udp), data_end))
            return -1;

        pkt->udp = udp;
        pkt->src_port = udp->source;
        pkt->dst_port = udp->dest;
        pkt->l4_payload_len = l4_len > sizeof(*udp) ? l4_len - sizeof(*udp) : 0;

        /* Set payload pointer and compute payload hash */
        {
            void *p = (void *)(udp + 1);
            if (p + 4 <= data_end) {
                pkt->payload = p;
                pkt->l4_payload_hash4 = *(__u32 *)p;
            } else if (p < data_end) {
                pkt->payload = p;
            }
        }
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *icmp = l4_hdr;
        if (!bounds_check(icmp, sizeof(*icmp), data_end))
            return -1;

        pkt->icmp = icmp;
        /* ICMP doesn't have ports; use type/code as pseudo-port */
        pkt->src_port = 0;
        pkt->dst_port = bpf_htons(icmp->type);
        pkt->l4_payload_len = l4_len > sizeof(*icmp) ? l4_len - sizeof(*icmp) : 0;
        break;
    }
    default:
        /* Unknown L4 protocol; still allow processing */
        pkt->l4_hdr = l4_hdr;
        pkt->l4_payload_len = l4_len;
        break;
    }

    return 0;
}

#endif /* __PARSER_H__ */
