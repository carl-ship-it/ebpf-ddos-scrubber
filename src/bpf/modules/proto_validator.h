// SPDX-License-Identifier: GPL-2.0
#ifndef __MOD_PROTO_VALIDATOR_H__
#define __MOD_PROTO_VALIDATOR_H__

#include "../common/types.h"
#include "../common/maps.h"
#include "../common/helpers.h"

/* ===== Deep Protocol Validation Module =====
 *
 * Performs application-layer protocol inspection to detect and block:
 *   1. DNS amplification attacks (response flooding, malformed queries)
 *   2. NTP amplification attacks (monlist/mode 7, control/mode 6)
 *   3. SSDP reflection attacks (inbound M-SEARCH responses)
 *   4. Memcached amplification (exposed UDP memcached)
 *   5. TCP state machine violations (out-of-order flags, handshake abuse)
 *
 * Each sub-validator parses the L7 payload with BPF verifier-safe bounds
 * checks and applies configurable strictness levels controlled by the
 * escalation engine and per-protocol config keys.
 *
 * Returns:
 *   VERDICT_PASS - Packet is protocol-conformant (or validation disabled)
 *   VERDICT_DROP - Protocol violation or amplification pattern detected
 */

/* Well-known service ports (host byte order, compared after ntohs) */
#define PROTO_PORT_DNS        53
#define PROTO_PORT_NTP        123
#define PROTO_PORT_SSDP       1900
#define PROTO_PORT_MEMCACHED  11211

/* DNS validation thresholds */
#define DNS_MAX_PKT_NON_EDNS  512   /* RFC 1035 maximum UDP DNS without EDNS */
#define DNS_AMP_ANCOUNT_LIMIT 10    /* Likely amplification if ancount exceeds */
#define DNS_OPCODE_SHIFT      11    /* Opcode occupies bits 14..11 of flags */
#define DNS_OPCODE_MASK       0x0F  /* 4-bit opcode after shift */

/* TCP state violation threshold */
#define TCP_VIOLATION_LIMIT   3     /* Violations before hard drop */

/* =====================================================================
 *  DNS Validation
 *
 *  Mode 1 (basic):
 *    - Block inbound DNS responses (QR=1) with large answer counts,
 *      which indicate amplification reflection.
 *
 *  Mode 2 (strict):
 *    - All of mode 1, plus:
 *    - Require exactly 1 question (qdcount == 1)
 *    - Require opcode == QUERY (standard query, opcode 0)
 *    - Enforce RFC 1035 512-byte limit for non-EDNS queries
 * ===================================================================== */
static __always_inline int dns_validate(struct xdp_md *ctx,
                                        struct packet_ctx *pkt,
                                        struct global_stats *stats,
                                        __u32 dns_mode)
{
    /* Re-derive fresh payload pointer from ctx to satisfy BPF verifier.
     * Stack-stored packet pointers lose their type on kernel 5.14. */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 pay_off = pkt->payload_offset;
    if (!pay_off || pay_off > 1500)
        return VERDICT_PASS;

    void *payload = data + pay_off;
    if (payload > data_end)
        return VERDICT_PASS;

    struct dns_header *dns = (struct dns_header *)payload;
    if ((void *)(dns + 1) > data_end)
        return VERDICT_PASS;  /* Too short to be DNS; let upper layers decide */

    __u16 flags = bpf_ntohs(dns->flags);
    __u16 qdcount = bpf_ntohs(dns->qdcount);
    __u16 ancount = bpf_ntohs(dns->ancount);
    __u16 payload_len = pkt->l4_payload_len;

    /* Check QR bit: 1 = response */
    int is_response = !!(flags & (1 << 15));  /* DNS_FLAG_QR is bit 15 */

    /* --- Mode 1 & 2: Block amplification responses --- */
    if (is_response) {
        /* DNS response coming TO us with high answer count = amplification */
        if (ancount > DNS_AMP_ANCOUNT_LIMIT) {
            if (stats) {
                stats->dns_queries_blocked++;
                stats->proto_violation_dropped++;
            }
            stats_drop(stats, pkt->pkt_len);
            emit_event(pkt, ATTACK_DNS_AMP, 1, DROP_DNS_AMP, 0, 0);
            return VERDICT_DROP;
        }
    }

    /* --- Mode 2 (strict): Additional query validation --- */
    if (dns_mode >= 2) {
        /* For queries (QR=0), validate structure */
        if (!is_response) {
            /* Must have exactly 1 question */
            if (qdcount != 1) {
                if (stats) {
                    stats->dns_queries_blocked++;
                    stats->proto_violation_dropped++;
                }
                stats_drop(stats, pkt->pkt_len);
                emit_event(pkt, ATTACK_PROTO_VIOLATION, 1,
                           DROP_PROTO_INVALID, 0, 0);
                return VERDICT_DROP;
            }

            /* Opcode must be QUERY (0) */
            __u8 opcode = (flags >> DNS_OPCODE_SHIFT) & DNS_OPCODE_MASK;
            if (opcode != DNS_OPCODE_QUERY) {
                if (stats) {
                    stats->dns_queries_blocked++;
                    stats->proto_violation_dropped++;
                }
                stats_drop(stats, pkt->pkt_len);
                emit_event(pkt, ATTACK_PROTO_VIOLATION, 1,
                           DROP_PROTO_INVALID, 0, 0);
                return VERDICT_DROP;
            }

            /* Enforce 512-byte limit for non-EDNS (no OPT RR detection,
             * so conservatively apply to all non-response traffic) */
            if (payload_len > DNS_MAX_PKT_NON_EDNS) {
                if (stats) {
                    stats->dns_queries_blocked++;
                    stats->proto_violation_dropped++;
                }
                stats_drop(stats, pkt->pkt_len);
                emit_event(pkt, ATTACK_PROTO_VIOLATION, 1,
                           DROP_PROTO_INVALID, 0, 0);
                return VERDICT_DROP;
            }
        }
    }

    /* Passed validation */
    if (stats)
        stats->dns_queries_validated++;

    return VERDICT_PASS;
}

/* =====================================================================
 *  NTP Validation
 *
 *  - Block mode 7 (NTP_MODE_PRIVATE / monlist) unconditionally
 *  - Block mode 6 (NTP_MODE_CONTROL) unless connection is established
 *  - Validate minimum packet size for mode 3 (client) / mode 4 (server)
 * ===================================================================== */
static __always_inline int ntp_validate(struct xdp_md *ctx,
                                        struct packet_ctx *pkt,
                                        struct global_stats *stats)
{
    /* Re-derive fresh payload pointer from ctx to satisfy BPF verifier. */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 pay_off = pkt->payload_offset;
    if (!pay_off || pay_off > 1500)
        return VERDICT_PASS;

    void *payload = data + pay_off;
    if (payload > data_end)
        return VERDICT_PASS;

    struct ntp_header *ntp = (struct ntp_header *)payload;
    if ((void *)(ntp + 1) > data_end)
        return VERDICT_PASS;  /* Too short to parse */

    __u8 flags = ntp->flags;
    __u8 mode = flags & 0x07;  /* Mode is lowest 3 bits */

    /* --- Block mode 7 (monlist) unconditionally --- */
    if (mode == NTP_MODE_PRIVATE) {
        if (stats) {
            stats->ntp_monlist_blocked++;
            stats->proto_violation_dropped++;
        }
        stats_drop(stats, pkt->pkt_len);
        emit_event(pkt, ATTACK_NTP_AMP, 1, DROP_NTP_AMP, 0, 0);
        return VERDICT_DROP;
    }

    /* --- Block mode 6 (control) unless established connection --- */
    if (mode == NTP_MODE_CONTROL) {
        /* Check if there is an established conntrack entry */
        struct conntrack_key ct_key = {
            .src_ip = pkt->src_ip,
            .dst_ip = pkt->dst_ip,
            .src_port = pkt->src_port,
            .dst_port = pkt->dst_port,
            .protocol = IPPROTO_UDP,
        };

        struct conntrack_entry *ct;
        ct = bpf_map_lookup_elem(&conntrack_map, &ct_key);

        if (!ct || ct->state < CT_STATE_ESTABLISHED) {
            /* Also check reverse direction */
            struct conntrack_key ct_key_rev = {
                .src_ip = pkt->dst_ip,
                .dst_ip = pkt->src_ip,
                .src_port = pkt->dst_port,
                .dst_port = pkt->src_port,
                .protocol = IPPROTO_UDP,
            };

            struct conntrack_entry *ct_rev;
            ct_rev = bpf_map_lookup_elem(&conntrack_map, &ct_key_rev);

            if (!ct_rev || ct_rev->state < CT_STATE_ESTABLISHED) {
                if (stats) {
                    stats->ntp_monlist_blocked++;
                    stats->proto_violation_dropped++;
                }
                stats_drop(stats, pkt->pkt_len);
                emit_event(pkt, ATTACK_NTP_AMP, 1, DROP_NTP_AMP, 0, 0);
                return VERDICT_DROP;
            }
        }
    }

    /* --- Validate minimum packet size for client/server mode --- */
    if (mode == NTP_MODE_CLIENT || mode == NTP_MODE_SERVER) {
        if (pkt->l4_payload_len < NTP_MIN_LEN) {
            if (stats)
                stats->proto_violation_dropped++;
            stats_drop(stats, pkt->pkt_len);
            emit_event(pkt, ATTACK_PROTO_VIOLATION, 1,
                       DROP_PROTO_INVALID, 0, 0);
            return VERDICT_DROP;
        }
    }

    return VERDICT_PASS;
}

/* =====================================================================
 *  SSDP Validation
 *
 *  Block inbound SSDP reflection responses. In a DDoS scrubber context,
 *  we should never receive M-SEARCH responses from the Internet.
 *  Response patterns start with "HTTP/1.1" or "NOTIFY".
 * ===================================================================== */
static __always_inline int ssdp_validate(struct xdp_md *ctx,
                                         struct packet_ctx *pkt,
                                         struct global_stats *stats)
{
    /* Re-derive fresh payload pointer from ctx to satisfy BPF verifier. */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u16 pay_off = pkt->payload_offset;
    if (!pay_off || pay_off > 1500)
        return VERDICT_PASS;

    void *payload = data + pay_off;
    if (payload > data_end)
        return VERDICT_PASS;

    /* Need at least 8 bytes to check response pattern signatures */
    if ((void *)payload + 8 > data_end)
        return VERDICT_PASS;

    /* Read the first 8 bytes of payload for pattern matching.
     * "HTTP/1.1" = 0x48 0x54 0x54 0x50 0x2F 0x31 0x2E 0x31
     * "NOTIFY "  = 0x4E 0x4F 0x54 0x49 0x46 0x59 0x20 ...
     */
    __u8 *p = (__u8 *)payload;

    /* Check for "HTTP/1.1" (SSDP response) */
    int is_http = (p[0] == 'H' && p[1] == 'T' && p[2] == 'T' &&
                   p[3] == 'P' && p[4] == '/' && p[5] == '1' &&
                   p[6] == '.' && p[7] == '1');

    /* Check for "NOTIFY " (SSDP notification) */
    int is_notify = (p[0] == 'N' && p[1] == 'O' && p[2] == 'T' &&
                     p[3] == 'I' && p[4] == 'F' && p[5] == 'Y');

    if (is_http || is_notify) {
        if (stats) {
            stats->ssdp_amp_dropped++;
            stats->proto_violation_dropped++;
        }
        stats_drop(stats, pkt->pkt_len);
        emit_event(pkt, ATTACK_SSDP_AMP, 1, DROP_SSDP_AMP, 0, 0);
        return VERDICT_DROP;
    }

    return VERDICT_PASS;
}

/* =====================================================================
 *  Memcached Validation
 *
 *  Block all inbound memcached UDP traffic. The memcached UDP protocol
 *  should never be exposed to the public Internet — any inbound traffic
 *  on UDP port 11211 is either misconfiguration or amplification attack.
 * ===================================================================== */
static __always_inline int memcached_validate(struct packet_ctx *pkt,
                                              struct global_stats *stats)
{
    /* Unconditionally block all inbound UDP memcached traffic */
    if (stats) {
        stats->memcached_amp_dropped++;
        stats->proto_violation_dropped++;
    }
    stats_drop(stats, pkt->pkt_len);
    emit_event(pkt, ATTACK_MEMCACHED_AMP, 1, DROP_MEMCACHED_AMP, 0, 0);
    return VERDICT_DROP;
}

/* =====================================================================
 *  TCP State Machine Validation
 *
 *  Validates that TCP flag transitions match the expected connection
 *  state tracked in conntrack_map. Detects:
 *    - Packets with flags impossible for the current state
 *    - Out-of-window sequence numbers
 *    - Repeated violations exceeding threshold
 *
 *  At ESCALATION_HIGH or ESCALATION_CRITICAL: strict mode drops on
 *  first violation instead of allowing a tolerance window.
 * ===================================================================== */
static __always_inline int tcp_state_validate(struct xdp_md *ctx,
                                              struct packet_ctx *pkt,
                                              struct global_stats *stats,
                                              __u64 now_ns)
{
    __u64 tcp_state_enabled = get_config(CFG_TCP_STATE_ENABLE);
    if (!tcp_state_enabled)
        return VERDICT_PASS;

    if (pkt->ip_proto != IPPROTO_TCP)
        return VERDICT_PASS;

    if (!pkt->l4_offset)
        return VERDICT_PASS;

    /* Re-derive fresh TCP pointer from ctx to satisfy BPF verifier.
     * Clamp offset to reasonable max to prove bounded addition. */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u16 l4_off = pkt->l4_offset;
    if (l4_off > 1500)
        return VERDICT_PASS;
    struct tcphdr *tcp = (struct tcphdr *)(data + l4_off);
    if ((void *)(tcp + 1) > data_end)
        return VERDICT_PASS;

    __u8 flags = pkt->tcp_flags;
    __u64 escalation = get_config(CFG_ESCALATION_LEVEL);
    int strict_mode = (escalation >= ESCALATION_HIGH);
    __u32 violation_limit = strict_mode ? 1 : TCP_VIOLATION_LIMIT;

    /* Build conntrack key for forward lookup */
    struct conntrack_key ct_key = {
        .src_ip = pkt->src_ip,
        .dst_ip = pkt->dst_ip,
        .src_port = pkt->src_port,
        .dst_port = pkt->dst_port,
        .protocol = IPPROTO_TCP,
    };

    struct conntrack_entry *ct;
    ct = bpf_map_lookup_elem(&conntrack_map, &ct_key);

    if (!ct) {
        /* No conntrack entry: only a SYN is valid for new connections */
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN)
            return VERDICT_PASS;  /* Valid: initiating new connection */

        /* RST without conntrack is tolerated (e.g., response to probes) */
        if (flags & TCP_FLAG_RST)
            return VERDICT_PASS;

        /* Any other flags without conntrack = state violation */
        if (stats) {
            stats->tcp_state_violations++;
            stats->proto_violation_dropped++;
            stats->tcp_state_dropped++;
        }
        stats_drop(stats, pkt->pkt_len);
        emit_event(pkt, ATTACK_PROTO_VIOLATION, 1, DROP_TCP_STATE, 0, 0);
        return VERDICT_DROP;
    }

    /* ---- Validate flags against connection state ---- */
    int violation = 0;

    switch (ct->state) {
    case CT_STATE_NEW:
        /* Only SYN is valid in NEW state */
        if (!((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == TCP_FLAG_SYN))
            violation = 1;
        break;

    case CT_STATE_SYN_SENT:
        /* Expect SYN-ACK (from peer) or RST */
        if (!((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) ==
              (TCP_FLAG_SYN | TCP_FLAG_ACK)) &&
            !(flags & TCP_FLAG_RST))
            violation = 1;
        break;

    case CT_STATE_SYN_RECV:
        /* Expect ACK (handshake completion) or RST */
        if (!(flags & TCP_FLAG_ACK) && !(flags & TCP_FLAG_RST))
            violation = 1;
        /* Pure SYN retransmit without ACK in SYN_RECV is suspicious */
        if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK))
            violation = 1;
        break;

    case CT_STATE_ESTABLISHED:
        /* Allow data (ACK, PSH+ACK), FIN, RST */
        /* Disallow bare SYN in established state */
        if ((flags & TCP_FLAG_SYN) && !(flags & TCP_FLAG_ACK))
            violation = 1;
        break;

    case CT_STATE_FIN_WAIT:
        /* Expect FIN-ACK, ACK, or RST */
        if ((flags & TCP_FLAG_SYN))
            violation = 1;
        break;

    case CT_STATE_CLOSED:
    case CT_STATE_TIME_WAIT:
        /* Only RST is valid in closed/time-wait state */
        if (!(flags & TCP_FLAG_RST))
            violation = 1;
        break;

    default:
        break;
    }

    /* ---- Sequence number window validation (basic) ---- */
    if (!violation && ct->state >= CT_STATE_ESTABLISHED &&
        ct->seq_expected != 0) {
        __u32 seq = pkt->tcp_seq;
        __u32 expected = ct->seq_expected;

        /* Allow a window of +/- 2^30 around expected sequence number.
         * This catches wildly out-of-range sequence numbers while
         * tolerating normal TCP window scaling and retransmissions. */
        __u32 diff = seq - expected;
        /* If diff > 2^30 in unsigned, seq is either far ahead or behind */
        if (diff > (1U << 30) && diff < (0U - (1U << 30)))
            violation = 1;
    }

    /* ---- Handle violations ---- */
    if (violation) {
        ct->violation_count++;

        if (stats)
            stats->tcp_state_violations++;

        /* Check if violation count exceeds threshold */
        if (ct->violation_count > violation_limit) {
            if (stats) {
                stats->proto_violation_dropped++;
                stats->tcp_state_dropped++;
            }
            stats_drop(stats, pkt->pkt_len);
            emit_event(pkt, ATTACK_PROTO_VIOLATION, 1,
                       DROP_TCP_STATE, 0, 0);
            return VERDICT_DROP;
        }
    }

    return VERDICT_PASS;
}

/* =====================================================================
 *  Main Entry Point: Protocol Validation Dispatcher
 *
 *  Checks CFG_PROTO_VALID_ENABLE, then dispatches to the appropriate
 *  protocol-specific validator based on ip_proto and dst_port.
 *
 *  Returns:
 *    VERDICT_PASS - Packet passes all applicable protocol checks
 *    VERDICT_DROP - Protocol violation or amplification detected
 * ===================================================================== */
static __always_inline int proto_validate(struct xdp_md *ctx,
                                          struct packet_ctx *pkt,
                                          struct global_stats *stats,
                                          __u64 now_ns)
{
    __u64 proto_valid_enabled = get_config(CFG_PROTO_VALID_ENABLE);
    if (!proto_valid_enabled)
        return VERDICT_PASS;

    /* ---- TCP state machine validation ---- */
    if (pkt->ip_proto == IPPROTO_TCP) {
        int verdict = tcp_state_validate(ctx, pkt, stats, now_ns);
        if (verdict == VERDICT_DROP)
            return VERDICT_DROP;
    }

    /* ---- UDP protocol-specific validators ---- */
    if (pkt->ip_proto == IPPROTO_UDP) {
        __u16 dst_port = bpf_ntohs(pkt->dst_port);

        /* Re-derive fresh UDP payload pointer from ctx to satisfy BPF verifier.
         * Use payload_offset which was already set by the parser. */
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        __u16 pay_off = pkt->payload_offset;
        if (!pay_off || pay_off > 1500)
            return VERDICT_PASS;

        void *payload = data + pay_off;
        if (payload > data_end)
            return VERDICT_PASS;

        /* Store fresh payload pointer for sub-validators */
        pkt->payload = payload;

        /* DNS (port 53) */
        if (dst_port == PROTO_PORT_DNS) {
            __u32 dns_mode = (__u32)get_config(CFG_DNS_VALID_MODE);
            if (dns_mode > 0)
                return dns_validate(ctx, pkt, stats, dns_mode);
        }

        /* NTP (port 123) */
        if (dst_port == PROTO_PORT_NTP)
            return ntp_validate(ctx, pkt, stats);

        /* SSDP (port 1900) */
        if (dst_port == PROTO_PORT_SSDP)
            return ssdp_validate(ctx, pkt, stats);

        /* Memcached (port 11211) */
        if (dst_port == PROTO_PORT_MEMCACHED)
            return memcached_validate(pkt, stats);

        /* ---- Port protocol map: check for additional registered ports ---- */
        __u32 *proto_flags = bpf_map_lookup_elem(&port_proto_map,
                                                  &pkt->dst_port);
        if (proto_flags && *proto_flags != 0) {
            /* Port is registered for protocol-aware handling.
             * Dispatch based on flag bits:
             *   bit 0 = DNS, bit 1 = NTP, bit 2 = SSDP, bit 3 = memcached */
            if (*proto_flags & (1 << 0)) {
                __u32 dns_mode = (__u32)get_config(CFG_DNS_VALID_MODE);
                if (dns_mode > 0)
                    return dns_validate(ctx, pkt, stats, dns_mode);
            }
            if (*proto_flags & (1 << 1))
                return ntp_validate(ctx, pkt, stats);
            if (*proto_flags & (1 << 2))
                return ssdp_validate(ctx, pkt, stats);
            if (*proto_flags & (1 << 3))
                return memcached_validate(pkt, stats);
        }
    }

    return VERDICT_PASS;
}

#endif /* __MOD_PROTO_VALIDATOR_H__ */
