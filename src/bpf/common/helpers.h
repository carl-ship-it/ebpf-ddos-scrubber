// SPDX-License-Identifier: GPL-2.0
#ifndef __HELPERS_H__
#define __HELPERS_H__

#include "types.h"

/* ===== Boundary check helpers ===== */

/* Verify pointer + size is within packet bounds */
static __always_inline int bounds_check(void *ptr, __u32 size, void *data_end)
{
    return ((void *)ptr + size <= data_end);
}

/* ===== Min / Max ===== */

static __always_inline __u64 min_u64(__u64 a, __u64 b)
{
    return a < b ? a : b;
}

static __always_inline __u64 max_u64(__u64 a, __u64 b)
{
    return a > b ? a : b;
}

static __always_inline __u32 min_u32(__u32 a, __u32 b)
{
    return a < b ? a : b;
}

/* ===== Jenkins one-at-a-time hash ===== */

static __always_inline __u32 jhash_1word(__u32 a, __u32 initval)
{
    __u32 hash = initval + a;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static __always_inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval)
{
    __u32 hash = initval + a;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += b;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static __always_inline __u32 jhash_3words(__u32 a, __u32 b, __u32 c,
                                          __u32 initval)
{
    __u32 hash = initval + a;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += b;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += c;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

/* ===== SipHash-2-4 (simplified for BPF) =====
 * Used for SYN Cookie generation.
 */

#define SIPROUND           \
    do {                   \
        v0 += v1;          \
        v1 = (v1 << 13) | (v1 >> (64-13)); \
        v1 ^= v0;         \
        v0 = (v0 << 32) | (v0 >> 32);      \
        v2 += v3;          \
        v3 = (v3 << 16) | (v3 >> (64-16)); \
        v3 ^= v2;         \
        v0 += v3;          \
        v3 = (v3 << 21) | (v3 >> (64-21)); \
        v3 ^= v0;         \
        v2 += v1;          \
        v1 = (v1 << 17) | (v1 >> (64-17)); \
        v1 ^= v2;         \
        v2 = (v2 << 32) | (v2 >> 32);      \
    } while (0)

static __always_inline __u64 siphash_2_4(__u64 key0, __u64 key1,
                                          __u32 src_ip, __u32 dst_ip,
                                          __u16 src_port, __u16 dst_port)
{
    __u64 v0 = key0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = key1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = key0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = key1 ^ 0x7465646279746573ULL;

    __u64 m = ((__u64)src_ip) | ((__u64)dst_ip << 32);
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;

    m = ((__u64)src_port) | ((__u64)dst_port << 16) | ((__u64)0x0600 << 32);
    v3 ^= m;
    SIPROUND;
    SIPROUND;
    v0 ^= m;

    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;

    return v0 ^ v1 ^ v2 ^ v3;
}

/* ===== Internet checksum helpers ===== */

static __always_inline __u16 csum_fold(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend)
{
    csum += addend;
    return csum + (csum < addend);
}

static __always_inline __u32 csum_diff4(__be32 old_val, __be32 new_val,
                                         __u32 csum)
{
    /* RFC 1624 incremental checksum update */
    __u32 tmp = ~csum & 0xffff;
    tmp += ~old_val & 0xffff;
    tmp += ~(old_val >> 16) & 0xffff;
    tmp += new_val & 0xffff;
    tmp += (new_val >> 16) & 0xffff;
    return csum_fold(tmp);
}

/* ===== TCP flags extraction ===== */

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

static __always_inline __u8 extract_tcp_flags(struct tcphdr *tcp)
{
    __u8 flags = 0;
    if (tcp->fin) flags |= TCP_FLAG_FIN;
    if (tcp->syn) flags |= TCP_FLAG_SYN;
    if (tcp->rst) flags |= TCP_FLAG_RST;
    if (tcp->psh) flags |= TCP_FLAG_PSH;
    if (tcp->ack) flags |= TCP_FLAG_ACK;
    if (tcp->urg) flags |= TCP_FLAG_URG;
    if (tcp->ece) flags |= TCP_FLAG_ECE;
    if (tcp->cwr) flags |= TCP_FLAG_CWR;
    return flags;
}

/* ===== Token bucket rate limiter ===== */

static __always_inline int token_bucket_consume(struct rate_limiter *rl,
                                                 __u64 now_ns,
                                                 __u64 tokens_needed)
{
    __u64 elapsed_ns;
    __u64 new_tokens;

    if (rl->rate_pps == 0)
        return 1; /* Rate=0 means no limit */

    elapsed_ns = now_ns - rl->last_refill_ns;

    /* Refill tokens: rate_pps tokens per second */
    new_tokens = (elapsed_ns * rl->rate_pps) / 1000000000ULL;
    if (new_tokens > 0) {
        rl->tokens = min_u64(rl->tokens + new_tokens, rl->burst_size);
        rl->last_refill_ns = now_ns;
    }

    rl->total_packets++;

    if (rl->tokens >= tokens_needed) {
        rl->tokens -= tokens_needed;
        return 1; /* Allowed */
    }

    rl->dropped_packets++;
    return 0; /* Dropped */
}

/* ===== Config map reader ===== */

static __always_inline __u64 get_config(__u32 key)
{
    __u64 *val;
    /* Forward declaration — actual map defined in maps.h */
    val = bpf_map_lookup_elem(&config_map, &key);
    if (!val)
        return 0;
    return *val;
}

/* ===== Event emission ===== */

static __always_inline void emit_event(struct packet_ctx *pkt,
                                        __u8 attack_type,
                                        __u8 action,
                                        __u8 drop_reason,
                                        __u64 pps_est,
                                        __u64 bps_est)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->src_ip = pkt->src_ip;
    e->dst_ip = pkt->dst_ip;
    e->src_port = pkt->src_port;
    e->dst_port = pkt->dst_port;
    e->protocol = pkt->ip_proto;
    e->attack_type = attack_type;
    e->action = action;
    e->drop_reason = drop_reason;
    e->pps_estimate = pps_est;
    e->bps_estimate = bps_est;

    bpf_ringbuf_submit(e, 0);
}

/* ===== Statistics update ===== */

static __always_inline struct global_stats *get_stats(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&stats_map, &key);
}

static __always_inline void stats_rx(struct global_stats *s,
                                      __u16 pkt_len)
{
    if (s) {
        s->rx_packets++;
        s->rx_bytes += pkt_len;
    }
}

static __always_inline void stats_drop(struct global_stats *s,
                                        __u16 pkt_len)
{
    if (s) {
        s->dropped_packets++;
        s->dropped_bytes += pkt_len;
    }
}

static __always_inline void stats_tx(struct global_stats *s,
                                      __u16 pkt_len)
{
    if (s) {
        s->tx_packets++;
        s->tx_bytes += pkt_len;
    }
}

#endif /* __HELPERS_H__ */
