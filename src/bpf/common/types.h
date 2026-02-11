// SPDX-License-Identifier: GPL-2.0
#ifndef __TYPES_H__
#define __TYPES_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ===== Verdict constants ===== */
#define VERDICT_PASS   0
#define VERDICT_DROP   1
#define VERDICT_TX     2  /* XDP_TX: send back out same interface */
#define VERDICT_REDIR  3  /* XDP_REDIRECT: forward to another interface */

/* ===== Protocol numbers ===== */
#define PROTO_TCP   IPPROTO_TCP
#define PROTO_UDP   IPPROTO_UDP
#define PROTO_ICMP  IPPROTO_ICMP
#define PROTO_GRE   IPPROTO_GRE

/* ===== Attack type IDs (for stats/events) ===== */
#define ATTACK_NONE             0
#define ATTACK_SYN_FLOOD        1
#define ATTACK_UDP_FLOOD        2
#define ATTACK_ICMP_FLOOD       3
#define ATTACK_ACK_FLOOD        4
#define ATTACK_DNS_AMP          5
#define ATTACK_NTP_AMP          6
#define ATTACK_SSDP_AMP         7
#define ATTACK_MEMCACHED_AMP    8
#define ATTACK_FRAGMENT         9
#define ATTACK_RST_FLOOD       10

/* ===== Drop reason codes ===== */
#define DROP_BLACKLIST          1
#define DROP_RATE_LIMIT         2
#define DROP_SYN_FLOOD          3
#define DROP_UDP_FLOOD          4
#define DROP_ICMP_FLOOD         5
#define DROP_ACK_INVALID        6
#define DROP_DNS_AMP            7
#define DROP_NTP_AMP            8
#define DROP_FRAGMENT           9
#define DROP_PARSE_ERROR       10
#define DROP_FINGERPRINT       11

/* ===== Configuration keys (config map indices) ===== */
#define CFG_ENABLED             0   /* Global enable/disable */
#define CFG_SYN_RATE_PPS        1   /* SYN rate limit per source IP */
#define CFG_UDP_RATE_PPS        2   /* UDP rate limit per source IP */
#define CFG_ICMP_RATE_PPS       3   /* ICMP rate limit per source IP */
#define CFG_GLOBAL_PPS_LIMIT    4   /* Global PPS limit */
#define CFG_GLOBAL_BPS_LIMIT    5   /* Global BPS limit */
#define CFG_SYN_COOKIE_ENABLE   6   /* SYN Cookie enable */
#define CFG_CONNTRACK_ENABLE    7   /* Connection tracking enable */
#define CFG_BASELINE_PPS        8   /* Learned baseline PPS */
#define CFG_BASELINE_BPS        9   /* Learned baseline BPS */
#define CFG_ATTACK_THRESHOLD   10   /* Attack detection threshold (multiplier x100) */
#define CFG_MAX                64

/* ===== Conntrack states ===== */
#define CT_STATE_NEW           0
#define CT_STATE_SYN_SENT      1
#define CT_STATE_SYN_RECV      2
#define CT_STATE_ESTABLISHED   3
#define CT_STATE_FIN_WAIT      4
#define CT_STATE_CLOSED        5

/* ===== Conntrack flags ===== */
#define CT_FLAG_SYN_COOKIE_VERIFIED  (1 << 0)
#define CT_FLAG_WHITELISTED          (1 << 1)
#define CT_FLAG_SUSPECT              (1 << 2)

/* ===== Packet context: parsed packet metadata ===== */
struct packet_ctx {
    void *data;
    void *data_end;

    /* L2 */
    struct ethhdr *eth;
    __u16 eth_proto;       /* Host byte order */

    /* L3 */
    struct iphdr *iph;
    __u8  ip_proto;
    __be32 src_ip;
    __be32 dst_ip;
    __u16 pkt_len;         /* IP total length */
    __u8  ttl;
    __u8  is_fragment;     /* 1 if IP fragment */

    /* L4 */
    union {
        struct tcphdr  *tcp;
        struct udphdr  *udp;
        struct icmphdr *icmp;
        void *l4_hdr;
    };
    __be16 src_port;
    __be16 dst_port;
    __u8  tcp_flags;       /* Extracted TCP flags */
    __u16 l4_payload_len;  /* Payload length after L4 header */
};

/* ===== Rate limiter entry (per-CPU) ===== */
struct rate_limiter {
    __u64 tokens;
    __u64 last_refill_ns;
    __u64 rate_pps;
    __u64 burst_size;
    __u64 total_packets;
    __u64 dropped_packets;
};

/* ===== Connection tracking key ===== */
struct conntrack_key {
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8   protocol;
    __u8   pad[3];
};

/* ===== Connection tracking entry ===== */
struct conntrack_entry {
    __u64 last_seen_ns;
    __u32 packets_fwd;
    __u32 packets_rev;
    __u64 bytes_fwd;
    __u64 bytes_rev;
    __u8  state;
    __u8  flags;
    __u8  pad[6];
};

/* ===== Per-CPU global statistics ===== */
struct global_stats {
    __u64 rx_packets;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 tx_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
    /* Per-attack-type counters */
    __u64 syn_flood_dropped;
    __u64 udp_flood_dropped;
    __u64 icmp_flood_dropped;
    __u64 ack_flood_dropped;
    __u64 dns_amp_dropped;
    __u64 ntp_amp_dropped;
    __u64 fragment_dropped;
    __u64 acl_dropped;
    __u64 rate_limited;
    /* Conntrack */
    __u64 conntrack_new;
    __u64 conntrack_established;
    /* SYN Cookie */
    __u64 syn_cookies_sent;
    __u64 syn_cookies_validated;
    __u64 syn_cookies_failed;
};

/* ===== LPM trie key for CIDR matching ===== */
struct lpm_key_v4 {
    __u32 prefixlen;
    __be32 addr;
};

/* ===== Event sent to userspace via ring buffer ===== */
struct event {
    __u64 timestamp_ns;
    __be32 src_ip;
    __be32 dst_ip;
    __be16 src_port;
    __be16 dst_port;
    __u8  protocol;
    __u8  attack_type;
    __u8  action;          /* 0=pass, 1=drop */
    __u8  drop_reason;
    __u64 pps_estimate;
    __u64 bps_estimate;
};

/* ===== SYN Cookie context ===== */
struct syn_cookie_ctx {
    __u32 seed_current;
    __u32 seed_previous;
    __u64 seed_update_ns;
};

/* ===== Attack signature entry ===== */
struct attack_sig {
    __u8  protocol;
    __u8  flags_mask;
    __u8  flags_match;
    __u8  pad;
    __be16 src_port_min;
    __be16 src_port_max;
    __be16 dst_port_min;
    __be16 dst_port_max;
    __u16 pkt_len_min;
    __u16 pkt_len_max;
    __u32 payload_hash;    /* First 4 bytes payload hash, 0 = don't check */
};

#endif /* __TYPES_H__ */
