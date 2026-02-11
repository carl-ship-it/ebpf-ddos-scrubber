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
#define VERDICT_BYPASS 4  /* Whitelisted — skip all checks, XDP_PASS */

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
#define ATTACK_GEOIP_BLOCK     11
#define ATTACK_REPUTATION      12
#define ATTACK_PROTO_VIOLATION  13
#define ATTACK_PAYLOAD_MATCH   14
#define ATTACK_THREAT_INTEL    15

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
#define DROP_GEOIP             12
#define DROP_REPUTATION        13
#define DROP_PROTO_INVALID     14
#define DROP_PAYLOAD_MATCH     15
#define DROP_SSDP_AMP          16
#define DROP_MEMCACHED_AMP     17
#define DROP_TCP_STATE          18
#define DROP_THREAT_INTEL      19
#define DROP_ESCALATION        20

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
#define CFG_GEOIP_ENABLE       11   /* GeoIP blocking enable */
#define CFG_REPUTATION_ENABLE  12   /* IP reputation enable */
#define CFG_REPUTATION_THRESH  13   /* Score threshold for auto-block (0-1000) */
#define CFG_PROTO_VALID_ENABLE 14   /* Protocol validation enable */
#define CFG_PAYLOAD_MATCH_EN   15   /* Payload fingerprint enable */
#define CFG_ESCALATION_LEVEL   16   /* Current escalation level (0-3) */
#define CFG_THREAT_INTEL_EN    17   /* Threat intel feed blocking enable */
#define CFG_DNS_VALID_MODE     18   /* DNS validation mode: 0=off, 1=basic, 2=strict */
#define CFG_TCP_STATE_ENABLE   19   /* TCP state machine validation enable */
#define CFG_ADAPTIVE_RATE      20   /* Adaptive rate limiting enable */
#define CFG_MAX                64

/* ===== Escalation Levels ===== */
#define ESCALATION_LOW          0   /* Normal: observe, baseline learning */
#define ESCALATION_MEDIUM       1   /* Rate limiting active, loose thresholds */
#define ESCALATION_HIGH         2   /* Aggressive filtering, tight thresholds */
#define ESCALATION_CRITICAL     3   /* Full scrub, challenge-response, BGP signal */

/* ===== Conntrack states ===== */
#define CT_STATE_NEW           0
#define CT_STATE_SYN_SENT      1
#define CT_STATE_SYN_RECV      2
#define CT_STATE_ESTABLISHED   3
#define CT_STATE_FIN_WAIT      4
#define CT_STATE_CLOSED        5
#define CT_STATE_TIME_WAIT     6
#define CT_STATE_RST           7

/* ===== Conntrack flags ===== */
#define CT_FLAG_SYN_COOKIE_VERIFIED  (1 << 0)
#define CT_FLAG_WHITELISTED          (1 << 1)
#define CT_FLAG_SUSPECT              (1 << 2)
#define CT_FLAG_REPUTATION_OK        (1 << 3)
#define CT_FLAG_GEOIP_CHECKED        (1 << 4)

/* ===== GeoIP country action ===== */
#define GEOIP_ACTION_PASS      0
#define GEOIP_ACTION_DROP      1
#define GEOIP_ACTION_RATE_LIMIT 2  /* Apply stricter rate limit */
#define GEOIP_ACTION_MONITOR   3   /* Pass but mark for monitoring */

/* ===== Reputation scoring weights ===== */
#define REP_WEIGHT_SYN_NO_ACK    50   /* SYN without completing handshake */
#define REP_WEIGHT_RATE_EXCEEDED  30   /* Hit rate limit */
#define REP_WEIGHT_PROTO_ANOMALY  40   /* Protocol anomaly detected */
#define REP_WEIGHT_BAD_PAYLOAD    60   /* Known bad payload pattern */
#define REP_WEIGHT_FRAGMENT       20   /* Fragmented traffic */
#define REP_WEIGHT_PORT_SCAN      70   /* Port scanning behavior */
#define REP_WEIGHT_DECAY_TICK     5    /* Decay per tick (1s) */

/* ===== Protocol validation: DNS ===== */
#define DNS_MAX_QUERY_LEN      255
#define DNS_FLAG_QR             (1 << 15)  /* Query/Response */
#define DNS_OPCODE_QUERY        0
#define DNS_RCODE_NOERROR       0

/* ===== Protocol validation: NTP ===== */
#define NTP_MODE_CLIENT         3
#define NTP_MODE_SERVER         4
#define NTP_MODE_CONTROL        6
#define NTP_MODE_PRIVATE        7   /* monlist — always block */
#define NTP_MIN_LEN             48

/* ===== Payload match entry ===== */
#define PAYLOAD_PATTERN_MAX_LEN 16
#define PAYLOAD_MATCH_MAX_RULES 512

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

    /* Pre-extracted TCP fields (avoids re-dereferencing pkt->tcp
     * which loses packet pointer type in the BPF verifier) */
    __u32 tcp_seq;         /* TCP seq in host byte order */
    __u32 tcp_ack_seq;     /* TCP ack_seq in host byte order */

    /* L7 payload pointer (after L4 header) */
    void *payload;

    /* Pre-extracted ICMP fields */
    __u8  icmp_type;
    __u8  icmp_code;

    /* Offset from pkt->data to L4 payload start (for fresh pointer derivation) */
    __u16 payload_offset;

    /* Offset from pkt->data to L4 header start (for fresh pointer derivation) */
    __u16 l4_offset;

    /* First 4 bytes of L4 payload as uint32, for fingerprint hash */
    __u32 l4_payload_hash4;
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
    __u8  tcp_window_scale;
    __u8  violation_count;    /* Protocol violation count */
    __u32 seq_expected;       /* Expected next sequence number */
};

/* ===== GeoIP LPM entry ===== */
struct geoip_entry {
    __u16 country_code;   /* 2-byte country code packed: 'C'<<8|'N' */
    __u8  action;         /* GEOIP_ACTION_* */
    __u8  pad;
};

/* ===== IP Reputation entry ===== */
struct ip_reputation {
    __u32 score;             /* 0 = clean, higher = worse, 1000 = blocked */
    __u32 total_packets;
    __u32 dropped_packets;
    __u32 violation_count;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 last_decay_ns;
    __u16 distinct_ports;    /* Port scan detection */
    __u8  blocked;           /* Auto-blocked flag */
    __u8  flags;
};

/* ===== Payload match rule ===== */
struct payload_rule {
    __u8  pattern[PAYLOAD_PATTERN_MAX_LEN];
    __u8  mask[PAYLOAD_PATTERN_MAX_LEN];  /* 0xFF = must match, 0x00 = wildcard */
    __u16 pattern_len;
    __u16 offset;            /* Offset from L4 payload start */
    __u8  protocol;          /* 0 = any, 6 = TCP, 17 = UDP */
    __u8  action;            /* 0 = drop, 1 = rate-limit, 2 = monitor */
    __be16 dst_port;         /* 0 = any port */
    __u32 hit_count;         /* Incremented on match */
    __u32 rule_id;
};

/* ===== DNS header structure ===== */
struct dns_header {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
} __attribute__((packed));

/* ===== NTP header structure ===== */
struct ntp_header {
    __u8  flags;             /* LI(2) | VN(3) | Mode(3) */
    __u8  stratum;
    __u8  poll;
    __u8  precision;
    __u32 root_delay;
    __u32 root_dispersion;
    __u32 reference_id;
} __attribute__((packed));

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
    /* === New advanced counters === */
    __u64 geoip_dropped;
    __u64 reputation_dropped;
    __u64 proto_violation_dropped;
    __u64 payload_match_dropped;
    __u64 tcp_state_dropped;
    __u64 ssdp_amp_dropped;
    __u64 memcached_amp_dropped;
    __u64 threat_intel_dropped;
    __u64 reputation_auto_blocked;
    __u64 escalation_upgrades;
    __u64 dns_queries_validated;
    __u64 dns_queries_blocked;
    __u64 ntp_monlist_blocked;
    __u64 tcp_state_violations;
    __u64 port_scan_detected;
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
    __u32 reputation_score;  /* Attacker's reputation score at drop time */
    __u16 country_code;      /* GeoIP country code */
    __u8  escalation_level;  /* Current escalation level */
    __u8  pad;
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

/* ===== Threat intel entry (for threat feed IPs) ===== */
struct threat_intel_entry {
    __u8  source_id;      /* Feed source: 0=spamhaus, 1=abuseipdb, 2=emerging, 3=custom */
    __u8  threat_type;    /* 0=botnet, 1=scanner, 2=tor_exit, 3=proxy, 4=malware */
    __u8  confidence;     /* 0-100 confidence score */
    __u8  action;         /* 0=drop, 1=rate-limit, 2=monitor */
    __u32 last_updated;   /* Unix timestamp of last update */
};

/* ===== Port scan tracking entry ===== */
struct port_scan_entry {
    __u64 window_start_ns;
    __u32 distinct_ports;
    __u32 port_bitmap[2]; /* Quick 64-bit bitmap for first 64 ports */
};

#endif /* __TYPES_H__ */
