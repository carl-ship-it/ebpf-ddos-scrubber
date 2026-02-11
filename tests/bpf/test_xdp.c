// SPDX-License-Identifier: GPL-2.0
/*
 * BPF XDP program test harness.
 * Uses bpf_prog_test_run_opts (BPF_PROG_TEST_RUN) to send crafted packets
 * through the loaded XDP program and verify verdicts.
 *
 * Compile: gcc -o test_xdp test_xdp.c -lbpf -lelf -lz
 * Run:     sudo ./test_xdp ../build/obj/xdp_ddos_scrubber.o
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define TEST_PASS  0
#define TEST_FAIL  1

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define RUN_TEST(name) do {                             \
    tests_run++;                                        \
    printf("  [%d] %-50s ", tests_run, name);           \
    if (test_##name() == TEST_PASS) {                   \
        tests_passed++;                                 \
        printf("\033[32mPASS\033[0m\n");                \
    } else {                                            \
        tests_failed++;                                 \
        printf("\033[31mFAIL\033[0m\n");                \
    }                                                   \
} while (0)

/* ===== Packet builders ===== */

struct test_pkt {
    struct ethhdr eth;
    struct iphdr  ip;
    union {
        struct tcphdr  tcp;
        struct udphdr  udp;
        struct icmphdr icmp;
    };
    char payload[64];
} __attribute__((packed));

static void build_eth(struct ethhdr *eth, __u16 proto)
{
    memset(eth->h_source, 0x11, ETH_ALEN);
    memset(eth->h_dest, 0x22, ETH_ALEN);
    eth->h_proto = htons(proto);
}

static void build_ip(struct iphdr *ip, __u8 proto,
                     const char *src, const char *dst, __u16 tot_len)
{
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(tot_len);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = proto;
    ip->check = 0;
    inet_pton(AF_INET, src, &ip->saddr);
    inet_pton(AF_INET, dst, &ip->daddr);
}

static void build_tcp_syn(struct tcphdr *tcp, __u16 sport, __u16 dport)
{
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->seq = htonl(1000);
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->window = htons(65535);
}

static void build_tcp_ack(struct tcphdr *tcp, __u16 sport, __u16 dport)
{
    memset(tcp, 0, sizeof(*tcp));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->seq = htonl(1001);
    tcp->ack_seq = htonl(2001);
    tcp->doff = 5;
    tcp->ack = 1;
    tcp->window = htons(65535);
}

static void build_udp(struct udphdr *udp, __u16 sport, __u16 dport, __u16 len)
{
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(len);
    udp->check = 0;
}

static void build_icmp_echo(struct icmphdr *icmp)
{
    icmp->type = 8; /* Echo Request */
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(1);
    icmp->un.echo.sequence = htons(1);
}

/* ===== BPF prog runner ===== */

static int prog_fd = -1;
static int config_map_fd = -1;

static int run_xdp(void *pkt, __u32 pkt_len, __u32 *retval)
{
    LIBBPF_OPTS(bpf_test_run_opts, opts,
        .data_in = pkt,
        .data_size_in = pkt_len,
        .repeat = 1,
    );

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err < 0)
        return err;

    *retval = opts.retval;
    return 0;
}

static int set_config(__u32 key, __u64 value)
{
    return bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
}

/* ===== Test cases ===== */

/* When scrubber is disabled (CFG_ENABLED=0), all packets pass */
int test_disabled_passes_all(void)
{
    set_config(0 /* CFG_ENABLED */, 0);

    struct test_pkt pkt = {};
    build_eth(&pkt.eth, ETH_P_IP);
    build_ip(&pkt.ip, IPPROTO_TCP, "10.0.0.1", "192.168.1.1",
             sizeof(struct iphdr) + sizeof(struct tcphdr));
    build_tcp_syn(&pkt.tcp, 12345, 80);

    __u32 retval;
    if (run_xdp(&pkt, sizeof(pkt.eth) + sizeof(pkt.ip) + sizeof(pkt.tcp), &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_PASS ? TEST_PASS : TEST_FAIL;
}

/* Valid TCP SYN should pass (no SYN cookie, no rate limit) */
int test_tcp_syn_pass(void)
{
    set_config(0, 1); /* Enable */
    set_config(6, 0); /* SYN Cookie off */
    set_config(7, 0); /* Conntrack off */

    struct test_pkt pkt = {};
    build_eth(&pkt.eth, ETH_P_IP);
    build_ip(&pkt.ip, IPPROTO_TCP, "10.0.0.1", "192.168.1.1",
             sizeof(struct iphdr) + sizeof(struct tcphdr));
    build_tcp_syn(&pkt.tcp, 12345, 80);

    __u32 retval;
    if (run_xdp(&pkt, sizeof(pkt.eth) + sizeof(pkt.ip) + sizeof(pkt.tcp), &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_PASS ? TEST_PASS : TEST_FAIL;
}

/* Valid UDP packet should pass */
int test_udp_pass(void)
{
    set_config(0, 1);
    set_config(6, 0);
    set_config(7, 0);

    struct test_pkt pkt = {};
    build_eth(&pkt.eth, ETH_P_IP);
    build_ip(&pkt.ip, IPPROTO_UDP, "10.0.0.1", "192.168.1.1",
             sizeof(struct iphdr) + sizeof(struct udphdr) + 10);
    build_udp(&pkt.udp, 54321, 443, sizeof(struct udphdr) + 10);

    __u32 retval;
    __u32 pkt_size = sizeof(pkt.eth) + sizeof(pkt.ip) + sizeof(pkt.udp) + 10;
    if (run_xdp(&pkt, pkt_size, &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_PASS ? TEST_PASS : TEST_FAIL;
}

/* Valid ICMP Echo Request should pass */
int test_icmp_echo_pass(void)
{
    set_config(0, 1);

    struct test_pkt pkt = {};
    build_eth(&pkt.eth, ETH_P_IP);
    build_ip(&pkt.ip, IPPROTO_ICMP, "10.0.0.1", "192.168.1.1",
             sizeof(struct iphdr) + sizeof(struct icmphdr));
    build_icmp_echo(&pkt.icmp);

    __u32 retval;
    if (run_xdp(&pkt, sizeof(pkt.eth) + sizeof(pkt.ip) + sizeof(pkt.icmp), &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_PASS ? TEST_PASS : TEST_FAIL;
}

/* Truncated packet (too short for IP header) should be dropped */
int test_truncated_drop(void)
{
    set_config(0, 1);

    struct ethhdr eth = {};
    build_eth(&eth, ETH_P_IP);

    /* Only Ethernet header, no IP — should fail parse */
    __u32 retval;
    if (run_xdp(&eth, sizeof(eth), &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_DROP ? TEST_PASS : TEST_FAIL;
}

/* IP fragment (MF=1) should be dropped */
int test_fragment_drop(void)
{
    set_config(0, 1);

    struct test_pkt pkt = {};
    build_eth(&pkt.eth, ETH_P_IP);
    build_ip(&pkt.ip, IPPROTO_TCP, "10.0.0.1", "192.168.1.1",
             sizeof(struct iphdr) + sizeof(struct tcphdr));
    /* Set MF (More Fragments) flag */
    pkt.ip.frag_off = htons(0x2000);
    build_tcp_syn(&pkt.tcp, 12345, 80);

    __u32 retval;
    if (run_xdp(&pkt, sizeof(pkt.eth) + sizeof(pkt.ip) + sizeof(pkt.tcp), &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_DROP ? TEST_PASS : TEST_FAIL;
}

/* DNS amplification: large response from port 53 should be dropped */
int test_dns_amp_drop(void)
{
    set_config(0, 1);

    /* Build a large UDP packet from port 53 */
    char buf[1024];
    memset(buf, 0, sizeof(buf));

    struct ethhdr *eth = (void *)buf;
    struct iphdr  *ip  = (void *)(eth + 1);
    struct udphdr *udp = (void *)((char *)ip + 20);

    build_eth(eth, ETH_P_IP);
    build_ip(ip, IPPROTO_UDP, "8.8.8.8", "192.168.1.1", 20 + 8 + 600);
    build_udp(udp, 53, 12345, 8 + 600);

    __u32 retval;
    if (run_xdp(buf, 14 + 20 + 8 + 600, &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_DROP ? TEST_PASS : TEST_FAIL;
}

/* NTP amplification: large response from port 123 should be dropped */
int test_ntp_amp_drop(void)
{
    set_config(0, 1);

    char buf[1024];
    memset(buf, 0, sizeof(buf));

    struct ethhdr *eth = (void *)buf;
    struct iphdr  *ip  = (void *)(eth + 1);
    struct udphdr *udp = (void *)((char *)ip + 20);

    build_eth(eth, ETH_P_IP);
    build_ip(ip, IPPROTO_UDP, "1.2.3.4", "192.168.1.1", 20 + 8 + 500);
    build_udp(udp, 123, 12345, 8 + 500);

    __u32 retval;
    if (run_xdp(buf, 14 + 20 + 8 + 500, &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_DROP ? TEST_PASS : TEST_FAIL;
}

/* Non-IPv4 (e.g., IPv6 or ARP) should be dropped by parser */
int test_non_ipv4_drop(void)
{
    set_config(0, 1);

    struct ethhdr eth = {};
    char payload[64] = {};
    char buf[sizeof(eth) + sizeof(payload)];

    build_eth(&eth, 0x86DD); /* IPv6 */
    memcpy(buf, &eth, sizeof(eth));
    memcpy(buf + sizeof(eth), payload, sizeof(payload));

    __u32 retval;
    if (run_xdp(buf, sizeof(buf), &retval) < 0)
        return TEST_FAIL;

    return retval == XDP_DROP ? TEST_PASS : TEST_FAIL;
}

/* ===== Main ===== */

int main(int argc, char **argv)
{
    const char *obj_path;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object.o>\n", argv[0]);
        return 1;
    }
    obj_path = argv[1];

    printf("=== XDP DDoS Scrubber BPF Test Suite ===\n");
    printf("Loading: %s\n\n", obj_path);

    /* Load BPF object */
    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    /* Find program */
    prog = bpf_object__find_program_by_name(obj, "xdp_ddos_scrubber");
    if (!prog) {
        fprintf(stderr, "Program 'xdp_ddos_scrubber' not found\n");
        bpf_object__close(obj);
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    /* Find config map */
    map = bpf_object__find_map_by_name(obj, "config_map");
    if (!map) {
        fprintf(stderr, "Map 'config_map' not found\n");
        bpf_object__close(obj);
        return 1;
    }
    config_map_fd = bpf_map__fd(map);

    printf("Running tests...\n\n");

    /* ---- Run all tests ---- */
    RUN_TEST(disabled_passes_all);
    RUN_TEST(tcp_syn_pass);
    RUN_TEST(udp_pass);
    RUN_TEST(icmp_echo_pass);
    RUN_TEST(truncated_drop);
    RUN_TEST(fragment_drop);
    RUN_TEST(dns_amp_drop);
    RUN_TEST(ntp_amp_drop);
    RUN_TEST(non_ipv4_drop);

    /* ---- Summary ---- */
    printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf(" (%d failed)", tests_failed);
    printf(" ===\n");

    bpf_object__close(obj);
    return tests_failed > 0 ? 1 : 0;
}
