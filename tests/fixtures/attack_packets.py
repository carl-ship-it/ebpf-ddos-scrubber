#!/usr/bin/env python3
"""
Generate test packet fixtures (pcap) for various DDoS attack types.
Uses Scapy to craft realistic attack traffic.

Usage:
    pip install scapy
    python3 attack_packets.py [output_dir]

Generates:
    - syn_flood.pcap       : SYN flood from random sources
    - udp_flood.pcap       : UDP flood to random ports
    - dns_amp.pcap         : DNS amplification (large responses from port 53)
    - ntp_amp.pcap         : NTP monlist amplification
    - icmp_flood.pcap      : ICMP Echo flood
    - ack_flood.pcap       : Spoofed ACK packets
    - fragment.pcap        : IP fragment attack
    - ssdp_amp.pcap        : SSDP amplification
    - mixed_attack.pcap    : Mixed attack traffic
    - legitimate.pcap      : Normal traffic baseline
"""

import sys
import os
import random

try:
    from scapy.all import (
        Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, Raw,
        wrpcap, RandIP, RandShort,
    )
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy")
    sys.exit(1)

OUTPUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "."
TARGET_IP = "192.168.1.100"
PKT_COUNT = 1000


def gen_syn_flood():
    """SYN flood: random source IPs, random source ports, target port 80."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP, ttl=random.randint(30, 128))
            / TCP(sport=RandShort(), dport=80, flags="S", seq=random.randint(0, 2**32))
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "syn_flood.pcap"), pkts)
    print(f"  syn_flood.pcap: {len(pkts)} packets")


def gen_udp_flood():
    """UDP flood: random source IPs, random ports, small payload."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP)
            / UDP(sport=RandShort(), dport=random.randint(1, 65535))
            / Raw(load=os.urandom(random.randint(8, 64)))
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "udp_flood.pcap"), pkts)
    print(f"  udp_flood.pcap: {len(pkts)} packets")


def gen_dns_amp():
    """DNS amplification: large responses from port 53."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP)
            / UDP(sport=53, dport=RandShort())
            / DNS(qr=1, qd=DNSQR(qname="example.com"))
            / Raw(load=os.urandom(random.randint(512, 1400)))
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "dns_amp.pcap"), pkts)
    print(f"  dns_amp.pcap: {len(pkts)} packets")


def gen_ntp_amp():
    """NTP amplification: large responses from port 123."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP)
            / UDP(sport=123, dport=RandShort())
            / Raw(load=os.urandom(random.randint(468, 1400)))
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "ntp_amp.pcap"), pkts)
    print(f"  ntp_amp.pcap: {len(pkts)} packets")


def gen_icmp_flood():
    """ICMP flood: Echo Request from random sources, some oversized."""
    pkts = []
    for _ in range(PKT_COUNT):
        size = random.choice([64, 128, 256, 1024, 2048])  # Some oversized
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP)
            / ICMP(type=8, code=0)
            / Raw(load=os.urandom(size))
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "icmp_flood.pcap"), pkts)
    print(f"  icmp_flood.pcap: {len(pkts)} packets")


def gen_ack_flood():
    """ACK flood: spoofed ACK packets with no connection state."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP)
            / TCP(
                sport=RandShort(),
                dport=80,
                flags="A",
                seq=random.randint(0, 2**32),
                ack=random.randint(0, 2**32),
            )
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "ack_flood.pcap"), pkts)
    print(f"  ack_flood.pcap: {len(pkts)} packets")


def gen_fragment():
    """IP fragment attack: packets with MF flag and small fragments."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP, flags="MF", frag=0)
            / TCP(sport=RandShort(), dport=80, flags="S")
        )
        pkts.append(pkt)
        # Second fragment (non-first)
        pkt2 = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP, frag=8)
            / Raw(load=os.urandom(32))
        )
        pkts.append(pkt2)
    wrpcap(os.path.join(OUTPUT_DIR, "fragment.pcap"), pkts)
    print(f"  fragment.pcap: {len(pkts)} packets")


def gen_ssdp_amp():
    """SSDP amplification: responses from port 1900."""
    pkts = []
    for _ in range(PKT_COUNT):
        pkt = (
            Ether()
            / IP(src=RandIP(), dst=TARGET_IP)
            / UDP(sport=1900, dport=RandShort())
            / Raw(load=os.urandom(random.randint(256, 800)))
        )
        pkts.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "ssdp_amp.pcap"), pkts)
    print(f"  ssdp_amp.pcap: {len(pkts)} packets")


def gen_legitimate():
    """Normal traffic: established TCP, DNS queries, HTTPS, small ICMP."""
    pkts = []
    # TCP established (ACK+PSH with data)
    for _ in range(300):
        pkt = (
            Ether()
            / IP(src="10.0.0.50", dst=TARGET_IP, ttl=64)
            / TCP(sport=random.randint(1024, 65535), dport=443, flags="AP")
            / Raw(load=os.urandom(random.randint(64, 1400)))
        )
        pkts.append(pkt)

    # DNS queries (small, to port 53)
    for _ in range(200):
        pkt = (
            Ether()
            / IP(src="10.0.0.50", dst=TARGET_IP)
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(qd=DNSQR(qname="example.com"))
        )
        pkts.append(pkt)

    # ICMP echo (small, normal)
    for _ in range(100):
        pkt = (
            Ether()
            / IP(src="10.0.0.50", dst=TARGET_IP, ttl=64)
            / ICMP(type=8, code=0)
            / Raw(load=os.urandom(56))
        )
        pkts.append(pkt)

    random.shuffle(pkts)
    wrpcap(os.path.join(OUTPUT_DIR, "legitimate.pcap"), pkts)
    print(f"  legitimate.pcap: {len(pkts)} packets")


def gen_mixed():
    """Mixed attack: combines multiple attack vectors."""
    pkts = []
    generators = [
        gen_syn_flood_pkt, gen_udp_flood_pkt, gen_dns_amp_pkt,
        gen_icmp_flood_pkt, gen_ack_flood_pkt, gen_legitimate_pkt,
    ]

    for _ in range(PKT_COUNT * 3):
        gen = random.choice(generators)
        pkts.append(gen())

    random.shuffle(pkts)
    wrpcap(os.path.join(OUTPUT_DIR, "mixed_attack.pcap"), pkts)
    print(f"  mixed_attack.pcap: {len(pkts)} packets")


# Helpers for mixed generator
def gen_syn_flood_pkt():
    return Ether() / IP(src=RandIP(), dst=TARGET_IP) / TCP(sport=RandShort(), dport=80, flags="S")

def gen_udp_flood_pkt():
    return Ether() / IP(src=RandIP(), dst=TARGET_IP) / UDP(sport=RandShort(), dport=RandShort()) / Raw(load=b"x" * 32)

def gen_dns_amp_pkt():
    return Ether() / IP(src=RandIP(), dst=TARGET_IP) / UDP(sport=53, dport=RandShort()) / Raw(load=b"x" * 600)

def gen_icmp_flood_pkt():
    return Ether() / IP(src=RandIP(), dst=TARGET_IP) / ICMP(type=8) / Raw(load=b"x" * 64)

def gen_ack_flood_pkt():
    return Ether() / IP(src=RandIP(), dst=TARGET_IP) / TCP(sport=RandShort(), dport=80, flags="A")

def gen_legitimate_pkt():
    return Ether() / IP(src="10.0.0.50", dst=TARGET_IP, ttl=64) / TCP(sport=RandShort(), dport=443, flags="AP") / Raw(load=b"x" * 200)


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"=== Generating test packet fixtures in {OUTPUT_DIR}/ ===\n")

    gen_syn_flood()
    gen_udp_flood()
    gen_dns_amp()
    gen_ntp_amp()
    gen_icmp_flood()
    gen_ack_flood()
    gen_fragment()
    gen_ssdp_amp()
    gen_legitimate()
    gen_mixed()

    print(f"\nDone. Generated 10 pcap files.")
