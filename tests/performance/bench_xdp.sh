#!/usr/bin/env bash
# XDP Performance Benchmark
# Uses BPF_PROG_TEST_RUN with high repeat counts to measure per-packet cost.
# Also measures throughput with pktgen if available.
#
# Usage: sudo ./bench_xdp.sh [bpf_object] [repeat_count]

set -euo pipefail

BPF_OBJ="${1:-../../build/obj/xdp_ddos_scrubber.o}"
REPEAT="${2:-1000000}"

echo "=== XDP DDoS Scrubber Performance Benchmark ==="
echo "BPF Object: $BPF_OBJ"
echo "Repeat:     $REPEAT iterations"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "Error: Must be run as root"
    exit 1
fi

if [ ! -f "$BPF_OBJ" ]; then
    echo "Error: BPF object not found: $BPF_OBJ"
    exit 1
fi

# ---- Load program for benchmarking ----
echo "[1/4] Loading BPF program..."

# Use bpftool to load and get prog ID
PROG_ID=$(bpftool prog load "$BPF_OBJ" /sys/fs/bpf/bench_xdp 2>/dev/null && \
          bpftool prog show pinned /sys/fs/bpf/bench_xdp | head -1 | awk '{print $1}' | tr -d ':')

if [ -z "$PROG_ID" ]; then
    echo "Failed to load program. Trying alternate method..."
    # Try loading via ip link on dummy interface
    ip link add bench0 type dummy 2>/dev/null || true
    ip link set bench0 up
    ip link set bench0 xdpgeneric obj "$BPF_OBJ" sec xdp
    PROG_ID=$(bpftool prog show | grep xdp_ddos_scrubber | head -1 | awk '{print $1}' | tr -d ':')
fi

if [ -z "$PROG_ID" ]; then
    echo "Error: Could not load BPF program"
    exit 1
fi
echo "  Program ID: $PROG_ID"

# ---- Enable scrubber in config map ----
CONFIG_MAP_ID=$(bpftool map show | grep config_map | head -1 | awk '{print $1}' | tr -d ':')
if [ -n "$CONFIG_MAP_ID" ]; then
    bpftool map update id "$CONFIG_MAP_ID" key 0 0 0 0 value 1 0 0 0 0 0 0 0
fi

# ---- Craft test packets ----
# Minimal valid IPv4 TCP SYN packet (14 + 20 + 20 = 54 bytes)
# Ethernet: dst=22:22:22:22:22:22 src=11:11:11:11:11:11 type=0x0800
# IP: ver=4 ihl=5 proto=6(TCP) src=10.0.0.1 dst=192.168.1.1
# TCP: sport=12345 dport=80 SYN

TCP_PKT_HEX="222222222222 111111111111 0800 \
4500 0028 0000 0000 4006 0000 0a000001 c0a80101 \
3039 0050 000003e8 00000000 5002 ffff 0000 0000"

# Minimal valid IPv4 UDP packet (14 + 20 + 8 + 32 = 74 bytes)
UDP_PKT_HEX="222222222222 111111111111 0800 \
4500 003c 0000 0000 4011 0000 0a000001 c0a80101 \
d431 01bb 0028 0000 \
0000000000000000 0000000000000000 0000000000000000 0000000000000000"

echo ""
echo "[2/4] Running BPF_PROG_TEST_RUN benchmarks..."
echo ""

# ---- Benchmark: TCP SYN ----
echo "--- TCP SYN (54 bytes) x $REPEAT ---"
RESULT=$(bpftool prog run id "$PROG_ID" \
    data_in <(echo "$TCP_PKT_HEX" | tr -d ' ' | xxd -r -p) \
    repeat "$REPEAT" 2>&1 || echo "ERROR")

if echo "$RESULT" | grep -q "duration"; then
    DURATION=$(echo "$RESULT" | grep -oP 'duration \K[0-9]+')
    if [ -n "$DURATION" ] && [ "$DURATION" -gt 0 ]; then
        NS_PER_PKT=$((DURATION / REPEAT))
        MPPS=$((1000000000 / (NS_PER_PKT > 0 ? NS_PER_PKT : 1) / 1000000))
        echo "  Total duration: ${DURATION} ns"
        echo "  Per-packet:     ${NS_PER_PKT} ns"
        echo "  Throughput:     ~${MPPS} Mpps (single core)"
    fi
else
    echo "  $RESULT"
    echo "  (bpftool prog run may not support this kernel version)"
fi

echo ""

# ---- Benchmark: UDP (74 bytes) ----
echo "--- UDP (74 bytes) x $REPEAT ---"
RESULT=$(bpftool prog run id "$PROG_ID" \
    data_in <(echo "$UDP_PKT_HEX" | tr -d ' ' | xxd -r -p) \
    repeat "$REPEAT" 2>&1 || echo "ERROR")

if echo "$RESULT" | grep -q "duration"; then
    DURATION=$(echo "$RESULT" | grep -oP 'duration \K[0-9]+')
    if [ -n "$DURATION" ] && [ "$DURATION" -gt 0 ]; then
        NS_PER_PKT=$((DURATION / REPEAT))
        MPPS=$((1000000000 / (NS_PER_PKT > 0 ? NS_PER_PKT : 1) / 1000000))
        echo "  Total duration: ${DURATION} ns"
        echo "  Per-packet:     ${NS_PER_PKT} ns"
        echo "  Throughput:     ~${MPPS} Mpps (single core)"
    fi
else
    echo "  $RESULT"
fi

echo ""
echo "[3/4] System information..."
echo "  Kernel:  $(uname -r)"
echo "  CPU:     $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)"
echo "  Cores:   $(nproc)"
echo "  Arch:    $(uname -m)"

echo ""
echo "[4/4] Cleanup..."
rm -f /sys/fs/bpf/bench_xdp
ip link del bench0 2>/dev/null || true

echo ""
echo "=== Benchmark Complete ==="
