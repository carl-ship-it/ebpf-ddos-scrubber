#!/usr/bin/env bash
# Integration test for the XDP pipeline using network namespaces.
# Creates a veth pair, loads XDP on one end, and sends test traffic.
#
# Requires: root, iproute2, hping3/scapy, bpftool
#
# Usage: sudo ./test_pipeline.sh

set -euo pipefail

BPF_OBJ="../../build/obj/xdp_ddos_scrubber.o"
NS="ddos-test"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
HOST_IP="10.200.0.1"
NS_IP="10.200.0.2"

PASS=0
FAIL=0
TOTAL=0

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
RESET='\033[0m'

cleanup() {
    echo ""
    echo "Cleaning up..."
    ip link set dev "$VETH_HOST" xdp off 2>/dev/null || true
    ip link set dev "$VETH_HOST" xdpgeneric off 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    echo "Done."
}

trap cleanup EXIT

assert_eq() {
    local name="$1" got="$2" want="$3"
    TOTAL=$((TOTAL + 1))
    if [ "$got" = "$want" ]; then
        PASS=$((PASS + 1))
        printf "  [%d] %-45s ${GREEN}PASS${RESET}\n" "$TOTAL" "$name"
    else
        FAIL=$((FAIL + 1))
        printf "  [%d] %-45s ${RED}FAIL${RESET} (got=%s want=%s)\n" "$TOTAL" "$name" "$got" "$want"
    fi
}

echo "=== XDP Pipeline Integration Tests ==="
echo ""

# ---- Check root ----
if [ "$EUID" -ne 0 ]; then
    echo "Error: Must be run as root"
    exit 1
fi

# ---- Check BPF object ----
if [ ! -f "$BPF_OBJ" ]; then
    echo "Error: BPF object not found: $BPF_OBJ"
    echo "Run 'make all' from project root first."
    exit 1
fi

# ---- Setup network namespace ----
echo "[Setup] Creating network namespace and veth pair..."

ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"

ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

ip netns exec "$NS" ip addr add "${NS_IP}/24" dev "$VETH_NS"
ip netns exec "$NS" ip link set "$VETH_NS" up
ip netns exec "$NS" ip link set lo up

# Verify connectivity before XDP
echo "[Setup] Verifying baseline connectivity..."
ip netns exec "$NS" ping -c 1 -W 1 "$HOST_IP" >/dev/null 2>&1
assert_eq "Baseline ping works" "0" "0"

# ---- Load XDP program (generic/skb mode for veth) ----
echo "[Setup] Loading XDP program on $VETH_HOST (skb mode)..."
ip link set dev "$VETH_HOST" xdpgeneric obj "$BPF_OBJ" sec xdp

# Verify XDP is loaded
XDP_LOADED=$(ip link show "$VETH_HOST" | grep -c "xdp" || true)
assert_eq "XDP program loaded" "$XDP_LOADED" "1"

# ---- Configure: enable scrubber ----
echo "[Setup] Configuring BPF maps..."
# Find config_map and set CFG_ENABLED=1
CONFIG_MAP_ID=$(bpftool map show | grep config_map | head -1 | awk '{print $1}' | tr -d ':')
if [ -n "$CONFIG_MAP_ID" ]; then
    bpftool map update id "$CONFIG_MAP_ID" key 0 0 0 0 value 1 0 0 0 0 0 0 0
    echo "  Scrubber enabled"
fi

echo ""
echo "--- Test Cases ---"

# ---- Test 1: ICMP ping should pass ----
PING_RESULT=$(ip netns exec "$NS" ping -c 2 -W 2 "$HOST_IP" 2>&1 && echo "OK" || echo "FAIL")
if echo "$PING_RESULT" | grep -q "OK"; then
    assert_eq "ICMP ping passes through XDP" "OK" "OK"
else
    assert_eq "ICMP ping passes through XDP" "FAIL" "OK"
fi

# ---- Test 2: TCP connection should pass ----
# Start a simple listener on host
timeout 5 bash -c "echo 'HTTP/1.0 200 OK\r\n\r\nOK' | nc -l -p 8888" &
NC_PID=$!
sleep 0.5

TCP_RESULT=$(ip netns exec "$NS" bash -c "echo '' | nc -w 2 ${HOST_IP} 8888 2>&1" && echo "OK" || echo "FAIL")
kill "$NC_PID" 2>/dev/null || true
if echo "$TCP_RESULT" | grep -q "OK"; then
    assert_eq "TCP connection passes" "OK" "OK"
else
    assert_eq "TCP connection passes" "FAIL" "OK"
fi

# ---- Test 3: Check stats map is being updated ----
STATS_MAP_ID=$(bpftool map show | grep stats_map | head -1 | awk '{print $1}' | tr -d ':')
if [ -n "$STATS_MAP_ID" ]; then
    STATS=$(bpftool map dump id "$STATS_MAP_ID" 2>/dev/null | head -5)
    if [ -n "$STATS" ]; then
        assert_eq "Stats map has data" "OK" "OK"
    else
        assert_eq "Stats map has data" "EMPTY" "OK"
    fi
else
    assert_eq "Stats map has data" "NOT_FOUND" "OK"
fi

# ---- Test 4: Check XDP program info ----
PROG_INFO=$(bpftool prog show | grep xdp_ddos_scrubber | head -1)
if [ -n "$PROG_INFO" ]; then
    assert_eq "BPF program visible in bpftool" "OK" "OK"
else
    assert_eq "BPF program visible in bpftool" "NOT_FOUND" "OK"
fi

# ---- Summary ----
echo ""
echo "=== Results: ${PASS}/${TOTAL} passed ==="
if [ "$FAIL" -gt 0 ]; then
    echo "   ${FAIL} FAILED"
    exit 1
fi
echo "=== All tests passed ==="
