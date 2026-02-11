#!/usr/bin/env bash
# Master test runner — runs all test suites.
#
# Usage:
#   ./tests/run_all.sh [--unit] [--bpf] [--integration] [--bench]
#
# Default: runs all non-benchmark tests.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

RUN_UNIT=0
RUN_BPF=0
RUN_INTEGRATION=0
RUN_BENCH=0
RUN_ALL=1

for arg in "$@"; do
    RUN_ALL=0
    case "$arg" in
        --unit)        RUN_UNIT=1 ;;
        --bpf)         RUN_BPF=1 ;;
        --integration) RUN_INTEGRATION=1 ;;
        --bench)       RUN_BENCH=1 ;;
        --all)         RUN_ALL=1 ;;
        *)             echo "Unknown: $arg"; exit 1 ;;
    esac
done

if [ "$RUN_ALL" = 1 ]; then
    RUN_UNIT=1
    RUN_BPF=1
    RUN_INTEGRATION=1
fi

TOTAL_PASS=0
TOTAL_FAIL=0

section() {
    echo ""
    echo "================================================================"
    echo "  $1"
    echo "================================================================"
    echo ""
}

# ===== 1. Go Unit Tests =====
if [ "$RUN_UNIT" = 1 ]; then
    section "Go Unit Tests"
    if cd src/control-plane && go test -v -race -count=1 ./...; then
        TOTAL_PASS=$((TOTAL_PASS + 1))
        echo "  >>> Go unit tests: PASSED"
    else
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
        echo "  >>> Go unit tests: FAILED"
    fi
    cd "$PROJECT_ROOT"
fi

# ===== 2. BPF XDP Tests =====
if [ "$RUN_BPF" = 1 ]; then
    section "BPF XDP Tests"

    # Build BPF object if needed
    if [ ! -f build/obj/xdp_ddos_scrubber.o ]; then
        echo "Building BPF object..."
        make all
    fi

    # Build test harness
    if [ ! -f tests/bpf/test_xdp ]; then
        echo "Building BPF test harness..."
        cd tests/bpf && make && cd "$PROJECT_ROOT"
    fi

    if [ "$EUID" = 0 ]; then
        if cd tests/bpf && sudo ./test_xdp ../../build/obj/xdp_ddos_scrubber.o; then
            TOTAL_PASS=$((TOTAL_PASS + 1))
            echo "  >>> BPF XDP tests: PASSED"
        else
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            echo "  >>> BPF XDP tests: FAILED"
        fi
        cd "$PROJECT_ROOT"
    else
        echo "  Skipping BPF tests (requires root). Run with sudo."
    fi
fi

# ===== 3. Integration Tests =====
if [ "$RUN_INTEGRATION" = 1 ]; then
    section "Integration Tests"

    if [ "$EUID" = 0 ]; then
        # Pipeline test (netns + XDP)
        if bash tests/integration/test_pipeline.sh; then
            TOTAL_PASS=$((TOTAL_PASS + 1))
            echo "  >>> Pipeline integration test: PASSED"
        else
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            echo "  >>> Pipeline integration test: FAILED"
        fi
    else
        echo "  Skipping integration tests (requires root). Run with sudo."
    fi

    # API test (requires running control plane)
    if curl -s http://localhost:9090/api/v1/status >/dev/null 2>&1; then
        if bash tests/integration/test_api.sh; then
            TOTAL_PASS=$((TOTAL_PASS + 1))
            echo "  >>> API integration test: PASSED"
        else
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
            echo "  >>> API integration test: FAILED"
        fi
    else
        echo "  Skipping API tests (control plane not running on :9090)"
    fi
fi

# ===== 4. Performance Benchmarks =====
if [ "$RUN_BENCH" = 1 ]; then
    section "Performance Benchmarks"

    # Go benchmarks
    echo "--- Go Benchmarks ---"
    cd src/control-plane && go test -bench=. -benchmem ./... 2>/dev/null || true
    cd "$PROJECT_ROOT"

    # XDP benchmarks (requires root)
    if [ "$EUID" = 0 ]; then
        echo ""
        echo "--- XDP Benchmarks ---"
        bash tests/performance/bench_xdp.sh || true
    else
        echo "  Skipping XDP benchmarks (requires root)"
    fi
fi

# ===== Summary =====
section "Test Summary"
echo "  Suites passed: $TOTAL_PASS"
echo "  Suites failed: $TOTAL_FAIL"

if [ "$TOTAL_FAIL" -gt 0 ]; then
    echo ""
    echo "  RESULT: FAIL"
    exit 1
fi

echo ""
echo "  RESULT: ALL PASSED"
