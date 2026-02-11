#!/usr/bin/env bash
# Integration test for the REST API.
# Requires the control plane to be running on localhost:9090.
#
# Usage: ./test_api.sh [base_url]

set -euo pipefail

BASE="${1:-http://localhost:9090/api/v1}"
PASS=0
FAIL=0
TOTAL=0

# Colors
GREEN='\033[32m'
RED='\033[31m'
RESET='\033[0m'

assert_status() {
    local name="$1" method="$2" path="$3" expected="$4"
    shift 4
    TOTAL=$((TOTAL + 1))

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$BASE$path" "$@")

    if [ "$status" = "$expected" ]; then
        PASS=$((PASS + 1))
        printf "  [%d] %-45s ${GREEN}PASS${RESET} (%s)\n" "$TOTAL" "$name" "$status"
    else
        FAIL=$((FAIL + 1))
        printf "  [%d] %-45s ${RED}FAIL${RESET} (got %s, want %s)\n" "$TOTAL" "$name" "$status" "$expected"
    fi
}

assert_json() {
    local name="$1" path="$2" jq_expr="$3" expected="$4"
    TOTAL=$((TOTAL + 1))

    local body
    body=$(curl -s "$BASE$path")
    local actual
    actual=$(echo "$body" | jq -r "$jq_expr" 2>/dev/null || echo "PARSE_ERROR")

    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS + 1))
        printf "  [%d] %-45s ${GREEN}PASS${RESET} (%s)\n" "$TOTAL" "$name" "$actual"
    else
        FAIL=$((FAIL + 1))
        printf "  [%d] %-45s ${RED}FAIL${RESET} (got '%s', want '%s')\n" "$TOTAL" "$name" "$actual" "$expected"
    fi
}

echo "=== DDoS Scrubber API Integration Tests ==="
echo "Base URL: $BASE"
echo ""

# ---- Status ----
echo "--- Status ---"
assert_status "GET /status returns 200"       GET  /status       200
assert_json   "status has version field"       /status ".version" "0.1.0"
assert_json   "status has enabled field"       /status ".enabled" "true"

# ---- Stats ----
echo "--- Stats ---"
assert_status "GET /stats returns 200"         GET  /stats        200

# ---- ACL ----
echo "--- ACL ---"
assert_status "GET /acl/blacklist returns 200" GET  /acl/blacklist 200
assert_status "GET /acl/whitelist returns 200" GET  /acl/whitelist 200

assert_status "POST blacklist entry"           POST /acl/blacklist 200 \
    -H "Content-Type: application/json" \
    -d '{"cidr":"10.99.99.0/24","reason":1}'

assert_status "DELETE blacklist entry"         DELETE /acl/blacklist 200 \
    -H "Content-Type: application/json" \
    -d '{"cidr":"10.99.99.0/24"}'

assert_status "POST whitelist entry"           POST /acl/whitelist 200 \
    -H "Content-Type: application/json" \
    -d '{"cidr":"172.16.99.0/24"}'

assert_status "DELETE whitelist entry"         DELETE /acl/whitelist 200 \
    -H "Content-Type: application/json" \
    -d '{"cidr":"172.16.99.0/24"}'

# ---- Rate Config ----
echo "--- Rate Limit ---"
assert_status "GET /config/rate returns 200"   GET  /config/rate   200

assert_status "PUT rate config"                PUT  /config/rate   200 \
    -H "Content-Type: application/json" \
    -d '{"synRatePps":2000,"udpRatePps":20000,"icmpRatePps":200,"globalPpsLimit":0,"globalBpsLimit":0}'

# ---- Conntrack ----
echo "--- Conntrack ---"
assert_status "GET /conntrack returns 200"     GET  /conntrack     200
assert_status "POST /conntrack/flush"          POST /conntrack/flush 200

# ---- Signatures ----
echo "--- Signatures ---"
assert_status "POST signature"                 POST /signatures    200 \
    -H "Content-Type: application/json" \
    -d '{"index":0,"protocol":17,"srcPortMin":53,"srcPortMax":53,"pktLenMin":512,"pktLenMax":65535}'

assert_status "DELETE all signatures"          DELETE /signatures  200

# ---- Enable/Disable ----
echo "--- Enable/Disable ---"
assert_status "PUT disable scrubber"           PUT  /status/enabled 200 \
    -H "Content-Type: application/json" \
    -d '{"enabled":false}'

assert_json   "scrubber is disabled"           /status ".enabled" "false"

assert_status "PUT enable scrubber"            PUT  /status/enabled 200 \
    -H "Content-Type: application/json" \
    -d '{"enabled":true}'

assert_json   "scrubber is enabled"            /status ".enabled" "true"

# ---- Summary ----
echo ""
echo "=== Results: ${PASS}/${TOTAL} passed"
if [ "$FAIL" -gt 0 ]; then
    echo "   ${FAIL} FAILED"
    exit 1
fi
echo "=== All tests passed ==="
