#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Common test utilities for owsync tests

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASS=0
FAIL=0

# Binary location
OWSYNC="${OWSYNC:-../bin/owsync}"

# Test key
TEST_KEY="8b2b64411001592abf237c204845e610e5a743a1472822b3d2b86069ec3658d3"

# Create a config file for encrypted mode testing
# Usage: create_config <config_path> <sync_dir> <db_path> <encryption_key>
create_config() {
    local config_path="$1"
    local sync_dir="$2"
    local db_path="$3"
    local encryption_key="$4"

    cat > "$config_path" <<EOF
sync_dir=$sync_dir
database=$db_path
encryption_key=$encryption_key
include=*
EOF
    chmod 600 "$config_path"
}

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        FAIL=$((FAIL + 1))
    fi
}

cleanup() {
    # Try graceful termination first, then force
    pkill owsync 2>/dev/null || true
    sleep 0.2
    pkill -9 owsync 2>/dev/null || true
    rm -rf /tmp/node1 /tmp/node2 /tmp/test_node*
    mkdir -p /tmp/node1 /tmp/node2
}

print_summary() {
    echo ""
    echo "========================================="
    echo "Test Summary"
    echo "========================================="
    echo -e "Total Tests: $((PASS + FAIL))"
    echo -e "${GREEN}Passed: $PASS${NC}"
    echo -e "${RED}Failed: $FAIL${NC}"
    if [ $FAIL -eq 0 ]; then
        RATE=100
    else
        RATE=$(( (PASS * 100) / (PASS + FAIL) ))
    fi
    echo -e "Pass Rate: ${YELLOW}${RATE}%${NC}"
    echo "========================================="
}

# Wait for server to be ready
wait_for_server() {
    local port=$1
    local timeout=5
    local count=0
    while ! nc -z 127.0.0.1 $port 2>/dev/null; do
        sleep 0.1
        count=$((count + 1))
        if [ $count -gt $((timeout * 10)) ]; then
            return 1
        fi
    done
    return 0
}
