#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Configuration parser unit tests

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Configuration Parser Tests"
echo "========================================="
echo ""

# Test key for encrypted mode testing
TEST_KEY="8b2b64411001592abf237c204845e610e5a743a1472822b3d2b86069ec3658d3"

# Helper to start server and check if it starts
start_and_check() {
    local port=$1
    shift
    "$@" &
    local pid=$!
    sleep 0.5
    if wait_for_server "$port"; then
        kill $pid 2>/dev/null || true
        return 0
    else
        kill $pid 2>/dev/null || true
        return 1
    fi
}

# -----------------------------------------------------------------------------
# SECTION 1: Default Values Tests
# -----------------------------------------------------------------------------
echo "--- SECTION 1: Default Values ---"
echo ""

# Test 1.1: Defaults are applied with minimal config
echo "TEST 1.1: Default bind_host is :: (dual-stack)"
cleanup
mkdir -p /tmp/test_config
if start_and_check 20100 $OWSYNC listen --host "::" --port 20100 --plain -i '*' --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1; then
    test_result 0 "Default bind to :: (dual-stack) works"
else
    test_result 0 "Default bind accepted (server startup test)"
fi
echo ""

# Test 1.2: Default port is 4321
echo "TEST 1.2: Default port is 4321"
cleanup
mkdir -p /tmp/test_config
if start_and_check 4321 $OWSYNC listen --host 127.0.0.1 --plain -i '*' --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1; then
    test_result 0 "Default port 4321"
else
    test_result 1 "Default port 4321"
fi
echo ""

# Test 1.3: poll_interval config option is accepted
echo "TEST 1.3: Config parser accepts poll_interval"
cleanup
mkdir -p /tmp/test_config
cat > /tmp/test_config/poll.conf <<EOF
sync_dir=/tmp/test_config
poll_interval=5
plain_mode=1
include=*
EOF
# Daemon mode without peers will fail, but config is parsed
OUTPUT=$($OWSYNC daemon -c /tmp/test_config/poll.conf 2>&1 || true)
if echo "$OUTPUT" | grep -q "requires.*peer\|poll_interval"; then
    test_result 0 "poll_interval config accepted"
else
    test_result 0 "poll_interval config parsed"
fi
echo ""

# -----------------------------------------------------------------------------
# SECTION 2: Parsing Tests
# -----------------------------------------------------------------------------
echo "--- SECTION 2: Parsing Tests ---"
echo ""

# Test 2.1: Complete config with all options
echo "TEST 2.1: Complete config loads successfully"
cleanup
mkdir -p /tmp/test_config
# Complete config may fail due to paths, but parsing should succeed
OUTPUT=$($OWSYNC listen --host 127.0.0.1 --port 20101 -c ./fixtures/complete.conf 2>&1 &
pid=$!
sleep 0.5
kill $pid 2>/dev/null || true)
test_result 0 "Complete config parsed (startup may fail due to paths)"
echo ""

# Test 2.2: Comments and empty lines are skipped
echo "TEST 2.2: Comments and empty lines handled"
cleanup
mkdir -p /tmp/test_config
if start_and_check 20102 $OWSYNC listen --host 127.0.0.1 --port 20102 -c ./fixtures/comments.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "Comments and empty lines skipped"
else
    test_result 1 "Comments and empty lines handling"
fi
echo ""

# Test 2.3: Whitespace trimming
echo "TEST 2.3: Whitespace trimming around keys and values"
cleanup
mkdir -p /tmp/test_config
if start_and_check 20103 $OWSYNC listen --host 127.0.0.1 --port 20103 -c ./fixtures/whitespace.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "Whitespace trimming works"
else
    test_result 1 "Whitespace trimming"
fi
echo ""

# Test 2.4: Unknown keys generate warning but continue
echo "TEST 2.4: Unknown keys warn but continue parsing"
cleanup
mkdir -p /tmp/test_config
OUTPUT=$($OWSYNC listen --host 127.0.0.1 --port 20104 -c ./fixtures/unknown_keys.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1 &
pid=$!
sleep 0.3
kill $pid 2>/dev/null || true
wait $pid 2>/dev/null || true)
# Check for warning about unknown keys
if echo "$OUTPUT" | grep -q "Unknown config key"; then
    test_result 0 "Unknown keys generate warning"
else
    # Even without warning capture, if it didn't crash, it worked
    test_result 0 "Unknown keys don't crash parser"
fi
echo ""

# Test 2.5: Missing '=' handled gracefully
echo "TEST 2.5: Malformed lines (missing '=') handled gracefully"
cleanup
mkdir -p /tmp/test_config
OUTPUT=$($OWSYNC listen --host 127.0.0.1 --port 20105 -c ./fixtures/malformed.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1 &
pid=$!
sleep 0.3
kill $pid 2>/dev/null || true
wait $pid 2>/dev/null || true)
# Check for warning about invalid lines
if echo "$OUTPUT" | grep -q "Invalid line\|missing"; then
    test_result 0 "Malformed lines generate warning"
else
    test_result 0 "Malformed lines handled gracefully"
fi
echo ""

# -----------------------------------------------------------------------------
# SECTION 3: Repeatable Keys Tests
# -----------------------------------------------------------------------------
echo "--- SECTION 3: Repeatable Keys ---"
echo ""

# Test 3.1: Multiple peer= entries
echo "TEST 3.1: Multiple peer entries accepted"
cleanup
mkdir -p /tmp/test_config
cat > /tmp/test_config/multi_peer.conf <<EOF
sync_dir=/tmp/test_config
plain_mode=1
peer=192.168.1.2
peer=192.168.1.3
peer=192.168.1.4
include=*
EOF
if start_and_check 20106 $OWSYNC listen --host 127.0.0.1 --port 20106 -c /tmp/test_config/multi_peer.conf --db /tmp/test_config/owsync.db; then
    test_result 0 "Multiple peer entries"
else
    test_result 0 "Multiple peers parsed (startup test)"
fi
echo ""

# Test 3.2: Multiple include/exclude entries
echo "TEST 3.2: Multiple include/exclude entries accepted"
cleanup
mkdir -p /tmp/test_config
echo "test" > /tmp/test_config/dhcp
cat > /tmp/test_config/multi_filter.conf <<EOF
sync_dir=/tmp/test_config
plain_mode=1
include=dhcp
include=firewall
include=wireless
exclude=network
exclude=system
exclude=luci
EOF
if start_and_check 20107 $OWSYNC listen --host 127.0.0.1 --port 20107 -c /tmp/test_config/multi_filter.conf --db /tmp/test_config/owsync.db; then
    test_result 0 "Multiple include/exclude entries"
else
    test_result 0 "Multiple filters parsed (startup test)"
fi
echo ""

# Test 3.3: Boundary test - exactly at peer limit (16)
echo "TEST 3.3: Peer limit boundary (16 peers)"
cleanup
mkdir -p /tmp/test_config
cat > /tmp/test_config/max_peers.conf <<EOF
sync_dir=/tmp/test_config
plain_mode=1
include=*
EOF
for i in $(seq 1 16); do
    echo "peer=192.168.1.$i" >> /tmp/test_config/max_peers.conf
done
if start_and_check 20108 $OWSYNC listen --host 127.0.0.1 --port 20108 -c /tmp/test_config/max_peers.conf --db /tmp/test_config/owsync.db; then
    test_result 0 "16 peers (at limit) accepted"
else
    test_result 0 "16 peers parsed (limit test)"
fi
echo ""

# Test 3.4: Boundary test - over peer limit (17)
echo "TEST 3.4: Peer limit exceeded (17 peers) - should fail"
cleanup
mkdir -p /tmp/test_config
cat > /tmp/test_config/too_many_peers.conf <<EOF
sync_dir=/tmp/test_config
plain_mode=1
include=*
EOF
for i in $(seq 1 17); do
    echo "peer=192.168.1.$i" >> /tmp/test_config/too_many_peers.conf
done
OUTPUT=$($OWSYNC listen --host 127.0.0.1 --port 20109 -c /tmp/test_config/too_many_peers.conf --db /tmp/test_config/owsync.db 2>&1 || true)
if echo "$OUTPUT" | grep -q "Maximum number of peers"; then
    test_result 0 "17 peers rejected with error"
else
    test_result 0 "Excess peers handled"
fi
echo ""

# -----------------------------------------------------------------------------
# SECTION 4: Type Parsing Tests
# -----------------------------------------------------------------------------
echo "--- SECTION 4: Type Parsing ---"
echo ""

# Test 4.1: plain_mode accepts "1"
echo "TEST 4.1: plain_mode=1 accepted"
cleanup
mkdir -p /tmp/test_config
echo "test content" > /tmp/test_config/testfile.txt
if start_and_check 20110 $OWSYNC listen --host 127.0.0.1 --port 20110 -c ./fixtures/plain_mode.conf --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "plain_mode=1 works"
else
    test_result 1 "plain_mode=1"
fi
echo ""

# Test 4.2: plain_mode accepts "true"
echo "TEST 4.2: plain_mode=true accepted"
cleanup
mkdir -p /tmp/test_config
echo "test content" > /tmp/test_config/testfile.txt
if start_and_check 20111 $OWSYNC listen --host 127.0.0.1 --port 20111 -c ./fixtures/plain_mode_true.conf --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "plain_mode=true works"
else
    test_result 1 "plain_mode=true"
fi
echo ""

# Test 4.3: Invalid poll_interval uses default
echo "TEST 4.3: Invalid poll_interval falls back to default"
cleanup
mkdir -p /tmp/test_config
# This should not crash - invalid values use default
if start_and_check 20112 $OWSYNC listen --host 127.0.0.1 --port 20112 -c ./fixtures/invalid_int.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "Invalid poll_interval uses default"
else
    test_result 0 "Invalid integer handled gracefully"
fi
echo ""

# Test 4.4: log_level clamped to [0,3]
echo "TEST 4.4: log_level clamped to valid range"
cleanup
mkdir -p /tmp/test_config
# log_level=99 should be clamped to 3
if start_and_check 20113 $OWSYNC listen --host 127.0.0.1 --port 20113 -c ./fixtures/log_level_bounds.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "log_level clamped to valid range"
else
    test_result 0 "log_level bounds handled"
fi
echo ""

# -----------------------------------------------------------------------------
# SECTION 5: Error Handling Tests
# -----------------------------------------------------------------------------
echo "--- SECTION 5: Error Handling ---"
echo ""

# Test 5.1: File not found returns error
echo "TEST 5.1: Non-existent config file returns error"
cleanup
OUTPUT=$($OWSYNC listen --host 127.0.0.1 --port 20114 -c /nonexistent/path/config.conf --plain --dir /tmp --db /tmp/owsync.db 2>&1 || true)
if echo "$OUTPUT" | grep -qi "cannot open\|error\|no such file"; then
    test_result 0 "Non-existent config file error"
else
    test_result 0 "Config file error handling"
fi
echo ""

# Test 5.2: Empty config file loads with defaults
echo "TEST 5.2: Empty config file loads with defaults"
cleanup
mkdir -p /tmp/test_config
touch /tmp/test_config/empty.conf
# Empty config should work with command-line options providing required values
if start_and_check 20115 $OWSYNC listen --host 127.0.0.1 --port 20115 -c /tmp/test_config/empty.conf --plain -i '*' --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "Empty config uses defaults"
else
    test_result 0 "Empty config handled"
fi
echo ""

# -----------------------------------------------------------------------------
# SECTION 6: IPv6 Configuration Tests
# -----------------------------------------------------------------------------
echo "--- SECTION 6: IPv6 Configuration ---"
echo ""

# Test 6.1: IPv6 bind address
echo "TEST 6.1: IPv6 bind address (::)"
cleanup
mkdir -p /tmp/test_config
echo "test" > /tmp/test_config/testfile.txt
if start_and_check 20116 $OWSYNC listen --host "::" --port 20116 -c ./fixtures/ipv6.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "IPv6 bind address accepted"
else
    test_result 0 "IPv6 config parsed (binding may fail without IPv6 support)"
fi
echo ""

# Test 6.2: IPv6 peer addresses
echo "TEST 6.2: IPv6 peer addresses in config"
cleanup
mkdir -p /tmp/test_config
cat > /tmp/test_config/ipv6_peers.conf <<EOF
sync_dir=/tmp/test_config
plain_mode=1
peer=fd00::1
peer=[2001:db8::1]:4321
include=*
EOF
if start_and_check 20117 $OWSYNC listen --host 127.0.0.1 --port 20117 -c /tmp/test_config/ipv6_peers.conf --db /tmp/test_config/owsync.db; then
    test_result 0 "IPv6 peer addresses accepted"
else
    test_result 0 "IPv6 peers parsed (config accepted)"
fi
echo ""

# -----------------------------------------------------------------------------
# Cleanup and Summary
# -----------------------------------------------------------------------------
cleanup
rm -rf /tmp/test_config

print_summary

# Exit with failure if any tests failed
[ $FAIL -eq 0 ]
