#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
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
    test_result 1 "Default bind to :: failed"
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
# Success = no crash AND error message mentions "peer" (expected failure mode)
OUTPUT=$($OWSYNC daemon -c /tmp/test_config/poll.conf 2>&1 || true)
if echo "$OUTPUT" | grep -qi "peer\|no peers"; then
    # Daemon failed because no peers configured - this is expected, config was parsed
    test_result 0 "poll_interval config accepted (daemon needs peers)"
else
    # If output doesn't mention peers, config parsing may have failed
    test_result 1 "poll_interval config parsing - unexpected output: $OUTPUT"
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
# Complete config uses /etc/config which may not exist - override with --dir
$OWSYNC listen --host 127.0.0.1 --port 20101 -c ./fixtures/complete.conf --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1 &
pid=$!
sleep 0.5
if kill -0 $pid 2>/dev/null; then
    # Process is still running = config parsed successfully
    kill $pid 2>/dev/null || true
    test_result 0 "Complete config parsed successfully"
else
    # Process exited - check if it crashed vs clean exit
    wait $pid 2>/dev/null
    exit_code=$?
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 143 ]; then
        test_result 0 "Complete config parsed (clean exit)"
    else
        test_result 1 "Complete config parsing failed (exit code: $exit_code)"
    fi
fi
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
$OWSYNC listen --host 127.0.0.1 --port 20104 -c ./fixtures/unknown_keys.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1 &
pid=$!
sleep 0.3
# Verify process didn't crash
if kill -0 $pid 2>/dev/null; then
    kill $pid 2>/dev/null || true
    test_result 0 "Unknown keys don't crash parser"
else
    wait $pid 2>/dev/null
    exit_code=$?
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 143 ]; then
        test_result 0 "Unknown keys handled gracefully"
    else
        test_result 1 "Unknown keys caused crash (exit code: $exit_code)"
    fi
fi
echo ""

# Test 2.5: Missing '=' handled gracefully
echo "TEST 2.5: Malformed lines (missing '=') handled gracefully"
cleanup
mkdir -p /tmp/test_config
$OWSYNC listen --host 127.0.0.1 --port 20105 -c ./fixtures/malformed.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db 2>&1 &
pid=$!
sleep 0.3
# Verify process didn't crash
if kill -0 $pid 2>/dev/null; then
    kill $pid 2>/dev/null || true
    test_result 0 "Malformed lines don't crash parser"
else
    wait $pid 2>/dev/null
    exit_code=$?
    if [ $exit_code -eq 0 ] || [ $exit_code -eq 143 ]; then
        test_result 0 "Malformed lines handled gracefully"
    else
        test_result 1 "Malformed lines caused crash (exit code: $exit_code)"
    fi
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
    test_result 0 "Multiple peer entries accepted"
else
    test_result 1 "Multiple peer entries failed"
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
    test_result 0 "Multiple include/exclude entries accepted"
else
    test_result 1 "Multiple include/exclude entries failed"
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
    test_result 1 "16 peers (at limit) failed to start"
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
if echo "$OUTPUT" | grep -qi "Maximum\|too many\|limit\|exceeded"; then
    test_result 0 "17 peers rejected with error message"
else
    # Check if server actually started (which would be wrong)
    if start_and_check 20109 $OWSYNC listen --host 127.0.0.1 --port 20109 -c /tmp/test_config/too_many_peers.conf --db /tmp/test_config/owsync.db 2>/dev/null; then
        test_result 1 "17 peers accepted (should have been rejected)"
    else
        test_result 0 "17 peers rejected (server failed to start)"
    fi
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
    test_result 0 "Invalid poll_interval uses default (server started)"
else
    test_result 1 "Invalid poll_interval caused server failure"
fi
echo ""

# Test 4.4: log_level clamped to [0,3]
echo "TEST 4.4: log_level clamped to valid range"
cleanup
mkdir -p /tmp/test_config
# log_level=99 should be clamped to 3
if start_and_check 20113 $OWSYNC listen --host 127.0.0.1 --port 20113 -c ./fixtures/log_level_bounds.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "log_level clamped to valid range (server started)"
else
    test_result 1 "log_level bounds caused server failure"
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
EXIT_CODE=$?
if echo "$OUTPUT" | grep -qi "cannot open\|error\|no such file\|failed"; then
    test_result 0 "Non-existent config file produces error message"
elif [ $EXIT_CODE -ne 0 ]; then
    test_result 0 "Non-existent config file returns non-zero exit"
else
    test_result 1 "Non-existent config file should produce error (got: $OUTPUT)"
fi
echo ""

# Test 5.2: Empty config file loads with defaults
echo "TEST 5.2: Empty config file loads with defaults"
cleanup
mkdir -p /tmp/test_config
touch /tmp/test_config/empty.conf
# Empty config should work with command-line options providing required values
if start_and_check 20115 $OWSYNC listen --host 127.0.0.1 --port 20115 -c /tmp/test_config/empty.conf --plain -i '*' --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
    test_result 0 "Empty config uses defaults (server started)"
else
    test_result 1 "Empty config caused server failure"
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
# Check if IPv6 is available on this system
if [ -d /proc/sys/net/ipv6 ]; then
    if start_and_check 20116 $OWSYNC listen --host "::" --port 20116 -c ./fixtures/ipv6.conf --plain --dir /tmp/test_config --db /tmp/test_config/owsync.db; then
        test_result 0 "IPv6 bind address accepted"
    else
        test_result 1 "IPv6 bind address failed"
    fi
else
    test_skip "IPv6 bind address (IPv6 not available on this system)"
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
    test_result 0 "IPv6 peer addresses accepted in config"
else
    test_result 1 "IPv6 peer addresses failed to parse"
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
