#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Daemon mode tests
#
# These tests use different loopback IPs (127.0.0.1, 127.0.0.2, 127.0.0.3)
# on the same port to simulate multiple nodes. This matches the production
# design where all HA cluster nodes use the same port.

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Daemon Mode Tests"
echo "========================================="
echo ""

# Test 1: Basic Daemon Startup Validation
echo "TEST 1: Basic Daemon Startup Validation"
cleanup
echo "test content" > /tmp/node1/file1.txt

# Start a listener for daemon to connect to (node2 on 127.0.0.2)
$OWSYNC listen --host 127.0.0.2 --port 21000 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon (node1 on 127.0.0.1, connects to node2)
timeout 3 $OWSYNC daemon --host 127.0.0.1 --port 21000 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.2 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 2

# Check if daemon is still running
kill -0 $DAEMON_PID 2>/dev/null
DAEMON_RUNNING=$?

# Cleanup
kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

[ $DAEMON_RUNNING -eq 0 ]
test_result $? "Daemon starts successfully"
echo ""

# Test 2: Missing --auto-sync Error
echo "TEST 2: Missing --auto-sync Validation"
cleanup

$OWSYNC daemon --host 127.0.0.1 --port 21001 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db 2>&1 | grep -q "requires at least one --auto-sync peer"
test_result $? "Daemon rejects missing --auto-sync peer"
echo ""

# Test 3: Initial Sync on Startup
echo "TEST 3: Initial Sync on Startup"
cleanup
echo "initial content" > /tmp/node1/file1.txt

# Start listener (node2 on 127.0.0.2)
$OWSYNC listen --host 127.0.0.2 --port 21002 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon (node1 on 127.0.0.1, will sync immediately on startup)
timeout 4 $OWSYNC daemon --host 127.0.0.1 --port 21002 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.2 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 2

# Check if file was synced
[ -f /tmp/node2/file1.txt ] && [ "$(cat /tmp/node2/file1.txt)" = "initial content" ]
RESULT=$?

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

test_result $RESULT "Initial sync on daemon startup"
echo ""

# Test 4: Change Detection and Auto-Sync
echo "TEST 4: Change Detection and Auto-Sync"
cleanup
echo "original" > /tmp/node1/file1.txt

# Start listener (node2 on 127.0.0.2)
$OWSYNC listen --host 127.0.0.2 --port 21003 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon with short poll interval (node1 on 127.0.0.1)
timeout 12 $OWSYNC daemon --host 127.0.0.1 --port 21003 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 2 --auto-sync 127.0.0.2 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 3

# Initial sync should have happened
[ -f /tmp/node2/file1.txt ]
INITIAL_SYNC=$?

# Modify file
sleep 1
echo "modified" > /tmp/node1/file1.txt

# Wait for polling to detect change and sync
sleep 4

# Check if modification was synced
[ "$(cat /tmp/node2/file1.txt 2>/dev/null)" = "modified" ]
CHANGE_SYNC=$?

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

[ $INITIAL_SYNC -eq 0 ] && [ $CHANGE_SYNC -eq 0 ]
test_result $? "Change detection and auto-sync"
echo ""

# Test 5: File Deletion Detection
echo "TEST 5: File Deletion Detection"
cleanup
echo "to be deleted" > /tmp/node1/file1.txt

# Start listener (node2 on 127.0.0.2)
$OWSYNC listen --host 127.0.0.2 --port 21004 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon with short poll interval (node1 on 127.0.0.1)
timeout 12 $OWSYNC daemon --host 127.0.0.1 --port 21004 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 2 --auto-sync 127.0.0.2 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 3

# Initial sync
[ -f /tmp/node2/file1.txt ]
INITIAL=$?

# Delete file
rm /tmp/node1/file1.txt

# Wait for sync
sleep 4

# Check deletion propagated
[ ! -f /tmp/node2/file1.txt ]
DELETED=$?

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

[ $INITIAL -eq 0 ] && [ $DELETED -eq 0 ]
test_result $? "File deletion detection and sync"
echo ""

# Test 6: Multiple Peers
echo "TEST 6: Multiple Peers"
cleanup
mkdir -p /tmp/test_node3
echo "multi-peer test" > /tmp/node1/file1.txt

# Start listeners (node2 on 127.0.0.2, node3 on 127.0.0.3)
$OWSYNC listen --host 127.0.0.2 --port 21005 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER1_PID=$!
$OWSYNC listen --host 127.0.0.3 --port 21005 --plain -i '*' --dir /tmp/test_node3 --db /tmp/test_node3/owsync.db >/dev/null 2>&1 &
LISTENER2_PID=$!
sleep 1

# Start daemon with two peers (node1 on 127.0.0.1)
$OWSYNC daemon --host 127.0.0.1 --port 21005 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.2 --auto-sync 127.0.0.3 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 3

# Check both peers got the file
[ -f /tmp/node2/file1.txt ] && [ -f /tmp/test_node3/file1.txt ]
RESULT=$?

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER1_PID 2>/dev/null || true
kill $LISTENER2_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER1_PID 2>/dev/null || true
wait $LISTENER2_PID 2>/dev/null || true
rm -rf /tmp/test_node3

test_result $RESULT "Multi-peer sync"
echo ""

# Test 7: Partial Peer Failure
echo "TEST 7: Partial Peer Failure (one peer down)"
cleanup
echo "partial failure test" > /tmp/node1/file1.txt

# Start only one listener (node2 on 127.0.0.2, node3 is DOWN)
$OWSYNC listen --host 127.0.0.2 --port 21006 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon with two peers (one will fail)
timeout 5 $OWSYNC daemon --host 127.0.0.1 --port 21006 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.2 --auto-sync 127.0.0.3 2>/dev/null &
DAEMON_PID=$!
sleep 3

# Check that working peer still got the file
[ -f /tmp/node2/file1.txt ]
RESULT=$?

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

test_result $RESULT "Partial peer failure handled"
echo ""

# Test 8: Graceful Shutdown
echo "TEST 8: Graceful Shutdown (SIGTERM)"
cleanup

# Start daemon without peer (will fail to sync but still tests shutdown)
$OWSYNC daemon --host 127.0.0.1 --port 21007 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.4 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 1

# Send SIGTERM
kill -TERM $DAEMON_PID 2>/dev/null

# Wait for clean exit
wait $DAEMON_PID 2>/dev/null
EXIT_CODE=$?

# Should exit cleanly (0) or with timeout-related code
[ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 143 ]  # 143 = 128 + 15 (SIGTERM)
test_result $? "Graceful shutdown on SIGTERM"
echo ""

# Test 9: Interrupt Handling
echo "TEST 9: Interrupt Handling (SIGINT)"
cleanup

$OWSYNC daemon --host 127.0.0.1 --port 21008 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.4 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 1

# Send SIGINT
kill -INT $DAEMON_PID 2>/dev/null

# Wait for clean exit
wait $DAEMON_PID 2>/dev/null
EXIT_CODE=$?

[ $EXIT_CODE -eq 0 ] || [ $EXIT_CODE -eq 130 ]  # 130 = 128 + 2 (SIGINT)
test_result $? "Interrupt handling (SIGINT)"
echo ""

# Test 10: Include/Exclude Patterns in Daemon Mode
echo "TEST 10: Include/Exclude Patterns"
cleanup
echo "included content" > /tmp/node1/config.txt
echo "excluded content" > /tmp/node1/secret.txt

# Start listener (node2 on 127.0.0.2)
$OWSYNC listen --host 127.0.0.2 --port 21009 --plain --dir /tmp/node2 --db /tmp/node2/owsync.db --include "config.txt" >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon with include pattern (node1 on 127.0.0.1)
timeout 5 $OWSYNC daemon --host 127.0.0.1 --port 21009 --plain --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 10 --auto-sync 127.0.0.2 --include "config.txt" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 3

# Check included file was synced, excluded was not
[ -f /tmp/node2/config.txt ] && [ ! -f /tmp/node2/secret.txt ]
RESULT=$?

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

test_result $RESULT "Include/exclude patterns in daemon mode"
echo ""

# Test 11: IPv6 Dual-Stack Binding
echo "TEST 11: IPv6 Dual-Stack Binding (::)"
cleanup
echo "ipv6 test content" > /tmp/node1/file1.txt

# Start listener on :: (dual-stack)
$OWSYNC listen --host "::" --port 21010 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Verify it's listening on IPv6 (not just IPv4) using netstat
# On Linux, dual-stack shows as :::port or [::]:port
LISTEN_OUTPUT=$(netstat -tln 2>/dev/null | grep "21010" || true)
if echo "$LISTEN_OUTPUT" | grep -q ":::21010"; then
    test_result 0 "IPv6 dual-stack binding (:::21010)"
elif echo "$LISTEN_OUTPUT" | grep -q "0.0.0.0:21010"; then
    # Fallback to IPv4 - this would indicate the bug is present
    test_result 1 "IPv6 dual-stack binding (got IPv4 instead)"
elif [ -z "$LISTEN_OUTPUT" ]; then
    test_result 1 "IPv6 dual-stack binding (server not listening)"
else
    # Some other format but listening - verify daemon is running
    if kill -0 $LISTENER_PID 2>/dev/null; then
        test_result 0 "IPv6 dual-stack binding (listening on alternate format)"
    else
        test_result 1 "IPv6 dual-stack binding (daemon crashed)"
    fi
fi

kill $LISTENER_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true
echo ""

# Test 12: IPv6 Loopback Connectivity
echo "TEST 12: IPv6 Loopback Connectivity (::1)"
cleanup
echo "ipv6 loopback test" > /tmp/node1/file1.txt

# Start listener on IPv6 loopback
$OWSYNC listen --host "::1" --port 21011 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Verify listening on ::1
LISTEN_OUTPUT=$(netstat -tln 2>/dev/null | grep "21011" || true)
if echo "$LISTEN_OUTPUT" | grep -qE "::1:21011|\[::1\]:21011"; then
    LISTENING=0
else
    # IPv6 might not be available
    LISTENING=1
fi

kill $LISTENER_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

if [ $LISTENING -eq 0 ]; then
    test_result 0 "IPv6 loopback binding (::1)"
else
    # Skip if IPv6 not available
    test_skip "IPv6 loopback binding (IPv6 not available on this system)"
fi
echo ""

# Test 13: IPv4-Only Binding (0.0.0.0)
echo "TEST 13: IPv4-Only Binding (0.0.0.0)"
cleanup
echo "ipv4 only test" > /tmp/node1/file1.txt

# Start listener on IPv4 only
$OWSYNC listen --host "0.0.0.0" --port 21012 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Verify it's listening on IPv4
LISTEN_OUTPUT=$(netstat -tln 2>/dev/null | grep "21012" || true)
if echo "$LISTEN_OUTPUT" | grep -q "0.0.0.0:21012"; then
    test_result 0 "IPv4-only binding (0.0.0.0:21012)"
else
    test_result 1 "IPv4-only binding"
fi

kill $LISTENER_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true
echo ""

# Test 14: IPv6 Loopback Sync (::1 to ::1)
echo "TEST 14: IPv6 Loopback Sync (::1 to ::1)"
cleanup
echo "ipv6 sync test content" > /tmp/node1/file1.txt

# Start listener on IPv6 loopback
$OWSYNC listen --host "::1" --port 21013 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Verify listener is on IPv6
LISTEN_CHECK=$(netstat -tln 2>/dev/null | grep "21013" || true)
if ! echo "$LISTEN_CHECK" | grep -qE "::1:21013|\[::1\]:21013"; then
    kill $LISTENER_PID 2>/dev/null || true
    test_skip "IPv6 loopback sync (IPv6 not available)"
else
    # Connect and sync via IPv6 loopback (host and port are separate args)
    timeout 3 $OWSYNC connect "::1" --port 21013 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
    CONNECT_RESULT=$?

    # Check if file was synced
    if [ $CONNECT_RESULT -eq 0 ] && [ -f /tmp/node2/file1.txt ] && [ "$(cat /tmp/node2/file1.txt)" = "ipv6 sync test content" ]; then
        RESULT=0
    else
        RESULT=1
    fi

    kill $LISTENER_PID 2>/dev/null || true
    wait $LISTENER_PID 2>/dev/null || true

    test_result $RESULT "IPv6 loopback sync (::1)"
fi
echo ""

# Test 15: Daemon with IPv6 Peer Sync
echo "TEST 15: Daemon with IPv6 Peer Sync"
cleanup
echo "daemon ipv6 sync" > /tmp/node1/file1.txt

# Start listener on IPv6 loopback (uses same port as daemon for simplicity)
$OWSYNC listen --host "::1" --port 21014 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Verify listener is on IPv6
LISTEN_CHECK=$(netstat -tln 2>/dev/null | grep "21014" || true)
if ! echo "$LISTEN_CHECK" | grep -qE "::1:21014|\[::1\]:21014"; then
    kill $LISTENER_PID 2>/dev/null || true
    test_skip "Daemon IPv6 sync (IPv6 not available)"
else
    # Start daemon with IPv6 peer (port is global, so listener and peers use same port)
    timeout 4 $OWSYNC daemon --host "::1" --port 21014 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 60 --auto-sync "::1" >/dev/null 2>&1 &
    DAEMON_PID=$!

    # Wait for initial sync (daemon does immediate sync on startup)
    sleep 2

    # Check if file was synced
    if [ -f /tmp/node2/file1.txt ] && [ "$(cat /tmp/node2/file1.txt)" = "daemon ipv6 sync" ]; then
        RESULT=0
    else
        RESULT=1
    fi

    kill $DAEMON_PID 2>/dev/null || true
    kill $LISTENER_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
    wait $LISTENER_PID 2>/dev/null || true

    test_result $RESULT "Daemon syncs to IPv6 peer (::1)"
fi
echo ""

# Test 16: Peer With Source Address Format (addr,source)
echo "TEST 16: Peer With Source Address Format"
cleanup
echo "r26 source test" > /tmp/node1/file1.txt

# Start listener (node2 on 127.0.0.2)
$OWSYNC listen --host 127.0.0.2 --port 21015 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Start daemon with per-peer source address format: peer,source_address
# This tests that daemon correctly parses comma-separated format "127.0.0.2,127.0.0.1" into:
# - parsed_peer = "127.0.0.2" (where to connect)
# - source_address = "127.0.0.1" (what to bind to before connect)
timeout 4 $OWSYNC daemon --host 127.0.0.1 --port 21015 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 60 --auto-sync "127.0.0.2,127.0.0.1" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 2

# Check if file was synced (proves parsing worked and sync succeeded)
if [ -f /tmp/node2/file1.txt ] && [ "$(cat /tmp/node2/file1.txt)" = "r26 source test" ]; then
    RESULT=0
else
    RESULT=1
fi

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

test_result $RESULT "Peer with source address format (addr,source)"
echo ""

# Test 17: Multiple Peers Mixed Format (some with source, some without)
echo "TEST 17: Multiple Peers Mixed Format"
cleanup
mkdir -p /tmp/test_node3
echo "r26 mixed peers test" > /tmp/node1/file1.txt

# Start listeners (node2 on 127.0.0.2, node3 on 127.0.0.3)
$OWSYNC listen --host 127.0.0.2 --port 21016 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER1_PID=$!
$OWSYNC listen --host 127.0.0.3 --port 21016 --plain -i '*' --dir /tmp/test_node3 --db /tmp/test_node3/owsync.db >/dev/null 2>&1 &
LISTENER2_PID=$!
sleep 1

# Start daemon with mixed peer formats:
# - 127.0.0.2,127.0.0.1 (with source address)
# - 127.0.0.3 (without source address - legacy format)
$OWSYNC daemon --host 127.0.0.1 --port 21016 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 60 --auto-sync "127.0.0.2,127.0.0.1" --auto-sync 127.0.0.3 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 3

# Check both peers got the file
if [ -f /tmp/node2/file1.txt ] && [ -f /tmp/test_node3/file1.txt ]; then
    RESULT=0
else
    RESULT=1
fi

kill $DAEMON_PID 2>/dev/null || true
kill $LISTENER1_PID 2>/dev/null || true
kill $LISTENER2_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $LISTENER1_PID 2>/dev/null || true
wait $LISTENER2_PID 2>/dev/null || true
rm -rf /tmp/test_node3

test_result $RESULT "Mixed peer formats (with/without source)"
echo ""

# Test 18: IPv6 Peer With Source Address
echo "TEST 18: IPv6 Peer With Source Address"
cleanup
echo "r26 ipv6 source test" > /tmp/node1/file1.txt

# Start listener on IPv6 loopback
$OWSYNC listen --host "::1" --port 21017 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 1

# Verify listener is on IPv6
LISTEN_CHECK=$(netstat -tln 2>/dev/null | grep "21017" || true)
if ! echo "$LISTEN_CHECK" | grep -qE "::1:21017|\[::1\]:21017"; then
    kill $LISTENER_PID 2>/dev/null || true
    test_skip "IPv6 peer with source (IPv6 not available)"
else
    # Start daemon with per-peer source address IPv6 format: peer,source
    # Uses ::1 for both peer and source since we're on loopback
    timeout 4 $OWSYNC daemon --host "::1" --port 21017 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 60 --auto-sync "::1,::1" >/dev/null 2>&1 &
    DAEMON_PID=$!
    sleep 2

    # Check if file was synced
    if [ -f /tmp/node2/file1.txt ] && [ "$(cat /tmp/node2/file1.txt)" = "r26 ipv6 source test" ]; then
        RESULT=0
    else
        RESULT=1
    fi

    kill $DAEMON_PID 2>/dev/null || true
    kill $LISTENER_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
    wait $LISTENER_PID 2>/dev/null || true

    test_result $RESULT "IPv6 peer with source address"
fi
echo ""

print_summary
[ $FAIL -eq 0 ]
