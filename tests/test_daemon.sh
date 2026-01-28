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

print_summary
[ $FAIL -eq 0 ]
