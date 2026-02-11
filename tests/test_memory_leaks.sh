#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Memory leak detection tests - Uses Valgrind to detect leaks during realistic usage

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Memory Leak Detection Tests"
echo "========================================="
echo ""

# Check if valgrind is available
if ! command -v valgrind &> /dev/null; then
    echo "ERROR: valgrind not found. Install with: sudo apt-get install valgrind"
    exit 1
fi

VALGRIND="valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --error-exitcode=1"
VALGRIND_QUIET="valgrind --leak-check=full --show-leak-kinds=definite,possible --errors-for-leak-kinds=definite --error-exitcode=1 --log-file=/tmp/valgrind.log"

# Test 1: Listen Mode - Single Connection Cycle
echo "TEST 1: Listen Mode - Single Connection (Valgrind)"
cleanup
echo "test data" > /tmp/node1/file1.txt

# Start listener under valgrind
$VALGRIND_QUIET $OWSYNC listen --host 127.0.0.1 --port 21100 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
LISTENER_PID=$!
sleep 3

# Connect once
$OWSYNC connect 127.0.0.1 --port 21100 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1 || true
sleep 2

# Stop listener
kill -TERM $LISTENER_PID 2>/dev/null
wait $LISTENER_PID 2>/dev/null
RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo "✅ PASS: No memory leaks in single connection"
else
    echo "❌ FAIL: Memory leaks detected (see /tmp/valgrind.log)"
    cat /tmp/valgrind.log
fi
test_result $RESULT "Listen mode - single connection"
echo ""

# Test 2: Multiple Connection Cycles
echo "TEST 2: Listen Mode - Multiple Connections (10 cycles)"
cleanup
echo "test data" > /tmp/node1/file1.txt

$VALGRIND_QUIET $OWSYNC listen --host 127.0.0.1 --port 21101 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
LISTENER_PID=$!
sleep 3

# Connect 10 times
for i in {1..10}; do
    echo "Connection cycle $i..."
    $OWSYNC connect 127.0.0.1 --port 21101 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1 || true
    sleep 1
done

kill -TERM $LISTENER_PID 2>/dev/null
wait $LISTENER_PID 2>/dev/null
RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo "✅ PASS: No memory leaks in 10 connections"
else
    echo "❌ FAIL: Memory leaks detected (see /tmp/valgrind.log)"
    cat /tmp/valgrind.log
fi
test_result $RESULT "Multiple connections (10 cycles)"
echo ""

# Test 3: Daemon Mode - Multiple Poll Cycles
echo "TEST 3: Daemon Mode - Multiple Poll Cycles (30 seconds)"
cleanup
echo "daemon test" > /tmp/node1/file1.txt

# Start peer listener
$OWSYNC listen --host 127.0.0.1 --port 21102 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
PEER_PID=$!
sleep 2

# Start daemon with 5-second poll interval under valgrind
$VALGRIND_QUIET $OWSYNC daemon --host 127.0.0.1 --port 21103 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --poll-interval 5 --auto-sync 127.0.0.1 &
DAEMON_PID=$!

# Let it run for 30 seconds (6 poll cycles)
echo "Running daemon for 30 seconds (6 poll cycles)..."
sleep 30

# Create a file change to trigger sync
echo "new content" > /tmp/node1/file2.txt
sleep 7  # Wait for poll + sync

# Graceful shutdown
kill -TERM $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null
DAEMON_RESULT=$?

kill -TERM $PEER_PID 2>/dev/null
wait $PEER_PID 2>/dev/null

if [ $DAEMON_RESULT -eq 0 ]; then
    echo "✅ PASS: No memory leaks in daemon mode"
else
    echo "❌ FAIL: Memory leaks detected (see /tmp/valgrind.log)"
    cat /tmp/valgrind.log
fi
test_result $DAEMON_RESULT "Daemon mode - multiple poll cycles"
echo ""

# Test 4: Connect Mode - File Transfer
echo "TEST 4: Connect Mode - Large File Transfer"
cleanup

# Create 1MB file
dd if=/dev/urandom of=/tmp/node1/largefile.bin bs=1M count=1 2>/dev/null

$OWSYNC listen --host 127.0.0.1 --port 21104 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 2

# Connect with valgrind
$VALGRIND_QUIET $OWSYNC connect 127.0.0.1 --port 21104 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db
RESULT=$?

kill -TERM $LISTENER_PID 2>/dev/null
wait $LISTENER_PID 2>/dev/null

if [ $RESULT -eq 0 ]; then
    echo "✅ PASS: No memory leaks in large file transfer"
else
    echo "❌ FAIL: Memory leaks detected (see /tmp/valgrind.log)"
    cat /tmp/valgrind.log
fi
test_result $RESULT "Large file transfer"
echo ""

# Test 5: Filter Patterns Memory
echo "TEST 5: Multiple Include/Exclude Patterns"
cleanup
echo "test1" > /tmp/node1/test1.txt
echo "test2" > /tmp/node1/test2.txt
echo "skip" > /tmp/node1/skip.txt

$OWSYNC listen --host 127.0.0.1 --port 21105 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID=$!
sleep 2

# Connect with multiple filters under valgrind
$VALGRIND_QUIET $OWSYNC connect 127.0.0.1 --port 21105 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db \
    --include "test*.txt" --include "*.bin" \
    --exclude "skip*" --exclude "*.tmp"
RESULT=$?

kill -TERM $LISTENER_PID 2>/dev/null
wait $LISTENER_PID 2>/dev/null

if [ $RESULT -eq 0 ]; then
    echo "✅ PASS: No memory leaks with filters"
else
    echo "❌ FAIL: Memory leaks detected (see /tmp/valgrind.log)"
    cat /tmp/valgrind.log
fi
test_result $RESULT "Multiple filter patterns"
echo ""

cleanup
print_summary

exit $FAIL
