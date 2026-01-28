#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Core functionality tests

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Core Functionality Tests"
echo "========================================="
echo ""

# Test 1: File Deletion Propagation (Tombstones)
echo "TEST 1: File Deletion Propagation"
cleanup
echo "content1" > /tmp/node1/file1.txt
echo "content2" > /tmp/node1/file2.txt

$OWSYNC listen --host 127.0.0.1 --port 20001 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20001 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

rm /tmp/node1/file1.txt

$OWSYNC listen --host 127.0.0.1 --port 20002 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20002 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

[ ! -f /tmp/node2/file1.txt ] && [ -f /tmp/node2/file2.txt ]
test_result $? "File deletion propagated (tombstone)"
echo ""

# Test 2: File Modification Detection
echo "TEST 2: File Modification Detection"
cleanup
echo "original" > /tmp/node1/test.txt

$OWSYNC listen --host 127.0.0.1 --port 20003 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20003 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

sleep 1
echo "modified" > /tmp/node1/test.txt

$OWSYNC listen --host 127.0.0.1 --port 20004 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20004 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

[ "$(cat /tmp/node2/test.txt)" = "modified" ]
test_result $? "File modification detected and synced"
echo ""

# Test 3: Exclude Patterns
echo "TEST 3: Exclude Patterns"
cleanup
echo "included" > /tmp/node1/file.txt
echo "excluded" > /tmp/node1/secret.txt

$OWSYNC listen --host 127.0.0.1 --port 20005 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db --exclude "secret.txt" &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20005 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db --exclude "secret.txt" >/dev/null 2>&1
kill $PID 2>/dev/null

[ -f /tmp/node2/file.txt ] && [ ! -f /tmp/node2/secret.txt ]
test_result $? "Exclude patterns working"
echo ""

# Test 4: Large File
echo "TEST 4: Large File (1MB)"
cleanup
dd if=/dev/urandom of=/tmp/node1/large.bin bs=1024 count=1024 2>/dev/null

$OWSYNC listen --host 127.0.0.1 --port 20007 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20007 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

SIZE1=$(stat -c%s /tmp/node1/large.bin 2>/dev/null)
SIZE2=$(stat -c%s /tmp/node2/large.bin 2>/dev/null)
[ "$SIZE1" = "$SIZE2" ] && [ "$SIZE1" -gt 1000000 ]
test_result $? "Large file sync (1MB)"
echo ""

# Test 5: Encrypted Mode
echo "TEST 5: Encrypted Mode"
cleanup
echo "encrypted content" > /tmp/node1/encrypted.txt

# Create config files with encryption key (keys no longer accepted on command line)
create_config /tmp/node1/owsync.conf /tmp/node1 /tmp/node1/owsync.db "$TEST_KEY"
create_config /tmp/node2/owsync.conf /tmp/node2 /tmp/node2/owsync.db "$TEST_KEY"

$OWSYNC listen --host 127.0.0.1 --port 20009 -c /tmp/node1/owsync.conf &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20009 -c /tmp/node2/owsync.conf >/dev/null 2>&1
kill $PID 2>/dev/null

[ -f /tmp/node2/encrypted.txt ] && [ "$(cat /tmp/node2/encrypted.txt)" = "encrypted content" ]
test_result $? "Encrypted mode sync"
echo ""

cleanup
print_summary

exit $FAIL
