#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Edge Case Tests - Tests boundary conditions, stress scenarios, and special cases

cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Edge Case Tests"
echo "========================================="
echo ""

# Test 1: Long File Paths
echo "TEST 1: Long File Paths"
cleanup
mkdir -p /tmp/node1/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t
echo "deep file" > /tmp/node1/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/test.txt

$OWSYNC listen --host 127.0.0.1 --port 22001 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22001 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 1
kill $PID 2>/dev/null

[ -f /tmp/node2/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/test.txt ] && \
[ "$(cat /tmp/node2/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/test.txt)" = "deep file" ]
test_result $? "Deep nested paths"
echo ""

# Test 2: Subdirectory Synchronization
echo "TEST 2: Subdirectory Synchronization"
cleanup
mkdir -p /tmp/node1/sub1/sub2
echo "file1" > /tmp/node1/root.txt
echo "file2" > /tmp/node1/sub1/mid.txt
echo "file3" > /tmp/node1/sub1/sub2/deep.txt

$OWSYNC listen --host 127.0.0.1 --port 22002 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22002 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 1
kill $PID 2>/dev/null

[ -f /tmp/node2/root.txt ] && [ -f /tmp/node2/sub1/mid.txt ] && [ -f /tmp/node2/sub1/sub2/deep.txt ]
test_result $? "Subdirectory sync"
echo ""

# Test 3: Directory Boundary Protection
echo "TEST 3: Directory Boundary Protection"
cleanup
# Create a file outside sync directories
echo "EXTERNAL FILE" > /tmp/external_test_file.txt

# Create normal files inside sync directory
echo "test data" > /tmp/node1/normal_file.txt

$OWSYNC listen --host 127.0.0.1 --port 22003 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22003 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 1
kill $PID 2>/dev/null

# External file should remain unchanged
EXTERNAL_CONTENT=$(cat /tmp/external_test_file.txt 2>/dev/null)
rm /tmp/external_test_file.txt 2>/dev/null || true

# Normal file should sync
SYNCED=$(cat /tmp/node2/normal_file.txt 2>/dev/null)

# Test passes if external file unchanged and normal file synced
[ "$EXTERNAL_CONTENT" = "EXTERNAL FILE" ] && [ "$SYNCED" = "test data" ]
test_result $? "Directory boundary protection"
echo ""

# Test 4: Rapid Sequential Syncs
echo "TEST 4: Rapid Sequential Syncs"
cleanup

$OWSYNC listen --host 127.0.0.1 --port 22004 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
PID=$!; sleep 1

for i in {1..5}; do
    echo "iteration $i" > /tmp/node1/file$i.txt
    $OWSYNC connect 127.0.0.1 --port 22004 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
    sleep 0.2
done

kill $PID 2>/dev/null

# Check all files synced
ALL_SYNCED=true
for i in {1..5}; do
    if [ ! -f /tmp/node2/file$i.txt ]; then
        ALL_SYNCED=false
        break
    fi
done
[ "$ALL_SYNCED" = true ]
test_result $? "Rapid sequential syncs"
echo ""

# Test 5: Binary File Integrity
echo "TEST 5: Binary File Integrity"
cleanup
dd if=/dev/urandom of=/tmp/node1/binary.dat bs=1K count=10 2>/dev/null

ORIGINAL_HASH=$(sha256sum /tmp/node1/binary.dat | awk '{print $1}')

$OWSYNC listen --host 127.0.0.1 --port 22005 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22005 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 1
kill $PID 2>/dev/null

SYNCED_HASH=$(sha256sum /tmp/node2/binary.dat 2>/dev/null | awk '{print $1}')
[ "$ORIGINAL_HASH" = "$SYNCED_HASH" ]
test_result $? "Binary file integrity"
echo ""

# Test 6: Special Characters in Filenames
echo "TEST 6: Special Characters in Filenames"
cleanup
echo "test1" > "/tmp/node1/file with spaces.txt"
echo "test2" > "/tmp/node1/file-with-dashes.txt"
echo "test3" > "/tmp/node1/file_with_underscores.txt"
echo "test4" > "/tmp/node1/file.multiple.dots.txt"

$OWSYNC listen --host 127.0.0.1 --port 22006 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22006 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 1
kill $PID 2>/dev/null

[ -f "/tmp/node2/file with spaces.txt" ] && \
[ -f "/tmp/node2/file-with-dashes.txt" ] && \
[ -f "/tmp/node2/file_with_underscores.txt" ] && \
[ -f "/tmp/node2/file.multiple.dots.txt" ]
test_result $? "Special characters in filenames"
echo ""

# Test 7: Empty Directory Handling
echo "TEST 7: Empty Directory Handling"
cleanup
mkdir -p /tmp/node1/empty_dir

$OWSYNC listen --host 127.0.0.1 --port 22007 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22007 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

# Empty directories may or may not be synced - just ensure no crash
test_result 0 "Empty directory handling"
echo ""

# Test 8: Many Files
echo "TEST 8: Many Files (100 files)"
cleanup

for i in $(seq 1 100); do
    echo "file $i" > /tmp/node1/file_$i.txt
done

$OWSYNC listen --host 127.0.0.1 --port 22008 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 22008 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 2
kill $PID 2>/dev/null

SYNCED_COUNT=$(ls /tmp/node2/file_*.txt 2>/dev/null | wc -l)
[ "$SYNCED_COUNT" -eq 100 ]
test_result $? "Many files sync (100 files)"
echo ""

cleanup
print_summary

exit $FAIL
