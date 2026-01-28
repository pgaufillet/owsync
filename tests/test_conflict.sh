#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Conflict resolution tests

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Conflict Resolution Tests"
echo "========================================="
echo ""

# Test 1: Both nodes modify - Remote Newer Wins
echo "TEST 1: Conflict - Remote Newer Wins"
cleanup

echo "version0" > /tmp/node1/conflict.txt
$OWSYNC listen --host 127.0.0.1 --port 21001 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21001 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

echo "node1_version" > /tmp/node1/conflict.txt
sleep 1
echo "node2_version" > /tmp/node2/conflict.txt

$OWSYNC listen --host 127.0.0.1 --port 21002 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21002 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

[ "$(cat /tmp/node1/conflict.txt)" = "node2_version" ]
test_result $? "Remote newer wins (LWW)"
echo ""

# Test 2: Both nodes modify - Local Newer Wins
echo "TEST 2: Conflict - Local Newer Wins"
cleanup

echo "version0" > /tmp/node1/conflict.txt
$OWSYNC listen --host 127.0.0.1 --port 21003 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21003 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

echo "node2_version" > /tmp/node2/conflict.txt
sleep 1
echo "node1_version" > /tmp/node1/conflict.txt

$OWSYNC listen --host 127.0.0.1 --port 21004 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21004 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

[ "$(cat /tmp/node1/conflict.txt)" = "node1_version" ]
test_result $? "Local newer wins (LWW)"
echo ""

# Test 3: Delete vs Modify - Deletion Newer
echo "TEST 3: Delete vs Modify - Deletion Wins"
cleanup

echo "initial" > /tmp/node1/conflict.txt
$OWSYNC listen --host 127.0.0.1 --port 21007 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21007 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

echo "modified" > /tmp/node1/conflict.txt
sleep 1
rm /tmp/node2/conflict.txt

$OWSYNC listen --host 127.0.0.1 --port 21008 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21008 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

$OWSYNC listen --host 127.0.0.1 --port 21009 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21009 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

[ ! -f /tmp/node1/conflict.txt ]
test_result $? "Deletion wins over modification"
echo ""

# Test 4: File Recreated After Deletion
echo "TEST 4: File Recreation After Deletion"
cleanup

echo "original" > /tmp/node1/file.txt
$OWSYNC listen --host 127.0.0.1 --port 21013 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21013 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

rm /tmp/node1/file.txt

$OWSYNC listen --host 127.0.0.1 --port 21014 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21014 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

sleep 1
echo "recreated" > /tmp/node1/file.txt

$OWSYNC listen --host 127.0.0.1 --port 21015 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21015 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

[ "$(cat /tmp/node2/file.txt 2>/dev/null)" = "recreated" ]
test_result $? "File recreation after deletion"
echo ""

cleanup
print_summary

exit $FAIL
