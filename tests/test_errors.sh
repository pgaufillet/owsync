#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Error Handling Tests - Tests various error conditions and edge cases

cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Error Handling Tests"
echo "========================================="
echo ""

# Test 1: Invalid Directory Path
echo "TEST 1: Invalid Directory Path"
cleanup
OUTPUT=$(timeout 5 $OWSYNC listen --host 127.0.0.1 --port 21000 --plain -i '*' --dir /nonexistent/path --db /tmp/test.db 2>&1 || true)
echo "$OUTPUT" | grep -q "does not exist"
test_result $? "Invalid directory error message"
echo ""

# Test 2: File Instead of Directory
echo "TEST 2: File Instead of Directory"
cleanup
echo "test" > /tmp/notadir.txt
OUTPUT=$(timeout 5 $OWSYNC listen --host 127.0.0.1 --port 21000 --plain -i '*' --dir /tmp/notadir.txt --db /tmp/test.db 2>&1 || true)
rm /tmp/notadir.txt
echo "$OUTPUT" | grep -q "not a directory"
test_result $? "File path rejected"
echo ""

# Test 3: Permission Denied
echo "TEST 3: Permission Denied"
cleanup
mkdir -p /tmp/readonly_test
chmod 444 /tmp/readonly_test
OUTPUT=$(timeout 5 $OWSYNC listen --host 127.0.0.1 --port 21000 --plain -i '*' --dir /tmp/readonly_test --db /tmp/test.db 2>&1 || true)
chmod 755 /tmp/readonly_test
rmdir /tmp/readonly_test
echo "$OUTPUT" | grep -q -i "permission\|cannot.*write\|read"
test_result $? "Permission denied error"
echo ""

# Test 4: Encryption Key Mismatch
echo "TEST 4: Encryption Key Mismatch"
cleanup
echo "test data" > /tmp/node1/test.txt
KEY1="0000000000000000000000000000000000000000000000000000000000000001"
KEY2="0000000000000000000000000000000000000000000000000000000000000002"

# Create config files with different encryption keys
create_config /tmp/node2/owsync.conf /tmp/node2 /tmp/node2/owsync.db "$KEY1"
create_config /tmp/node1/owsync.conf /tmp/node1 /tmp/node1/owsync.db "$KEY2"

$OWSYNC listen --host 127.0.0.1 --port 21001 -c /tmp/node2/owsync.conf >/dev/null 2>&1 &
PID=$!; sleep 1
timeout 5 $OWSYNC connect 127.0.0.1 --port 21001 -c /tmp/node1/owsync.conf >/dev/null 2>&1 || true
kill $PID 2>/dev/null

# File should not sync correctly with wrong key
CONTENT=$(cat /tmp/node2/test.txt 2>/dev/null || echo "no-file")
[ "$CONTENT" != "test data" ]
test_result $? "Key mismatch protection"
echo ""

# Test 5: Concurrent Connections
echo "TEST 5: Concurrent Connections"
cleanup
echo "test" > /tmp/node1/file.txt

timeout 15 $OWSYNC listen --host 127.0.0.1 --port 21002 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
PID=$!; sleep 1

timeout 10 $OWSYNC connect 127.0.0.1 --port 21002 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1 &
CONN1=$!
sleep 0.5
timeout 10 $OWSYNC connect 127.0.0.1 --port 21002 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1 &
CONN2=$!

wait $CONN1 2>/dev/null || true
wait $CONN2 2>/dev/null || true
sleep 1
kill $PID 2>/dev/null

[ -f /tmp/node2/file.txt ]
test_result $? "Concurrent connections handled"
echo ""

# Test 6: Invalid Address Format
echo "TEST 6: Invalid Address Format"
cleanup
timeout 5 $OWSYNC connect invalid-address --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
EXIT_CODE=$?
# Should fail - connection error or address parsing error (exit code 1 or 124 from timeout)
[ $EXIT_CODE -ne 0 ]
test_result $? "Invalid address rejected"
echo ""

# Test 7: Connection Refused
echo "TEST 7: Connection Refused"
cleanup
echo "test" > /tmp/node1/file.txt
timeout 5 $OWSYNC connect 127.0.0.1 --port 21999 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
# Should fail with non-zero exit code
[ $? -ne 0 ]
test_result $? "Connection failure detected"
echo ""

# Test 8: Corrupted Database Recovery
echo "TEST 8: Corrupted Database Recovery"
cleanup
echo "test content" > /tmp/node1/file.txt

# Create corrupted database (invalid JSON)
echo "This is not valid JSON {{{" > /tmp/node1/owsync.db

# Start listener with corrupted DB
$OWSYNC listen --host 127.0.0.1 --port 21004 --plain -i '*' \
    --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1 &
PID=$!
sleep 2

# Verify process is running (didn't crash)
if ! kill -0 $PID 2>/dev/null; then
    kill $PID 2>/dev/null || true
    test_result 1 "Corrupted database recovery (process crashed)"
else
    # Try to sync - should work after recovery
    $OWSYNC connect 127.0.0.1 --port 21004 --plain -i '*' \
        --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1

    kill $PID 2>/dev/null || true

    # Verify file was synced (proves recovery worked)
    if [ -f /tmp/node2/file.txt ]; then
        # Verify DB was recreated (valid JSON now)
        if python3 -c "import json; json.load(open('/tmp/node1/owsync.db'))" 2>/dev/null || \
           jq . /tmp/node1/owsync.db >/dev/null 2>&1; then
            test_result 0 "Corrupted database recovery (DB recreated as valid JSON)"
        else
            # Sync worked but DB still invalid - partial recovery
            test_result 1 "Corrupted database recovery (sync worked but DB still invalid)"
        fi
    else
        test_result 1 "Corrupted database recovery (sync failed)"
    fi
fi
echo ""

# Test 9: Conflicting Listener on Same Port
echo "TEST 9: Conflicting Listener on Same Port"
cleanup
$OWSYNC listen --host 127.0.0.1 --port 21005 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1 &
PID1=$!; sleep 1

# Try to start another listener on the same port
timeout 5 $OWSYNC listen --host 127.0.0.1 --port 21005 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
PID2=$!
sleep 1

# Second listener should fail or exit
ps -p $PID2 >/dev/null 2>&1
RUNNING=$?
kill $PID1 $PID2 2>/dev/null || true

# Second process should not be running (exit code 1)
[ $RUNNING -ne 0 ]
test_result $? "Port conflict detected"
echo ""

# Test 10: Very Long Filename
echo "TEST 10: Very Long Filename"
cleanup
# Create a file with a very long name (but within limits)
LONGNAME=$(printf 'a%.0s' {1..200})
if echo "content" > "/tmp/node1/$LONGNAME.txt" 2>/dev/null; then
    TESTFILE="$LONGNAME.txt"
else
    echo "content" > "/tmp/node1/longfile.txt"
    TESTFILE="longfile.txt"
fi

$OWSYNC listen --host 127.0.0.1 --port 21006 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 21006 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1
sleep 0.5
kill $PID 2>/dev/null || true

# Verify long filename didn't crash the daemon (check if we got any file)
if [ -f "/tmp/node2/$TESTFILE" ] || ls /tmp/node2/*.txt 2>/dev/null | grep -q .; then
    test_result 0 "Long filename synced successfully"
else
    # Check if daemon crashed vs just didn't sync the file
    if [ -d /tmp/node2 ]; then
        test_result 1 "Long filename sync failed (no files synced)"
    else
        test_result 1 "Long filename caused daemon failure"
    fi
fi
echo ""

cleanup
print_summary

exit $FAIL
