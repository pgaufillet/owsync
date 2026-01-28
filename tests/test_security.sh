#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Security regression tests

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Security Vulnerability Regression Tests"
echo "========================================="

cleanup

# Setup
mkdir -p /tmp/node1
mkdir -p /tmp/node2
rm -f /tmp/pwned

# Start listener (victim)
echo "Starting listener..."
if command -v stdbuf >/dev/null; then
    stdbuf -oL -eL $OWSYNC listen --host 127.0.0.1 --port 21200 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/tmp/listener_debug.log 2>&1 &
else
    $OWSYNC listen --host 127.0.0.1 --port 21200 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/tmp/listener_debug.log 2>&1 &
fi
LISTENER_PID=$!
disown $LISTENER_PID
sleep 2

# Test 1: Command Injection via Directory Name (VULN-001)
echo "TEST 1: Command Injection via Directory Name"
# Create a directory path that would trigger command injection if passed to system("mkdir -p ...")
# payload: "inject; touch pwned_file"
# Note: filenames cannot contain '/', so we use a local file for the probe
INJECT_DIR="inject; touch pwned_file"
mkdir -p "/tmp/node1/$INJECT_DIR"
echo "data" > "/tmp/node1/$INJECT_DIR/file.txt"

# Ensure pwned_file doesn't exist in PWD (where owsync listener runs)
# The listener runs in the background, likely inheriting PWD from the script context.
# We are in tests/
rm -f pwned_file

echo "Syncing file with malicious directory name..."
$OWSYNC connect 127.0.0.1 --port 21200 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1

# Check if exploit worked (file created in listener's CWD)
if [ -f "pwned_file" ]; then
    echo -e "${RED}❌ FAIL: Command injection successful! ./pwned_file created.${NC}"
    rm -f pwned_file
    FAIL=1
else
    echo -e "${GREEN}✅ PASS: Command injection prevented (no ./pwned_file created)${NC}"
    PASS=$((PASS + 1))
fi

# Verify the file was actually synced (it's a valid filename)
if [ -f "/tmp/node2/$INJECT_DIR/file.txt" ]; then
    echo -e "${GREEN}✅ PASS: File with shell characters synced correctly${NC}"
    echo "Proof - listing of /tmp/node2:"
    ls -lR /tmp/node2
    PASS=$((PASS + 1))
else
    echo -e "${YELLOW}⚠️  INFO: Maliciously named file was not synced (rejected?), which is acceptable.${NC}"
    echo "Listing of /tmp/node2:"
    ls -lR /tmp/node2
fi

echo ""

# Test 2: Symlink Attack (VULN-002/VULN-008)
echo "TEST 2: Symlink Attack Prevention"
cleanup
rm -f /tmp/target_file
echo "sensitive data" > /tmp/target_file

# Create a scenario where node2 has a symlink pointing to /tmp/target_file
# and node1 tries to write to that filename.
# Note: In a real attack, the attacker would first sync the symlink, then the file.
# But our current implementation ignores symlinks in scan (FTW_PHYS).
# So we manually create the symlink on the victim side to simulate a race condition or pre-existing state.

mkdir -p /tmp/node2
ln -s /tmp/target_file /tmp/node2/link.txt

mkdir -p /tmp/node1
echo "overwrite" > /tmp/node1/link.txt

# Start listener again
$OWSYNC listen --host 127.0.0.1 --port 21201 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
LISTENER_PID_2=$!
disown $LISTENER_PID_2
sleep 2

echo "Syncing file over existing symlink..."
$OWSYNC connect 127.0.0.1 --port 21201 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1

# Check if target file was overwritten
CONTENT=$(cat /tmp/target_file)
if [ "$CONTENT" == "overwrite" ]; then
    echo -e "${RED}❌ FAIL: Symlink followed! Target file overwritten.${NC}"
    FAIL=$((FAIL + 1))
else
    echo -e "${GREEN}✅ PASS: Symlink not followed. Target file intact.${NC}"
    PASS=$((PASS + 1))
fi

# Check if the symlink was replaced (expected behavior with rename atomic replacement)
if [ -L "/tmp/node2/link.txt" ]; then
     echo -e "${YELLOW}⚠️  INFO: Symlink still exists (open() failed).${NC}"
else
     echo -e "${GREEN}✅ PASS: Symlink replaced with real file (atomic rename behavior).${NC}"
     PASS=$((PASS + 1))
fi

echo ""

# Test 3: File Permission Preservation (VULN-009)
echo "TEST 3: File Permission Preservation"
rm -f /tmp/node1/script.sh /tmp/node2/script.sh
echo "#!/bin/sh" > /tmp/node1/script.sh
echo "echo hello" >> /tmp/node1/script.sh
chmod +x /tmp/node1/script.sh

echo "Syncing executable script..."
$OWSYNC connect 127.0.0.1 --port 21201 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/dev/null 2>&1

MODE=$(stat -c %a /tmp/node2/script.sh 2>/dev/null)
echo "File mode: $MODE"

if [[ "$MODE" == *"7"* ]] || [[ "$MODE" == *"5"* ]] || [[ "$MODE" == *"1"* ]]; then
    # Check if any execute bit is set (User, Group, or Other)
    # Actually we expect 755 or 775 depending on umask, but 'x' should be present.
    # checking for odd number in octal is a simple check for 'x' (1)
    if [ $((MODE % 2)) -eq 1 ] || [ $(((MODE / 10) % 2)) -eq 1 ] || [ $(((MODE / 100) % 2)) -eq 1 ]; then
         echo -e "${GREEN}✅ PASS: Execute permission preserved ($MODE)${NC}"
         PASS=$((PASS + 1))
    else
         echo -e "${RED}❌ FAIL: Execute permission lost ($MODE)${NC}"
         FAIL=$((FAIL + 1))
    fi
else
    echo -e "${RED}❌ FAIL: Execute permission lost ($MODE)${NC}"
    FAIL=$((FAIL + 1))
fi

echo ""

# Test 4: Large File Rejection (VULN-007)
echo "TEST 4: Large File Rejection (DoS Mitigation)"
# MAX_MESSAGE_SIZE is 32MB. Hex encoding doubles size.
# So files > 16MB should be rejected. We use 20MB.
rm -f /tmp/node1/large.bin /tmp/node2/large.bin
dd if=/dev/zero of=/tmp/node1/large.bin bs=1M count=20 2>/dev/null

echo "Syncing 20MB file (should be rejected)..."
$OWSYNC connect 127.0.0.1 --port 21201 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db >/tmp/client_large.log 2>&1

if [ -f "/tmp/node2/large.bin" ]; then
    echo -e "${RED}❌ FAIL: Large file was synced (DoS mitigation failed)${NC}"
    FAIL=$((FAIL + 1))
else
    if grep -q "too large" /tmp/client_large.log; then
        echo -e "${GREEN}✅ PASS: Large file rejected with error message${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${YELLOW}⚠️  INFO: Large file not synced, but specific error message not found.${NC}"
        cat /tmp/client_large.log
        # Still a pass for security, but warning for usability
        PASS=$((PASS + 1))
    fi
fi
rm -f /tmp/node1/large.bin

echo ""

# Test 5: Debug Option Rejection (VULN-012)
echo "TEST 5: Debug Option Rejection (Release Build)"
# --debug-clock-offset should be rejected in release builds
if $OWSYNC listen --help 2>&1 | grep -q "debug-clock-offset"; then
    echo -e "${YELLOW}⚠️  INFO: --debug-clock-offset present in help (Debug build?). Skipping rejection test.${NC}"
else
    if $OWSYNC listen --debug-clock-offset 10 --host 127.0.0.1 --port 21299 --plain -i '*' --dir /tmp/node1 >/dev/null 2>&1; then
        echo -e "${RED}❌ FAIL: --debug-clock-offset accepted in presumed release build${NC}"
        FAIL=$((FAIL + 1))
        # Kill it if it started
        pkill -f "owsync.*21299" || true
    else
        echo -e "${GREEN}✅ PASS: --debug-clock-offset rejected${NC}"
        PASS=$((PASS + 1))
    fi
fi


kill $LISTENER_PID 2>/dev/null || true
kill $LISTENER_PID_2 2>/dev/null || true
wait 2>/dev/null || true

if [ $FAIL -ne 0 ]; then
    echo "--- Listener Log ---"
    cat /tmp/listener_debug.log
    echo "--------------------"
fi

rm -f /tmp/pwned /tmp/target_file
print_summary
exit $FAIL
