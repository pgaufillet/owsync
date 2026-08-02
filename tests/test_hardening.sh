#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Regression tests for the v1.3.0 hardening pass.
#
# Every test here fails against the pre-fix binary: each one reproduces a
# specific defect (data loss, traversal, DoS, misreported identity) rather than
# asserting that the fixed code still works.
#
# The defects with no functional symptom - the out-of-bounds reads behind the
# framing fixes - are covered by test_asan.sh instead.

set -e
cd "$(dirname "$0")"
source ./common.sh

BASE=/tmp/owsync_hardening
PROBE=./proto_probe.py

echo "========================================="
echo "Hardening Regression Tests"
echo "========================================="

reset_dirs() {
    pkill -9 owsync 2>/dev/null || true
    sleep 0.3
    rm -rf "$BASE"
    mkdir -p "$BASE/node1" "$BASE/node2"
}

# Wait until the listener accepts connections.
#
# Deliberately not common.sh's wait_for_server: its `nc -z` probe closes hard
# enough to raise SIGPIPE in the server's Hello write, which would take a
# pre-SIGPIPE-fix binary down before the test it is meant to exercise runs.
# Reading the Hello first and closing gracefully leaves the daemon healthy.
wait_for_listener() {
    local port="$1"
    local count=0

    while [ $count -lt 50 ]; do
        if (exec 3<>/dev/tcp/127.0.0.1/"$port"; read -r -N 1 -t 2 -u 3 _; exec 3<&-) 2>/dev/null; then
            return 0
        fi
        sleep 0.1
        count=$((count + 1))
    done
    return 1
}

# Start a listener in the background and wait for it to accept connections
LISTENER_PID=""
start_listener() {
    local port="$1"
    local dir="$2"
    shift 2

    "$@" $OWSYNC listen --host 127.0.0.1 --port "$port" --plain -i '*' \
        --dir "$dir" --db "$dir/owsync.db" >/dev/null 2>&1 &
    LISTENER_PID=$!
    disown $LISTENER_PID 2>/dev/null || true
    wait_for_listener "$port"
}

listener_alive() {
    [ -n "$LISTENER_PID" ] && kill -0 "$LISTENER_PID" 2>/dev/null
}

stop_listener() {
    pkill -9 owsync 2>/dev/null || true
    sleep 0.3
}

sync_from() {
    local port="$1"
    local dir="$2"
    $OWSYNC connect 127.0.0.1 --port "$port" --plain -i '*' \
        --dir "$dir" --db "$dir/owsync.db" >/dev/null 2>&1 || true
}

cleanup
reset_dirs

# ---------------------------------------------------------------------------
# TEST 1: the --foreground flag is gone
#
# It never daemonized anything - it only picked a log destination - so it
# promised process management owsync does not do.
# ---------------------------------------------------------------------------
echo ""
echo "TEST 1: --foreground flag removed"

# A binary that still accepts the flag starts listening, so bound the run:
# exit 124 (timeout expired) means the flag was accepted.
set +e
timeout 3 $OWSYNC listen --foreground --host 127.0.0.1 --port 21900 --plain \
    --dir "$BASE/node2" --db "$BASE/node2/owsync.db" >/dev/null 2>&1
FLAG_RC=$?
set -e
stop_listener

if [ $FLAG_RC -eq 0 ] || [ $FLAG_RC -eq 124 ]; then
    test_result 1 "--foreground must be rejected (exit $FLAG_RC)"
else
    test_result 0 "--foreground is rejected"
fi

if $OWSYNC --help 2>&1 | grep -q -- "--foreground"; then
    test_result 1 "help must not advertise --foreground"
else
    test_result 0 "help no longer advertises --foreground"
fi

# ---------------------------------------------------------------------------
# TEST 2: hostname comes from gethostname(), not $HOSTNAME
#
# $HOSTNAME is a shell-internal variable and is absent under procd/systemd, so
# every peer used to introduce itself as "unknown".
# ---------------------------------------------------------------------------
echo ""
echo "TEST 2: peer identity survives an empty environment"

reset_dirs
REAL_HOSTNAME=$(hostname)
start_listener 21901 "$BASE/node2" env -u HOSTNAME

REPORTED=$(env -u HOSTNAME $OWSYNC connect 127.0.0.1 --port 21901 --plain -i '*' \
    --dir "$BASE/node1" --db "$BASE/node1/owsync.db" -v 2>&1 \
    | sed -n 's/.*Handshake OK, hostname=//p' | head -1)
stop_listener

if [ "$REPORTED" = "$REAL_HOSTNAME" ]; then
    test_result 0 "peer reports its real hostname ($REPORTED)"
else
    test_result 1 "peer reported '$REPORTED', expected '$REAL_HOSTNAME'"
fi

# ---------------------------------------------------------------------------
# TESTS 3-5: wire framing and receive-side resource limits
#
# The CLI always writes whole, well-formed messages, so these paths are only
# reachable by speaking the protocol directly.
# ---------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo ""
    test_skip "wire-protocol probes (python3 not available)"
else
    echo ""
    echo "TEST 3: message split across TCP segments"
    reset_dirs
    start_listener 21902 "$BASE/node2"
    if python3 "$PROBE" fragmented 21902; then
        test_result 0 "fragmented length prefix and payload are reassembled"
    else
        test_result 1 "fragmented message dropped the session"
    fi
    stop_listener

    echo ""
    echo "TEST 4: zero-length message frame"
    reset_dirs
    start_listener 21903 "$BASE/node2"
    if python3 "$PROBE" zero-length 21903; then
        test_result 0 "zero-length frame rejected and daemon kept serving"
    else
        test_result 1 "zero-length frame was mishandled"
    fi
    stop_listener

    echo ""
    echo "TEST 5: concurrent large-message allocation cap"
    reset_dirs
    start_listener 21904 "$BASE/node2"
    # 32MB is MAX_MESSAGE_SIZE; the budget admits two of them at once
    if python3 "$PROBE" alloc-cap 21904 33554432 2; then
        test_result 0 "receive budget refuses the third 32MB announcement"
    else
        test_result 1 "peers can reserve unbounded memory before sending payload"
    fi
    stop_listener
fi

# ---------------------------------------------------------------------------
# TEST 6: receive-side path traversal by prefix collision
#
# A plain strncmp() prefix test accepts "/tmp/x/node2EVIL" as being inside
# "/tmp/x/node2". Reaching it needs a symlink in the receiver's sync root
# pointing at the sibling directory.
# ---------------------------------------------------------------------------
echo ""
echo "TEST 6: path traversal via sibling-directory prefix collision"

reset_dirs
EVIL="$BASE/node2EVIL"
mkdir -p "$EVIL" "$BASE/node1/link"
echo "attacker payload" > "$BASE/node1/link/pwned.txt"
# Sent alongside the attack so "nothing landed in EVIL" cannot pass by accident
# when the session never ran at all
echo "ordinary file" > "$BASE/node1/benign.txt"
ln -s "$EVIL" "$BASE/node2/link"

start_listener 21905 "$BASE/node2"
sync_from 21905 "$BASE/node1"
stop_listener

if [ ! -f "$BASE/node2/benign.txt" ]; then
    test_result 1 "inconclusive: the sync session never delivered anything"
elif [ -e "$EVIL/pwned.txt" ]; then
    test_result 1 "file written outside the sync root ($EVIL/pwned.txt)"
else
    test_result 0 "write outside the sync root refused"
fi

# ---------------------------------------------------------------------------
# TEST 7: an unreadable file is not a deleted file
#
# When hashing fails the file used to vanish from the scan, get tombstoned, and
# the tombstone then deleted the peers' good copies.
# ---------------------------------------------------------------------------
echo ""
echo "TEST 7: transient read failure does not propagate as a delete"

if [ "$(id -u)" = "0" ]; then
    test_skip "unreadable-file test (running as root, chmod 000 is not enforced)"
else
    reset_dirs
    echo "important data" > "$BASE/node1/keep.txt"

    start_listener 21906 "$BASE/node2"
    sync_from 21906 "$BASE/node1"

    if [ ! -f "$BASE/node2/keep.txt" ]; then
        stop_listener
        test_result 1 "inconclusive: the file never reached the peer in the first place"
    else
        # Make the source unreadable, then sync again
        chmod 000 "$BASE/node1/keep.txt"
        sleep 1.1  # Tombstone mtime must land after the file's own mtime
        sync_from 21906 "$BASE/node1"
        stop_listener
        chmod 644 "$BASE/node1/keep.txt"

        if [ -f "$BASE/node2/keep.txt" ]; then
            test_result 0 "peer copy survived an unreadable source file"
        else
            test_result 1 "peer copy was deleted because the source could not be hashed"
        fi
    fi
fi

# ---------------------------------------------------------------------------
# TEST 8: a peer that hangs up mid-handshake must not kill the daemon
#
# The server writes its Hello as soon as it accepts. Writing to a socket the
# peer has already closed raises SIGPIPE, whose default action terminates the
# process - one probe connection was enough to take the daemon down.
# ---------------------------------------------------------------------------
echo ""
echo "TEST 8: daemon survives a peer that disconnects mid-handshake"

reset_dirs
echo "payload" > "$BASE/node1/after.txt"
start_listener 21907 "$BASE/node2"

# Connect and hang up immediately, several times
for _ in 1 2 3; do
    (exec 3<>/dev/tcp/127.0.0.1/21907) 2>/dev/null || true
    sleep 0.2
done

if ! listener_alive; then
    stop_listener
    test_result 1 "daemon died after a peer disconnected mid-handshake"
else
    sync_from 21907 "$BASE/node1"
    stop_listener
    if [ -f "$BASE/node2/after.txt" ]; then
        test_result 0 "daemon survived and still serves sync sessions"
    else
        test_result 1 "daemon survived but no longer completes a sync"
    fi
fi

reset_dirs
rm -rf "$BASE"
print_summary

if [ $FAIL -gt 0 ]; then
    echo -e "${RED}❌ Hardening Regression Tests: FAILED${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Hardening Regression Tests: PASSED${NC}"
exit 0
