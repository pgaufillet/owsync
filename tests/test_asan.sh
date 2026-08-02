#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Memory-safety regression test.
#
# Some defects in the receive path leave no functional trace: parsing a wire
# buffer as a NUL-terminated string reads past the allocation on every single
# message, yet the sync still completes and every behavioural test passes. Only
# a sanitizer build turns them into an observable failure, so this suite
# rebuilds owsync with AddressSanitizer + UBSan and drives real sessions
# through it.

set -e
cd "$(dirname "$0")"
source ./common.sh

ASAN_DIR=/tmp/owsync_asan
ASAN_BIN="$ASAN_DIR/bin/owsync"
ASAN_LOGS="$ASAN_DIR/logs"
KEY="$TEST_KEY"

echo "========================================="
echo "Memory Safety Tests (ASan + UBSan)"
echo "========================================="

if ! echo 'int main(void){return 0;}' | \
        ${CC:-cc} -fsanitize=address,undefined -x c - -o /dev/null 2>/dev/null; then
    test_skip "sanitizer build (compiler has no -fsanitize=address,undefined support)"
    print_summary
    exit 0
fi

echo "Building instrumented binary..."
rm -rf "$ASAN_DIR"
mkdir -p "$ASAN_DIR" "$ASAN_LOGS"

if ! make -C .. \
        BUILD_DIR="$ASAN_DIR/build" BIN_DIR="$ASAN_DIR/bin" \
        CFLAGS="-Wall -Wextra -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
        LDFLAGS="-lpthread -fsanitize=address,undefined" >"$ASAN_LOGS/build.log" 2>&1; then
    echo "Build failed:"
    tail -20 "$ASAN_LOGS/build.log"
    test_result 1 "instrumented build"
    print_summary
    exit 1
fi
test_result 0 "instrumented build"

# Sanitizers must report rather than be swallowed by the daemon's error handling
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:exitcode=1"
export UBSAN_OPTIONS="print_stacktrace=1"

reset_dirs() {
    pkill -9 owsync 2>/dev/null || true
    sleep 0.3
    rm -rf "$ASAN_DIR/node1" "$ASAN_DIR/node2"
    mkdir -p "$ASAN_DIR/node1" "$ASAN_DIR/node2"
}

# Count AddressSanitizer / UBSan reports across a session's logs
sanitizer_hits() {
    grep -c -E "ERROR: AddressSanitizer|ERROR: LeakSanitizer|runtime error:" "$@" 2>/dev/null \
        | awk -F: '{ total += $NF } END { print total + 0 }'
}

run_session() {
    local name="$1"
    local port="$2"
    shift 2  # Remaining args are extra owsync flags (e.g. --plain)

    # owsync refuses a key and --plain together. An empty OWSYNC_KEY still counts
    # as a key, so the variable has to be removed rather than blanked.
    local -a env_prefix=(env "OWSYNC_KEY=$KEY")
    case " $* " in
    *" --plain "*) env_prefix=(env -u OWSYNC_KEY) ;;
    esac

    reset_dirs
    echo "content for $name" > "$ASAN_DIR/node1/file.txt"
    mkdir -p "$ASAN_DIR/node1/sub"
    echo "nested" > "$ASAN_DIR/node1/sub/nested.txt"

    "${env_prefix[@]}" "$ASAN_BIN" listen --host 127.0.0.1 --port "$port" -i '*' \
        --dir "$ASAN_DIR/node2" --db "$ASAN_DIR/node2/owsync.db" "$@" \
        >"$ASAN_LOGS/$name-listen.log" 2>&1 &
    disown $! 2>/dev/null || true
    sleep 2

    "${env_prefix[@]}" "$ASAN_BIN" connect 127.0.0.1 --port "$port" -i '*' \
        --dir "$ASAN_DIR/node1" --db "$ASAN_DIR/node1/owsync.db" "$@" \
        >"$ASAN_LOGS/$name-connect.log" 2>&1 || true
    sleep 0.5
    pkill -9 owsync 2>/dev/null || true
    sleep 0.3
}

# ---------------------------------------------------------------------------
# TEST 1-2: ordinary sync sessions, plain and encrypted
#
# Both paths reach the JSON parser with a wire buffer; the plain path hands it
# the raw read buffer, the encrypted path the decrypt output.
# ---------------------------------------------------------------------------
echo ""
echo "TEST 1: plain-mode sync under sanitizers"
run_session plain 21910 --plain
HITS=$(sanitizer_hits "$ASAN_LOGS/plain-listen.log" "$ASAN_LOGS/plain-connect.log")
if [ "$HITS" = "0" ] && [ -f "$ASAN_DIR/node2/file.txt" ]; then
    test_result 0 "plain sync completed with no sanitizer reports"
elif [ "$HITS" != "0" ]; then
    test_result 1 "$HITS sanitizer report(s) during plain sync"
    grep -m1 -A6 -E "ERROR: AddressSanitizer|runtime error:" \
        "$ASAN_LOGS/plain-listen.log" "$ASAN_LOGS/plain-connect.log" || true
else
    test_result 1 "plain sync did not transfer the file"
fi

echo ""
echo "TEST 2: encrypted sync under sanitizers"
run_session encrypted 21911
HITS=$(sanitizer_hits "$ASAN_LOGS/encrypted-listen.log" "$ASAN_LOGS/encrypted-connect.log")
if [ "$HITS" = "0" ] && [ -f "$ASAN_DIR/node2/file.txt" ]; then
    test_result 0 "encrypted sync completed with no sanitizer reports"
elif [ "$HITS" != "0" ]; then
    test_result 1 "$HITS sanitizer report(s) during encrypted sync"
    grep -m1 -A6 -E "ERROR: AddressSanitizer|runtime error:" \
        "$ASAN_LOGS/encrypted-listen.log" "$ASAN_LOGS/encrypted-connect.log" || true
else
    test_result 1 "encrypted sync did not transfer the file"
fi

# ---------------------------------------------------------------------------
# TEST 3: hostile frames under sanitizers
#
# A zero-length announcement produces a zero-byte buffer. Handing that to a
# string parser is invisible in normal operation and fatal under ASan.
# ---------------------------------------------------------------------------
echo ""
echo "TEST 3: hostile wire frames under sanitizers"

if ! command -v python3 >/dev/null 2>&1; then
    test_skip "hostile-frame probes (python3 not available)"
else
    reset_dirs
    echo "data" > "$ASAN_DIR/node1/file.txt"
    "$ASAN_BIN" listen --host 127.0.0.1 --port 21912 --plain -i '*' \
        --dir "$ASAN_DIR/node2" --db "$ASAN_DIR/node2/owsync.db" \
        >"$ASAN_LOGS/hostile-listen.log" 2>&1 &
    disown $! 2>/dev/null || true
    sleep 2

    python3 ./proto_probe.py zero-length 21912 >/dev/null 2>&1 || true
    python3 ./proto_probe.py fragmented 21912 >/dev/null 2>&1 || true
    sleep 0.5
    pkill -9 owsync 2>/dev/null || true
    sleep 0.3

    HITS=$(sanitizer_hits "$ASAN_LOGS/hostile-listen.log")
    if [ "$HITS" = "0" ]; then
        test_result 0 "hostile frames handled with no sanitizer reports"
    else
        test_result 1 "$HITS sanitizer report(s) on hostile frames"
        grep -m1 -A6 -E "ERROR: AddressSanitizer|runtime error:" \
            "$ASAN_LOGS/hostile-listen.log" || true
    fi
fi

pkill -9 owsync 2>/dev/null || true
print_summary

if [ $FAIL -gt 0 ]; then
    echo "Sanitizer logs kept in $ASAN_LOGS"
    echo -e "${RED}❌ Memory Safety Tests: FAILED${NC}"
    exit 1
fi

rm -rf "$ASAN_DIR"
echo -e "${GREEN}✅ Memory Safety Tests: PASSED${NC}"
exit 0
