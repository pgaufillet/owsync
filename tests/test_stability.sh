#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Memory stability tests

set -e
cd "$(dirname "$0")"
source ./common.sh

echo "========================================="
echo "Memory Stability Test (Constant State)"
echo "========================================="

cleanup

DURATION=${1:-120}
INTERVAL=10
CYCLES=$((DURATION / INTERVAL))

# Create a fixed set of 50 files
echo "Creating 50 static files..."
mkdir -p /tmp/node1
for i in {1..50}; do
    echo "Static content $i" > /tmp/node1/file$i.txt
done

# Start dummy peer
../bin/owsync listen --host 127.0.0.1 --port 21104 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1 &
PEER_PID=$!
sleep 1

# Start daemon with aggressive polling (1s) to accelerate the test
# We use a 1s interval so we get more "reloads" per second
echo "Starting daemon with 1s polling..."
../bin/owsync daemon --host 127.0.0.1 --port 21105 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db \
    --poll-interval 1 --auto-sync 127.0.0.1 >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 2

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo "Daemon failed to start"
    kill $PEER_PID
    exit 1
fi

INITIAL_MEM=$(ps -o rss= -p $DAEMON_PID | awk '{print $1}')
echo "Initial Memory: ${INITIAL_MEM} KB"
echo "Running for $DURATION seconds..."
echo "Time(s) | RSS(KB) | Delta(KB)"
echo "--------|---------|----------"

for i in $(seq 1 $CYCLES); do
    sleep $INTERVAL
    CURRENT_MEM=$(ps -o rss= -p $DAEMON_PID | awk '{print $1}')
    DELTA=$((CURRENT_MEM - INITIAL_MEM))
    printf "%7d | %7d | %8d\n" $((i*INTERVAL)) $CURRENT_MEM $DELTA
done

# Check strict stability (allow max 100KB growth due to fragmentation)
if [ $DELTA -gt 100 ]; then
    echo "❌ FAIL: Memory grew by ${DELTA}KB (>100KB)"
    RESULT=1
else
    echo "✅ PASS: Memory stable (delta: ${DELTA}KB)"
    RESULT=0
fi

kill -TERM $DAEMON_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
kill -TERM $PEER_PID 2>/dev/null || true
wait $PEER_PID 2>/dev/null || true

echo "Done."
exit $RESULT
