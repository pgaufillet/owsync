#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Long-duration stress test - Simulates realistic daemon operation for extended periods
# Monitor with: watch -n 1 'ps aux | grep owsync'

set -e
cd "$(dirname "$0")"
source ./common.sh

DURATION=${1:-300}  # Default 5 minutes, pass seconds as arg
POLL_INTERVAL=10

echo "========================================="
echo "Long-Duration Stress Test ($DURATION seconds)"
echo "========================================="
echo ""

cleanup

# Create initial files
mkdir -p /tmp/node1/dir1 /tmp/node1/dir2
for i in {1..20}; do
    echo "Initial file $i" > /tmp/node1/file$i.txt
done

# Start peer listener
echo "Starting peer listener..."
$OWSYNC listen --host 127.0.0.1 --port 22000 --plain -i '*' --dir /tmp/node2 --db /tmp/node2/owsync.db >/tmp/stress_peer.log 2>&1 &
PEER_PID=$!
sleep 2

# Start daemon
echo "Starting daemon with $POLL_INTERVAL second polling..."
$OWSYNC daemon --host 127.0.0.1 --port 22001 --plain -i '*' --dir /tmp/node1 --db /tmp/node1/owsync.db \
    --poll-interval $POLL_INTERVAL --auto-sync 127.0.0.1 >/tmp/stress_daemon.log 2>&1 &
DAEMON_PID=$!
sleep 3

echo "Daemon PID: $DAEMON_PID"
echo "Peer PID: $PEER_PID"
echo ""

# Function to get memory usage in KB
get_memory() {
    local pid=$1
    ps -o rss= -p $pid 2>/dev/null | awk '{print $1}' || echo "0"
}

# Record initial memory
INITIAL_MEM=$(get_memory $DAEMON_PID)
echo "Initial daemon memory: ${INITIAL_MEM} KB"
echo ""

# Background file churn simulation
(
    sleep 15
    CYCLE=0
    while kill -0 $DAEMON_PID 2>/dev/null; do
        CYCLE=$((CYCLE + 1))

        # Modify existing files (60% of time)
        if [ $((RANDOM % 10)) -lt 6 ]; then
            FILE_NUM=$((RANDOM % 20 + 1))
            echo "Cycle $CYCLE: modified file$FILE_NUM.txt" >> /tmp/node1/file$FILE_NUM.txt
        fi

        # Create new files (20% of time)
        if [ $((RANDOM % 10)) -lt 2 ]; then
            NEW_FILE="/tmp/node1/newfile_${CYCLE}.txt"
            echo "New file created at cycle $CYCLE" > "$NEW_FILE"
        fi

        # Delete files (20% of time)
        if [ $((RANDOM % 10)) -lt 2 ] && [ $CYCLE -gt 3 ]; then
            OLD_CYCLE=$((CYCLE - 3))
            rm -f "/tmp/node1/newfile_${OLD_CYCLE}.txt" 2>/dev/null
        fi

        sleep $((POLL_INTERVAL + 2))
    done
) &
CHURN_PID=$!

# Monitor memory usage
echo "Monitoring memory usage every 30 seconds..."
echo "Time(s) | RSS(KB) | Delta(KB) | Files"
echo "--------|---------|-----------|------"

START_TIME=$(date +%s)
LAST_CHECK=0

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [ $ELAPSED -ge $DURATION ]; then
        break
    fi

    # Check memory every 30 seconds
    if [ $((ELAPSED - LAST_CHECK)) -ge 30 ]; then
        CURRENT_MEM=$(get_memory $DAEMON_PID)
        DELTA=$((CURRENT_MEM - INITIAL_MEM))
        FILE_COUNT=$(find /tmp/node1 -type f | wc -l)

        printf "%7d | %7d | %9d | %5d\n" $ELAPSED $CURRENT_MEM $DELTA $FILE_COUNT

        LAST_CHECK=$ELAPSED

        # Alert if memory grows > 5MB
        if [ $DELTA -gt 5120 ]; then
            echo "⚠️  WARNING: Memory grew by ${DELTA}KB (>5MB threshold)"
        fi
    fi

    sleep 5
done

echo ""
echo "Stress test duration complete. Shutting down..."

# Final memory check
FINAL_MEM=$(get_memory $DAEMON_PID)
TOTAL_DELTA=$((FINAL_MEM - INITIAL_MEM))

echo ""
echo "========================================="
echo "Memory Usage Summary"
echo "========================================="
echo "Initial memory:  ${INITIAL_MEM} KB"
echo "Final memory:    ${FINAL_MEM} KB"
echo "Growth:          ${TOTAL_DELTA} KB"
echo ""

# Calculate leak rate
POLL_CYCLES=$((DURATION / POLL_INTERVAL))
echo "Poll cycles completed: ~${POLL_CYCLES}"

if [ $TOTAL_DELTA -gt 1024 ]; then
    LEAK_PER_CYCLE=$((TOTAL_DELTA / POLL_CYCLES))
    echo "Average growth per cycle: ${LEAK_PER_CYCLE} KB"
    echo ""
    if [ $LEAK_PER_CYCLE -gt 100 ]; then
        echo "❌ FAIL: Significant memory leak detected (${LEAK_PER_CYCLE} KB/cycle)"
        RESULT=1
    elif [ $LEAK_PER_CYCLE -gt 10 ]; then
        echo "⚠️  WARNING: Possible memory leak (${LEAK_PER_CYCLE} KB/cycle)"
        RESULT=0
    else
        echo "✅ PASS: Acceptable memory growth (${LEAK_PER_CYCLE} KB/cycle)"
        RESULT=0
    fi
else
    echo "✅ PASS: Minimal memory growth (<1MB over $DURATION seconds)"
    RESULT=0
fi

# Cleanup
kill -TERM $DAEMON_PID 2>/dev/null || true
kill -TERM $PEER_PID 2>/dev/null || true
kill -TERM $CHURN_PID 2>/dev/null || true
wait $DAEMON_PID 2>/dev/null || true
wait $PEER_PID 2>/dev/null || true
wait $CHURN_PID 2>/dev/null || true

echo ""
echo "Daemon log tail:"
tail -20 /tmp/stress_daemon.log

cleanup

exit $RESULT
