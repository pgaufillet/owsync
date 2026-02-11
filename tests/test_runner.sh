#!/bin/bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Main test runner for owsync

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Change to test directory
cd "$(dirname "$0")"

# Check if binary exists
if [ ! -f "../bin/owsync" ]; then
    echo -e "${RED}ERROR:${NC} owsync binary not found. Run 'make' first."
    exit 1
fi

export OWSYNC="../bin/owsync"

echo ""
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}   owsync Test Suite${NC}"
echo -e "${BLUE}=========================================${NC}"
echo ""

# Track overall results
TOTAL_PASS=0
TOTAL_FAIL=0
SUITE_FAIL=0

# Function to run a test suite
run_suite() {
    local suite_name="$1"
    local suite_script="$2"

    echo -e "${YELLOW}Running: $suite_name${NC}"
    echo ""

    if bash $suite_script; then
        echo -e "${GREEN}✅ $suite_name: PASSED${NC}"
        echo ""
        return 0
    else
        echo -e "${RED}❌ $suite_name: FAILED${NC}"
        echo ""
        SUITE_FAIL=$((SUITE_FAIL + 1))
        return 1
    fi
}

# Run test suites
run_suite "Core Functionality Tests" "./test_core.sh"
run_suite "Configuration Parser Tests" "./test_config.sh"
run_suite "Conflict Resolution Tests" "./test_conflict.sh"
run_suite "Error Handling Tests" "./test_errors.sh"
run_suite "Edge Case Tests" "./test_edge_cases.sh"
run_suite "Daemon Mode Tests" "./test_daemon.sh"
run_suite "Security Regression Tests" "./test_security.sh"
run_suite "Memory Stability Test (Short)" "./test_stability.sh 20"

# Print final summary
echo -e "${BLUE}=========================================${NC}"
echo -e "${BLUE}   Final Test Summary${NC}"
echo -e "${BLUE}=========================================${NC}"

if [ $SUITE_FAIL -eq 0 ]; then
    echo -e "${GREEN}All test suites passed!${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}$SUITE_FAIL test suite(s) failed${NC}"
    echo ""
    exit 1
fi
