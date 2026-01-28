#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Static analysis script - Runs cppcheck on owsync source code to detect potential issues:
# - Memory leaks
# - Null pointer dereferences
# - Buffer overflows
# - Uninitialized variables
# - Resource leaks (file handles, sockets)
#
# OPTIONAL: This script gracefully skips if cppcheck is not installed.
#
# Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
#
# Usage: ./scripts/static-analysis.sh [--strict]
#   --strict: Treat warnings as errors (exit code 1 on any issue)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Parse arguments
STRICT_MODE=false
for arg in "$@"; do
    case "$arg" in
        --strict)
            STRICT_MODE=true
            ;;
    esac
done

echo "=========================================="
echo "Static Analysis: owsync"
echo "=========================================="

# Check if cppcheck is available
if ! command -v cppcheck >/dev/null 2>&1; then
    echo "${YELLOW}SKIP: cppcheck not installed (optional)${NC}"
    echo "Install with: apt install cppcheck (Debian/Ubuntu)"
    echo "             brew install cppcheck (macOS)"
    exit 0
fi

CPPCHECK_VERSION=$(cppcheck --version 2>/dev/null | head -1)
echo "Using: $CPPCHECK_VERSION"
echo ""

# Define source directories
SRC_DIR="$PROJECT_DIR/src"
INCLUDE_DIR="$PROJECT_DIR/include"

if [ ! -d "$SRC_DIR" ]; then
    echo "${RED}ERROR: Source directory not found: $SRC_DIR${NC}"
    exit 1
fi

# Run cppcheck with comprehensive checks
echo "Running cppcheck..."
echo ""

CPPCHECK_ARGS="--enable=all"
CPPCHECK_ARGS="$CPPCHECK_ARGS --suppress=missingIncludeSystem"
CPPCHECK_ARGS="$CPPCHECK_ARGS --suppress=unusedFunction"
CPPCHECK_ARGS="$CPPCHECK_ARGS --inline-suppr"
CPPCHECK_ARGS="$CPPCHECK_ARGS --std=c11"
CPPCHECK_ARGS="$CPPCHECK_ARGS --force"

# Add include path if it exists
if [ -d "$INCLUDE_DIR" ]; then
    CPPCHECK_ARGS="$CPPCHECK_ARGS -I$INCLUDE_DIR"
fi

# Error exit code for strict mode
if [ "$STRICT_MODE" = "true" ]; then
    CPPCHECK_ARGS="$CPPCHECK_ARGS --error-exitcode=1"
fi

# Run cppcheck
cppcheck $CPPCHECK_ARGS "$SRC_DIR" 2>&1 | while IFS= read -r line; do
    # Colorize output
    case "$line" in
        *error:*)
            printf "${RED}%s${NC}\n" "$line"
            ;;
        *warning:*)
            printf "${YELLOW}%s${NC}\n" "$line"
            ;;
        *style:*|*performance:*)
            printf "%s\n" "$line"
            ;;
        *)
            printf "%s\n" "$line"
            ;;
    esac
done

RESULT=$?

echo ""
echo "=========================================="
if [ $RESULT -eq 0 ]; then
    echo "${GREEN}Static analysis completed successfully${NC}"
else
    echo "${RED}Static analysis found issues${NC}"
fi
echo "=========================================="

exit $RESULT
