# owsync Testing Guide

## Quick Start

```bash
make test
```

That's it! The command will build the binary (if needed) and run all tests.

## Test Coverage

### Test Coverage

The test suite covers:
- ✅ Configuration parsing and validation
- ✅ File synchronization (create, modify, delete)
- ✅ Conflict resolution (Last-Write-Wins algorithm)
- ✅ Encryption (AES-256-GCM)
- ✅ Pattern filtering (exclude/include)
- ✅ Large files (1MB+)
- ✅ Tombstone propagation
- ✅ Daemon mode operation
- ✅ Error handling
- ✅ Memory leak detection

## Running Tests

### All Tests
```bash
make test
```

### Specific Test Suite
```bash
cd tests
./test_core.sh        # Core functionality
./test_conflict.sh    # Conflict resolution
```

### Individual Test Development
```bash
cd tests
bash -x ./test_core.sh  # With debug output
```

## Test Structure

```
tests/
├── common.sh              # Shared utilities (cleanup, assertions)
├── test_runner.sh         # Orchestrates all test suites
├── test_config.sh         # Configuration parsing tests
├── test_core.sh           # Core functionality tests
├── test_conflict.sh       # Conflict resolution tests
├── test_daemon.sh         # Daemon mode tests
├── test_errors.sh         # Error handling tests
├── test_edge_cases.sh     # Edge case tests
├── test_security.sh       # Security regression tests
├── test_memory_leaks.sh   # Memory leak detection
├── test_stability.sh      # Long-running stability tests
├── test_stress_longrun.sh # Stress testing (manual)
└── fixtures/              # Test configuration files
```

## CI/CD Integration

### GitHub Actions Example
```yaml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install dependencies
        run: sudo apt-get install -y libjson-c-dev libssl-dev
      - name: Build
        run: make
      - name: Test
        run: make test
```

### GitLab CI Example
```yaml
test:
  script:
    - apt-get update && apt-get install -y libjson-c-dev libssl-dev
    - make
    - make test
```

## Adding New Tests

1. Choose the appropriate test file (`test_core.sh` or `test_conflict.sh`)
2. Add your test function following this pattern:

```bash
echo "TEST X: Description"
cleanup

# Setup
echo "content" > /tmp/node1/file.txt

# Execute
$OWSYNC listen --host 127.0.0.1 --port 20099 --plain --dir /tmp/node1 --db /tmp/node1/owsync.db &
PID=$!; sleep 1
$OWSYNC connect 127.0.0.1 --port 20099 --plain --dir /tmp/node2 --db /tmp/node2/owsync.db >/dev/null 2>&1
kill $PID 2>/dev/null

# Assert
[ -f /tmp/node2/file.txt ]
test_result $? "Description of what was tested"
echo ""
```

3. Use unique port numbers (check existing tests for used ports)
4. Always call `cleanup` before each test
5. Use `test_result $? "description"` to record results

## Test Requirements

- **System**: Linux (uses /tmp for test directories)
- **Ports**: 20001-22000 (ensure not in use)
- **Build dependencies**: libjson-c-dev, libssl-dev
- **Test dependencies**:
  - `valgrind` - for memory leak tests
  - `nc` (netcat) - for port readiness checks

