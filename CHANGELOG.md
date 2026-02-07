# Changelog

All notable changes to owsync are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-02-01

### Added
- Per-peer source address support in daemon mode.
  Peers can now specify a local source IP for outgoing connections
  using the format `peer=destination,source` (e.g., `peer=192.168.1.2,10.0.0.1`).
- Warning log when database load fails, making recovery behavior
  visible in syslog.

### Fixed
- IPv6 dual-stack binding: `bind_host=::` now correctly creates an
  IPv6 socket with dual-stack support instead of falling back to IPv4.
- Time-of-check time-of-use race condition in file deletion during sync.

### Changed
- Test suite: rewrote 23 tests that could not fail to perform actual
  verification. Strengthened database corruption test to verify recovery
  behavior.

## [1.0.0] - 2026-01-28

Initial release.

- Bidirectional file synchronization over TCP
- AES-256-GCM encryption with pre-shared key
- SHA-256 content-based change detection
- Daemon mode with configurable poll interval
- Multi-peer parallel sync via threading
- UCI-compatible configuration
- Include/exclude file filter patterns
- Automatic conflict resolution (last-writer-wins)
