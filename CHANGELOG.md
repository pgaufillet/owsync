# Changelog

All notable changes to owsync are documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Heap read overflow on every received message: wire buffers were parsed with
  a NUL-terminated-string JSON API, reading past the allocation. Messages are
  now parsed with an explicit length.
- Zero-length message frames are rejected instead of producing a zero-byte
  buffer for the parser.
- Length prefixes and payloads split across TCP segments are now reassembled.
  Any segmentation used to drop the session.
- Partial writes and `EINTR` are retried instead of being treated as fatal.
- Files are no longer sent when `fread()` returns short: a file shrinking or
  failing to read mid-send used to overwrite the peer's good copy with
  truncated content.
- Received files are only renamed into place after a successful write and
  `fsync()`, and the parent directory is synced afterwards. A failed write no
  longer clobbers the destination, and the claimed atomicity now survives
  power loss.
- Receive-side path validation now applies the same boundary check as the send
  side. A symlink to a sibling directory sharing the sync root's name prefix
  (`/etc/configuration` vs `/etc/config`) allowed writes outside the root.
- A file that cannot be hashed is no longer treated as deleted. Transient read
  failures used to create a tombstone that then deleted the peers' copies.
- An aborted directory scan leaves the database untouched instead of
  tombstoning every file the walk never reached.
- `database_load()` checks `ftell()` and `fread()`; a short or unseekable read
  no longer parses as invalid JSON and wipes the database.
- `SIGPIPE` is ignored: a peer disconnecting mid-write used to terminate the
  daemon. Signal handlers now use `sigaction()` so a second `SIGTERM` cannot
  kill the daemon instead of shutting it down.
- Hostname now comes from `gethostname()` instead of `$HOSTNAME`, which is
  absent under procd and systemd and made every peer report itself as
  "unknown".
- Numeric options are validated instead of being passed through `atoi()`,
  which cannot report an error. On the wildcard binds (`::`, `0.0.0.0` - the
  default) an unparsable port silently became an ephemeral one, `99999`
  wrapped to 34463 and `-1` to 65535, so the daemon listened on a port no peer
  would reach. `--poll-interval -1` became `UINT32_MAX` seconds (~136 years),
  passing the `< 1` guard because the field is unsigned, which disabled
  polling. `--log-level abc` silently meant errors-only.
- A received `FileContent` with no `path` field dereferenced a NULL pointer
  and crashed the daemon. The path field is now required.
- A received `Hello` with no `hostname` field crashed the daemon on musl,
  where `printf("%s", NULL)` faults (reachable only at debug log level). The
  value is now guarded.

### Changed
- `--poll-interval 0` is now an error. It never disabled polling: it was
  silently replaced by the 60 s default.

### Security
- Accepted and outgoing sockets have send/receive timeouts, so a peer that
  connects and stalls can no longer hold a connection slot indefinitely.
- Concurrent inbound message buffers are capped in aggregate. Peers could
  previously make the daemon reserve 50 x 32MB by announcing large messages
  and never sending the payload.
- Peer-supplied file mode is masked to `0777` on write, so a peer can no
  longer set setuid/setgid/sticky bits on synced files (the scan side already
  transmits only `0777` bits).
- The encryption key is scrubbed before being freed.

### Removed
- `-f`/`--foreground`. It never daemonized anything - owsync leaves process
  management to procd/systemd - and only selected a log destination, which is
  now chosen by detecting whether stderr is a terminal.

### Added
- `test_hardening.sh`: regression tests for the defects above, each verified
  to fail against the previous release.
- `test_asan.sh`: AddressSanitizer/UBSan build driving real sync sessions and
  hostile wire frames, for the defects with no functional symptom.

## [1.2.0] - 2026-02-11

### Changed
- Relicensed from GPL-2.0-or-later to MIT.

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
