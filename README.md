# owsync

**owsync** is a lightweight, secure, and robust high-availability file synchronization tool designed specifically for **OpenWrt** routers but should be usable on most Linux systems.

## Features

*   **Ultra-Lightweight:** Single binary (~150KB stripped), minimal RAM usage (~2MB), zero runtime dependencies beyond standard OpenWrt packages.
*   **Secure:**
    *   **Default:** Traffic is encrypted using **AES-256-GCM** with a Pre-Shared Key (PSK).
    *   **Plain Mode:** Optional plaintext mode for use over secure VPNs (WireGuard/IPsec).
*   **Bi-Directional:** True multi-master sync. Changes on any node are propagated.
*   **Stateful & Correct:** Uses a persistent local database (Tombstones) to correctly handle **file deletions** across reboots.
*   **Robust:**
    *   **Clock Skew Protection:** Aborts sync if clocks differ by >60s.
    *   **Atomic Writes:** Database and file updates are atomic.
    *   **Symlink Safety:** Ignores symlinks to prevent loops.
*   **Flexible:** Supports **Glob patterns** for Inclusion and Exclusion.

## Dependencies

Required packages:
- `libjson-c` - JSON parsing (standard in OpenWrt)

### Encryption Support

By default, owsync builds with AES-256-GCM encryption support, which requires:

**Build-time:** `libssl-dev` headers for compilation (`libopenssl-dev` on OpenWrt/Alpine).
**Runtime:** `libssl` library for encrypted mode operation (`libopenssl` on OpenWrt/Alpine).

**Without encryption:** Build with `ENABLE_ENCRYPTION=0` to remove the OpenSSL dependency entirely. This produces a smaller binary (~40-50KB smaller) but only supports `plain_mode=1` for use over secure VPN connections (WireGuard/IPsec).

```bash
# Build without encryption (no OpenSSL dependency)
make ENABLE_ENCRYPTION=0
```

On OpenWrt, the encryption support is configurable via menuconfig (`CONFIG_OWSYNC_ENABLE_ENCRYPTION`). The `libopenssl` dependency is automatically added when encryption is enabled.

## Building

### Standard Build (with encryption)
```bash
make
```

### Lite Build (no encryption)
For maximum space savings (~40-50KB smaller), disable encryption:
```bash
make ENABLE_ENCRYPTION=0
```

### Debug Build
```bash
make DEBUG=1
```

### Custom Message Size Limit
The default maximum message size is 32MB, which allows syncing files up to ~16MB (due to hex encoding overhead). To increase this limit:
```bash
make MAX_MESSAGE_SIZE=$((64*1024*1024))  # 64MB messages, ~32MB files
```

### Cross-compilation for OpenWrt
Use the OpenWrt SDK with a package Makefile. See the [OpenWrt documentation](https://openwrt.org/docs/guide-developer/toolchain/use-buildsystem) for details on creating packages.

### Code Formatting
The codebase uses K&R style. To format all source files:
```bash
make format
```
Requires `astyle` (`apt install astyle`). Configuration is in `.astylerc`.

## Installation on OpenWrt

### From Package
OpenWrt <= 24.10:
```bash
opkg install owsync_*.ipk
```

OpenWrt >= 25.12:
```bash
apk add --allow-untrusted owsync_*.apk
```

### Manual Installation
```bash
make install DESTDIR=/path/to/root PREFIX=/usr
```

## Configuration

### Config File

owsync supports a simple key=value configuration file. This is the recommended method for production use as it keeps sensitive data (encryption keys) out of the process list.

```bash
owsync daemon -c /path/to/owsync.conf
```

Example config file:
```ini
# Network settings
bind_host=0.0.0.0
port=4321

# Paths
sync_dir=/etc/config
database=/var/lib/owsync/owsync.db

# Security (choose one)
encryption_key=<64-char hex key>
# OR
plain_mode=1

# Daemon settings
poll_interval=30

# Peers (repeatable)
peer=192.168.1.2
peer=192.168.1.3

# File filters (repeatable)
# IMPORTANT: Include patterns are required. If no includes are specified,
# nothing will be synced. Use 'include=*' to sync all files.
include=dhcp
include=firewall
exclude=network
exclude=system
```

### Security Note

Encryption keys can only be provided via:
1. Config file (`encryption_key=...`) - **recommended**
2. Environment variable `OWSYNC_KEY` - for scripting

Keys cannot be provided on the command line to prevent exposure in process listings.

## Quick Start

### Generate a Key
```bash
owsync genkey
```

### Using Config File
```bash
# Create config file
cat > owsync.conf <<EOF
bind_host=0.0.0.0
port=9000
sync_dir=/etc/config
database=/var/lib/owsync/owsync.db
encryption_key=$(owsync genkey)
peer=192.168.1.2
include=*
EOF

# Start daemon
owsync daemon -c owsync.conf
```

### Plaintext Mode (e.g. for use with WireGuard/VPN links)
```bash
# For use over secure tunnels only
owsync listen --plain -i '*' --dir /etc/config
owsync connect 192.168.1.2:9000 --plain -i '*' --dir /etc/config
```

### Using Environment Variable
```bash
export OWSYNC_KEY=$(owsync genkey)
owsync listen -i '*' --dir /etc/config
owsync connect 192.168.1.2:4321 -i '*' --dir /etc/config
```

## Command Reference

| Command | Description |
|---------|-------------|
| `owsync daemon -c FILE` | Run as daemon with config file (recommended) |
| `owsync listen [OPTIONS]` | Start server, wait for incoming connections |
| `owsync connect PEER [OPTIONS]` | Connect to peer and sync once |
| `owsync scan DIR` | Scan directory and display file states |
| `owsync genkey` | Generate a new 256-bit encryption key |

Run `owsync --help` for full options list.

### Daemon vs Listen/Connect

- **Daemon mode** (`owsync daemon`): Runs continuously, polls for changes, syncs automatically to configured peers. Best for production.
- **Listen mode** (`owsync listen`): Starts a server and waits. Use for one-shot syncs or testing.
- **Connect mode** (`owsync connect`): Connects to a listening peer, syncs once, then exits.

## How It Works

### Sync Protocol

owsync uses a **bidirectional** sync protocol over TCP:

1. **Handshake** - Peers exchange hostname, timestamp, and protocol version.
2. **Clock Check** - Sync aborts if clock difference exceeds 60 seconds.
3. **State Exchange** - Both peers send their complete file state (paths, SHA-256 hashes, modification times, tombstones).
4. **Diff Calculation** - Each peer independently calculates which files to request or delete.
5. **File Transfer** - Changed files are transferred in both directions simultaneously.
6. **Completion** - Both sides confirm sync completion.

### Key Concepts

**Hash-Based Change Detection**
- Files are identified by SHA-256 hash, not just modification time.
- A file only syncs when its content (hash) differs.
- Prevents infinite sync loops between peers.

**Conflict Resolution (Last-Write-Wins)**
- When both peers modify the same file, the newer version wins.
- Comparison uses modification time (millisecond precision).
- Tie-breaker: lexicographic hash comparison.

**Tombstones (Deletion Tracking)**
- Deleted files are marked as "tombstones" in the local database.
- Tombstones propagate to peers, ensuring deletions sync correctly.
- Tombstones expire after 30 days to prevent database bloat.

**Atomic Operations**
- Database writes use temporary file + rename (crash-safe).
- File writes use the same pattern to prevent corruption.

### Security Model

- **Encrypted mode (default):** AES-256-GCM encryption with Pre-Shared Key.
- **Plain mode:** No encryption, for use over secure tunnels (WireGuard/IPsec).

## License

MIT. See LICENSE file.

owsync has been developed using Claude Code from Anthropic.

## Maintainer

Pierre Gaufillet <pierre.gaufillet@bergamote.eu>

