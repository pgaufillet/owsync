/*
 * Copyright (C) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef OWSYNC_DAEMON_H
#define OWSYNC_DAEMON_H

#include "common.h"
#include "state.h"
#include "net.h"

/*
 * Start daemon mode: listen server + periodic polling + auto-sync.
 *
 * Spawns two threads:
 *   - Server thread: accepts incoming sync connections
 *   - Poller thread: scans directory, triggers sync to peers on changes
 *
 * Handles SIGINT/SIGTERM for graceful shutdown.
 * Runs until shutdown signal received.
 *
 * @param host   Host to bind ("::" for dual-stack, "0.0.0.0" for IPv4-only)
 * @param port   Port for listen and peer connections (as string)
 * @param peers  Array of peer hostnames (port is global)
 */
int start_daemon(const char *host, const char *port, const char *key,
                 const char *root, const char *db_path, file_filter_t *filter,
                 uint32_t poll_interval, char **peers, size_t peer_count,
                 int64_t clock_offset);

#endif
