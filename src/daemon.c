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
#include "daemon.h"
#include "log.h"
#include "net.h"
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/* Daemon state shared between server, poller, and signal handler */
typedef struct {
    /* Configuration (immutable after init) */
    const char *host;        /* Bind host */
    const char *port;        /* Port for listen and peers */
    const char *key;         /* Encryption key (NULL if plain mode) */
    const char *root;        /* Sync root directory */
    const char *db_path;     /* Database file path */
    file_filter_t *filter;   /* Include/exclude patterns */
    uint32_t poll_interval;  /* Seconds between filesystem scans */
    char **peers;            /* Peer hostnames (port is global) */
    size_t peer_count;       /* Number of peers */
    int64_t clock_offset;    /* Debug clock offset */

    /* Synchronization state */
    pthread_mutex_t sync_mutex;       /* Protects sync_in_progress */
    volatile bool sync_in_progress;   /* Prevents overlapping syncs */
    volatile sig_atomic_t shutdown;   /* Signal handler sets this (async-signal-safe) */
} daemon_context_t;

/* Arguments for sync worker thread (one per peer) */
typedef struct {
    const char *peer;        /* Peer hostname (shared, do not free) */
    const char *port;        /* Port (shared, do not free) */
    const char *key;         /* Encryption key (shared) */
    const char *root;        /* Sync root (shared) */
    const char *db_path;     /* Database path (shared) */
    file_filter_t *filter;   /* File filter (shared) */
    int64_t clock_offset;    /* Debug clock offset */
    char *source_address;    /* Per-peer source address (NULL if not set, owned by task) */
    char *parsed_peer;       /* Parsed peer address (owned by task) */
} sync_task_t;

/*
 * Global daemon context for signal handler access.
 * Signal handlers cannot receive arguments, so we use a global.
 * Set before signal registration, cleared on shutdown.
 */
static daemon_context_t *g_daemon_ctx = NULL;

/* SIGINT/SIGTERM handler for graceful shutdown */
static void signal_handler(int sig) {
    (void)sig;
    if (g_daemon_ctx) {
        g_daemon_ctx->shutdown = 1;  /* Poller checks this each second */
    }
}

/* Worker thread: sync to one peer (runs in parallel with other workers) */
static void *sync_peer_worker(void *arg) {
    sync_task_t *task = (sync_task_t *)arg;

    /* Use parsed_peer if available (comma-separated format with source) */
    const char *peer_addr = task->parsed_peer ? task->parsed_peer : task->peer;

    if (task->source_address) {
        log_info("Syncing to peer: %s:%s (source: %s)", peer_addr, task->port, task->source_address);
    } else {
        log_info("Syncing to peer: %s:%s", peer_addr, task->port);
    }

    int result = connect_peer(peer_addr, task->port, task->key, task->root,
                              task->db_path, task->filter, task->clock_offset,
                              task->source_address);

    if (result != OWSYNC_OK) {
        log_error("Sync to %s:%s failed: %d", peer_addr, task->port, result);
    } else {
        log_info("Sync to %s:%s completed", peer_addr, task->port);
    }

    /* Free allocated strings */
    free(task->source_address);
    free(task->parsed_peer);
    free(task);  /* Task struct owned by this thread */
    return NULL;
}

/*
 * Trigger parallel sync to all configured peers.
 * Spawns one thread per peer, waits for all to complete.
 * Prevents overlapping sync batches via sync_in_progress flag.
 */
static void trigger_sync_to_peers(daemon_context_t *ctx) {
    pthread_mutex_lock(&ctx->sync_mutex);

    if (ctx->sync_in_progress) {
        log_warning("Sync already in progress, skipping");
        pthread_mutex_unlock(&ctx->sync_mutex);
        return;
    }

    ctx->sync_in_progress = true;
    pthread_mutex_unlock(&ctx->sync_mutex);

    log_info("Triggering sync to %zu peers", ctx->peer_count);

    pthread_t *threads = calloc(ctx->peer_count, sizeof(pthread_t));
    bool *thread_created = calloc(ctx->peer_count, sizeof(bool));

    if (!threads || !thread_created) {
        log_error("Failed to allocate threads array");
        free(threads);
        free(thread_created);
        pthread_mutex_lock(&ctx->sync_mutex);
        ctx->sync_in_progress = false;
        pthread_mutex_unlock(&ctx->sync_mutex);
        return;
    }

    for (size_t i = 0; i < ctx->peer_count; i++) {
        sync_task_t *task = malloc(sizeof(sync_task_t));
        if (!task) {
            log_error("Failed to allocate sync task");
            continue;
        }

        /* All peers use the global port */
        task->peer = ctx->peers[i];
        task->port = ctx->port;
        task->key = ctx->key;
        task->root = ctx->root;
        task->db_path = ctx->db_path;
        task->filter = ctx->filter;
        task->clock_offset = ctx->clock_offset;

        /* Parse peer format "addr[,source_addr]" */
        task->source_address = NULL;
        task->parsed_peer = NULL;
        const char *comma = strchr(ctx->peers[i], ',');
        if (comma) {
            /* Has source address */
            size_t peer_len = comma - ctx->peers[i];
            task->parsed_peer = strndup(ctx->peers[i], peer_len);
            task->source_address = strdup(comma + 1);
            if (!task->parsed_peer || !task->source_address) {
                log_error("Failed to allocate peer address strings");
                free(task->parsed_peer);
                free(task->source_address);
                free(task);
                continue;
            }
        }

        if (pthread_create(&threads[i], NULL, sync_peer_worker, task) == 0) {
            thread_created[i] = true;
        } else {
            log_error("Failed to create sync thread for %s", ctx->peers[i]);
            free(task->source_address);
            free(task->parsed_peer);
            free(task);
        }
    }

    for (size_t i = 0; i < ctx->peer_count; i++) {
        if (thread_created[i]) {
            pthread_join(threads[i], NULL);
        }
    }

    free(threads);
    free(thread_created);

    pthread_mutex_lock(&ctx->sync_mutex);
    ctx->sync_in_progress = false;
    pthread_mutex_unlock(&ctx->sync_mutex);

    log_info("All peer syncs completed");
}

/*
 * Poller thread: periodically scan filesystem for changes.
 * On changes: save database, trigger sync to all peers.
 * Initial sync always runs on startup for state reconciliation.
 */
static void *poller_thread(void *arg) {
    daemon_context_t *ctx = (daemon_context_t *)arg;

    log_info("Poller started, interval=%us", ctx->poll_interval);

    database_t *db = database_new();
    if (!db) {
        log_error("Failed to create database");
        return NULL;
    }

    if (database_load(db, ctx->db_path) != OWSYNC_OK) {
        log_warning("Database load failed, will rebuild from filesystem scan");
    }

    bool dirty = false;
    log_info("Performing initial scan...");
    int result = database_update_from_scan(db, ctx->root, ctx->filter, &dirty);

    if (result != OWSYNC_OK) {
        log_error("Initial scan failed: %d", result);
    } else {
        if (dirty) {
            log_info("Initial scan detected local changes, saving database");
            database_save(db, ctx->db_path);
        } else {
            log_debug("No local changes detected in initial scan");
        }
    }

    database_free(db);

    /*
     * Always trigger initial sync to peers on startup, regardless of whether
     * local changes were detected. This ensures state reconciliation after
     * reboots or network partitions. The bidirectional sync protocol will:
     * - Push any local changes to peers
     * - Pull any remote changes from peers
     */
    log_info("Triggering initial sync to reconcile state with peers");
    trigger_sync_to_peers(ctx);

    while (!ctx->shutdown) {
        // Sleep in 1-second intervals to check shutdown flag frequently
        for (uint32_t i = 0; i < ctx->poll_interval && !ctx->shutdown; i++) {
            sleep(1);
        }

        if (ctx->shutdown) break;

        log_debug("Polling for changes...");

        db = database_new();
        if (!db) {
            log_error("Failed to create database");
            continue;
        }

        if (database_load(db, ctx->db_path) != OWSYNC_OK) {
            log_warning("Database load failed, will rebuild from filesystem scan");
        }

        dirty = false;
        result = database_update_from_scan(db, ctx->root, ctx->filter, &dirty);

        if (result != OWSYNC_OK) {
            log_error("Scan failed: %d", result);
            database_free(db);
            continue;
        }

        if (dirty) {
            log_info("Changes detected, saving database");
            database_save(db, ctx->db_path);
            database_free(db);

            trigger_sync_to_peers(ctx);
        } else {
            log_debug("No changes detected");
            database_free(db);
        }
    }

    log_info("Poller stopped");
    return NULL;
}

/* Server thread: accept incoming sync connections */
static void *server_thread(void *arg) {
    daemon_context_t *ctx = (daemon_context_t *)arg;

    log_info("Starting listen server on %s:%s", ctx->host, ctx->port);

    /* start_server runs until process termination */
    int result = start_server(ctx->host, ctx->port, ctx->key, ctx->root,
                              ctx->db_path, ctx->filter, ctx->clock_offset);

    if (result != OWSYNC_OK) {
        log_error("Server failed: %d", result);
    }

    return NULL;
}

/*
 * Main daemon entry point.
 * Starts server thread (accepts connections) and poller thread (scans + syncs).
 * Blocks until SIGINT/SIGTERM received.
 */
int start_daemon(const char *host, const char *port, const char *key,
                 const char *root, const char *db_path, file_filter_t *filter,
                 uint32_t poll_interval, char **peers, size_t peer_count,
                 int64_t clock_offset) {

    daemon_context_t ctx = {
        .host = host,
        .port = port,
        .key = key,
        .root = root,
        .db_path = db_path,
        .filter = filter,
        .poll_interval = poll_interval ? poll_interval : 60,
        .peers = peers,
        .peer_count = peer_count,
        .clock_offset = clock_offset,
        .sync_in_progress = false,
        .shutdown = 0
    };

    if (pthread_mutex_init(&ctx.sync_mutex, NULL) != 0) {
        log_error("Failed to initialize sync mutex");
        return OWSYNC_ERROR;
    }

    g_daemon_ctx = &ctx;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    pthread_t server_tid, poller_tid;

    if (pthread_create(&server_tid, NULL, server_thread, &ctx) != 0) {
        log_error("Failed to create server thread");
        pthread_mutex_destroy(&ctx.sync_mutex);
        return OWSYNC_ERROR;
    }

    if (pthread_create(&poller_tid, NULL, poller_thread, &ctx) != 0) {
        log_error("Failed to create poller thread");
        ctx.shutdown = 1;
        pthread_cancel(server_tid);
        pthread_join(server_tid, NULL);
        pthread_mutex_destroy(&ctx.sync_mutex);
        return OWSYNC_ERROR;
    }

    log_info("Daemon started (server + poller)");

    pthread_join(poller_tid, NULL);

    pthread_cancel(server_tid);
    pthread_join(server_tid, NULL);

    pthread_mutex_destroy(&ctx.sync_mutex);

    log_info("Shutdown complete");
    return OWSYNC_OK;
}
