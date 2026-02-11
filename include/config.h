/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 */
#ifndef OWSYNC_CONFIG_H
#define OWSYNC_CONFIG_H

#include "common.h"
#include <stdbool.h>
#include <stddef.h>

#define CONFIG_MAX_PEERS 16
#define CONFIG_MAX_PATTERNS 64
#define CONFIG_MAX_LINE_LEN 1024
#define CONFIG_MAX_KEY_LEN 128
#define CONFIG_MAX_VALUE_LEN 512
#define CONFIG_MAX_PATH_LEN 256

/*
 * owsync configuration structure
 *
 * Configuration file format (simple key=value):
 *   # Comments start with #
 *   bind_host=::              # Host to bind (:: for dual-stack, 0.0.0.0 for IPv4-only)
 *   port=4321                 # Port for listen and peer connections
 *   sync_dir=/etc/config
 *   database=/etc/owsync/owsync.db
 *   encryption_key=<64-char hex key>
 *   plain_mode=1
 *   poll_interval=30
 *   peer=192.168.1.2          # Peer host (uses global port)
 *   peer=fd00::2              # IPv6 peer
 *   include=dhcp
 *   include=firewall
 *   exclude=network
 *   exclude=system
 */
typedef struct {
    /* Network settings */
    char bind_host[CONFIG_MAX_VALUE_LEN];
    char port[16];  /* Port as string for getaddrinfo */

    /* Paths */
    char sync_dir[CONFIG_MAX_PATH_LEN];
    char database[CONFIG_MAX_PATH_LEN];

    /* Security */
    char encryption_key[CONFIG_MAX_VALUE_LEN];
    bool plain_mode;

    /* Daemon settings */
    uint32_t poll_interval;
    int log_level;  /* 0=error, 1=warning, 2=info, 3=debug */

    /* Peers (repeatable) */
    char *peers[CONFIG_MAX_PEERS];
    size_t peer_count;

    /* File filters (repeatable) */
    char *includes[CONFIG_MAX_PATTERNS];
    size_t include_count;
    char *excludes[CONFIG_MAX_PATTERNS];
    size_t exclude_count;

    /* Internal flags */
    bool loaded;
} owsync_config_t;

/**
 * Initialize config structure with defaults
 */
void config_init(owsync_config_t *config);

/**
 * Load configuration from file
 * Returns OWSYNC_OK on success, error code on failure
 */
int config_load(owsync_config_t *config, const char *path);

/**
 * Free dynamically allocated config members
 */
void config_free(owsync_config_t *config);

/**
 * Add a peer address to config
 * Returns OWSYNC_OK on success, OWSYNC_ERROR if max peers reached
 */
int config_add_peer(owsync_config_t *config, const char *peer);

/**
 * Add an include pattern to config
 * Returns OWSYNC_OK on success, OWSYNC_ERROR if max patterns reached
 */
int config_add_include(owsync_config_t *config, const char *pattern);

/**
 * Add an exclude pattern to config
 * Returns OWSYNC_OK on success, OWSYNC_ERROR if max patterns reached
 */
int config_add_exclude(owsync_config_t *config, const char *pattern);

#endif /* OWSYNC_CONFIG_H */
