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
#ifndef OWSYNC_NET_H
#define OWSYNC_NET_H

#include "common.h"
#include "state.h"
#include "sync.h"
#include "crypto.h"
#include <sys/socket.h>
#include <netinet/in.h>

/* Protocol message types for bidirectional sync */
typedef enum {
    MSG_HELLO,         /* Handshake: hostname, timestamp, version */
    MSG_SYNC_STATE,    /* File state list exchange */
    MSG_REQUEST_FILES, /* Request specific files from peer */
    MSG_FILE_CONTENT,  /* File data transfer */
    MSG_END_OF_SYNC,   /* Sync completion marker */
} message_type_t;

/*
 * Protocol message with type-specific payload.
 * Serialized to JSON over the wire (length-prefixed).
 */
typedef struct {
    message_type_t type;
    union {
        struct {
            char *hostname;      /* Peer identifier */
            uint64_t timestamp;  /* Peer's current time (for clock skew check) */
            uint32_t version;    /* Protocol version (must match) */
        } hello;
        struct {
            file_state_list_t *files;  /* Complete file state snapshot */
        } sync_state;
        struct {
            path_list_t *paths;  /* Files to request from peer */
        } request_files;
        struct {
            char *path;          /* Relative path */
            uint8_t *data;       /* File contents */
            size_t data_len;     /* Content length */
            uint32_t mode;       /* Unix permissions */
        } file_content;
    } payload;
} message_t;

/* TCP channel with optional encryption */
typedef struct {
    int fd;                /* Socket file descriptor */
    bool is_encrypted;     /* True if using AES-256-GCM encryption */
#ifdef ENABLE_ENCRYPTION
    security_context_t *security_ctx;  /* Encryption context (NULL if plain) */
#endif
} channel_t;

/* Message lifecycle */
message_t *message_new(message_type_t type);
void message_free(message_t *msg);

/* Channel operations (length-prefixed JSON, optionally encrypted) */
channel_t *channel_new(int fd, bool is_encrypted, void *security_ctx);
void channel_free(channel_t *channel);  /* Closes socket */
int channel_send(channel_t *channel, message_t *msg);
int channel_receive(channel_t *channel, message_t **out_msg);

/* Server mode: listen for incoming connections, spawn threads */
int start_server(const char *host, const char *port, const char *key,
                 const char *root, const char *db_path, file_filter_t *filter,
                 int64_t clock_offset);

/* Client mode: connect to peer, run one sync session */
int connect_peer(const char *host, const char *port, const char *key,
                 const char *root, const char *db_path, file_filter_t *filter,
                 int64_t clock_offset);

#endif
