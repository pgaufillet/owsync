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
#include "net.h"
#include "sync.h"
#include "log.h"
#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/stat.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>

#define MAX_CONNECTIONS 50  /* Limit concurrent connections to prevent resource exhaustion */
static volatile int active_connections = 0;  /* Atomic counter for DoS protection */

/* Create directory and all parent directories (like mkdir -p) */
static int mkdir_recursive(const char *path, mode_t mode) {
    char tmp[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;

    if (snprintf(tmp, sizeof(tmp), "%s", path) >= (int)sizeof(tmp)) {
        return -1;
    }
    len = strlen(tmp);
    if (len > 0 && tmp[len - 1] == '/')
        tmp[len - 1] = 0;

    /* Create each component */
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

/*
 * Validate that relative_path stays within root directory.
 * Prevents path traversal attacks (e.g., "../../../etc/passwd").
 *
 * Security checks:
 *   1. No absolute paths (starting with /)
 *   2. No parent directory references (..)
 *   3. Resolved path (following symlinks) must be under root
 *   4. Boundary check: next char after root prefix must be / or NUL
 *      (prevents "/root" matching "/rootdir/file")
 */
static int is_path_safe(const char *root, const char *relative_path) {
    if (!root || !relative_path) return 0;

    /* Reject obvious traversal attempts before filesystem access */
    if (relative_path[0] == '/') return 0;
    if (strstr(relative_path, "..")) return 0;

    char full_path[MAX_PATH_LEN];
    if (snprintf(full_path, sizeof(full_path), "%s/%s", root, relative_path) >= (int)sizeof(full_path)) {
        return 0;
    }

    char real_full[MAX_PATH_LEN];
    char real_root[MAX_PATH_LEN];

    /* Resolve symlinks for both paths */
    if (!realpath(root, real_root)) return 0;
    if (!realpath(full_path, real_full)) return 0;  /* File must exist */

    /* Verify resolved path is under root */
    size_t root_len = strlen(real_root);
    if (strncmp(real_full, real_root, root_len) != 0) return 0;

    /* Boundary check: prevent prefix collision (e.g., /root vs /rootdir) */
    if (real_full[root_len] != '/' && real_full[root_len] != '\0') return 0;

    return 1;
}

message_t *message_new(message_type_t type) {
    message_t *msg = calloc(1, sizeof(message_t));
    if (!msg) return NULL;
    msg->type = type;
    return msg;
}

void message_free(message_t *msg) {
    if (!msg) return;

    switch (msg->type) {
    case MSG_HELLO:
        free(msg->payload.hello.hostname);
        break;
    case MSG_SYNC_STATE:
        file_state_list_free(msg->payload.sync_state.files);
        break;
    case MSG_REQUEST_FILES:
        if (msg->payload.request_files.paths) {
            for (size_t i = 0; i < msg->payload.request_files.paths->count; i++) {
                free(msg->payload.request_files.paths->paths[i]);
            }
            free(msg->payload.request_files.paths->paths);
            free(msg->payload.request_files.paths);
        }
        break;
    case MSG_FILE_CONTENT:
        free(msg->payload.file_content.path);
        free(msg->payload.file_content.data);
        break;
    case MSG_END_OF_SYNC:
        break;
    }

    free(msg);
}

/* Serialize file state to JSON object for wire protocol */
static struct json_object *file_state_to_json(file_state_t *state) {
    struct json_object *obj = json_object_new_object();
    if (!obj) return NULL;

    json_object_object_add(obj, "path", json_object_new_string(state->path));

    if (state->hash) {
        json_object_object_add(obj, "hash", json_object_new_string(state->hash));
    } else {
        json_object_object_add(obj, "hash", NULL);
    }

    json_object_object_add(obj, "mtime", json_object_new_double((double)state->mtime));
    json_object_object_add(obj, "size", json_object_new_double((double)state->size));
    json_object_object_add(obj, "mode", json_object_new_int((int)state->mode));
    json_object_object_add(obj, "deleted", json_object_new_boolean(state->deleted));

    return obj;
}

/* Deserialize file state from JSON (caller must free returned state) */
static file_state_t *json_to_file_state(struct json_object *obj) {
    if (!obj) return NULL;

    file_state_t *state = calloc(1, sizeof(file_state_t));
    if (!state) return NULL;

    struct json_object *path = NULL;
    if (json_object_object_get_ex(obj, "path", &path) &&
            json_object_is_type(path, json_type_string)) {
        state->path = strdup(json_object_get_string(path));
    }

    struct json_object *hash = NULL;
    if (json_object_object_get_ex(obj, "hash", &hash) &&
            json_object_is_type(hash, json_type_string)) {
        const char *hash_str = json_object_get_string(hash);
        if (hash_str) {
            state->hash = strdup(hash_str);
        }
    }

    struct json_object *mtime = NULL;
    if (json_object_object_get_ex(obj, "mtime", &mtime)) {
        state->mtime = (uint64_t)json_object_get_double(mtime);
    }

    struct json_object *size = NULL;
    if (json_object_object_get_ex(obj, "size", &size)) {
        state->size = (uint64_t)json_object_get_double(size);
    }

    struct json_object *mode = NULL;
    if (json_object_object_get_ex(obj, "mode", &mode)) {
        state->mode = (uint32_t)json_object_get_int(mode);
    }

    struct json_object *deleted = NULL;
    if (json_object_object_get_ex(obj, "deleted", &deleted) &&
            json_object_is_type(deleted, json_type_boolean)) {
        state->deleted = json_object_get_boolean(deleted);
    }

    return state;
}

/* Serialize message to JSON for transmission */
static struct json_object *message_to_json(message_t *msg) {
    struct json_object *root = json_object_new_object();
    if (!root) return NULL;

    switch (msg->type) {
    case MSG_HELLO:
        json_object_object_add(root, "type", json_object_new_string("Hello"));
        json_object_object_add(root, "hostname", json_object_new_string(msg->payload.hello.hostname));
        json_object_object_add(root, "timestamp", json_object_new_double((double)msg->payload.hello.timestamp));
        json_object_object_add(root, "version", json_object_new_int(msg->payload.hello.version));
        break;

    case MSG_SYNC_STATE: {
        json_object_object_add(root, "type", json_object_new_string("SyncState"));
        struct json_object *files = json_object_new_array();
        for (size_t i = 0; i < msg->payload.sync_state.files->count; i++) {
            struct json_object *file_obj = file_state_to_json(&msg->payload.sync_state.files->files[i]);
            if (file_obj) {
                json_object_array_add(files, file_obj);
            }
        }
        json_object_object_add(root, "files", files);
        break;
    }

    case MSG_REQUEST_FILES: {
        json_object_object_add(root, "type", json_object_new_string("RequestFiles"));
        struct json_object *paths = json_object_new_array();
        for (size_t i = 0; i < msg->payload.request_files.paths->count; i++) {
            json_object_array_add(paths, json_object_new_string(msg->payload.request_files.paths->paths[i]));
        }
        json_object_object_add(root, "paths", paths);
        break;
    }

    case MSG_FILE_CONTENT: {
        json_object_object_add(root, "type", json_object_new_string("FileContent"));
        json_object_object_add(root, "path", json_object_new_string(msg->payload.file_content.path));
        json_object_object_add(root, "mode", json_object_new_int((int)msg->payload.file_content.mode));
        char *encoded = hex_encode(msg->payload.file_content.data, msg->payload.file_content.data_len);
        if (encoded) {
            json_object_object_add(root, "data", json_object_new_string(encoded));
            free(encoded);
        }
        break;
    }

    case MSG_END_OF_SYNC:
        json_object_object_add(root, "type", json_object_new_string("EndOfSync"));
        break;
    }

    return root;
}

/* Parse JSON into message struct (caller must free with message_free) */
static message_t *json_to_message(struct json_object *root) {
    if (!root) return NULL;

    struct json_object *type_obj = NULL;
    if (!json_object_object_get_ex(root, "type", &type_obj) ||
            !json_object_is_type(type_obj, json_type_string)) {
        return NULL;
    }

    const char *type_str = json_object_get_string(type_obj);
    message_t *msg = NULL;

    if (strcmp(type_str, "Hello") == 0) {
        msg = message_new(MSG_HELLO);
        if (!msg) return NULL;

        struct json_object *hostname = NULL;
        if (json_object_object_get_ex(root, "hostname", &hostname) &&
                json_object_is_type(hostname, json_type_string)) {
            msg->payload.hello.hostname = strdup(json_object_get_string(hostname));
        }

        struct json_object *timestamp = NULL;
        if (json_object_object_get_ex(root, "timestamp", &timestamp)) {
            msg->payload.hello.timestamp = (uint64_t)json_object_get_double(timestamp);
        }

        struct json_object *version = NULL;
        if (json_object_object_get_ex(root, "version", &version)) {
            msg->payload.hello.version = (uint32_t)json_object_get_int(version);
        }

    } else if (strcmp(type_str, "SyncState") == 0) {
        msg = message_new(MSG_SYNC_STATE);
        if (!msg) return NULL;

        msg->payload.sync_state.files = file_state_list_new();
        struct json_object *files = NULL;
        if (json_object_object_get_ex(root, "files", &files) &&
                json_object_is_type(files, json_type_array)) {
            size_t len = json_object_array_length(files);
            for (size_t i = 0; i < len; i++) {
                struct json_object *file_obj = json_object_array_get_idx(files, i);
                file_state_t *state = json_to_file_state(file_obj);
                if (state) {
                    file_state_list_add(msg->payload.sync_state.files, state);
                    free(state);
                }
            }
        }

    } else if (strcmp(type_str, "RequestFiles") == 0) {
        msg = message_new(MSG_REQUEST_FILES);
        if (!msg) return NULL;

        msg->payload.request_files.paths = path_list_new();
        struct json_object *paths = NULL;
        if (json_object_object_get_ex(root, "paths", &paths) &&
                json_object_is_type(paths, json_type_array)) {
            size_t len = json_object_array_length(paths);
            for (size_t i = 0; i < len; i++) {
                struct json_object *path_obj = json_object_array_get_idx(paths, i);
                if (json_object_is_type(path_obj, json_type_string)) {
                    path_list_add(msg->payload.request_files.paths,
                                  json_object_get_string(path_obj));
                }
            }
        }

    } else if (strcmp(type_str, "FileContent") == 0) {
        msg = message_new(MSG_FILE_CONTENT);
        if (!msg) return NULL;

        struct json_object *path = NULL;
        if (json_object_object_get_ex(root, "path", &path) &&
                json_object_is_type(path, json_type_string)) {
            msg->payload.file_content.path = strdup(json_object_get_string(path));
        }

        struct json_object *mode = NULL;
        if (json_object_object_get_ex(root, "mode", &mode)) {
            msg->payload.file_content.mode = (uint32_t)json_object_get_int(mode);
        }

        struct json_object *data = NULL;
        if (json_object_object_get_ex(root, "data", &data) &&
                json_object_is_type(data, json_type_string)) {
            size_t data_len = 0;
            msg->payload.file_content.data = hex_decode(json_object_get_string(data), &data_len);
            msg->payload.file_content.data_len = data_len;
        }

    } else if (strcmp(type_str, "EndOfSync") == 0) {
        msg = message_new(MSG_END_OF_SYNC);
    }

    return msg;
}

channel_t *channel_new(int fd, bool is_encrypted, void *security_ctx) {
    channel_t *channel = malloc(sizeof(channel_t));
    if (!channel) return NULL;

    channel->fd = fd;
    channel->is_encrypted = is_encrypted;

#ifdef ENABLE_ENCRYPTION
    channel->security_ctx = security_ctx;
#endif

    return channel;
}

void channel_free(channel_t *channel) {
    if (!channel) return;
    if (channel->fd >= 0) {
        close(channel->fd);
    }
    free(channel);
}

/*
 * Send message over channel.
 * Wire format: [4-byte big-endian length][JSON payload]
 * If encrypted: payload is [nonce][ciphertext][tag]
 */
int channel_send(channel_t *channel, message_t *msg) {
    if (!channel || !msg) return OWSYNC_ERROR;

    struct json_object *json = message_to_json(msg);
    if (!json) return OWSYNC_ERROR;

    const char *json_str = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN);
    if (!json_str) {
        json_object_put(json);
        return OWSYNC_ERROR;
    }

    size_t json_len = strlen(json_str);
    uint8_t *data_to_send = (uint8_t *)json_str;
    size_t data_len = json_len;
    uint8_t *allocated_buf = NULL;

#ifdef ENABLE_ENCRYPTION
    if (channel->is_encrypted && channel->security_ctx) {
        uint8_t *encrypted = NULL;
        size_t encrypted_len = 0;

        int result = security_encrypt(channel->security_ctx, (uint8_t *)json_str, json_len,
                                      &encrypted, &encrypted_len);

        if (result != OWSYNC_OK) {
            json_object_put(json);
            return result;
        }

        data_to_send = encrypted;
        data_len = encrypted_len;
        allocated_buf = encrypted;
    }
#endif

    if (data_len > MAX_MESSAGE_SIZE) {
        if (allocated_buf) free(allocated_buf);
        json_object_put(json);
        return OWSYNC_ERROR;
    }

    uint32_t len_be = htonl((uint32_t)data_len);
    if (write(channel->fd, &len_be, 4) != 4) {
        if (allocated_buf) free(allocated_buf);
        json_object_put(json);
        return OWSYNC_ERROR_IO;
    }

    ssize_t written = write(channel->fd, data_to_send, data_len);

    if (allocated_buf) free(allocated_buf);
    json_object_put(json);

    if (written != (ssize_t)data_len) {
        return OWSYNC_ERROR_IO;
    }

    return OWSYNC_OK;
}

/*
 * Receive message from channel.
 * Reads length prefix, validates size, then reads payload.
 * Decrypts if channel is encrypted.
 */
int channel_receive(channel_t *channel, message_t **out_msg) {
    if (!channel || !out_msg) return OWSYNC_ERROR;

    /* Read 4-byte big-endian length prefix */
    uint32_t len_be = 0;
    if (read(channel->fd, &len_be, 4) != 4) {
        return OWSYNC_ERROR_IO;
    }

    uint32_t len = ntohl(len_be);
    if (len > MAX_MESSAGE_SIZE) {
        log_error("Incoming message size %u exceeds MAX_MESSAGE_SIZE (%d)",
                  len, MAX_MESSAGE_SIZE);
        return OWSYNC_ERROR;
    }

    uint8_t *buffer = malloc(len);
    if (!buffer) return OWSYNC_ERROR_MEMORY;

    ssize_t total_read = 0;
    while (total_read < len) {
        ssize_t n = read(channel->fd, buffer + total_read, len - total_read);
        if (n <= 0) {
            free(buffer);
            return OWSYNC_ERROR_IO;
        }
        total_read += n;
    }

    uint8_t *json_data = buffer;

#ifdef ENABLE_ENCRYPTION
    if (channel->is_encrypted && channel->security_ctx) {
        uint8_t *decrypted = NULL;
        size_t decrypted_len = 0;

        int result = security_decrypt(channel->security_ctx, buffer, len, &decrypted, &decrypted_len);
        free(buffer);

        if (result != OWSYNC_OK) {
            return result;
        }

        json_data = decrypted;
    }
#endif

    struct json_object *root = json_tokener_parse((char *)json_data);
    free(json_data);

    if (!root) return OWSYNC_ERROR;

    message_t *msg = json_to_message(root);
    json_object_put(root);

    if (!msg) return OWSYNC_ERROR;

    *out_msg = msg;
    return OWSYNC_OK;
}

/* Get hostname for HELLO message (from environment or "unknown") */
static char *get_hostname(void) {
    char *hostname = getenv("HOSTNAME");
    if (hostname) {
        return strdup(hostname);
    }
    return strdup("unknown");
}

/* Arguments passed to connection handler thread */
typedef struct {
    int client_fd;         /* Client socket */
    const char *key;       /* Encryption key (shared, do not free) */
    char *root;            /* Sync root directory (owned) */
    char *db_path;         /* Database path (owned) */
    file_filter_t *filter; /* File filter (shared, do not free) */
    int64_t clock_offset;  /* Debug clock offset */
} connection_args_t;

/*
 * Execute bidirectional sync protocol.
 * Used by both server (incoming connections) and client (outgoing connections).
 *
 * Protocol flow:
 *   1. Exchange HELLO (hostname, timestamp, version)
 *   2. Validate clock skew and protocol version
 *   3. Exchange SYNC_STATE (complete file lists)
 *   4. Calculate diff and send REQUEST_FILES
 *   5. Serve requested files to peer
 *   6. Receive and apply files from peer
 *   7. Exchange END_OF_SYNC
 */
static int handle_protocol(channel_t *channel, const char *root, const char *db_path,
                           file_filter_t *filter, int64_t clock_offset) {
    uint64_t now = get_time_sec() + clock_offset;
    uint64_t now_ms = get_time_ms() + (clock_offset * 1000);

    log_debug("Starting protocol: root=%s, db=%s", root, db_path);

    message_t *hello = message_new(MSG_HELLO);
    hello->payload.hello.hostname = get_hostname();
    hello->payload.hello.timestamp = now;
    hello->payload.hello.version = PROTOCOL_VERSION;

    log_debug("Sending Hello message");
    if (channel_send(channel, hello) != OWSYNC_OK) {
        log_error("Failed to send Hello");
        message_free(hello);
        return OWSYNC_ERROR_IO;
    }
    message_free(hello);

    log_debug("Waiting for peer Hello");

    message_t *peer_hello = NULL;
    if (channel_receive(channel, &peer_hello) != OWSYNC_OK) {
        log_error("Failed to receive Hello");
        return OWSYNC_ERROR_IO;
    }

    log_debug("Received message type: %d", peer_hello->type);

    if (peer_hello->type != MSG_HELLO) {
        log_error("Expected Hello, got type %d", peer_hello->type);
        message_free(peer_hello);
        return OWSYNC_ERROR_PROTOCOL;
    }

    if (peer_hello->payload.hello.version != PROTOCOL_VERSION) {
        log_error("Version mismatch");
        message_free(peer_hello);
        return OWSYNC_ERROR_VERSION_MISMATCH;
    }

    uint64_t peer_time = peer_hello->payload.hello.timestamp;
    uint64_t diff = (now > peer_time) ? (now - peer_time) : (peer_time - now);
    if (diff > CLOCK_SKEW_THRESHOLD) {
        log_error("Clock skew too large: %lu seconds", diff);
        message_free(peer_hello);
        return OWSYNC_ERROR_CLOCK_SKEW;
    }

    log_debug("Handshake OK, hostname=%s", peer_hello->payload.hello.hostname);
    message_free(peer_hello);

    /* Load DB and scan filesystem for current state */
    log_debug("Loading database from %s", db_path);
    database_t *db = database_new();
    if (!db) return OWSYNC_ERROR_MEMORY;

    if (database_load(db, db_path) != OWSYNC_OK) {
        log_warning("Database load failed, will rebuild from filesystem scan");
    }

    bool dirty = false;
    log_debug("Scanning directory %s", root);
    database_update_from_scan(db, root, filter, &dirty);
    if (dirty) {
        log_debug("Database dirty, saving");
        database_save(db, db_path);
    }

    file_state_list_t *local_files = database_get_all_filtered(db, filter);
    log_debug("Local files count: %zu", local_files ? local_files->count : 0);

    message_t *sync_state = message_new(MSG_SYNC_STATE);
    sync_state->payload.sync_state.files = local_files;

    log_debug("Sending SyncState with %zu files", local_files->count);
    if (channel_send(channel, sync_state) != OWSYNC_OK) {
        log_error("Failed to send SyncState");
        // Don't free local_files here - we need it for diff calculation
        sync_state->payload.sync_state.files = NULL;
        message_free(sync_state);
        file_state_list_free(local_files);
        database_free(db);
        return OWSYNC_ERROR_IO;
    }
    // Don't free local_files - we still need it for diff calculation
    sync_state->payload.sync_state.files = NULL;
    message_free(sync_state);

    log_debug("Waiting for peer SyncState");
    message_t *peer_sync_state = NULL;
    if (channel_receive(channel, &peer_sync_state) != OWSYNC_OK) {
        log_error("Failed to receive SyncState");
        file_state_list_free(local_files);
        database_free(db);
        return OWSYNC_ERROR_IO;
    }

    if (peer_sync_state->type != MSG_SYNC_STATE) {
        log_error("Expected SyncState, got type %d", peer_sync_state->type);
        message_free(peer_sync_state);
        file_state_list_free(local_files);
        database_free(db);
        return OWSYNC_ERROR_PROTOCOL;
    }

    file_state_list_t *remote_files = peer_sync_state->payload.sync_state.files;
    log_debug("Received SyncState with %zu files", remote_files ? remote_files->count : 0);
    peer_sync_state->payload.sync_state.files = NULL;
    message_free(peer_sync_state);

    /* Calculate what files we need from remote */
    log_debug("Calculating diff");
    sync_plan_t *plan = NULL;
    calculate_diff(local_files, remote_files, filter, &plan);
    log_debug("Files to request: %zu, Files to delete: %zu",
              plan->files_to_request.count, plan->files_to_delete.count);
    file_state_list_free(remote_files);

    bool deletion_performed = false;
    for (size_t i = 0; i < plan->files_to_delete.count; i++) {
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", root, plan->files_to_delete.paths[i]);

        /* Attempt to delete file directly (unlink handles non-existent files safely) */
        if (unlink(full_path) == 0) {
            log_info("Deleted: %s", plan->files_to_delete.paths[i]);
            deletion_performed = true;
        }

        file_state_t *entry = database_get(db, plan->files_to_delete.paths[i]);
        if (entry) {
            entry->deleted = true;
            entry->mtime = now_ms;
            free(entry->hash);
            entry->hash = NULL;
            entry->size = 0;
        }
    }

    if (deletion_performed) {
        database_save(db, db_path);
    }

    message_t *request = message_new(MSG_REQUEST_FILES);
    request->payload.request_files.paths = path_list_new();
    if (request->payload.request_files.paths) {
        request->payload.request_files.paths->paths = plan->files_to_request.paths;
        request->payload.request_files.paths->count = plan->files_to_request.count;
        plan->files_to_request.paths = NULL;
        plan->files_to_request.count = 0;
    }

    if (channel_send(channel, request) != OWSYNC_OK) {
        message_free(request);
        sync_plan_free(plan);
        file_state_list_free(local_files);
        database_free(db);
        return OWSYNC_ERROR_IO;
    }
    message_free(request);
    sync_plan_free(plan);

    bool received_peer_request = false;
    bool received_end_of_sync = false;
    bool received_new_files = false;

    while (!received_peer_request || !received_end_of_sync) {
        message_t *msg = NULL;
        if (channel_receive(channel, &msg) != OWSYNC_OK) {
            file_state_list_free(local_files);
            database_free(db);
            return OWSYNC_ERROR_IO;
        }

        switch (msg->type) {
        case MSG_REQUEST_FILES: {
            for (size_t i = 0; i < msg->payload.request_files.paths->count; i++) {
                const char *path = msg->payload.request_files.paths->paths[i];

                if (!is_path_safe(root, path)) continue;
                if (!file_filter_matches(filter, path)) continue;

                char full_path[MAX_PATH_LEN];
                if (snprintf(full_path, sizeof(full_path), "%s/%s", root, path) >= (int)sizeof(full_path)) {
                    continue;
                }

                FILE *fp = fopen(full_path, "rb");
                if (!fp) continue;

                fseek(fp, 0, SEEK_END);
                long file_size = ftell(fp);
                fseek(fp, 0, SEEK_SET);

                if (file_size > (MAX_MESSAGE_SIZE / 2)) {
                    log_error("File '%s' too large to sync (%ld bytes). "
                              "Max file size is %d bytes (due to encoding overhead).",
                              path, file_size, MAX_MESSAGE_SIZE / 2);
                    fclose(fp);
                    continue;
                }

                uint8_t *data = malloc(file_size);
                if (!data) {
                    fclose(fp);
                    continue;
                }

                fread(data, 1, file_size, fp);
                fclose(fp);

                message_t *file_msg = message_new(MSG_FILE_CONTENT);
                file_msg->payload.file_content.path = strdup(path);
                file_msg->payload.file_content.data = data;
                file_msg->payload.file_content.data_len = file_size;

                file_state_t *fs = database_get(db, path);
                if (fs) {
                    file_msg->payload.file_content.mode = fs->mode;
                } else {
                    file_msg->payload.file_content.mode = 0644;
                }

                channel_send(channel, file_msg);
                message_free(file_msg);
            }

            message_t *end_msg = message_new(MSG_END_OF_SYNC);
            channel_send(channel, end_msg);
            message_free(end_msg);

            received_peer_request = true;
            break;
        }

        case MSG_FILE_CONTENT: {
            const char *path = msg->payload.file_content.path;

            if (path[0] == '/' || strstr(path, "..")) {
                message_free(msg);
                continue;
            }

            if (!file_filter_matches(filter, path)) {
                message_free(msg);
                continue;
            }

            char full_path[MAX_PATH_LEN];
            if (snprintf(full_path, sizeof(full_path), "%s/%s", root, path) >= (int)sizeof(full_path)) {
                message_free(msg);
                continue;
            }

            char *dir_path = strdup(full_path);
            char *dir = dirname(dir_path);

            if (mkdir_recursive(dir, 0755) != 0) {
                free(dir_path);
                message_free(msg);
                continue;
            }

            // Verify directory security
            char real_dir[MAX_PATH_LEN];
            char real_root[MAX_PATH_LEN];
            bool safe = false;
            if (realpath(dir, real_dir) && realpath(root, real_root)) {
                if (strncmp(real_dir, real_root, strlen(real_root)) == 0) {
                    safe = true;
                }
            }
            free(dir_path);

            if (!safe) {
                message_free(msg);
                continue;
            }

            char tmp_path[MAX_PATH_LEN + 5];  // +5 for ".tmp\0"
            if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", full_path) >= (int)sizeof(tmp_path)) {
                message_free(msg);
                continue;
            }

            int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
            if (fd >= 0) {
                write(fd, msg->payload.file_content.data, msg->payload.file_content.data_len);
                fchmod(fd, msg->payload.file_content.mode);
                close(fd);
                if (rename(tmp_path, full_path) == 0) {
                    log_info("Synced: %s", path);
                    received_new_files = true;
                } else {
                    unlink(tmp_path);
                }
            }

            break;
        }

        case MSG_END_OF_SYNC:
            received_end_of_sync = true;
            break;

        default:
            message_free(msg);
            file_state_list_free(local_files);
            database_free(db);
            return OWSYNC_ERROR_PROTOCOL;
        }

        message_free(msg);
    }

    if (received_new_files) {
        database_update_from_scan(db, root, filter, &dirty);
        database_save(db, db_path);
    }

    file_state_list_free(local_files);
    database_free(db);
    return OWSYNC_OK;
}

/* Thread entry point for handling incoming connections */
static void *handle_connection(void *arg) {
    connection_args_t *args = (connection_args_t *)arg;

    channel_t *channel = NULL;

#ifdef ENABLE_ENCRYPTION
    security_context_t *sec_ctx = NULL;
    if (args->key) {
        sec_ctx = security_context_new(args->key);
        if (!sec_ctx) {
            close(args->client_fd);
            free(args->root);
            free(args->db_path);
            free(args);
            return NULL;
        }
        channel = channel_new(args->client_fd, true, sec_ctx);
    } else {
        channel = channel_new(args->client_fd, false, NULL);
    }
#else
    channel = channel_new(args->client_fd, false, NULL);
#endif

    if (!channel) {
#ifdef ENABLE_ENCRYPTION
        security_context_free(sec_ctx);
#endif
        close(args->client_fd);
        free(args->root);
        free(args->db_path);
        free(args);
        return NULL;
    }

    int result = handle_protocol(channel, args->root, args->db_path, args->filter, args->clock_offset);

    if (result != OWSYNC_OK) {
        log_error("Session error: %d", result);
    }

    channel_free(channel);
#ifdef ENABLE_ENCRYPTION
    security_context_free(sec_ctx);
#endif

    free(args->root);
    free(args->db_path);
    free(args);

    __sync_fetch_and_sub(&active_connections, 1);
    return NULL;
}

/*
 * Start TCP server accepting sync connections.
 * Supports both IPv4 and IPv6.
 * Spawns detached thread per connection. Runs until process termination.
 *
 * @param host  Host to bind ("::" for dual-stack, "0.0.0.0" for IPv4-only, or specific address)
 * @param port  Port to bind (as string)
 */
int start_server(const char *host, const char *port, const char *key,
                 const char *root, const char *db_path, file_filter_t *filter,
                 int64_t clock_offset) {
    if (!host || !port || !root || !db_path) return OWSYNC_ERROR;

    int sockfd = -1;
    int port_num = atoi(port);
    int opt = 1;

    /*
     * Handle wildcard addresses explicitly (like lease-sync does).
     * This avoids getaddrinfo returning IPv4 first when we want IPv6 dual-stack.
     */
    if (strcmp(host, "::") == 0) {
        /* IPv6 dual-stack: try IPv6 first, fall back to IPv4 if unavailable */
        sockfd = socket(AF_INET6, SOCK_STREAM, 0);
        if (sockfd < 0) {
            if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
                log_info("IPv6 not available, falling back to IPv4-only");
                goto ipv4_fallback;
            }
            log_error("socket(AF_INET6) failed: %s", strerror(errno));
            return OWSYNC_ERROR_IO;
        }

        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        /* Enable dual-stack: allow IPv4 connections via IPv4-mapped addresses */
        int v6only = 0;
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0) {
            log_warning("setsockopt(IPV6_V6ONLY) failed: %s", strerror(errno));
            /* Continue anyway - dual-stack might still work */
        }

        struct sockaddr_in6 addr6 = {0};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port_num);

        if (bind(sockfd, (struct sockaddr *)&addr6, sizeof(addr6)) < 0) {
            log_error("bind(:::%d) failed: %s", port_num, strerror(errno));
            close(sockfd);
            return OWSYNC_ERROR_IO;
        }

        log_info("Bound to IPv6 dual-stack (:::%d)", port_num);

    } else if (strcmp(host, "0.0.0.0") == 0) {
ipv4_fallback:
        /* IPv4-only */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            log_error("socket(AF_INET) failed: %s", strerror(errno));
            return OWSYNC_ERROR_IO;
        }

        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr4 = {0};
        addr4.sin_family = AF_INET;
        addr4.sin_addr.s_addr = INADDR_ANY;
        addr4.sin_port = htons(port_num);

        if (bind(sockfd, (struct sockaddr *)&addr4, sizeof(addr4)) < 0) {
            log_error("bind(0.0.0.0:%d) failed: %s", port_num, strerror(errno));
            close(sockfd);
            return OWSYNC_ERROR_IO;
        }

        log_info("Bound to IPv4-only (0.0.0.0:%d)", port_num);

    } else {
        /* Specific address: use getaddrinfo to resolve */
        struct addrinfo hints = {0};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;

        struct addrinfo *result = NULL;
        int gai_err = getaddrinfo(host, port, &hints, &result);
        if (gai_err != 0) {
            log_error("getaddrinfo(%s) failed: %s", host, gai_strerror(gai_err));
            return OWSYNC_ERROR_IO;
        }

        struct addrinfo *rp;
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sockfd < 0) continue;

            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            if (rp->ai_family == AF_INET6) {
                int v6only = 0;
                setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            }

            if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
                break;  /* Success */
            }

            close(sockfd);
            sockfd = -1;
        }

        freeaddrinfo(result);

        if (sockfd < 0) {
            log_error("Could not bind to %s:%s", host, port);
            return OWSYNC_ERROR_IO;
        }
    }

    if (listen(sockfd, 10) < 0) {
        log_error("listen() failed: %s", strerror(errno));
        close(sockfd);
        return OWSYNC_ERROR_IO;
    }

    log_info("Listening on %s:%s", host, port);

    while (1) {
        struct sockaddr_storage client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);

        if (client_fd < 0) {
            continue;
        }

        int count = __sync_add_and_fetch(&active_connections, 1);
        if (count > MAX_CONNECTIONS) {
            __sync_sub_and_fetch(&active_connections, 1);
            close(client_fd);
            continue;
        }

        connection_args_t *args = malloc(sizeof(connection_args_t));
        if (!args) {
            __sync_fetch_and_sub(&active_connections, 1);
            close(client_fd);
            continue;
        }

        args->client_fd = client_fd;
        args->key = key;
        args->root = strdup(root);
        args->db_path = strdup(db_path);
        args->filter = filter;
        args->clock_offset = clock_offset;

        pthread_t thread;
        if (pthread_create(&thread, NULL, handle_connection, args) != 0) {
            __sync_fetch_and_sub(&active_connections, 1);
            close(client_fd);
            free(args->root);
            free(args->db_path);
            free(args);
            continue;
        }
        pthread_detach(thread);
    }

    close(sockfd);
    return OWSYNC_OK;
}

/*
 * Connect to peer and run one sync session.
 * Supports both IPv4 and IPv6 via getaddrinfo().
 * Returns after sync completes or on error.
 *
 * @param host  Peer hostname or IP address (IPv4 or IPv6)
 * @param port  Port to connect to (as string for getaddrinfo)
 */
int connect_peer(const char *host, const char *port, const char *key,
                 const char *root, const char *db_path, file_filter_t *filter,
                 int64_t clock_offset) {
    if (!host || !port || !root || !db_path) return OWSYNC_ERROR;

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;     /* Accept IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *result = NULL;
    int gai_err = getaddrinfo(host, port, &hints, &result);

    if (gai_err != 0) {
        log_error("getaddrinfo failed for %s:%s: %s", host, port, gai_strerror(gai_err));
        return OWSYNC_ERROR_IO;
    }

    int sockfd = -1;
    struct addrinfo *rp;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;  /* Success */
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(result);

    if (sockfd < 0) {
        log_error("Could not connect to %s:%s", host, port);
        return OWSYNC_ERROR_IO;
    }

    channel_t *channel = NULL;

#ifdef ENABLE_ENCRYPTION
    security_context_t *sec_ctx = NULL;
    if (key) {
        sec_ctx = security_context_new(key);
        if (!sec_ctx) {
            close(sockfd);
            return OWSYNC_ERROR_CRYPTO;
        }
        channel = channel_new(sockfd, true, sec_ctx);
    } else {
        channel = channel_new(sockfd, false, NULL);
    }
#else
    channel = channel_new(sockfd, false, NULL);
#endif

    if (!channel) {
#ifdef ENABLE_ENCRYPTION
        security_context_free(sec_ctx);
#endif
        close(sockfd);
        return OWSYNC_ERROR_MEMORY;
    }

    int result_code = handle_protocol(channel, root, db_path, filter, clock_offset);

    channel_free(channel);
#ifdef ENABLE_ENCRYPTION
    security_context_free(sec_ctx);
#endif

    return result_code;
}
