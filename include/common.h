/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 */
#ifndef OWSYNC_COMMON_H
#define OWSYNC_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define OWSYNC_VERSION "1.2.0"
#define PROTOCOL_VERSION 1                          /* Wire protocol version for compatibility checks */
#define MAX_PATH_LEN 4096                           /* Maximum file path length */

/*
 * Maximum message size (default 32MB).
 * This limits the largest file that can be synced (effective limit is ~16MB due to hex encoding).
 * Can be overridden at build time: make MAX_MESSAGE_SIZE=$((64*1024*1024))
 */
#ifndef OWSYNC_MAX_MESSAGE_SIZE
#define OWSYNC_MAX_MESSAGE_SIZE (32 * 1024 * 1024)
#endif
#define MAX_MESSAGE_SIZE OWSYNC_MAX_MESSAGE_SIZE

#define CLOCK_SKEW_THRESHOLD 60                     /* Max acceptable clock difference in seconds */
#define TOMBSTONE_TTL_MS (30ULL * 24 * 3600 * 1000) /* Tombstone retention: 30 days in milliseconds */
#define AES_KEY_SIZE 32                             /* AES-256 key size in bytes */
#define AES_NONCE_SIZE 12                           /* GCM nonce size in bytes */

/* Error codes returned by owsync functions */
typedef enum {
    OWSYNC_OK = 0,                   /* Success */
    OWSYNC_ERROR = -1,               /* Generic error */
    OWSYNC_ERROR_MEMORY = -2,        /* Memory allocation failed */
    OWSYNC_ERROR_IO = -3,            /* I/O error (file or network) */
    OWSYNC_ERROR_PROTOCOL = -4,      /* Protocol violation (unexpected message) */
    OWSYNC_ERROR_CRYPTO = -5,        /* Encryption/decryption failed */
    OWSYNC_ERROR_CLOCK_SKEW = -6,    /* Peer clock difference exceeds threshold */
    OWSYNC_ERROR_VERSION_MISMATCH = -7, /* Protocol version mismatch */
} owsync_error_t;

/* Dynamic byte buffer with automatic growth */
typedef struct {
    char *data;       /* Buffer contents */
    size_t len;       /* Current data length */
    size_t capacity;  /* Allocated size (grows by doubling) */
} buffer_t;

/* Buffer management functions */
buffer_t *buffer_new(size_t initial_capacity);
int buffer_append(buffer_t *buf, const void *data, size_t len);
void buffer_free(buffer_t *buf);

/* Hex encoding/decoding for hashes and binary data */
char *hex_encode(const uint8_t *data, size_t len);
uint8_t *hex_decode(const char *hex, size_t *out_len);

/* Time utilities */
uint64_t get_time_ms(void);  /* Current time in milliseconds since epoch */
uint64_t get_time_sec(void); /* Current time in seconds since epoch */

#endif
