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
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

/* Create dynamic buffer with specified initial capacity */
buffer_t *buffer_new(size_t initial_capacity) {
    buffer_t *buf = malloc(sizeof(buffer_t));
    if (!buf) return NULL;

    buf->data = malloc(initial_capacity);
    if (!buf->data) {
        free(buf);
        return NULL;
    }

    buf->len = 0;
    buf->capacity = initial_capacity;
    return buf;
}

/*
 * Append data to buffer, growing capacity as needed.
 * Capacity doubles each time to amortize reallocation cost.
 */
int buffer_append(buffer_t *buf, const void *data, size_t len) {
    if (!buf || !data) return OWSYNC_ERROR;

    /* Grow buffer if needed (doubling strategy) */
    if (buf->len + len > buf->capacity) {
        size_t new_capacity = buf->capacity * 2;
        while (new_capacity < buf->len + len) {
            new_capacity *= 2;
        }

        char *new_data = realloc(buf->data, new_capacity);
        if (!new_data) return OWSYNC_ERROR_MEMORY;

        buf->data = new_data;
        buf->capacity = new_capacity;
    }

    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return OWSYNC_OK;
}

void buffer_free(buffer_t *buf) {
    if (!buf) return;
    free(buf->data);
    free(buf);
}

/*
 * Encode binary data as lowercase hex string.
 * Returns newly allocated string (caller must free).
 */
char *hex_encode(const uint8_t *data, size_t len) {
    if (!data) return NULL;

    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;

    for (size_t i = 0; i < len; i++) {
        snprintf(hex + i * 2, 3, "%02x", data[i]);
    }
    hex[len * 2] = '\0';

    return hex;
}

/*
 * Decode hex string to binary data.
 * Returns NULL if string has odd length or contains non-hex characters.
 * Caller must free returned buffer.
 */
uint8_t *hex_decode(const char *hex, size_t *out_len) {
    if (!hex || !out_len) return NULL;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return NULL;  /* Must have even number of chars */

    size_t byte_len = hex_len / 2;
    uint8_t *bytes = malloc(byte_len);
    if (!bytes) return NULL;

    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        if (!isxdigit(byte_str[0]) || !isxdigit(byte_str[1])) {
            free(bytes);
            return NULL;  /* Invalid hex character */
        }
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }

    *out_len = byte_len;
    return bytes;
}

/* Get current time in milliseconds since Unix epoch */
uint64_t get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

/* Get current time in seconds since Unix epoch */
uint64_t get_time_sec(void) {
    return (uint64_t)time(NULL);
}
