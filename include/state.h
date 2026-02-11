/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 */
#ifndef OWSYNC_STATE_H
#define OWSYNC_STATE_H

#include "common.h"
#include <glob.h>

/*
 * File state record - tracks a file's metadata for synchronization.
 * Used both in memory and persisted to the JSON database.
 */
typedef struct {
    char *path;       /* Relative path from sync root */
    char *hash;       /* SHA-256 content hash (hex string), NULL if deleted */
    uint64_t mtime;   /* Last modification time in milliseconds since epoch */
    uint64_t size;    /* File size in bytes */
    uint32_t mode;    /* Unix file permissions (octal, e.g., 0644) */
    bool deleted;     /* Tombstone flag: true if file was deleted */
} file_state_t;

/* Dynamic array of file states for bulk operations */
typedef struct {
    file_state_t *files;  /* Array of file states (shallow copy of data) */
    size_t count;         /* Number of entries */
    size_t capacity;      /* Allocated slots (grows by doubling) */
} file_state_list_t;

/* Hash table entry with chaining for collision resolution */
typedef struct {
    char *path;          /* Key: relative file path (duplicated for fast lookup) */
    file_state_t state;  /* Value: file metadata (owns its strings) */
    void *next;          /* Next entry in chain (db_entry_t*) */
} db_entry_t;

/*
 * Hash table for file state storage.
 * Uses DJB2 hashing with chaining. Persisted to JSON.
 */
typedef struct {
    db_entry_t **buckets;  /* Array of bucket heads (chains) */
    size_t bucket_count;   /* Number of buckets (fixed at 256) */
    size_t entry_count;    /* Total entries across all buckets */
} database_t;

/* List of glob patterns for file filtering */
typedef struct {
    char **patterns;  /* Array of fnmatch-compatible patterns */
    size_t count;     /* Number of patterns */
} pattern_list_t;

/*
 * File filter for include/exclude pattern matching.
 * Excludes are checked first. If no includes are specified,
 * nothing matches (conservative default for security).
 */
typedef struct {
    pattern_list_t includes;  /* Whitelist patterns (must match to sync) */
    pattern_list_t excludes;  /* Blacklist patterns (never sync if matched) */
} file_filter_t;

/* File state lifecycle */
file_state_t *file_state_new(const char *path);
void file_state_free(file_state_t *state);
file_state_t *file_state_clone(const file_state_t *state);  /* Deep copy */

/* File state list operations */
file_state_list_t *file_state_list_new(void);
int file_state_list_add(file_state_list_t *list, file_state_t *state);  /* Copies by value */
void file_state_list_free(file_state_list_t *list);

/* Database operations (hash table with JSON persistence) */
database_t *database_new(void);
void database_free(database_t *db);
int database_load(database_t *db, const char *path);   /* Load from JSON file */
int database_save(database_t *db, const char *path);   /* Atomic save via rename */
int database_put(database_t *db, const char *path, file_state_t *state);  /* Deep copies state */
file_state_t *database_get(database_t *db, const char *path);  /* Returns internal pointer */
file_state_list_t *database_get_all_filtered(database_t *db, file_filter_t *filter);
int database_update_from_scan(database_t *db, const char *root, file_filter_t *filter, bool *dirty);

/* File filter operations */
file_filter_t *file_filter_new(char **includes, size_t include_count,
                               char **excludes, size_t exclude_count);
void file_filter_free(file_filter_t *filter);
bool file_filter_matches(file_filter_t *filter, const char *path);

/* Directory scanning and hashing */
int scan_directory(const char *root, file_filter_t *filter, file_state_list_t **out_list);
int compute_hash(const char *path, char **out_hash);  /* SHA-256, returns hex string */

#endif
