/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 */
#include "state.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ftw.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fnmatch.h>
#include <openssl/evp.h>
#include <json-c/json.h>

#define DB_BUCKET_COUNT 256  /* Hash table buckets - power of 2 for fast modulo */

/*
 * Compute DJB2 hash of a string for hash table indexing.
 * Fast, simple, and good distribution for file paths.
 */
static uint32_t hash_string(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    }
    return hash;
}

/* Allocate new file state with path. Other fields are zeroed. */
file_state_t *file_state_new(const char *path) {
    file_state_t *state = calloc(1, sizeof(file_state_t));
    if (!state) return NULL;

    state->path = strdup(path);
    if (!state->path) {
        free(state);
        return NULL;
    }

    return state;
}

void file_state_free(file_state_t *state) {
    if (!state) return;
    free(state->path);
    free(state->hash);
    free(state);
}

/*
 * Deep copy a file state. All strings are duplicated.
 * Returns NULL on allocation failure.
 */
file_state_t *file_state_clone(const file_state_t *state) {
    if (!state) return NULL;

    file_state_t *clone = malloc(sizeof(file_state_t));
    if (!clone) return NULL;

    clone->path = strdup(state->path);
    clone->hash = state->hash ? strdup(state->hash) : NULL;
    clone->mtime = state->mtime;
    clone->size = state->size;
    clone->mode = state->mode;
    clone->deleted = state->deleted;

    if (!clone->path || (state->hash && !clone->hash)) {
        file_state_free(clone);
        return NULL;
    }

    return clone;
}

file_state_list_t *file_state_list_new(void) {
    file_state_list_t *list = malloc(sizeof(file_state_list_t));
    if (!list) return NULL;

    list->files = NULL;
    list->count = 0;
    list->capacity = 0;
    return list;
}

/*
 * Add file state to list by shallow copy.
 * Caller retains ownership of state's strings (list does not duplicate).
 * List grows by doubling capacity when full.
 */
int file_state_list_add(file_state_list_t *list, file_state_t *state) {
    if (!list || !state) return OWSYNC_ERROR;

    if (list->count >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        file_state_t *new_files = realloc(list->files, new_capacity * sizeof(file_state_t));
        if (!new_files) return OWSYNC_ERROR_MEMORY;

        list->files = new_files;
        list->capacity = new_capacity;
    }

    list->files[list->count++] = *state;
    return OWSYNC_OK;
}

void file_state_list_free(file_state_list_t *list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->files[i].path);
        free(list->files[i].hash);
    }
    free(list->files);
    free(list);
}

/* Create empty hash table with 256 buckets (chaining for collisions) */
database_t *database_new(void) {
    database_t *db = malloc(sizeof(database_t));
    if (!db) return NULL;

    db->bucket_count = DB_BUCKET_COUNT;
    db->buckets = calloc(DB_BUCKET_COUNT, sizeof(db_entry_t *));
    if (!db->buckets) {
        free(db);
        return NULL;
    }

    db->entry_count = 0;
    return db;
}

void database_free(database_t *db) {
    if (!db) return;

    for (size_t i = 0; i < db->bucket_count; i++) {
        db_entry_t *entry = db->buckets[i];
        while (entry) {
            db_entry_t *next = entry->next;
            free(entry->path);
            free(entry->state.path);
            free(entry->state.hash);
            free(entry);
            entry = next;
        }
    }

    free(db->buckets);
    free(db);
}

/*
 * Insert or update file state in database.
 * Deep copies all strings - caller retains ownership of state.
 * Updates in place if path exists, otherwise inserts at bucket head.
 */
int database_put(database_t *db, const char *path, file_state_t *state) {
    if (!db || !path || !state) return OWSYNC_ERROR;

    uint32_t hash = hash_string(path);
    size_t bucket = hash % db->bucket_count;

    /* Search chain for existing entry */
    db_entry_t *entry = db->buckets[bucket];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            /* Update existing entry - free old strings first */
            free(entry->state.path);
            free(entry->state.hash);

            /* Deep copy the new state */
            entry->state.path = state->path ? strdup(state->path) : NULL;
            entry->state.hash = state->hash ? strdup(state->hash) : NULL;
            entry->state.mtime = state->mtime;
            entry->state.size = state->size;
            entry->state.mode = state->mode;
            entry->state.deleted = state->deleted;
            return OWSYNC_OK;
        }
        entry = entry->next;
    }

    /* Insert new entry at bucket head */
    db_entry_t *new_entry = malloc(sizeof(db_entry_t));
    if (!new_entry) return OWSYNC_ERROR_MEMORY;

    new_entry->path = strdup(path);
    if (!new_entry->path) {
        free(new_entry);
        return OWSYNC_ERROR_MEMORY;
    }

    /* Deep copy the state */
    new_entry->state.path = state->path ? strdup(state->path) : NULL;
    new_entry->state.hash = state->hash ? strdup(state->hash) : NULL;
    new_entry->state.mtime = state->mtime;
    new_entry->state.size = state->size;
    new_entry->state.mode = state->mode;
    new_entry->state.deleted = state->deleted;

    new_entry->next = db->buckets[bucket];
    db->buckets[bucket] = new_entry;
    db->entry_count++;

    return OWSYNC_OK;
}

/*
 * Look up file state by path.
 * Returns pointer to internal state (do not free).
 * Returns NULL if not found.
 */
file_state_t *database_get(database_t *db, const char *path) {
    if (!db || !path) return NULL;

    uint32_t hash = hash_string(path);
    size_t bucket = hash % db->bucket_count;

    db_entry_t *entry = db->buckets[bucket];
    while (entry) {
        if (strcmp(entry->path, path) == 0) {
            return &entry->state;
        }
        entry = entry->next;
    }

    return NULL;
}

file_state_list_t *database_get_all_filtered(database_t *db, file_filter_t *filter) {
    if (!db) return NULL;

    file_state_list_t *list = file_state_list_new();
    if (!list) return NULL;

    for (size_t i = 0; i < db->bucket_count; i++) {
        db_entry_t *entry = db->buckets[i];
        while (entry) {
            if (!filter || file_filter_matches(filter, entry->state.path)) {
                file_state_t clone = {0};
                clone.path = strdup(entry->state.path);
                clone.hash = entry->state.hash ? strdup(entry->state.hash) : NULL;
                clone.mtime = entry->state.mtime;
                clone.size = entry->state.size;
                clone.mode = entry->state.mode;
                clone.deleted = entry->state.deleted;

                if (file_state_list_add(list, &clone) != OWSYNC_OK) {
                    free(clone.path);
                    free(clone.hash);
                    file_state_list_free(list);
                    return NULL;
                }
            }
            entry = entry->next;
        }
    }

    return list;
}

/*
 * Load database from JSON file.
 * Returns OWSYNC_OK even if file doesn't exist (empty DB).
 * JSON format: { "files": { "path": { "hash":..., "mtime":..., ... }, ... } }
 */
int database_load(database_t *db, const char *path) {
    if (!db || !path) return OWSYNC_ERROR;

    FILE *fp = fopen(path, "r");
    if (!fp) return OWSYNC_OK;  /* No file = empty database */

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *content = malloc(file_size + 1);
    if (!content) {
        fclose(fp);
        return OWSYNC_ERROR_MEMORY;
    }

    fread(content, 1, file_size, fp);
    content[file_size] = '\0';
    fclose(fp);

    struct json_object *root = json_tokener_parse(content);
    free(content);

    if (!root) return OWSYNC_ERROR;

    struct json_object *files_obj = NULL;
    if (!json_object_object_get_ex(root, "files", &files_obj) ||
            !json_object_is_type(files_obj, json_type_object)) {
        json_object_put(root);
        return OWSYNC_ERROR;
    }

    json_object_object_foreach(files_obj, path_key, entry) {
        if (!path_key) continue;

        file_state_t state = {0};
        state.path = strdup(path_key);

        struct json_object *hash = NULL;
        if (json_object_object_get_ex(entry, "hash", &hash) &&
                json_object_is_type(hash, json_type_string)) {
            const char *hash_str = json_object_get_string(hash);
            if (hash_str) {
                state.hash = strdup(hash_str);
            }
        }

        struct json_object *mtime = NULL;
        if (json_object_object_get_ex(entry, "mtime", &mtime)) {
            state.mtime = (uint64_t)json_object_get_double(mtime);
        }

        struct json_object *size = NULL;
        if (json_object_object_get_ex(entry, "size", &size)) {
            state.size = (uint64_t)json_object_get_double(size);
        }

        struct json_object *mode = NULL;
        if (json_object_object_get_ex(entry, "mode", &mode)) {
            state.mode = (uint32_t)json_object_get_int(mode);
        }

        struct json_object *deleted = NULL;
        if (json_object_object_get_ex(entry, "deleted", &deleted) &&
                json_object_is_type(deleted, json_type_boolean)) {
            state.deleted = json_object_get_boolean(deleted);
        }

        database_put(db, path_key, &state);

        free(state.path);
        free(state.hash);
    }

    json_object_put(root);
    return OWSYNC_OK;
}

/*
 * Save database to JSON file atomically.
 * Writes to .db_tmp then renames to prevent corruption on crash.
 */
int database_save(database_t *db, const char *path) {
    if (!db || !path) return OWSYNC_ERROR;

    struct json_object *root = json_object_new_object();
    if (!root) return OWSYNC_ERROR_MEMORY;

    struct json_object *files_obj = json_object_new_object();
    if (!files_obj) {
        json_object_put(root);
        return OWSYNC_ERROR_MEMORY;
    }

    json_object_object_add(root, "files", files_obj);

    for (size_t i = 0; i < db->bucket_count; i++) {
        db_entry_t *entry = db->buckets[i];
        while (entry) {
            struct json_object *file_obj = json_object_new_object();
            if (!file_obj) {
                json_object_put(root);
                return OWSYNC_ERROR_MEMORY;
            }

            if (entry->state.hash) {
                json_object_object_add(file_obj, "hash",
                                       json_object_new_string(entry->state.hash));
            } else {
                json_object_object_add(file_obj, "hash", NULL);
            }

            json_object_object_add(file_obj, "mtime",
                                   json_object_new_double((double)entry->state.mtime));
            json_object_object_add(file_obj, "size",
                                   json_object_new_double((double)entry->state.size));
            json_object_object_add(file_obj, "mode",
                                   json_object_new_int((int)entry->state.mode));
            json_object_object_add(file_obj, "deleted",
                                   json_object_new_boolean(entry->state.deleted));

            json_object_object_add(files_obj, entry->path, file_obj);
            entry = entry->next;
        }
    }

    const char *json_str = json_object_to_json_string_ext(root,
                           JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);

    if (!json_str) {
        json_object_put(root);
        return OWSYNC_ERROR_MEMORY;
    }

    char tmp_path[MAX_PATH_LEN];
    snprintf(tmp_path, sizeof(tmp_path), "%s.db_tmp", path);

    FILE *fp = fopen(tmp_path, "w");
    if (!fp) {
        json_object_put(root);
        return OWSYNC_ERROR_IO;
    }

    fputs(json_str, fp);
    fclose(fp);
    json_object_put(root);

    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return OWSYNC_ERROR_IO;
    }

    return OWSYNC_OK;
}

/* Context passed to nftw callback via thread-local storage */
typedef struct {
    database_t *db;       /* Target database for scanned entries */
    const char *root;     /* Sync root directory path */
    size_t root_len;      /* Length of root (for stripping prefix) */
    file_filter_t *filter;/* Include/exclude patterns */
    uint64_t now_ms;      /* Scan start time for tombstones */
} scan_context_t;

/*
 * Thread-local scan context (nftw doesn't support user data parameter).
 *
 * Note: __thread storage class is supported by:
 *   - musl libc (OpenWrt default since 2015)
 *   - glibc
 *   - uclibc-ng
 * This is required because nftw() has no user-data parameter.
 */
static __thread scan_context_t *g_scan_ctx = NULL;

/*
 * nftw callback for directory scanning.
 * Computes hash for each regular file and adds to database.
 * Skips hidden files, temp files, and database files.
 */
static int scan_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;

    if (!g_scan_ctx) return 0;
    if (typeflag != FTW_F) return 0;  /* Only process regular files */

    const char *relative_path = fpath + g_scan_ctx->root_len;
    if (*relative_path == '/') relative_path++;

    if (relative_path[0] == '.' ||
            strstr(relative_path, ".tmp") ||
            strstr(relative_path, ".db")) {
        return 0;
    }

    if (g_scan_ctx->filter && !file_filter_matches(g_scan_ctx->filter, relative_path)) {
        return 0;
    }

    char *hash = NULL;
    if (compute_hash(fpath, &hash) != OWSYNC_OK) {
        return 0;
    }

    file_state_t state = {0};
    state.path = strdup(relative_path);
    state.hash = hash;
    state.mtime = (uint64_t)sb->st_mtim.tv_sec * 1000 + sb->st_mtim.tv_nsec / 1000000;
    state.size = sb->st_size;
    state.mode = (uint32_t)sb->st_mode & 0777;
    state.deleted = false;

    database_put(g_scan_ctx->db, relative_path, &state);

    // Free temporary strings (database_put makes its own copies)
    free(state.path);
    free(state.hash);

    return 0;
}

/*
 * Scan directory and update database with current state.
 *
 * Three-way merge:
 *   1. Scan disk into temporary database
 *   2. For each existing DB entry not on disk:
 *      - Mark as deleted (tombstone) if live
 *      - Remove tombstone if older than TOMBSTONE_TTL_MS
 *   3. For each disk file:
 *      - Add/update if changed
 *
 * Sets *dirty=true if any changes were made.
 */
int database_update_from_scan(database_t *db, const char *root, file_filter_t *filter, bool *dirty) {
    if (!db || !root || !dirty) return OWSYNC_ERROR;

    *dirty = false;
    uint64_t now_ms = get_time_ms();

    /* Phase 1: Scan filesystem into temporary database */
    database_t *disk_db = database_new();
    if (!disk_db) return OWSYNC_ERROR_MEMORY;

    scan_context_t ctx = {
        .db = disk_db,
        .root = root,
        .root_len = strlen(root),
        .filter = filter,
        .now_ms = now_ms
    };

    g_scan_ctx = &ctx;
    nftw(root, scan_callback, 64, FTW_PHYS);  /* FTW_PHYS: don't follow symlinks */
    g_scan_ctx = NULL;

    /* Phase 2: Detect deletions and expire old tombstones */
    for (size_t i = 0; i < db->bucket_count; i++) {
        db_entry_t *entry = db->buckets[i];
        db_entry_t *prev = NULL;

        while (entry) {
            db_entry_t *next = entry->next;
            file_state_t *disk_state = database_get(disk_db, entry->path);

            if (!disk_state) {
                /* File not on disk */
                if (!entry->state.deleted) {
                    /* Live file disappeared -> create tombstone */
                    entry->state.deleted = true;
                    entry->state.mtime = now_ms;
                    free(entry->state.hash);
                    entry->state.hash = NULL;
                    entry->state.size = 0;
                    *dirty = true;
                } else if (now_ms > entry->state.mtime &&
                           (now_ms - entry->state.mtime) > TOMBSTONE_TTL_MS) {
                    /* Tombstone expired -> remove from DB */
                    if (prev) {
                        prev->next = next;
                    } else {
                        db->buckets[i] = next;
                    }
                    free(entry->path);
                    file_state_free(&entry->state);
                    free(entry);
                    db->entry_count--;
                    *dirty = true;
                    entry = next;
                    continue;
                }
            }

            prev = entry;
            entry = next;
        }
    }

    /* Phase 3: Add/update entries for files on disk */
    for (size_t i = 0; i < disk_db->bucket_count; i++) {
        db_entry_t *entry = disk_db->buckets[i];
        while (entry) {
            file_state_t *old_state = database_get(db, entry->path);

            /* Check if file is new or changed */
            if (!old_state ||
                    (old_state->hash && entry->state.hash && strcmp(old_state->hash, entry->state.hash) != 0) ||
                    old_state->mtime != entry->state.mtime ||
                    old_state->size != entry->state.size ||
                    old_state->mode != entry->state.mode ||
                    old_state->deleted != entry->state.deleted) {

                file_state_t new_state = {0};
                new_state.path = strdup(entry->state.path);
                new_state.hash = entry->state.hash ? strdup(entry->state.hash) : NULL;
                new_state.mtime = entry->state.mtime;
                new_state.size = entry->state.size;
                new_state.mode = entry->state.mode;
                new_state.deleted = entry->state.deleted;

                database_put(db, entry->path, &new_state);

                /* Free temporary strings (database_put makes its own copies) */
                free(new_state.path);
                free(new_state.hash);

                *dirty = true;
            }

            entry = entry->next;
        }
    }

    database_free(disk_db);
    return OWSYNC_OK;
}

file_filter_t *file_filter_new(char **includes, size_t include_count,
                               char **excludes, size_t exclude_count) {
    file_filter_t *filter = malloc(sizeof(file_filter_t));
    if (!filter) return NULL;

    filter->includes.patterns = NULL;
    filter->includes.count = 0;
    filter->excludes.patterns = NULL;
    filter->excludes.count = 0;

    if (include_count > 0) {
        filter->includes.patterns = calloc(include_count, sizeof(char *));
        if (!filter->includes.patterns) {
            free(filter);
            return NULL;
        }
        for (size_t i = 0; i < include_count; i++) {
            filter->includes.patterns[i] = strdup(includes[i]);
            if (!filter->includes.patterns[i]) {
                filter->includes.count = i;  // Set count for partial cleanup
                file_filter_free(filter);
                return NULL;
            }
        }
        filter->includes.count = include_count;
    }

    if (exclude_count > 0) {
        filter->excludes.patterns = calloc(exclude_count, sizeof(char *));
        if (!filter->excludes.patterns) {
            file_filter_free(filter);
            return NULL;
        }
        for (size_t i = 0; i < exclude_count; i++) {
            filter->excludes.patterns[i] = strdup(excludes[i]);
            if (!filter->excludes.patterns[i]) {
                filter->excludes.count = i;  // Set count for partial cleanup
                file_filter_free(filter);
                return NULL;
            }
        }
        filter->excludes.count = exclude_count;
    }

    return filter;
}

void file_filter_free(file_filter_t *filter) {
    if (!filter) return;

    for (size_t i = 0; i < filter->includes.count; i++) {
        free(filter->includes.patterns[i]);
    }
    free(filter->includes.patterns);

    for (size_t i = 0; i < filter->excludes.count; i++) {
        free(filter->excludes.patterns[i]);
    }
    free(filter->excludes.patterns);

    free(filter);
}

/*
 * Check if path matches filter criteria.
 * Order: excludes checked first, then includes.
 * Conservative default: if no includes defined, nothing matches.
 */
bool file_filter_matches(file_filter_t *filter, const char *path) {
    if (!filter || !path) return true;

    /* Excludes take precedence */
    for (size_t i = 0; i < filter->excludes.count; i++) {
        if (fnmatch(filter->excludes.patterns[i], path, 0) == 0) {
            return false;
        }
    }

    /* No includes = sync nothing (safe default) */
    if (filter->includes.count == 0) {
        return false;
    }

    /* Must match at least one include pattern */
    for (size_t i = 0; i < filter->includes.count; i++) {
        if (fnmatch(filter->includes.patterns[i], path, 0) == 0) {
            return true;
        }
    }

    return false;
}

int scan_directory(const char *root, file_filter_t *filter, file_state_list_t **out_list) {
    if (!root || !out_list) return OWSYNC_ERROR;

    database_t *db = database_new();
    if (!db) return OWSYNC_ERROR_MEMORY;

    bool dirty = false;
    int result = database_update_from_scan(db, root, filter, &dirty);
    if (result != OWSYNC_OK) {
        database_free(db);
        return result;
    }

    *out_list = database_get_all_filtered(db, filter);
    database_free(db);

    return *out_list ? OWSYNC_OK : OWSYNC_ERROR_MEMORY;
}

/*
 * Compute SHA-256 hash of file contents.
 * Returns hex-encoded hash string (caller must free).
 */
int compute_hash(const char *path, char **out_hash) {
    if (!path || !out_hash) return OWSYNC_ERROR;

    FILE *fp = fopen(path, "rb");
    if (!fp) return OWSYNC_ERROR_IO;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(fp);
        return OWSYNC_ERROR_MEMORY;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(fp);
        return OWSYNC_ERROR;
    }

    uint8_t buffer[8192];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(fp);
            return OWSYNC_ERROR;
        }
    }

    fclose(fp);

    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return OWSYNC_ERROR;
    }

    EVP_MD_CTX_free(ctx);

    *out_hash = hex_encode(hash, hash_len);
    return *out_hash ? OWSYNC_OK : OWSYNC_ERROR_MEMORY;
}
