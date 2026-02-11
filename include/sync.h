/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 */
#ifndef OWSYNC_SYNC_H
#define OWSYNC_SYNC_H

#include "state.h"

/* Dynamic list of file paths */
typedef struct {
    char **paths;  /* Array of path strings (owned) */
    size_t count;  /* Number of paths */
} path_list_t;

/*
 * Synchronization plan computed by calculate_diff().
 * Lists actions needed to reconcile local state with remote.
 */
typedef struct {
    path_list_t files_to_request;  /* Files to fetch from remote (newer there) */
    path_list_t files_to_delete;   /* Files to delete locally (deleted on remote) */
} sync_plan_t;

/* Path list operations */
path_list_t *path_list_new(void);
int path_list_add(path_list_t *list, const char *path);  /* Duplicates path */
void path_list_free(path_list_t *list);

/* Sync plan operations */
sync_plan_t *sync_plan_new(void);
void sync_plan_free(sync_plan_t *plan);

/*
 * Calculate sync actions using Last-Write-Wins (LWW) conflict resolution.
 * Compares local and remote file states to determine what to request/delete.
 * Uses mtime as primary comparator, hash as tie-breaker for determinism.
 */
int calculate_diff(file_state_list_t *local, file_state_list_t *remote,
                   file_filter_t *filter, sync_plan_t **out_plan);

#endif
