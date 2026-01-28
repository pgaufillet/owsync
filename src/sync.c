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
#include "sync.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Create empty path list */
path_list_t *path_list_new(void) {
    path_list_t *list = calloc(1, sizeof(path_list_t));
    return list;
}

/* Add path to list (duplicates the string) */
int path_list_add(path_list_t *list, const char *path) {
    if (!list || !path) return OWSYNC_ERROR;

    char **new_paths = realloc(list->paths, sizeof(char *) * (list->count + 1));
    if (!new_paths) return OWSYNC_ERROR_MEMORY;

    list->paths = new_paths;
    list->paths[list->count] = strdup(path);
    if (!list->paths[list->count]) return OWSYNC_ERROR_MEMORY;

    list->count++;
    return OWSYNC_OK;
}

void path_list_free(path_list_t *list) {
    if (!list) return;

    for (size_t i = 0; i < list->count; i++) {
        free(list->paths[i]);
    }
    free(list->paths);
}

sync_plan_t *sync_plan_new(void) {
    sync_plan_t *plan = malloc(sizeof(sync_plan_t));
    if (!plan) return NULL;

    memset(plan, 0, sizeof(sync_plan_t));
    return plan;
}

void sync_plan_free(sync_plan_t *plan) {
    if (!plan) return;

    for (size_t i = 0; i < plan->files_to_request.count; i++) {
        free(plan->files_to_request.paths[i]);
    }
    free(plan->files_to_request.paths);

    for (size_t i = 0; i < plan->files_to_delete.count; i++) {
        free(plan->files_to_delete.paths[i]);
    }
    free(plan->files_to_delete.paths);

    free(plan);
}

/* Linear search for file state by path (O(n), acceptable for typical file counts) */
static file_state_t *find_file_state(file_state_list_t *list, const char *path) {
    if (!list || !path) return NULL;

    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->files[i].path, path) == 0) {
            return &list->files[i];
        }
    }

    return NULL;
}

/*
 * Calculate sync plan using Last-Write-Wins (LWW) conflict resolution.
 *
 * Decision matrix for each remote file:
 *
 * Remote State | Local State | Action
 * -------------|-------------|-------
 * deleted      | not found   | (ignore - already gone)
 * deleted      | deleted     | (ignore - both agree)
 * deleted      | live        | delete if remote.mtime > local.mtime
 * live         | not found   | request file
 * live         | deleted     | request if remote.mtime > local.mtime
 * live         | live        | request if hashes differ AND (remote.mtime > local.mtime
 *              |             |   OR (mtime equal AND hash tie-breaker favors remote))
 *
 * Hash tie-breaker: lexicographic comparison ensures deterministic winner
 * when clocks are synchronized but writes occurred simultaneously.
 */
int calculate_diff(file_state_list_t *local, file_state_list_t *remote,
                   file_filter_t *filter, sync_plan_t **out_plan) {
    if (!local || !remote || !out_plan) return OWSYNC_ERROR;

    sync_plan_t *plan = sync_plan_new();
    if (!plan) return OWSYNC_ERROR_MEMORY;

    log_debug("Starting diff: local=%zu files, remote=%zu files",
              local->count, remote->count);

    for (size_t i = 0; i < remote->count; i++) {
        file_state_t *remote_file = &remote->files[i];

        log_debug("Checking remote file: %s (deleted=%d)",
                  remote_file->path, remote_file->deleted);

        if (filter && !file_filter_matches(filter, remote_file->path)) {
            log_debug("File filtered out: %s", remote_file->path);
            continue;
        }

        file_state_t *local_file = find_file_state(local, remote_file->path);

        if (local_file) {
            /* File exists locally - check for conflicts */
            log_debug("Found in local: %s", remote_file->path);
            if (remote_file->deleted) {
                /* Remote deleted, local exists */
                if (!local_file->deleted) {
                    /* LWW: delete wins if remote mtime is newer */
                    if (remote_file->mtime > local_file->mtime) {
                        path_list_add(&plan->files_to_delete, remote_file->path);
                    }
                }
            } else {
                /* Remote is live */
                if (local_file->deleted) {
                    /* Local deleted, remote live - resurrect if remote newer */
                    if (remote_file->mtime > local_file->mtime) {
                        path_list_add(&plan->files_to_request, remote_file->path);
                    }
                } else {
                    /* Both live - check content difference */
                    if (local_file->hash && remote_file->hash &&
                            strcmp(local_file->hash, remote_file->hash) != 0) {
                        /* Hashes differ - apply LWW */
                        if (remote_file->mtime > local_file->mtime) {
                            path_list_add(&plan->files_to_request, remote_file->path);
                        } else if (remote_file->mtime == local_file->mtime) {
                            /* Tie-breaker: lexicographic hash comparison for determinism */
                            if (strcmp(remote_file->hash, local_file->hash) > 0) {
                                path_list_add(&plan->files_to_request, remote_file->path);
                            }
                        }
                    }
                }
            }
        } else {
            /* File not in local DB */
            log_debug("Not found in local: %s (deleted=%d)",
                      remote_file->path, remote_file->deleted);
            if (!remote_file->deleted) {
                /* New file from remote - request it */
                log_debug("Adding to request queue: %s", remote_file->path);
                path_list_add(&plan->files_to_request, remote_file->path);
            }
            /* If remote is deleted and not in local, nothing to do */
        }
    }

    log_debug("Diff complete: %zu to request, %zu to delete",
              plan->files_to_request.count, plan->files_to_delete.count);

    *out_plan = plan;
    return OWSYNC_OK;
}
