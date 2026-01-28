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

/*
 * owsync - Configuration file parser
 *
 * Simple key=value format compatible with lease-sync configuration.
 * Supports repeatable keys for peers, includes, and excludes.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

/* Trim leading and trailing whitespace in place */
static char *trim_whitespace(char *str) {
    if (!str)
        return NULL;

    /* Trim leading */
    while (isspace((unsigned char)*str))
        str++;

    if (*str == '\0')
        return str;

    /* Trim trailing */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';

    return str;
}

/* Parse integer value with validation */
static int parse_int(const char *str, int default_val) {
    if (!str || *str == '\0')
        return default_val;

    char *endptr;
    long val = strtol(str, &endptr, 10);

    if (*endptr != '\0' || val < 0 || val > INT32_MAX)
        return default_val;

    return (int)val;
}

void config_init(owsync_config_t *config) {
    if (!config)
        return;

    memset(config, 0, sizeof(owsync_config_t));

    /* Set generic Linux defaults (OpenWrt paths set via config file) */
    strncpy(config->bind_host, "::", sizeof(config->bind_host) - 1);  /* Dual-stack default */
    strncpy(config->port, "4321", sizeof(config->port) - 1);
    strncpy(config->sync_dir, ".", sizeof(config->sync_dir) - 1);
    strncpy(config->database, "/var/lib/owsync/owsync.db", sizeof(config->database) - 1);
    config->poll_interval = 60;
    config->log_level = 2;  /* Default: INFO */
    config->plain_mode = false;
    config->loaded = false;
}

int config_add_peer(owsync_config_t *config, const char *peer) {
    if (!config || !peer)
        return OWSYNC_ERROR;

    if (config->peer_count >= CONFIG_MAX_PEERS) {
        fprintf(stderr, "Error: Maximum number of peers (%d) exceeded\n", CONFIG_MAX_PEERS);
        return OWSYNC_ERROR;
    }

    config->peers[config->peer_count] = strdup(peer);
    if (!config->peers[config->peer_count])
        return OWSYNC_ERROR_MEMORY;

    config->peer_count++;
    return OWSYNC_OK;
}

int config_add_include(owsync_config_t *config, const char *pattern) {
    if (!config || !pattern)
        return OWSYNC_ERROR;

    if (config->include_count >= CONFIG_MAX_PATTERNS) {
        fprintf(stderr, "Error: Maximum number of include patterns (%d) exceeded\n", CONFIG_MAX_PATTERNS);
        return OWSYNC_ERROR;
    }

    config->includes[config->include_count] = strdup(pattern);
    if (!config->includes[config->include_count])
        return OWSYNC_ERROR_MEMORY;

    config->include_count++;
    return OWSYNC_OK;
}

int config_add_exclude(owsync_config_t *config, const char *pattern) {
    if (!config || !pattern)
        return OWSYNC_ERROR;

    if (config->exclude_count >= CONFIG_MAX_PATTERNS) {
        fprintf(stderr, "Error: Maximum number of exclude patterns (%d) exceeded\n", CONFIG_MAX_PATTERNS);
        return OWSYNC_ERROR;
    }

    config->excludes[config->exclude_count] = strdup(pattern);
    if (!config->excludes[config->exclude_count])
        return OWSYNC_ERROR_MEMORY;

    config->exclude_count++;
    return OWSYNC_OK;
}

void config_free(owsync_config_t *config) {
    if (!config)
        return;

    for (size_t i = 0; i < config->peer_count; i++) {
        free(config->peers[i]);
    }

    for (size_t i = 0; i < config->include_count; i++) {
        free(config->includes[i]);
    }

    for (size_t i = 0; i < config->exclude_count; i++) {
        free(config->excludes[i]);
    }

    /* Clear sensitive data */
    memset(config->encryption_key, 0, sizeof(config->encryption_key));
    memset(config, 0, sizeof(owsync_config_t));
}

int config_load(owsync_config_t *config, const char *path) {
    if (!config || !path)
        return OWSYNC_ERROR;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open config file '%s': %s\n", path, strerror(errno));
        return OWSYNC_ERROR_IO;
    }

    char line[CONFIG_MAX_LINE_LEN];
    int line_num = 0;

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline */
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';

        /* Trim whitespace */
        char *trimmed = trim_whitespace(line);

        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#')
            continue;

        /* Find = separator */
        char *eq = strchr(trimmed, '=');
        if (!eq) {
            fprintf(stderr, "Warning: Invalid line %d in config (missing '='): %s\n", line_num, trimmed);
            continue;
        }

        /* Split key and value */
        *eq = '\0';
        char *key = trim_whitespace(trimmed);
        char *value = trim_whitespace(eq + 1);

        /* Parse known keys */
        if (strcmp(key, "bind_host") == 0) {
            strncpy(config->bind_host, value, sizeof(config->bind_host) - 1);
        } else if (strcmp(key, "port") == 0) {
            strncpy(config->port, value, sizeof(config->port) - 1);
        } else if (strcmp(key, "sync_dir") == 0) {
            strncpy(config->sync_dir, value, sizeof(config->sync_dir) - 1);
        } else if (strcmp(key, "database") == 0) {
            strncpy(config->database, value, sizeof(config->database) - 1);
        } else if (strcmp(key, "encryption_key") == 0) {
            strncpy(config->encryption_key, value, sizeof(config->encryption_key) - 1);
        } else if (strcmp(key, "plain_mode") == 0) {
            config->plain_mode = (strcmp(value, "1") == 0 || strcmp(value, "true") == 0);
        } else if (strcmp(key, "poll_interval") == 0) {
            config->poll_interval = (uint32_t)parse_int(value, 60);
            if (config->poll_interval < 1)
                config->poll_interval = 60;
        } else if (strcmp(key, "log_level") == 0) {
            config->log_level = parse_int(value, 2);
            if (config->log_level < 0)
                config->log_level = 0;
            if (config->log_level > 3)
                config->log_level = 3;
        } else if (strcmp(key, "peer") == 0) {
            if (config_add_peer(config, value) != OWSYNC_OK) {
                fclose(fp);
                return OWSYNC_ERROR;
            }
        } else if (strcmp(key, "include") == 0) {
            if (config_add_include(config, value) != OWSYNC_OK) {
                fclose(fp);
                return OWSYNC_ERROR;
            }
        } else if (strcmp(key, "exclude") == 0) {
            if (config_add_exclude(config, value) != OWSYNC_OK) {
                fclose(fp);
                return OWSYNC_ERROR;
            }
        } else {
            fprintf(stderr, "Warning: Unknown config key '%s' on line %d\n", key, line_num);
        }
    }

    fclose(fp);
    config->loaded = true;
    return OWSYNC_OK;
}
