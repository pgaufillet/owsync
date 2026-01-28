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
#include "config.h"
#include "crypto.h"
#include "log.h"
#include "state.h"
#include "net.h"
#include "daemon.h"
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

static int validate_directory(const char *path) {
    if (!path) {
        fprintf(stderr, "Error: Directory path cannot be NULL\n");
        return OWSYNC_ERROR;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "Error: Directory '%s' does not exist: %s\n", path, strerror(errno));
        return OWSYNC_ERROR;
    }

    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "Error: '%s' is not a directory\n", path);
        return OWSYNC_ERROR;
    }

    if (access(path, R_OK | W_OK) != 0) {
        fprintf(stderr, "Error: Cannot read/write directory '%s': %s\n", path, strerror(errno));
        return OWSYNC_ERROR;
    }

    return OWSYNC_OK;
}

static void print_usage(const char *prog_name) {
    fprintf(stderr, "owsync %s - High-availability file synchronization tool\n\n", OWSYNC_VERSION);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s scan <DIR> [-i PATTERN...] [-e PATTERN...]\n", prog_name);
#ifdef ENABLE_ENCRYPTION
    fprintf(stderr, "  %s genkey\n", prog_name);
#endif
    fprintf(stderr, "  %s listen [OPTIONS]\n", prog_name);
    fprintf(stderr, "  %s connect <ADDR> [OPTIONS]\n", prog_name);
    fprintf(stderr, "  %s daemon [OPTIONS]\n\n", prog_name);

    fprintf(stderr, "Common Options:\n");
    fprintf(stderr, "  -c, --config FILE     Configuration file (key=value format)\n");
    fprintf(stderr, "  -p, --plain           Disable encryption (use only over secure VPN)\n");
    fprintf(stderr, "  -d, --dir DIR         Directory to sync (default: .)\n");
    fprintf(stderr, "  -b, --db PATH         Database path (default: /var/lib/owsync/owsync.db)\n");
    fprintf(stderr, "  -i, --include PATTERN Include pattern (can be repeated)\n");
    fprintf(stderr, "  -e, --exclude PATTERN Exclude pattern (can be repeated)\n");
    fprintf(stderr, "  -f, --foreground      Run in foreground (log to syslog + stderr)\n");
    fprintf(stderr, "  -v, --verbose         Enable debug logging (log_level=3)\n");
    fprintf(stderr, "  -q, --quiet           Quiet mode, errors only (log_level=0)\n");
    fprintf(stderr, "  --log-level N         Set log level (0=error, 1=warning, 2=info, 3=debug)\n");
    fprintf(stderr, "  -V, --version         Show version and exit\n");
    fprintf(stderr, "  -h, --help            Show this help message\n\n");

    fprintf(stderr, "Listen Options:\n");
    fprintf(stderr, "  -H, --host HOST       Bind host (default: :: for dual-stack)\n");
    fprintf(stderr, "  -P, --port PORT       Port for listen and peers (default: 4321)\n\n");

    fprintf(stderr, "Daemon Options:\n");
    fprintf(stderr, "  -H, --host HOST               Bind host (default: :: for dual-stack)\n");
    fprintf(stderr, "  -P, --port PORT               Port for listen and peers (default: 4321)\n");
    fprintf(stderr, "  --poll-interval SECONDS       Polling interval (default: 60)\n");
    fprintf(stderr, "  --auto-sync HOST              Peer host to auto-sync (repeatable)\n\n");

    fprintf(stderr, "Config File Format:\n");
    fprintf(stderr, "  bind_host=::                # :: for dual-stack, 0.0.0.0 for IPv4-only\n");
    fprintf(stderr, "  port=4321                   # Port for listen and peer connections\n");
    fprintf(stderr, "  sync_dir=/path/to/sync\n");
    fprintf(stderr, "  database=/path/to/owsync.db\n");
    fprintf(stderr, "  encryption_key=<64-char hex key>\n");
    fprintf(stderr, "  plain_mode=1\n");
    fprintf(stderr, "  poll_interval=30\n");
    fprintf(stderr, "  log_level=2\n");
    fprintf(stderr, "  peer=192.168.1.2            # Peer host (uses global port)\n");
    fprintf(stderr, "  peer=fd00::2                # IPv6 peer\n");
    fprintf(stderr, "  include=pattern\n");
    fprintf(stderr, "  exclude=pattern\n\n");

    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s genkey\n", prog_name);
    fprintf(stderr, "  %s daemon -c /etc/owsync/owsync.conf\n", prog_name);
    fprintf(stderr, "  %s listen --plain --dir /etc/config\n", prog_name);
    fprintf(stderr, "  %s scan /etc/config --exclude network\n", prog_name);
}

typedef struct {
    char *config_file;
    char *key;
    bool plain;
    char *dir;
    char *db;
    char **includes;
    size_t include_count;
    char **excludes;
    size_t exclude_count;
    char *host;         /* Bind host or peer host */
    char *port;         /* Port for listen and peer connections */
    int64_t clock_offset;
    uint32_t poll_interval;
    char **auto_sync_peers;  /* Peer hosts (port is global) */
    size_t auto_sync_count;
    int log_level;      /* 0=error, 1=warning, 2=info, 3=debug */
    bool foreground;    /* Run in foreground (syslog + stderr) */
} cli_options_t;

static int parse_options(int argc, char **argv, cli_options_t *opts, int start_idx) {
    memset(opts, 0, sizeof(cli_options_t));

    /* Initialize config with defaults */
    owsync_config_t config;
    config_init(&config);

    struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"plain", no_argument, 0, 'p'},
        {"dir", required_argument, 0, 'd'},
        {"db", required_argument, 0, 'b'},
        {"include", required_argument, 0, 'i'},
        {"exclude", required_argument, 0, 'e'},
        {"host", required_argument, 0, 'H'},
        {"port", required_argument, 0, 'P'},
        {"foreground", no_argument, 0, 'f'},
        {"verbose", no_argument, 0, 'v'},
        {"debug", no_argument, 0, 'v'},  /* alias for --verbose */
        {"quiet", no_argument, 0, 'q'},
        {"log-level", required_argument, 0, 2002},
#ifdef DEBUG
        {"debug-clock-offset", required_argument, 0, 1000},
#endif
        {"poll-interval", required_argument, 0, 2000},
        {"auto-sync", required_argument, 0, 2001},
        {"version", no_argument, 0, 'V'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    /* First pass: look for config file option */
    optind = start_idx;
    int c;
    while ((c = getopt_long(argc, argv, "c:pd:b:i:e:H:P:fvqVh", long_options, NULL)) != -1) {
        if (c == 'c') {
            opts->config_file = strdup(optarg);
            if (config_load(&config, optarg) != OWSYNC_OK) {
                config_free(&config);
                return OWSYNC_ERROR;
            }
            break;
        }
    }

    /* Set defaults from config (either loaded or built-in defaults) */
    opts->dir = strdup(config.sync_dir);
    opts->db = strdup(config.database);
    opts->host = strdup(config.bind_host);
    opts->port = strdup(config.port);
    opts->poll_interval = config.poll_interval;
    opts->log_level = config.log_level;
    opts->plain = config.plain_mode;
    opts->foreground = false;
    opts->clock_offset = 0;

    /* Copy encryption key from config if present */
    if (config.encryption_key[0] != '\0') {
        opts->key = strdup(config.encryption_key);
    }

    /* Copy peers from config */
    for (size_t i = 0; i < config.peer_count; i++) {
        char **new_peers = realloc(opts->auto_sync_peers,
                                   sizeof(char *) * (opts->auto_sync_count + 1));
        if (!new_peers) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            config_free(&config);
            return OWSYNC_ERROR_MEMORY;
        }
        opts->auto_sync_peers = new_peers;
        opts->auto_sync_peers[opts->auto_sync_count++] = strdup(config.peers[i]);
    }

    /* Copy includes from config */
    for (size_t i = 0; i < config.include_count; i++) {
        char **new_includes = realloc(opts->includes, sizeof(char *) * (opts->include_count + 1));
        if (!new_includes) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            config_free(&config);
            return OWSYNC_ERROR_MEMORY;
        }
        opts->includes = new_includes;
        opts->includes[opts->include_count++] = strdup(config.includes[i]);
    }

    /* Copy excludes from config */
    for (size_t i = 0; i < config.exclude_count; i++) {
        char **new_excludes = realloc(opts->excludes, sizeof(char *) * (opts->exclude_count + 1));
        if (!new_excludes) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            config_free(&config);
            return OWSYNC_ERROR_MEMORY;
        }
        opts->excludes = new_excludes;
        opts->excludes[opts->exclude_count++] = strdup(config.excludes[i]);
    }

    config_free(&config);

    /* Second pass: parse all CLI options (override config values) */
    optind = start_idx;
    while ((c = getopt_long(argc, argv, "c:pd:b:i:e:H:P:fvqVh", long_options, NULL)) != -1) {
        switch (c) {
        case 'c':
            /* Already handled in first pass */
            break;
        case 'p':
            opts->plain = true;
            break;
        case 'd':
            free(opts->dir);
            opts->dir = strdup(optarg);
            break;
        case 'b':
            free(opts->db);
            opts->db = strdup(optarg);
            break;
        case 'i': {
            char **new_includes = realloc(opts->includes, sizeof(char *) * (opts->include_count + 1));
            if (!new_includes) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                exit(1);
            }
            opts->includes = new_includes;
            opts->includes[opts->include_count++] = strdup(optarg);
            break;
        }
        case 'e': {
            char **new_excludes = realloc(opts->excludes, sizeof(char *) * (opts->exclude_count + 1));
            if (!new_excludes) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                exit(1);
            }
            opts->excludes = new_excludes;
            opts->excludes[opts->exclude_count++] = strdup(optarg);
            break;
        }
        case 'H':
            free(opts->host);
            opts->host = strdup(optarg);
            break;
        case 'P':
            free(opts->port);
            opts->port = strdup(optarg);
            break;
        case 'f':
            opts->foreground = true;
            break;
        case 'v':
            opts->log_level = LOG_LEVEL_DEBUG;
            break;
        case 'q':
            opts->log_level = LOG_LEVEL_ERROR;
            break;
        case 2002:
            opts->log_level = atoi(optarg);
            if (opts->log_level < 0) opts->log_level = 0;
            if (opts->log_level > 3) opts->log_level = 3;
            break;
#ifdef DEBUG
        case 1000:
            opts->clock_offset = atoll(optarg);
            break;
#endif
        case 2000:
            opts->poll_interval = (uint32_t)atoi(optarg);
            if (opts->poll_interval < 1) opts->poll_interval = 60;
            break;
        case 2001: {
            char **new_peers = realloc(opts->auto_sync_peers,
                                       sizeof(char *) * (opts->auto_sync_count + 1));
            if (!new_peers) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                exit(1);
            }
            opts->auto_sync_peers = new_peers;
            opts->auto_sync_peers[opts->auto_sync_count++] = strdup(optarg);
            break;
        }
        case 'V':
            printf("owsync %s\n", OWSYNC_VERSION);
            exit(0);
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            return OWSYNC_ERROR;
        }
    }

    /* Fall back to environment variable for key */
    if (!opts->key) {
        char *env_key = getenv("OWSYNC_KEY");
        if (env_key) {
            opts->key = strdup(env_key);
        }
    }

    return OWSYNC_OK;
}

static void free_options(cli_options_t *opts) {
    free(opts->config_file);
    free(opts->key);
    free(opts->dir);
    free(opts->db);
    free(opts->host);
    free(opts->port);

    for (size_t i = 0; i < opts->include_count; i++) {
        free(opts->includes[i]);
    }
    free(opts->includes);

    for (size_t i = 0; i < opts->exclude_count; i++) {
        free(opts->excludes[i]);
    }
    free(opts->excludes);

    for (size_t i = 0; i < opts->auto_sync_count; i++) {
        free(opts->auto_sync_peers[i]);
    }
    free(opts->auto_sync_peers);
}

static int cmd_scan(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s scan <DIR> [-i PATTERN...] [-e PATTERN...]\n", argv[0]);
        return 1;
    }

    char *scan_dir = argv[2];

    if (validate_directory(scan_dir) != OWSYNC_OK) {
        return 1;
    }

    cli_options_t opts;
    if (parse_options(argc, argv, &opts, 3) != OWSYNC_OK) {
        return 1;
    }

    file_filter_t *filter = file_filter_new(opts.includes, opts.include_count,
                                            opts.excludes, opts.exclude_count);

    /* Warn about conservative default if no includes specified */
    if (filter && filter->includes.count == 0) {
        fprintf(stderr, "Warning: No include patterns specified. Nothing will be matched.\n");
        fprintf(stderr, "Add include patterns (e.g., '-i *') to match files.\n");
    }

    file_state_list_t *files = NULL;
    int result = scan_directory(scan_dir, filter, &files);

    if (result == OWSYNC_OK && files) {
        struct json_object *array = json_object_new_array();
        for (size_t i = 0; i < files->count; i++) {
            struct json_object *obj = json_object_new_object();
            json_object_object_add(obj, "path", json_object_new_string(files->files[i].path));

            if (files->files[i].hash) {
                json_object_object_add(obj, "hash", json_object_new_string(files->files[i].hash));
            } else {
                json_object_object_add(obj, "hash", NULL);
            }

            json_object_object_add(obj, "mtime", json_object_new_double((double)files->files[i].mtime));
            json_object_object_add(obj, "size", json_object_new_double((double)files->files[i].size));
            json_object_object_add(obj, "deleted", json_object_new_boolean(files->files[i].deleted));

            json_object_array_add(array, obj);
        }

        const char *json = json_object_to_json_string_ext(array,
                           JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
        printf("%s\n", json);
        json_object_put(array);

        file_state_list_free(files);
    }

    file_filter_free(filter);
    free_options(&opts);

    return result == OWSYNC_OK ? 0 : 1;
}

#ifdef ENABLE_ENCRYPTION
static int cmd_genkey(void) {
    char *key = security_generate_key();
    if (!key) {
        fprintf(stderr, "Failed to generate key\n");
        return 1;
    }

    printf("%s\n", key);
    free(key);
    return 0;
}
#endif

static int cmd_listen(int argc, char **argv) {
    cli_options_t opts;
    if (parse_options(argc, argv, &opts, 2) != OWSYNC_OK) {
        free_options(&opts);
        return 1;
    }

    /* Initialize logging */
    log_mode_t log_mode = opts.foreground ? LOG_MODE_FOREGROUND : LOG_MODE_DAEMON;
    log_init("owsync", log_mode, opts.log_level);

    if (!opts.plain && !opts.key) {
        fprintf(stderr, "Error: Encryption key required. Provide via config file (encryption_key=...) or OWSYNC_KEY environment variable, or use --plain for unencrypted mode.\n");
        free_options(&opts);
        return 1;
    }

    if (opts.plain && opts.key) {
        fprintf(stderr, "Error: Cannot use both encryption key and --plain mode.\n");
        free_options(&opts);
        return 1;
    }

#ifndef ENABLE_ENCRYPTION
    if (opts.key) {
        fprintf(stderr, "Error: Encryption support is disabled in this build.\n");
        free_options(&opts);
        return 1;
    }
#endif

    if (validate_directory(opts.dir) != OWSYNC_OK) {
        free_options(&opts);
        return 1;
    }

    file_filter_t *filter = file_filter_new(opts.includes, opts.include_count,
                                            opts.excludes, opts.exclude_count);

    /* Warn about conservative default if no includes specified */
    if (filter && filter->includes.count == 0) {
        fprintf(stderr, "Warning: No include patterns specified. Nothing will be synced.\n");
        fprintf(stderr, "Add include patterns (e.g., '-i *') to sync files.\n");
    }

    int result = start_server(opts.host, opts.port, opts.key, opts.dir, opts.db, filter, opts.clock_offset);

    file_filter_free(filter);
    free_options(&opts);

    return result == OWSYNC_OK ? 0 : 1;
}

static int cmd_connect(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s connect <HOST> [OPTIONS]\n", argv[0]);
        return 1;
    }

    char *peer_host = argv[2];

    cli_options_t opts;
    if (parse_options(argc, argv, &opts, 3) != OWSYNC_OK) {
        free_options(&opts);
        return 1;
    }

    /* Initialize logging - CLI mode for one-shot commands */
    log_mode_t log_mode = opts.foreground ? LOG_MODE_FOREGROUND : LOG_MODE_CLI;
    log_init("owsync", log_mode, opts.log_level);

    if (!opts.plain && !opts.key) {
        fprintf(stderr, "Error: Encryption key required. Provide via config file (encryption_key=...) or OWSYNC_KEY environment variable, or use --plain for unencrypted mode.\n");
        free_options(&opts);
        return 1;
    }

    if (opts.plain && opts.key) {
        fprintf(stderr, "Error: Cannot use both encryption key and --plain mode.\n");
        free_options(&opts);
        return 1;
    }

#ifndef ENABLE_ENCRYPTION
    if (opts.key) {
        fprintf(stderr, "Error: Encryption support is disabled in this build.\n");
        free_options(&opts);
        return 1;
    }
#endif

    if (validate_directory(opts.dir) != OWSYNC_OK) {
        free_options(&opts);
        return 1;
    }

    file_filter_t *filter = file_filter_new(opts.includes, opts.include_count,
                                            opts.excludes, opts.exclude_count);

    /* Warn about conservative default if no includes specified */
    if (filter && filter->includes.count == 0) {
        fprintf(stderr, "Warning: No include patterns specified. Nothing will be synced.\n");
        fprintf(stderr, "Add include patterns (e.g., '-i *') to sync files.\n");
    }

    int result = connect_peer(peer_host, opts.port, opts.key, opts.dir, opts.db, filter, opts.clock_offset);

    file_filter_free(filter);
    free_options(&opts);

    return result == OWSYNC_OK ? 0 : 1;
}

static int cmd_daemon(int argc, char **argv) {
    cli_options_t opts;
    if (parse_options(argc, argv, &opts, 2) != OWSYNC_OK) {
        free_options(&opts);
        return 1;
    }

    /* Initialize logging */
    log_mode_t log_mode = opts.foreground ? LOG_MODE_FOREGROUND : LOG_MODE_DAEMON;
    log_init("owsync", log_mode, opts.log_level);

    if (!opts.plain && !opts.key) {
        fprintf(stderr, "Error: Encryption key required. Provide via config file (encryption_key=...) or OWSYNC_KEY environment variable, or use --plain for unencrypted mode.\n");
        free_options(&opts);
        return 1;
    }

    if (opts.plain && opts.key) {
        fprintf(stderr, "Error: Cannot use both encryption key and --plain mode.\n");
        free_options(&opts);
        return 1;
    }

#ifndef ENABLE_ENCRYPTION
    if (opts.key) {
        fprintf(stderr, "Error: Encryption support is disabled in this build.\n");
        free_options(&opts);
        return 1;
    }
#endif

    if (opts.auto_sync_count == 0) {
        fprintf(stderr, "Error: Daemon mode requires at least one --auto-sync peer\n");
        free_options(&opts);
        return 1;
    }

    if (validate_directory(opts.dir) != OWSYNC_OK) {
        free_options(&opts);
        return 1;
    }

    file_filter_t *filter = file_filter_new(opts.includes, opts.include_count,
                                            opts.excludes, opts.exclude_count);

    /* Warn about conservative default if no includes specified */
    if (filter && filter->includes.count == 0) {
        fprintf(stderr, "Warning: No include patterns specified. Nothing will be synced.\n");
        fprintf(stderr, "Add include patterns (e.g., 'include=*' in config) to sync files.\n");
    }

    uint32_t poll_interval = opts.poll_interval ? opts.poll_interval : 60;

    int result = start_daemon(opts.host, opts.port, opts.key, opts.dir, opts.db,
                              filter, poll_interval, opts.auto_sync_peers,
                              opts.auto_sync_count, opts.clock_offset);

    file_filter_free(filter);
    free_options(&opts);

    return result == OWSYNC_OK ? 0 : 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *command = argv[1];

    /* Handle --version and -V at top level */
    if (strcmp(command, "--version") == 0 || strcmp(command, "-V") == 0) {
        printf("owsync %s\n", OWSYNC_VERSION);
        return 0;
    }

    if (strcmp(command, "scan") == 0) {
        return cmd_scan(argc, argv);
    }
#ifdef ENABLE_ENCRYPTION
    else if (strcmp(command, "genkey") == 0) {
        return cmd_genkey();
    }
#endif
    else if (strcmp(command, "listen") == 0) {
        return cmd_listen(argc, argv);
    } else if (strcmp(command, "connect") == 0) {
        return cmd_connect(argc, argv);
    } else if (strcmp(command, "daemon") == 0) {
        return cmd_daemon(argc, argv);
    } else {
        fprintf(stderr, "Unknown command: %s\n\n", command);
        print_usage(argv[0]);
        return 1;
    }

    return 0;
}
