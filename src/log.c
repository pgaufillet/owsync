/* SPDX-License-Identifier: MIT
 * Copyright (c) 2025-2026 Pierre Gaufillet <pierre.gaufillet@bergamote.eu>
 */
#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

/* Global logging state */
static int g_log_level = LOG_LEVEL_INFO;
static log_mode_t g_log_mode = LOG_MODE_CLI;
static bool g_initialized = false;

void log_init(const char *ident, log_mode_t mode, int level) {
    g_log_mode = mode;
    g_log_level = level;

    if (mode != LOG_MODE_CLI) {
        int flags = LOG_PID;
        if (mode == LOG_MODE_FOREGROUND) {
            flags |= LOG_PERROR;  /* Also output to stderr */
        }
        openlog(ident, flags, LOG_DAEMON);
    }

    g_initialized = true;
}

void log_cleanup(void) {
    if (g_log_mode != LOG_MODE_CLI) {
        closelog();
    }
    g_initialized = false;
}

void log_set_level(int level) {
    if (level >= LOG_LEVEL_ERROR && level <= LOG_LEVEL_DEBUG) {
        g_log_level = level;
    }
}

int log_get_level(void) {
    return g_log_level;
}

bool log_is_initialized(void) {
    return g_initialized;
}

/*
 * Map our log levels to syslog priorities
 */
static int level_to_syslog(int level) {
    switch (level) {
    case LOG_LEVEL_ERROR:
        return LOG_ERR;
    case LOG_LEVEL_WARNING:
        return LOG_WARNING;
    case LOG_LEVEL_INFO:
        return LOG_INFO;
    case LOG_LEVEL_DEBUG:
        return LOG_DEBUG;
    default:
        return LOG_INFO;
    }
}

void log_write(int level, const char *fmt, ...) {
    /* Always log errors, otherwise check level */
    if (level != LOG_LEVEL_ERROR && level > g_log_level) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    if (g_log_mode == LOG_MODE_CLI || !g_initialized) {
        /* CLI mode or not initialized: stderr only */
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
    } else {
        /* Daemon/Foreground: syslog (LOG_PERROR handles stderr in foreground) */
        vsyslog(level_to_syslog(level), fmt, args);
    }

    va_end(args);
}
