#include "log.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static log_level_t current_level = LOG_LEVEL_INFO;
static FILE *current_stream = NULL;

static FILE *get_stream(void);

void log_set_level(log_level_t level)
{
    if (level < LOG_LEVEL_DEBUG) {
        level = LOG_LEVEL_DEBUG;
    } else if (level > LOG_LEVEL_ERROR) {
        level = LOG_LEVEL_ERROR;
    }
    current_level = level;
}

log_level_t log_get_level(void)
{
    return current_level;
}

void log_set_stream(FILE *stream)
{
    current_stream = stream ? stream : stderr;
}

const char *log_level_to_string(log_level_t level)
{
    switch (level) {
    case LOG_LEVEL_DEBUG:
        return "DEBUG";
    case LOG_LEVEL_INFO:
        return "INFO";
    case LOG_LEVEL_WARN:
        return "WARN";
    case LOG_LEVEL_ERROR:
        return "ERROR";
    default:
        return "UNKNOWN";
    }
}

log_level_t log_level_from_string(const char *value)
{
    if (!value) {
        return LOG_LEVEL_INVALID;
    }
    if (strcmp(value, "debug") == 0) {
        return LOG_LEVEL_DEBUG;
    }
    if (strcmp(value, "info") == 0) {
        return LOG_LEVEL_INFO;
    }
    if (strcmp(value, "warn") == 0) {
        return LOG_LEVEL_WARN;
    }
    if (strcmp(value, "error") == 0) {
        return LOG_LEVEL_ERROR;
    }
    return LOG_LEVEL_INVALID;
}

log_level_t log_level_default(void)
{
    return LOG_LEVEL_INFO;
}

void log_log(log_level_t level, const char *fmt, ...)
{
    if (level < current_level) {
        return;
    }

    FILE *stream = get_stream();
    if (!stream) {
        stream = stderr;
    }

    /* Pad after bracket so messages align (DEBUG/ERROR=5 chars, INFO/WARN=4) */
    const char *lvl = log_level_to_string(level);
    fprintf(stream, "[%s]%*s", lvl, 6 - (int)strlen(lvl), "");

    va_list args;
    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);

    fputc('\n', stream);
    fflush(stream);
}

/* Internal Functions */

static FILE *get_stream(void)
{
    return current_stream ? current_stream : stderr;
}
