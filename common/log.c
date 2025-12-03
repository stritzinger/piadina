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

void log_log(log_level_t level, const char *fmt, ...)
{
    if (level < current_level) {
        return;
    }

    FILE *stream = get_stream();
    if (!stream) {
        stream = stderr;
    }

    fprintf(stream, "[%s] ", log_level_to_string(level));

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
