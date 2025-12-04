#ifndef PIADINA_COMMON_LOG_H
#define PIADINA_COMMON_LOG_H

#include <stdio.h>

typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INVALID  /* Sentinel for parsing errors */
} log_level_t;

/**
 * Set the minimum log level accepted by the logger.
 * The function performs no dynamic allocation; the threshold is stored in a
 * static variable with process lifetime.
 */
void log_set_level(log_level_t level);

/**
 * Retrieve the current minimum log level.
 * Returned value is owned by the logger and remains valid for the entire
 * process lifetime; no allocation is involved.
 */
log_level_t log_get_level(void);

/**
 * Override the FILE stream used for log output.
 * Ownership of @stream stays with the caller; the logger never closes it.
 * Passing NULL restores the default stderr stream. No allocation occurs.
 */
void log_set_stream(FILE *stream);

/**
 * Emit a formatted log line at the given level.
 * Does not allocate memory; the message is written directly to the configured
 * FILE stream. The caller retains ownership of all format arguments.
 */
void log_log(log_level_t level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define log_debug(...) log_log(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define log_info(...) log_log(LOG_LEVEL_INFO, __VA_ARGS__)
#define log_warn(...) log_log(LOG_LEVEL_WARN, __VA_ARGS__)
#define log_error(...) log_log(LOG_LEVEL_ERROR, __VA_ARGS__)

const char *log_level_to_string(log_level_t level);

/**
 * Parse a log level from a string value.
 * Returns LOG_LEVEL_INVALID if the value is not recognized.
 * Accepts: "debug", "info", "warn", "error" (case-sensitive).
 */
log_level_t log_level_from_string(const char *value);

/**
 * Return the default log level (LOG_LEVEL_INFO).
 */
log_level_t log_level_default(void);

#endif /* PIADINA_COMMON_LOG_H */
