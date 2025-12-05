/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file log.h
 * @brief Simple logging abstraction with log levels.
 */
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
 * @brief Set the minimum log level accepted by the logger.
 *
 * Messages below this level will be suppressed.
 *
 * @param[in] level  The minimum log level to enable.
 *
 * @note Memory Management:
 *       The threshold is stored in a static variable with process lifetime.
 *       No dynamic allocation is performed.
 */
void log_set_level(log_level_t level);

/**
 * @brief Retrieve the current minimum log level.
 *
 * @return The current minimum log level.
 *
 * @note Memory Management:
 *       Returned value is a scalar owned by the logger; no allocation is involved.
 */
log_level_t log_get_level(void);

/**
 * @brief Override the FILE stream used for log output.
 *
 * @param[in] stream  The FILE stream to write logs to (e.g., stdout, stderr).
 *                    Pass NULL to restore the default (stderr).
 *
 * @note Memory Management:
 *       Ownership of @p stream stays with the caller; the logger never closes it.
 *       No allocation occurs.
 */
void log_set_stream(FILE *stream);

/**
 * @brief Emit a formatted log line at the given level.
 *
 * If @p level is below the current minimum log level, this function returns immediately.
 * Otherwise, it formats the message and writes it to the configured stream.
 *
 * @param[in] level  The severity level of the message.
 * @param[in] fmt    Printf-style format string.
 * @param[in] ...    Format arguments.
 *
 * @note Memory Management:
 *       Does not allocate memory; the message is written directly to the configured
 *       FILE stream. The caller retains ownership of all format arguments.
 */
void log_log(log_level_t level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define log_debug(...) log_log(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define log_info(...) log_log(LOG_LEVEL_INFO, __VA_ARGS__)
#define log_warn(...) log_log(LOG_LEVEL_WARN, __VA_ARGS__)
#define log_error(...) log_log(LOG_LEVEL_ERROR, __VA_ARGS__)

/**
 * @brief Convert a log level enum to its string representation.
 *
 * @param[in] level  The log level to convert.
 * @return           String representation ("debug", "info", etc.) or "unknown".
 *
 * @note Memory Management:
 *       Returns a pointer to static string constants. Caller must not free it.
 */
const char *log_level_to_string(log_level_t level);

/**
 * @brief Parse a log level from a string value.
 *
 * Accepts: "debug", "info", "warn", "error" (case-sensitive).
 *
 * @param[in] value  The string to parse.
 * @return           The corresponding log_level_t, or LOG_LEVEL_INVALID if not recognized.
 *
 * @note Memory Management:
 *       Caller retains ownership of @p value. No allocation occurs.
 */
log_level_t log_level_from_string(const char *value);

/**
 * @brief Return the default log level.
 *
 * @return LOG_LEVEL_INFO.
 *
 * @note Memory Management:
 *       No allocation.
 */
log_level_t log_level_default(void);

#endif /* PIADINA_COMMON_LOG_H */
