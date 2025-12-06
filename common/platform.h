/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file platform.h
 * @brief Platform-specific abstractions (executable path, etc.).
 */
#ifndef PIADINA_COMMON_PLATFORM_H
#define PIADINA_COMMON_PLATFORM_H

#include <stddef.h>
#include <limits.h>

/*
 * Safe path buffer size: prefer PATH_MAX when available, otherwise fall back
 * to 4096. Shared so callers avoid duplicating magic numbers.
 */
#ifndef PLATFORM_PATH_MAX
#ifdef PATH_MAX
#define PLATFORM_PATH_MAX PATH_MAX
#else
#define PLATFORM_PATH_MAX 4096
#endif
#endif

typedef enum {
    PLATFORM_OK = 0,
    PLATFORM_ERR_BUFFER_TOO_SMALL,
    PLATFORM_ERR_IO,
    PLATFORM_ERR_NOT_IMPLEMENTED,
    PLATFORM_ERR_INVALID_ARGUMENT
} platform_result_t;

/**
 * @brief Resolve the absolute filesystem path of the running executable.
 *
 * @param[in]  buf       Buffer to write the path into.
 * @param[in]  buf_size  Size of the buffer in bytes.
 * @return               PLATFORM_OK on success, or an error code.
 *
 * @note Memory Management:
 *       The caller owns @p buf and must provide sufficient storage.
 *       The function writes the NUL-terminated path into that buffer and never
 *       allocates memory internally.
 */
platform_result_t platform_get_self_exe_path(char *buf, size_t buf_size);

#endif /* PIADINA_COMMON_PLATFORM_H */
