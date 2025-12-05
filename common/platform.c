/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file platform.c
 * @brief Platform-specific abstractions implementation.
 */
#include "platform.h"

#include <errno.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#endif

platform_result_t platform_get_self_exe_path(char *buf, size_t buf_size)
{
    if (!buf || buf_size == 0) {
        return PLATFORM_ERR_INVALID_ARGUMENT;
    }

#ifdef __linux__
    if (buf_size < 2) {
        return PLATFORM_ERR_BUFFER_TOO_SMALL;
    }

    ssize_t len = readlink("/proc/self/exe", buf, buf_size - 1);
    if (len < 0) {
        if (errno == ENAMETOOLONG) {
            return PLATFORM_ERR_BUFFER_TOO_SMALL;
        }
        return PLATFORM_ERR_IO;
    }

    if ((size_t)len >= buf_size) {
        return PLATFORM_ERR_BUFFER_TOO_SMALL;
    }

    buf[len] = '\0';
    return PLATFORM_OK;
#else
    (void)buf;
    (void)buf_size;
    return PLATFORM_ERR_NOT_IMPLEMENTED;
#endif
}
