#ifndef PIADINA_COMMON_PLATFORM_H
#define PIADINA_COMMON_PLATFORM_H

#include <stddef.h>

typedef enum {
    PLATFORM_OK = 0,
    PLATFORM_ERR_BUFFER_TOO_SMALL,
    PLATFORM_ERR_IO,
    PLATFORM_ERR_NOT_IMPLEMENTED,
    PLATFORM_ERR_INVALID_ARGUMENT
} platform_result_t;

/**
 * Resolve the absolute filesystem path of the running executable.
 *
 * The caller must pass a writable buffer and its size; the function writes the
 * NUL-terminated path into that buffer and never allocates memory internally.
 * Ownership of @buf remains with the caller, and the contents stay valid until
 * the caller overwrites them.
 */
platform_result_t platform_get_self_exe_path(char *buf, size_t buf_size);

#endif /* PIADINA_COMMON_PLATFORM_H */
