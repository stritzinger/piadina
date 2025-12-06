/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file extractor_tar_gzip.h
 * @brief libarchive-backed tar+gzip extractor for Piadina.
 */
#ifndef PIADINA_EXTRACTOR_TAR_GZIP_H
#define PIADINA_EXTRACTOR_TAR_GZIP_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    TAR_RESULT_OK = 0,
    TAR_RESULT_INVALID_ARGUMENT,
    TAR_RESULT_IO,
    TAR_RESULT_NO_MEMORY,
    TAR_RESULT_PATH_TRAVERSAL,
    TAR_RESULT_CORRUPT_HEADER,
    TAR_RESULT_BACKEND
} tar_result_t;

typedef struct {
    /**
     * When true (default), existing files under the target root may be
     * overwritten by archive entries. When false, encountering an existing
     * path results in TAR_RESULT_UNSUPPORTED_ENTRY.
     */
    bool overwrite_existing;
} extractor_tar_gzip_options_t;

/**
 * @brief Extract a tar+gzip archive from an open file descriptor.
 *
 * @param[in] fd           File descriptor for the launcher binary.
 * @param[in] offset       Byte offset where the compressed archive begins.
 * @param[in] size         Size in bytes of the compressed archive.
 * @param[in] target_root  Directory where entries will be placed.
 * @param[in] options      Optional extraction options (NULL => defaults).
 * @return                 TAR_RESULT_OK on success, otherwise a tar_result_t error.
 *
 * @note Memory Management:
 *       The caller owns @p fd and @p target_root. This function does not
 *       close the file descriptor.
 */
tar_result_t extractor_tar_gzip_extract(int fd,
                                        uint64_t offset,
                                        uint64_t size,
                                        const char *target_root,
                                        const extractor_tar_gzip_options_t *options);

#endif /* PIADINA_EXTRACTOR_TAR_GZIP_H */
