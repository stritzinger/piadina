/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file archive.h
 * @brief Archive extraction dispatcher for Piadina.
 */
#ifndef PIADINA_ARCHIVE_H
#define PIADINA_ARCHIVE_H

#include <stdint.h>

typedef enum {
    PIADINA_ARCHIVE_OK = 0,
    PIADINA_ARCHIVE_ERR_INVALID_ARGUMENT,
    PIADINA_ARCHIVE_ERR_UNSUPPORTED_FORMAT,
    PIADINA_ARCHIVE_ERR_EXTRACT
} piadina_archive_result_t;

/**
 * @brief Return true if the given archive format is supported.
 *
 * @param[in] format  Archive format string (e.g., "tar+gzip").
 * @return            1 if supported, 0 otherwise.
 */
int piadina_archive_format_supported(const char *format);

/**
 * @brief Extract an archive from the launcher binary into @p target_root.
 *
 * @param[in] format       Archive format string (currently only "tar+gzip").
 * @param[in] fd           File descriptor for the launcher binary.
 * @param[in] offset       Byte offset where the archive starts.
 * @param[in] size         Length in bytes of the archive.
 * @param[in] target_root  Directory into which to extract the payload.
 * @return                 PIADINA_ARCHIVE_OK on success, otherwise an error.
 *
 * @note Memory Management:
 *       The file descriptor remains owned by the caller and is not closed.
 */
piadina_archive_result_t piadina_archive_extract(const char *format,
                                                 int fd,
                                                 uint64_t offset,
                                                 uint64_t size,
                                                 const char *target_root);

/**
 * @brief Convert an archive result code to a human-readable string.
 *
 * @param[in] result  Result code to describe.
 * @return            Static string; caller must not free.
 */
const char *piadina_archive_result_to_string(piadina_archive_result_t result);

#endif /* PIADINA_ARCHIVE_H */
