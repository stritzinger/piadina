/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file packer_tar_gzip.h
 * @brief libarchive-backed tar+gzip packer for Azdora.
 */
#ifndef AZDORA_PACKER_TAR_GZIP_H
#define AZDORA_PACKER_TAR_GZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PACKER_TGZ_OK = 0,
    PACKER_TGZ_ERR_INVALID_ARGUMENT,
    PACKER_TGZ_ERR_PATH,
    PACKER_TGZ_ERR_SYMLINK,
    PACKER_TGZ_ERR_STAT,
    PACKER_TGZ_ERR_IO,
    PACKER_TGZ_ERR_UNSUPPORTED_ENTRY,
    PACKER_TGZ_ERR_ARCHIVE
} packer_tar_gzip_result_t;

/**
 * @brief Stream a payload directory as tar+gzip into an open file descriptor.
 *
 * @param[in]  payload_root    Absolute or relative path to the payload directory.
 * @param[in]  out_fd          File descriptor positioned at the start of the archive block.
 * @param[out] out_bytes       Optional: number of bytes written to @p out_fd.
 * @param[in]  verbose         If true, list packed entries to stderr.
 * @param[in]  quiet           If true, suppress non-error output (disables progress).
 * @return                     PACKER_TGZ_OK on success, otherwise an error code.
 *
 * @note Memory Management:
 *       The caller owns @p payload_root and @p out_fd (the FD remains open).
 *       No internal buffers escape this function.
 */
packer_tar_gzip_result_t packer_tar_gzip_write(const char *payload_root,
                                               int out_fd,
                                               uint64_t *out_bytes,
                                               bool verbose,
                                               bool quiet);

/**
 * @brief Convert a packer result code to human-readable text.
 *
 * @param[in] result  Result code to describe.
 * @return            Static string; caller must not free.
 */
const char *packer_tar_gzip_result_to_string(packer_tar_gzip_result_t result);

#endif /* AZDORA_PACKER_TAR_GZIP_H */
