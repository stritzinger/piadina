/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file archive.c
 * @brief Archive extraction dispatcher for Piadina.
 */
#include "archive.h"

#include <string.h>

#include "extractor_tar_gzip.h"

#define ARCHIVE_FORMAT_TAR_GZIP "tar+gzip"

int piadina_archive_format_supported(const char *format)
{
    if (!format || strcmp(format, ARCHIVE_FORMAT_TAR_GZIP) == 0) {
        return 1;
    }
    return 0;
}

piadina_archive_result_t piadina_archive_extract(const char *format,
                                                 int fd,
                                                 uint64_t offset,
                                                 uint64_t size,
                                                 const char *target_root)
{
    const char *fmt = format ? format : ARCHIVE_FORMAT_TAR_GZIP;
    if (!piadina_archive_format_supported(fmt) || !target_root) {
        return PIADINA_ARCHIVE_ERR_INVALID_ARGUMENT;
    }

    if (strcmp(fmt, ARCHIVE_FORMAT_TAR_GZIP) != 0) {
        return PIADINA_ARCHIVE_ERR_UNSUPPORTED_FORMAT;
    }

    extractor_tar_gzip_options_t opts = {
        .overwrite_existing = true,
    };

    tar_result_t rc = extractor_tar_gzip_extract(fd, offset, size, target_root, &opts);
    if (rc != TAR_RESULT_OK) {
        return PIADINA_ARCHIVE_ERR_EXTRACT;
    }

    return PIADINA_ARCHIVE_OK;
}

const char *piadina_archive_result_to_string(piadina_archive_result_t result)
{
    switch (result) {
    case PIADINA_ARCHIVE_OK:
        return "ok";
    case PIADINA_ARCHIVE_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case PIADINA_ARCHIVE_ERR_UNSUPPORTED_FORMAT:
        return "unsupported archive format";
    case PIADINA_ARCHIVE_ERR_EXTRACT:
        return "archive extraction failed";
    default:
        return "unknown error";
    }
}
