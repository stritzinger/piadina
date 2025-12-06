/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file extractor_tar_gzip.c
 * @brief libarchive-backed tar+gzip extractor for Piadina.
 */
#include "extractor_tar_gzip.h"

#include "../libarchive/libarchive/archive.h"
#include "../libarchive/libarchive/archive_entry.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/log.h"

#ifndef ARCHIVE_EXTRACT_NO_OVERWRITE
#define ARCHIVE_EXTRACT_NO_OVERWRITE 0x0008
#endif

#define EXTRACT_READ_BLOCK (64 * 1024)

/* Internal Prototypes */

typedef struct {
    int fd;
    uint64_t remaining;
    uint8_t buffer[EXTRACT_READ_BLOCK];
} extractor_reader_t;

static ssize_t archive_read_cb(struct archive *a, void *client_data, const void **buff);
static la_int64_t archive_skip_cb(struct archive *a, void *client_data, la_int64_t request);
static tar_result_t ensure_directory(const char *path);
static tar_result_t join_under_root(const char *root, const char *relative, char **out_full);
static bool path_component_safe(const char *path);

/* Exported Functions */

tar_result_t extractor_tar_gzip_extract(int fd,
                                        uint64_t offset,
                                        uint64_t size,
                                        const char *target_root,
                                        const extractor_tar_gzip_options_t *options)
{
    tar_result_t result = TAR_RESULT_OK;
    struct archive *archive = NULL;
    extractor_reader_t reader;
    bool overwrite = true;

    if (!target_root || fd < 0) {
        return TAR_RESULT_INVALID_ARGUMENT;
    }

    if (options) {
        overwrite = options->overwrite_existing;
    }

    result = ensure_directory(target_root);
    if (result != TAR_RESULT_OK) {
        return result;
    }

    if (lseek(fd, (off_t)offset, SEEK_SET) < 0) {
        return TAR_RESULT_IO;
    }

    reader.fd = fd;
    reader.remaining = size;

    archive = archive_read_new();
    if (!archive) {
        return TAR_RESULT_BACKEND;
    }
    archive_read_support_format_tar(archive);
    archive_read_support_filter_gzip(archive);

    if (archive_read_open2(archive, &reader, NULL, archive_read_cb, archive_skip_cb, NULL) != ARCHIVE_OK) {
        result = TAR_RESULT_BACKEND;
        goto cleanup;
    }

    struct archive_entry *entry = NULL;
    int arc_rc = 0;
    while ((arc_rc = archive_read_next_header(archive, &entry)) == ARCHIVE_OK) {
        const char *rel_path = archive_entry_pathname(entry);
        if (!rel_path || rel_path[0] == '\0' || !path_component_safe(rel_path)) {
            result = TAR_RESULT_PATH_TRAVERSAL;
            break;
        }

        char rel_copy[PATH_MAX];
        rel_copy[0] = '\0';
        snprintf(rel_copy, sizeof(rel_copy), "%s", rel_path);

        char *full_path = NULL;
        result = join_under_root(target_root, rel_path, &full_path);
        if (result != TAR_RESULT_OK) {
            break;
        }
        archive_entry_set_pathname(entry, full_path);
        free(full_path);

        int extract_rc = archive_read_extract(archive, entry, overwrite ? 0 : ARCHIVE_EXTRACT_NO_OVERWRITE);
        if (extract_rc != ARCHIVE_OK && extract_rc != ARCHIVE_WARN) {
            result = (extract_rc == ARCHIVE_RETRY) ? TAR_RESULT_IO : TAR_RESULT_BACKEND;
            break;
        }

        log_debug("extracted: %s", rel_copy);
    }

    if (result == TAR_RESULT_OK && arc_rc != ARCHIVE_EOF) {
        result = TAR_RESULT_CORRUPT_HEADER;
    }

cleanup:
    if (archive) {
        archive_read_close(archive);
        archive_read_free(archive);
    }
    return result;
}

/* Internal Functions */

static ssize_t archive_read_cb(struct archive *a, void *client_data, const void **buff)
{
    (void)a;
    extractor_reader_t *ctx = (extractor_reader_t *)client_data;
    if (ctx->remaining == 0) {
        return 0;
    }

    size_t to_read = ctx->remaining < EXTRACT_READ_BLOCK ? (size_t)ctx->remaining : (size_t)EXTRACT_READ_BLOCK;
    ssize_t n = read(ctx->fd, ctx->buffer, to_read);
    if (n < 0) {
        return -errno;
    }
    ctx->remaining -= (uint64_t)n;
    *buff = ctx->buffer;
    return n;
}

static la_int64_t archive_skip_cb(struct archive *a, void *client_data, la_int64_t request)
{
    (void)a;
    extractor_reader_t *ctx = (extractor_reader_t *)client_data;
    if (request <= 0 || ctx->remaining == 0) {
        return 0;
    }

    uint64_t to_skip = (uint64_t)request;
    if (to_skip > ctx->remaining) {
        to_skip = ctx->remaining;
    }

    off_t rc = lseek(ctx->fd, (off_t)to_skip, SEEK_CUR);
    if (rc < 0) {
        return -1;
    }

    ctx->remaining -= to_skip;
    return (la_int64_t)to_skip;
}

static tar_result_t ensure_directory(const char *path)
{
    tar_result_t result = TAR_RESULT_OK;
    char *mutable = strdup(path);
    if (!mutable) {
        return TAR_RESULT_NO_MEMORY;
    }

    size_t len = strlen(mutable);
    if (len == 0) {
        free(mutable);
        return TAR_RESULT_INVALID_ARGUMENT;
    }

    if (mutable[len - 1] == '/') {
        mutable[len - 1] = '\0';
    }

    for (char *p = mutable + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(mutable, 0755) < 0 && errno != EEXIST) {
                result = TAR_RESULT_IO;
                goto cleanup;
            }
            *p = '/';
        }
    }

    if (mkdir(mutable, 0755) < 0 && errno != EEXIST) {
        result = TAR_RESULT_IO;
    }

cleanup:
    free(mutable);
    return result;
}

static tar_result_t join_under_root(const char *root, const char *relative, char **out_full)
{
    size_t root_len = strlen(root);
    size_t rel_len = strlen(relative);

    /* Reserve space for root + '/' + relative + '\0' */
    size_t total = root_len + 1 + rel_len + 1;
    char *combined = (char *)malloc(total);
    if (!combined) {
        return TAR_RESULT_NO_MEMORY;
    }

    memcpy(combined, root, root_len);
    combined[root_len] = '/';
    memcpy(combined + root_len + 1, relative, rel_len);
    combined[total - 1] = '\0';

    *out_full = combined;
    return TAR_RESULT_OK;
}

static bool path_component_safe(const char *path)
{
    if (!path || *path == '/') {
        return false;
    }

    const char *p = path;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
            return false;
        }
        p++;
    }
    return true;
}
