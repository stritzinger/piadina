/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file packer_tar_gzip.c
 * @brief libarchive-backed tar+gzip packer for Azdora.
 */
#include "packer_tar_gzip.h"

#include "../libarchive/libarchive/archive.h"
#include "../libarchive/libarchive/archive_entry.h"
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PACKER_READ_BLOCK (64 * 1024)

static int fts_path_compare(const FTSENT **a, const FTSENT **b);
static packer_tar_gzip_result_t copy_regular_file(struct archive *archive,
                                                  const char *source_path,
                                                  uint64_t *bytes_written,
                                                  uint64_t *progress_done,
                                                  uint64_t progress_total,
                                                  int *last_percent);
static bool symlink_target_safe(const char *target);
static bool symlink_resolves_within_root(const char *root_real,
                                         const char *link_path,
                                         const char *target);
static bool path_has_prefix(const char *path, const char *prefix);
static uint64_t compute_total_size(const char *root_real, packer_tar_gzip_result_t *out_rc);
static void maybe_print_progress(uint64_t done, uint64_t total, int *last_percent);

packer_tar_gzip_result_t packer_tar_gzip_write(const char *payload_root,
                                               int out_fd,
                                               uint64_t *out_bytes,
                                               bool verbose,
                                               bool quiet)
{
    packer_tar_gzip_result_t result = PACKER_TGZ_OK;
    struct archive *archive = NULL;
    struct archive_entry *entry = NULL;
    FTS *fts = NULL;
    uint64_t total_written = 0;
    off_t start_off = lseek(out_fd, 0, SEEK_CUR);
    uint64_t progress_total = 0;
    uint64_t progress_done = 0;
    int last_percent = -1;
    bool enable_progress = (!verbose && !quiet && isatty(fileno(stderr)));

    if (!payload_root || out_fd < 0) {
        return PACKER_TGZ_ERR_INVALID_ARGUMENT;
    }

    char *root_real = realpath(payload_root, NULL);
    if (!root_real) {
        return PACKER_TGZ_ERR_PATH;
    }

    char *paths[] = { root_real, NULL };
    fts = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, fts_path_compare);
    if (!fts) {
        free(root_real);
        return PACKER_TGZ_ERR_PATH;
    }

    if (enable_progress) {
        progress_total = compute_total_size(root_real, &result);
        if (result != PACKER_TGZ_OK) {
            enable_progress = false;
            result = PACKER_TGZ_OK;
        }
    }

    archive = archive_write_new();
    if (!archive) {
        result = PACKER_TGZ_ERR_ARCHIVE;
        goto cleanup;
    }

    archive_write_set_format_pax_restricted(archive);
    archive_write_add_filter_gzip(archive);

    if (archive_write_open_fd(archive, out_fd) != ARCHIVE_OK) {
        result = PACKER_TGZ_ERR_ARCHIVE;
        goto cleanup;
    }

    entry = archive_entry_new();
    if (!entry) {
        result = PACKER_TGZ_ERR_ARCHIVE;
        goto cleanup;
    }

    const size_t root_len = strlen(root_real);
    FTSENT *node = NULL;
    while ((node = fts_read(fts)) != NULL) {
        switch (node->fts_info) {
        case FTS_D:
        case FTS_F:
        case FTS_SL:
            break;
        case FTS_DP:
            /* post-order for directories already handled in FTS_D */
            continue;
        default:
            result = PACKER_TGZ_ERR_STAT;
            goto cleanup;
        }

        if (node->fts_level == 0) {
            /* Skip root entry itself; archive relative contents. */
            continue;
        }

        const char *rel_path = node->fts_path + root_len;
        if (*rel_path == '/') {
            rel_path++;
        }
        if (*rel_path == '\0') {
            /* Should not happen, but guard against empty names. */
            continue;
        }

        archive_entry_clear(entry);
        archive_entry_copy_stat(entry, node->fts_statp);
        archive_entry_set_pathname(entry, rel_path);

        switch (node->fts_info) {
        case FTS_D:
            archive_entry_set_filetype(entry, AE_IFDIR);
            archive_entry_set_size(entry, 0);
            break;
        case FTS_F:
            archive_entry_set_filetype(entry, AE_IFREG);
            archive_entry_set_size(entry, (la_int64_t)node->fts_statp->st_size);
            break;
        case FTS_SL: {
            char target[PATH_MAX];
            ssize_t len = readlink(node->fts_accpath, target, sizeof(target) - 1);
            if (len < 0) {
                result = PACKER_TGZ_ERR_IO;
                goto cleanup;
            }
            target[len] = '\0';
            if (!symlink_target_safe(target)) {
                result = PACKER_TGZ_ERR_SYMLINK;
                goto cleanup;
            }
            if (!symlink_resolves_within_root(root_real, node->fts_accpath, target)) {
                result = PACKER_TGZ_ERR_SYMLINK;
                goto cleanup;
            }
            archive_entry_set_filetype(entry, AE_IFLNK);
            archive_entry_set_symlink(entry, target);
            archive_entry_set_size(entry, 0);
            break;
        }
        default:
            result = PACKER_TGZ_ERR_UNSUPPORTED_ENTRY;
            goto cleanup;
        }

        int arc_rc = archive_write_header(archive, entry);
        if (arc_rc != ARCHIVE_OK) {
            result = PACKER_TGZ_ERR_ARCHIVE;
            goto cleanup;
        }

        if (node->fts_info == FTS_F && node->fts_statp->st_size > 0) {
            result = copy_regular_file(archive,
                                       node->fts_accpath,
                                       &total_written,
                                       &progress_done,
                                       progress_total,
                                       &last_percent);
            if (result != PACKER_TGZ_OK) {
                goto cleanup;
            }
            if (enable_progress) {
                maybe_print_progress(progress_done, progress_total, &last_percent);
            }
        }

        if (verbose) {
            fprintf(stderr, "[azdora] packed: %s\n", rel_path);
        }
    }

cleanup:
    if (entry) {
        archive_entry_free(entry);
    }
    if (archive) {
        archive_write_close(archive);
        archive_write_free(archive);
    }
    if (fts) {
        fts_close(fts);
    }
    free(root_real);

    if (out_bytes) {
        off_t end_off = lseek(out_fd, 0, SEEK_CUR);
        if (end_off != (off_t)-1 && start_off != (off_t)-1 && end_off >= start_off) {
            *out_bytes = (uint64_t)(end_off - start_off);
        } else {
            *out_bytes = total_written;
        }
    }

    if (enable_progress) {
        maybe_print_progress(progress_total, progress_total, &last_percent);
        fprintf(stderr, "\n");
    }

    return result;
}

const char *packer_tar_gzip_result_to_string(packer_tar_gzip_result_t result)
{
    switch (result) {
    case PACKER_TGZ_OK:
        return "ok";
    case PACKER_TGZ_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case PACKER_TGZ_ERR_PATH:
        return "invalid payload path";
    case PACKER_TGZ_ERR_SYMLINK:
        return "unsafe symlink (absolute or escaping payload)";
    case PACKER_TGZ_ERR_STAT:
        return "failed to stat payload entry";
    case PACKER_TGZ_ERR_IO:
        return "i/o error";
    case PACKER_TGZ_ERR_UNSUPPORTED_ENTRY:
        return "unsupported filesystem entry";
    case PACKER_TGZ_ERR_ARCHIVE:
        return "archive error";
    default:
        return "unknown error";
    }
}

static int fts_path_compare(const FTSENT **a, const FTSENT **b)
{
    return strcmp((*a)->fts_path, (*b)->fts_path);
}

static packer_tar_gzip_result_t copy_regular_file(struct archive *archive,
                                                  const char *source_path,
                                                  uint64_t *bytes_written,
                                                  uint64_t *progress_done,
                                                  uint64_t progress_total,
                                                  int *last_percent)
{
    int fd = open(source_path, O_RDONLY);
    if (fd < 0) {
        return PACKER_TGZ_ERR_IO;
    }

    uint8_t buffer[PACKER_READ_BLOCK];
    ssize_t n = 0;
    packer_tar_gzip_result_t result = PACKER_TGZ_OK;

    while ((n = read(fd, buffer, sizeof(buffer))) > 0) {
        ssize_t w = archive_write_data(archive, buffer, (size_t)n);
        if (w < 0) {
            result = PACKER_TGZ_ERR_ARCHIVE;
            break;
        }
        if (bytes_written) {
            *bytes_written += (uint64_t)w;
        }
        if (progress_done) {
            *progress_done += (uint64_t)w;
        }
    }

    if (n < 0) {
        result = PACKER_TGZ_ERR_IO;
    }

    close(fd);
    return result;
}

static bool symlink_target_safe(const char *target)
{
    if (!target) {
        return false;
    }
    if (target[0] == '/') {
        return false;
    }
    const char *p = target;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
            return false;
        }
        p++;
    }
    return true;
}

static bool symlink_resolves_within_root(const char *root_real,
                                         const char *link_path,
                                         const char *target)
{
    if (!root_real || !link_path || !target) {
        return false;
    }
    if (target[0] == '/') {
        return false;
    }

    char parent[PATH_MAX];
    char combined[PATH_MAX];
    char *last_slash = NULL;

    if (strlen(link_path) >= sizeof(parent)) {
        return false;
    }
    strcpy(parent, link_path);
    last_slash = strrchr(parent, '/');
    if (!last_slash) {
        return false;
    }
    *last_slash = '\0';

    if (snprintf(combined, sizeof(combined), "%s/%s", parent, target) >= (int)sizeof(combined)) {
        return false;
    }

    char resolved[PATH_MAX];
    if (!realpath(combined, resolved)) {
        return false;
    }

    return path_has_prefix(resolved, root_real);
}

static bool path_has_prefix(const char *path, const char *prefix)
{
    size_t p_len = strlen(prefix);
    if (strncmp(path, prefix, p_len) != 0) {
        return false;
    }
    return path[p_len] == '\0' || path[p_len] == '/';
}

static uint64_t compute_total_size(const char *root_real, packer_tar_gzip_result_t *out_rc)
{
    uint64_t total = 0;
    if (out_rc) {
        *out_rc = PACKER_TGZ_OK;
    }
    char *paths[] = { (char *)root_real, NULL };
    FTS *fts = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, fts_path_compare);
    if (!fts) {
        if (out_rc) {
            *out_rc = PACKER_TGZ_ERR_PATH;
        }
        return 0;
    }
    FTSENT *node = NULL;
    while ((node = fts_read(fts)) != NULL) {
        switch (node->fts_info) {
        case FTS_F:
            total += (uint64_t)node->fts_statp->st_size;
            break;
        default:
            break;
        }
    }
    fts_close(fts);
    return total;
}

static void maybe_print_progress(uint64_t done, uint64_t total, int *last_percent)
{
    if (total == 0) {
        return;
    }
    int percent = (int)((done * 100) / total);
    if (percent > 100) {
        percent = 100;
    }
    if (last_percent && percent == *last_percent) {
        return;
    }
    fprintf(stderr, "\r[azdora] packing: %3d%%", percent);
    if (last_percent) {
        *last_percent = percent;
    }
}
