/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file loader.c
 * @brief Footer/metadata loading and extraction orchestration for Piadina.
 */

#include "loader.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "archive.h"
#include "common/footer.h"
#include "common/log.h"
#include "common/platform.h"
#include "common/metadata_core.h"

/* Internal prototypes */
static int mkdir_p(const char *path);
static piadina_metadata_result_t load_metadata_block(int fd,
                                                     const piadina_footer_t *footer,
                                                     piadina_metadata_t *metadata,
                                                     const char **error_msg);

/* Exported Functions */

void piadina_loader_init(piadina_loader_t *loader)
{
    if (!loader) {
        return;
    }
    memset(loader, 0, sizeof(*loader));
    loader->fd = -1;
    piadina_metadata_init(&loader->metadata);
}

void piadina_loader_destroy(piadina_loader_t *loader)
{
    if (!loader) {
        return;
    }
    if (loader->fd >= 0) {
        close(loader->fd);
        loader->fd = -1;
    }
    if (loader->metadata_loaded) {
        piadina_metadata_destroy(&loader->metadata);
    }
    memset(loader, 0, sizeof(*loader));
    loader->fd = -1;
}

piadina_loader_result_t piadina_loader_load(const piadina_config_t *config,
                                            piadina_loader_t *loader,
                                            const char **error_msg)
{
    if (!config || !loader) {
        if (error_msg) {
            *error_msg = "invalid loader arguments";
        }
        return PIADINA_LOADER_ERR_IO;
    }

    size_t max_len = sizeof(loader->self_path);

    platform_result_t plat_result =
        platform_get_self_exe_path(loader->self_path, max_len);
    if (plat_result != PLATFORM_OK) {
        if (error_msg) {
            *error_msg = "failed to resolve self executable path";
        }
        return PIADINA_LOADER_ERR_IO;
    }

    log_debug("self path: %s", loader->self_path);

    loader->fd = open(loader->self_path, O_RDONLY);
    if (loader->fd < 0) {
        if (error_msg) {
            *error_msg = "failed to open self";
        }
        return PIADINA_LOADER_ERR_IO;
    }

    log_info("reading footer");
    footer_result_t footer_result = footer_read(loader->fd, &loader->footer);
    if (footer_result != FOOTER_OK) {
        if (error_msg) {
            *error_msg = footer_result_to_string(footer_result);
        }
        return PIADINA_LOADER_ERR_FOOTER;
    }
    loader->footer_loaded = true;
    if (log_get_level() == LOG_LEVEL_DEBUG) {
        footer_print(&loader->footer, stderr);
    }

    if (config->action == CONFIG_ACTION_PRINT_FOOTER) {
        return PIADINA_LOADER_OK;
    }

    if (config->action == CONFIG_ACTION_PRINT_METADATA ||
        config->action == CONFIG_ACTION_RUN) {
        log_info("reading metadata");
        const char *md_err = NULL;
        piadina_metadata_result_t md_rc =
            load_metadata_block(loader->fd, &loader->footer, &loader->metadata, &md_err);
        if (md_rc != PIADINA_METADATA_OK) {
            if (error_msg) {
                *error_msg = md_err ? md_err : piadina_metadata_result_to_string(md_rc);
            }
            return PIADINA_LOADER_ERR_METADATA;
        }
        loader->metadata_loaded = true;

        const char *cleanup_override = NULL;
        if (config->cleanup_policy_set) {
            cleanup_override = metadata_core_cleanup_policy_to_string(config->cleanup_policy);
        }
        int validate_override = config->validate_set ? (config->validate ? 1 : 0) : -1;
        const char *override_err = NULL;
        md_rc = piadina_metadata_apply_overrides(&loader->metadata,
                                                 config->cache_root_set ? config->cache_root : NULL,
                                                 cleanup_override,
                                                 validate_override,
                                                 &override_err);
        if (md_rc != PIADINA_METADATA_OK) {
            if (error_msg) {
                *error_msg = override_err ? override_err : piadina_metadata_result_to_string(md_rc);
            }
            return PIADINA_LOADER_ERR_OVERRIDES;
        }

        if (log_get_level() == LOG_LEVEL_DEBUG) {
            piadina_metadata_print(&loader->metadata, stderr);
        }
    }

    return PIADINA_LOADER_OK;
}

piadina_loader_result_t piadina_loader_extract(const piadina_loader_t *loader,
                                               const char *target_root,
                                               char *out_dir,
                                               size_t out_dir_len,
                                               const char **error_msg)
{
    if (!loader || loader->fd < 0 || !loader->footer_loaded) {
        if (error_msg) {
            *error_msg = "loader not initialized";
        }
        return PIADINA_LOADER_ERR_IO;
    }
    const piadina_footer_t *footer = &loader->footer;
    if (footer->archive_size == 0) {
        if (error_msg) {
            *error_msg = "no archive payload present";
        }
        return PIADINA_LOADER_ERR_EXTRACT;
    }

    if (target_root) {
        size_t len = strlen(target_root);
        if (len + 1 > out_dir_len) {
            if (error_msg) {
                *error_msg = "extraction path buffer too small";
            }
            return PIADINA_LOADER_ERR_EXTRACT;
        }
        memcpy(out_dir, target_root, len + 1);
        if (mkdir_p(out_dir) != 0) {
            if (error_msg) {
                *error_msg = "failed to create extraction directory";
            }
            return PIADINA_LOADER_ERR_EXTRACT;
        }
    } else {
        if (out_dir_len < sizeof("/tmp/piadina_payload_XXXXXX")) {
            if (error_msg) {
                *error_msg = "extraction path buffer too small";
            }
            return PIADINA_LOADER_ERR_EXTRACT;
        }
        char tmpl[] = "/tmp/piadina_payload_XXXXXX";
        char *dir = mkdtemp(tmpl);
        if (!dir) {
            if (error_msg) {
                *error_msg = "failed to create extraction directory";
            }
            return PIADINA_LOADER_ERR_EXTRACT;
        }
        snprintf(out_dir, out_dir_len, "%s", dir);
    }
    log_info("extracting archive to %s", out_dir);

    /* Use archive format from metadata (defaults applied during decode) */
    const char *archive_format = NULL;
    if (loader->metadata_loaded) {
        (void)piadina_metadata_get_string(&loader->metadata,
                                          METADATA_FIELD_ARCHIVE_FORMAT,
                                          &archive_format,
                                          NULL);
    }

    piadina_archive_result_t arc_rc = piadina_archive_extract(archive_format,
                                                              loader->fd,
                                                              footer->archive_offset,
                                                              footer->archive_size,
                                                              out_dir);
    if (arc_rc != PIADINA_ARCHIVE_OK) {
        if (error_msg) {
            *error_msg = piadina_archive_result_to_string(arc_rc);
        }
        log_error("archive extraction failed: %s",
                  piadina_archive_result_to_string(arc_rc));
        return PIADINA_LOADER_ERR_EXTRACT;
    }

    log_info("extraction completed");
    return PIADINA_LOADER_OK;
}

const char *piadina_loader_result_to_string(piadina_loader_result_t result)
{
    switch (result) {
    case PIADINA_LOADER_OK:
        return "ok";
    case PIADINA_LOADER_NO_FOOTER:
        return "no footer found";
    case PIADINA_LOADER_ERR_FOOTER:
        return "footer error";
    case PIADINA_LOADER_ERR_METADATA:
        return "metadata error";
    case PIADINA_LOADER_ERR_OVERRIDES:
        return "metadata override error";
    case PIADINA_LOADER_ERR_EXTRACT:
        return "extraction error";
    case PIADINA_LOADER_ERR_IO:
        return "I/O error";
    default:
        return "unknown loader error";
    }
}

/* Internal Functions */

static int mkdir_p(const char *path)
{
    if (!path || !*path) {
        return -1;
    }
    char tmp[4096];
    if (strlen(path) >= sizeof(tmp)) {
        return -1;
    }
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static piadina_metadata_result_t load_metadata_block(int fd,
                                                     const piadina_footer_t *footer,
                                                     piadina_metadata_t *metadata,
                                                     const char **error_msg)
{
    if (!footer || !metadata) {
        if (error_msg) {
            *error_msg = "invalid metadata arguments";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    if (footer->metadata_size == 0) {
        if (error_msg) {
            *error_msg = "no metadata present in footer";
        }
        return PIADINA_METADATA_ERR_MISSING_REQUIRED;
    }
    if (lseek(fd, (off_t)footer->metadata_offset, SEEK_SET) < 0) {
        if (error_msg) {
            *error_msg = "failed to seek metadata";
        }
        return PIADINA_METADATA_ERR_DECODE;
    }
    uint8_t *buf = malloc((size_t)footer->metadata_size);
    if (!buf) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
    }
    ssize_t n = read(fd, buf, (size_t)footer->metadata_size);
    if (n < 0 || (uint64_t)n != footer->metadata_size) {
        free(buf);
        if (error_msg) {
            *error_msg = "failed to read metadata";
        }
        return PIADINA_METADATA_ERR_DECODE;
    }
    piadina_metadata_result_t rc = piadina_metadata_decode(buf, (size_t)footer->metadata_size, metadata, error_msg);
    free(buf);
    return rc;
}
