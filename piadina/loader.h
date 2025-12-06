/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file loader.h
 * @brief Load footer and metadata from the self-extracting binary.
 */

#ifndef PIADINA_LOADER_H
#define PIADINA_LOADER_H

#include <stddef.h>
#include <stdbool.h>

#include "config.h"
#include "common/footer.h"
#include "metadata.h"

typedef enum {
    PIADINA_LOADER_OK = 0,
    PIADINA_LOADER_NO_FOOTER,
    PIADINA_LOADER_ERR_FOOTER,
    PIADINA_LOADER_ERR_METADATA,
    PIADINA_LOADER_ERR_OVERRIDES,
    PIADINA_LOADER_ERR_EXTRACT,
    PIADINA_LOADER_ERR_IO
} piadina_loader_result_t;

typedef struct {
    int fd;
    char self_path[4096];
    piadina_footer_t footer;
    bool footer_loaded;
    piadina_metadata_t metadata;
    bool metadata_loaded;
} piadina_loader_t;

/**
 * @brief Initialize loader to a clean state.
 *
 * Sets fd to -1 and initializes the embedded metadata map.
 */
void piadina_loader_init(piadina_loader_t *loader);

/**
 * @brief Destroy loader resources (fd/metadata) and reset state.
 */
void piadina_loader_destroy(piadina_loader_t *loader);

/**
 * @brief Read footer/metadata from the running binary and apply overrides.
 *
 * Resolves self path, opens the binary, reads/validates footer, decodes
 * metadata (for PRINT_METADATA/RUN), applies env/CLI overrides, and logs
 * footer/metadata at debug level.
 *
 * @param[in]  config     Parsed launcher config (env/CLI already applied).
 * @param[out] loader     Loader state to populate.
 * @param[out] error_msg  Optional error message on failure.
 * @return                PIADINA_LOADER_OK on success.
 */
piadina_loader_result_t piadina_loader_load(const piadina_config_t *config,
                                            piadina_loader_t *loader,
                                            const char **error_msg);

/**
 * @brief Extract the embedded archive to a target directory.
 *
 * Uses ARCHIVE_FORMAT from metadata (defaults applied during decode).
 *
 * @param[in]  loader       Loader with footer (and metadata if available).
 * @param[in]  target_root  Optional target directory; if NULL a temp dir is created.
 * @param[out] out_dir      Buffer to receive the extraction path.
 * @param[in]  out_dir_len  Size of @p out_dir buffer.
 * @param[out] error_msg    Optional error message on failure.
 * @return                  PIADINA_LOADER_OK on success.
 */
piadina_loader_result_t piadina_loader_extract(const piadina_loader_t *loader,
                                               const char *target_root,
                                               char *out_dir,
                                               size_t out_dir_len,
                                               const char **error_msg);

/**
 * @brief Human-readable string for loader result codes.
 */
const char *piadina_loader_result_to_string(piadina_loader_result_t result);

#endif /* PIADINA_LOADER_H */
