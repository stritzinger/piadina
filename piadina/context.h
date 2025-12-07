/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file context.h
 * @brief Resolve effective launcher context (paths, args, env) from metadata.
 */

#ifndef PIADINA_CONTEXT_H
#define PIADINA_CONTEXT_H

#include <stddef.h>

#include "metadata.h"

typedef struct {
    char *cache_root;      /* owned */
    char *payload_root;    /* owned */
    char *temp_dir;        /* owned */
    char *entry_path;      /* owned absolute path to ENTRY_POINT under payload_root */
    char *entry_point;     /* owned relative ENTRY_POINT from metadata */
    char *app_name;        /* owned, metadata APP_NAME */
    char *app_ver;         /* owned, metadata APP_VER */

    char **entry_args;         /* owned array of owned strings */
    size_t entry_args_count;

    char **entry_args_post;    /* owned array of owned strings */
    size_t entry_args_post_count;

    struct {
        char *key;   /* owned */
        char *value; /* owned */
    } *env;
    size_t env_count;
} piadina_context_t;

typedef enum {
    PIADINA_CONTEXT_OK = 0,
    PIADINA_CONTEXT_ERR_INVALID_ARGUMENT = PIADINA_METADATA_ERR_INVALID_ARGUMENT,
    PIADINA_CONTEXT_ERR_MISSING_REQUIRED = PIADINA_METADATA_ERR_MISSING_REQUIRED,
    PIADINA_CONTEXT_ERR_BAD_VALUE = PIADINA_METADATA_ERR_BAD_VALUE,
    PIADINA_CONTEXT_ERR_OUT_OF_MEMORY = PIADINA_METADATA_ERR_OUT_OF_MEMORY
} piadina_context_result_t;

/**
 * @brief Initialize context to empty.
 */
void piadina_context_init(piadina_context_t *ctx);

/**
 * @brief Destroy owned memory inside the context.
 */
void piadina_context_destroy(piadina_context_t *ctx);

/**
 * @brief Pretty-print resolved context to a stream.
 */
void piadina_context_print(const piadina_context_t *ctx, FILE *stream);

/**
 * @brief Resolve context from decoded metadata (after overrides).
 *
 * Resolves templates across all string fields (including ENTRY_POINT,
 * ENTRY_ARGS/ENTRY_ARGS_POST, ENV, and user maps), using process environment
 * plus metadata-derived variables (PAYLOAD_HASH, ARCHIVE_HASH, CACHE_ROOT,
 * PAYLOAD_ROOT). Unknown variables cause an error.
 *
 * Constructs:
 * - entry_path = payload_root + "/" + ENTRY_POINT
 * - entry_args, entry_args_post arrays
 * - env key/value pairs from metadata ENV
 *
 * @param[in]  metadata   Decoded metadata (overrides applied).
 * @param[out] ctx        Output context (must be initialized).
 * @param[out] error_msg  Optional error message on failure.
 * @return                PIADINA_CONTEXT_OK on success.
 */
piadina_context_result_t piadina_context_resolve(const piadina_metadata_t *metadata,
                                                 piadina_context_t *ctx,
                                                 const char **error_msg);

/**
 * @brief Return a human-readable string for a context resolver result.
 */
const char *piadina_context_result_to_string(piadina_context_result_t result);

#endif /* PIADINA_CONTEXT_H */
