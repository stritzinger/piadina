/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata.h
 * @brief Piadina launcher metadata representation and CBOR decoding.
 */

#ifndef PIADINA_METADATA_H
#define PIADINA_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "common/metadata_core.h"
#include "common/metadata_tree.h"

typedef enum {
    PIADINA_METADATA_OK = 0,
    PIADINA_METADATA_ERR_INVALID_ARGUMENT,
    PIADINA_METADATA_ERR_DECODE,
    PIADINA_METADATA_ERR_UNSUPPORTED_KEY,
    PIADINA_METADATA_ERR_MISSING_REQUIRED,
    PIADINA_METADATA_ERR_BAD_VALUE,
    PIADINA_METADATA_ERR_OUT_OF_MEMORY,
    PIADINA_METADATA_ERR_UNSUPPORTED_VERSION
} piadina_metadata_result_t;

typedef metadata_tree_type_t piadina_meta_type_t;
typedef metadata_tree_value_t piadina_meta_value_t;
typedef metadata_tree_array_t piadina_meta_array_t;
typedef metadata_tree_map_t piadina_meta_map_t;
typedef metadata_tree_map_entry_t piadina_meta_map_entry_t;
#define PIADINA_META_STRING METADATA_TREE_STRING
#define PIADINA_META_UINT METADATA_TREE_UINT
#define PIADINA_META_BOOL METADATA_TREE_BOOL
#define PIADINA_META_BYTES METADATA_TREE_BYTES
#define PIADINA_META_ARRAY METADATA_TREE_ARRAY
#define PIADINA_META_MAP METADATA_TREE_MAP

typedef struct {
    piadina_meta_map_t root; /* top-level metadata map */
} piadina_metadata_t;

/**
 * @brief Initialize a metadata struct.
 */
void piadina_metadata_init(piadina_metadata_t *metadata);

/**
 * @brief Destroy owned memory in the metadata struct.
 */
void piadina_metadata_destroy(piadina_metadata_t *metadata);

/**
 * @brief Decode a CBOR metadata blob into the in-memory representation.
 *
 * @param[in]  data       CBOR buffer.
 * @param[in]  size       Buffer size.
 * @param[out] metadata   Output struct (must be initialized).
 * @param[out] error_msg  Optional error message.
 * @return                PIADINA_METADATA_OK on success.
 */
piadina_metadata_result_t piadina_metadata_decode(const uint8_t *data,
                                                  size_t size,
                                                  piadina_metadata_t *metadata,
                                                  const char **error_msg);

/**
 * @brief Borrow the root metadata map.
 */
const piadina_meta_map_t *piadina_metadata_root(const piadina_metadata_t *metadata);

/**
 * @brief Get a string field by known identifier.
 */
piadina_metadata_result_t piadina_metadata_get_string(const piadina_metadata_t *metadata,
                                                      metadata_core_field_t field,
                                                      const char **out,
                                                      const char **error_msg);

/**
 * @brief Get a boolean field by known identifier.
 */
piadina_metadata_result_t piadina_metadata_get_bool(const piadina_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    bool *out,
                                                    const char **error_msg);

/**
 * @brief Get a uint field by known identifier.
 */
piadina_metadata_result_t piadina_metadata_get_uint(const piadina_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    uint64_t *out,
                                                    const char **error_msg);

/**
 * @brief Get a bytes field by known identifier.
 */
piadina_metadata_result_t piadina_metadata_get_bytes(const piadina_metadata_t *metadata,
                                                     metadata_core_field_t field,
                                                     const uint8_t **out,
                                                     size_t *len_out,
                                                     const char **error_msg);

/**
 * @brief Get an array value by known identifier.
 */
piadina_metadata_result_t piadina_metadata_get_array(const piadina_metadata_t *metadata,
                                                     metadata_core_field_t field,
                                                     const piadina_meta_array_t **out,
                                                     const char **error_msg);

/**
 * @brief Get a map value by known identifier (e.g., ENV).
 */
piadina_metadata_result_t piadina_metadata_get_map(const piadina_metadata_t *metadata,
                                                   metadata_core_field_t field,
                                                   const piadina_meta_map_t **out,
                                                   const char **error_msg);

/**
 * @brief Pretty-print the metadata tree for debugging.
 */
void piadina_metadata_print(const piadina_metadata_t *metadata, FILE *stream);

/**
 * @brief Human-readable string for a metadata result code.
 */
const char *piadina_metadata_result_to_string(piadina_metadata_result_t result);

/**
 * @brief Apply launcher overrides (env/CLI) to mutable metadata fields.
 *
 * Precedence: defaults < metadata < env < CLI. Only selected fields are
 * overridable (e.g., CACHE_ROOT, CLEANUP_POLICY, VALIDATE). Protected fields
 * such as VERSION, PAYLOAD_HASH, ARCHIVE_HASH, and ARCHIVE_FORMAT are not
 * modified.
 *
 * @param[in,out] metadata   Decoded metadata to update in place.
 * @param[in]     cache_root Optional cache root override (NULL to skip).
 * @param[in]     cleanup    Cleanup policy override (NULL to skip).
 * @param[in]     validate   Optional validate override; pass -1 to skip.
 * @param[out]    error_msg  Optional error message on failure.
 * @return                   PIADINA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       The function copies incoming strings; caller retains ownership of
 *       @p cache_root and @p cleanup.
 */
piadina_metadata_result_t piadina_metadata_apply_overrides(piadina_metadata_t *metadata,
                                                           const char *cache_root,
                                                           const char *cleanup,
                                                           int validate,
                                                           const char **error_msg);

#endif /* PIADINA_METADATA_H */
