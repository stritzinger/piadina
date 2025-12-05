/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata.h
 * @brief Azdora metadata representation and parsing.
 */
#ifndef AZDORA_METADATA_H
#define AZDORA_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "common/metadata_core.h"

typedef enum {
    AZDORA_METADATA_OK = 0,
    AZDORA_METADATA_ERR_INVALID_ARGUMENT,
    AZDORA_METADATA_ERR_PARSE,
    AZDORA_METADATA_ERR_UNSUPPORTED_KEY,
    AZDORA_METADATA_ERR_MISSING_REQUIRED,
    AZDORA_METADATA_ERR_BAD_VALUE,
    AZDORA_METADATA_ERR_OUT_OF_MEMORY
} azdora_metadata_result_t;

typedef enum {
    AZDORA_META_STRING = 0,
    AZDORA_META_UINT,
    AZDORA_META_BOOL,
    AZDORA_META_BYTES,
    AZDORA_META_ARRAY,
    AZDORA_META_MAP
} azdora_meta_type_t;

struct azdora_meta_value;

typedef struct {
    size_t count;
    size_t capacity;
    struct azdora_meta_value *items; /* owned array */
} azdora_meta_array_t;

typedef struct {
    char *key;                        /* owned */
    struct azdora_meta_value *value;  /* owned */
} azdora_meta_map_entry_t;

typedef struct {
    size_t count;
    size_t capacity;
    azdora_meta_map_entry_t *entries; /* owned array */
} azdora_meta_map_t;

typedef struct azdora_meta_value {
    azdora_meta_type_t type;
    union {
        char *str; /* owned */
        uint64_t uint_val;
        bool bool_val;
        struct {
            uint8_t *data; /* owned */
            size_t len;
        } bytes;
        azdora_meta_array_t array;
        azdora_meta_map_t map;
    } as;
} azdora_meta_value_t;

typedef struct {
    azdora_meta_map_t root; /* top-level metadata map */
} azdora_metadata_t;

/**
 * @brief Initialize a metadata struct.
 *
 * @param[out] metadata  Pointer to the metadata struct.
 *
 * @note Memory Management:
 *       Caller allocates the struct; this sets internal pointers to NULL.
 */
void azdora_metadata_init(azdora_metadata_t *metadata);

/**
 * @brief Destroy all owned memory within the metadata struct.
 *
 * @param[in] metadata  Pointer to the metadata struct.
 *
 * @note Memory Management:
 *       Caller retains the struct storage and may re-init it afterward.
 *       Frees all internal recursive structures.
 */
void azdora_metadata_destroy(azdora_metadata_t *metadata);

/**
 * @brief Apply a user-provided PATH=VALUE entry.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     entry      The entry string (e.g. "ENV.DB=foo").
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       The entry string is borrowed; any stored data is duplicated.
 */
azdora_metadata_result_t azdora_metadata_apply_meta(azdora_metadata_t *metadata,
                                                    const char *entry,
                                                    const char **error_msg);

/**
 * @brief Finalize metadata: enforce required fields and fill defaults.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       Allocates memory for default values if they are missing.
 */
azdora_metadata_result_t azdora_metadata_finalize(azdora_metadata_t *metadata,
                                                  const char **error_msg);

/**
 * @brief Borrow the top-level metadata map.
 *
 * @param[in] metadata  The metadata struct.
 * @return              Pointer to the root map.
 *
 * @note Memory Management:
 *       The returned pointer stays valid until azdora_metadata_destroy() is called.
 */
const azdora_meta_map_t *azdora_metadata_root(const azdora_metadata_t *metadata);

/**
 * @brief Set a scalar string field.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     field      The field identifier.
 * @param[in]     value      The string value.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       The value is duplicated and owned by the metadata struct.
 */
azdora_metadata_result_t azdora_metadata_set_field_string(azdora_metadata_t *metadata,
                                                          metadata_core_field_t field,
                                                          const char *value,
                                                          const char **error_msg);

/**
 * @brief Set a scalar boolean field.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     field      The field identifier.
 * @param[in]     value      The boolean value.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       Stored by value; no allocation.
 */
azdora_metadata_result_t azdora_metadata_set_field_bool(azdora_metadata_t *metadata,
                                                        metadata_core_field_t field,
                                                        bool value,
                                                        const char **error_msg);

/**
 * @brief Set a scalar uint field.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     field      The field identifier.
 * @param[in]     value      The uint value.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       Stored by value; no allocation.
 */
azdora_metadata_result_t azdora_metadata_set_field_uint(azdora_metadata_t *metadata,
                                                        metadata_core_field_t field,
                                                        uint64_t value,
                                                        const char **error_msg);

/**
 * @brief Set a scalar bytes field.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     field      The field identifier.
 * @param[in]     data       Pointer to the data.
 * @param[in]     len        Length of the data.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       The buffer is duplicated and owned by the metadata struct.
 */
azdora_metadata_result_t azdora_metadata_set_field_bytes(azdora_metadata_t *metadata,
                                                         metadata_core_field_t field,
                                                         const uint8_t *data,
                                                         size_t len,
                                                         const char **error_msg);

/**
 * @brief Add an element to an array field.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     field      The field identifier.
 * @param[in]     index      The index (ignored if append is true).
 * @param[in]     append     Whether to append or set at index.
 * @param[in]     value      The string value to add.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       The value is duplicated and owned by the metadata struct.
 */
azdora_metadata_result_t azdora_metadata_add_array_string(azdora_metadata_t *metadata,
                                                          metadata_core_field_t field,
                                                          size_t index,
                                                          bool append,
                                                          const char *value,
                                                          const char **error_msg);

/**
 * @brief Set a map entry (e.g., ENV.KEY) with string value.
 *
 * @param[in,out] metadata   The metadata struct.
 * @param[in]     field      The field identifier (must be a map field).
 * @param[in]     key        The key string.
 * @param[in]     value      The value string.
 * @param[out]    error_msg  Optional error message.
 * @return                   AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       Map keys and values are duplicated and owned by the metadata struct.
 */
azdora_metadata_result_t azdora_metadata_set_map_entry_string(azdora_metadata_t *metadata,
                                                              metadata_core_field_t field,
                                                              const char *key,
                                                              const char *value,
                                                              const char **error_msg);

/**
 * @brief Get a string value from the metadata.
 *
 * @param[in]  metadata   The metadata struct.
 * @param[in]  field      The field identifier.
 * @param[out] out        Pointer to store the string pointer.
 * @param[out] error_msg  Optional error message.
 * @return                AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       Returned pointer is borrowed and valid until azdora_metadata_destroy().
 */
azdora_metadata_result_t azdora_metadata_get_string(const azdora_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    const char **out,
                                                    const char **error_msg);

/**
 * @brief Get a boolean value from the metadata.
 *
 * @param[in]  metadata   The metadata struct.
 * @param[in]  field      The field identifier.
 * @param[out] out        Pointer to store the result.
 * @param[out] error_msg  Optional error message.
 * @return                AZDORA_METADATA_OK on success.
 */
azdora_metadata_result_t azdora_metadata_get_bool(const azdora_metadata_t *metadata,
                                                  metadata_core_field_t field,
                                                  bool *out,
                                                  const char **error_msg);

/**
 * @brief Get a uint value from the metadata.
 *
 * @param[in]  metadata   The metadata struct.
 * @param[in]  field      The field identifier.
 * @param[out] out        Pointer to store the result.
 * @param[out] error_msg  Optional error message.
 * @return                AZDORA_METADATA_OK on success.
 */
azdora_metadata_result_t azdora_metadata_get_uint(const azdora_metadata_t *metadata,
                                                  metadata_core_field_t field,
                                                  uint64_t *out,
                                                  const char **error_msg);

/**
 * @brief Get a byte string value from the metadata.
 *
 * @param[in]  metadata   The metadata struct.
 * @param[in]  field      The field identifier.
 * @param[out] out        Pointer to store the data pointer.
 * @param[out] len_out    Pointer to store the length.
 * @param[out] error_msg  Optional error message.
 * @return                AZDORA_METADATA_OK on success.
 *
 * @note Memory Management:
 *       Returned pointer is borrowed and valid until azdora_metadata_destroy().
 */
azdora_metadata_result_t azdora_metadata_get_bytes(const azdora_metadata_t *metadata,
                                                   metadata_core_field_t field,
                                                   const uint8_t **out,
                                                   size_t *len_out,
                                                   const char **error_msg);

/**
 * @brief Pretty-print the metadata tree.
 *
 * @param[in] metadata  The metadata struct.
 * @param[in] stream    Stream to print to (stderr if NULL).
 *
 * @note Memory Management:
 *       Does not take ownership of arguments.
 */
void azdora_metadata_print(const azdora_metadata_t *metadata, FILE *stream);

#endif /* AZDORA_METADATA_H */
