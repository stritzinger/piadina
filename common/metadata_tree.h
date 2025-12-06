/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata_tree.h
 * @brief Shared metadata tree representation (maps/arrays/scalars).
 */

#ifndef PIADINA_COMMON_METADATA_TREE_H
#define PIADINA_COMMON_METADATA_TREE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    METADATA_TREE_STRING = 0,
    METADATA_TREE_UINT,
    METADATA_TREE_BOOL,
    METADATA_TREE_BYTES,
    METADATA_TREE_ARRAY,
    METADATA_TREE_MAP
} metadata_tree_type_t;

struct metadata_tree_value;

typedef struct {
    size_t count;
    size_t capacity;
    struct metadata_tree_value *items; /* owned array */
} metadata_tree_array_t;

typedef struct {
    char *key;                          /* owned */
    struct metadata_tree_value *value;  /* owned */
} metadata_tree_map_entry_t;

typedef struct {
    size_t count;
    size_t capacity;
    metadata_tree_map_entry_t *entries; /* owned array */
} metadata_tree_map_t;

typedef struct metadata_tree_value {
    metadata_tree_type_t type;
    union {
        char *str; /* owned */
        uint64_t uint_val;
        bool bool_val;
        struct {
            uint8_t *data; /* owned */
            size_t len;
        } bytes;
        metadata_tree_array_t array;
        metadata_tree_map_t map;
    } as;
} metadata_tree_value_t;

/**
 * @brief Initialize an empty metadata map.
 *
 * @param[out] map Map to initialize; no allocation performed.
 */
void metadata_tree_map_init(metadata_tree_map_t *map);

/**
 * @brief Destroy all owned memory in a metadata map.
 *
 * Frees keys, values, and nested allocations. Safe on partially built maps.
 *
 * @param[in,out] map Map to destroy; reset to zeroed state on return.
 */
void metadata_tree_map_destroy(metadata_tree_map_t *map);

/**
 * @brief Find a value by key in a map.
 *
 * @param[in] map     Map to search.
 * @param[in] key     Key bytes (need not be null-terminated).
 * @param[in] key_len Length of key in bytes.
 * @return Pointer to value if present, NULL if not found.
 */
metadata_tree_value_t *metadata_tree_map_find(const metadata_tree_map_t *map,
                                              const char *key,
                                              size_t key_len);

/**
 * @brief Ensure a key exists in the map, creating a new value if missing.
 *
 * @param[in,out] map     Map to update.
 * @param[in]     key     Key bytes (need not be null-terminated).
 * @param[in]     key_len Length of key in bytes.
 * @param[out]    created Optional; set true if a new entry was created.
 * @return Value slot on success, or NULL on OOM.
 */
metadata_tree_value_t *metadata_tree_map_get_or_create(metadata_tree_map_t *map,
                                                       const char *key,
                                                       size_t key_len,
                                                       bool *created);

/**
 * @brief Put a string value into the map (copies the input).
 *
 * @param[in,out] map     Map to update.
 * @param[in]     key     Key bytes (need not be null-terminated).
 * @param[in]     key_len Length of key in bytes.
 * @param[in]     value   Null-terminated string to copy.
 * @return Value slot on success, or NULL on OOM.
 */
metadata_tree_value_t *metadata_tree_map_put_string(metadata_tree_map_t *map,
                                                    const char *key,
                                                    size_t key_len,
                                                    const char *value);

/**
 * @brief Put a uint value into the map.
 *
 * @param[in,out] map     Map to update.
 * @param[in]     key     Key bytes (need not be null-terminated).
 * @param[in]     key_len Length of key in bytes.
 * @param[in]     value   Unsigned integer to store.
 * @return Value slot on success, or NULL on OOM.
 */
metadata_tree_value_t *metadata_tree_map_put_uint(metadata_tree_map_t *map,
                                                  const char *key,
                                                  size_t key_len,
                                                  uint64_t value);

/**
 * @brief Put a bool value into the map.
 *
 * @param[in,out] map     Map to update.
 * @param[in]     key     Key bytes (need not be null-terminated).
 * @param[in]     key_len Length of key in bytes.
 * @param[in]     value   Boolean to store.
 * @return Value slot on success, or NULL on OOM.
 */
metadata_tree_value_t *metadata_tree_map_put_bool(metadata_tree_map_t *map,
                                                  const char *key,
                                                  size_t key_len,
                                                  bool value);

/**
 * @brief Put a byte string into the map (copies the input).
 *
 * @param[in,out] map     Map to update.
 * @param[in]     key     Key bytes (need not be null-terminated).
 * @param[in]     key_len Length of key in bytes.
 * @param[in]     data    Bytes to copy; NULL allowed only when len is zero.
 * @param[in]     len     Number of bytes to copy.
 * @return Value slot on success, or NULL on OOM.
 */
metadata_tree_value_t *metadata_tree_map_put_bytes(metadata_tree_map_t *map,
                                                   const char *key,
                                                   size_t key_len,
                                                   const uint8_t *data,
                                                   size_t len);

/**
 * @brief Ensure an array value has capacity for the given index.
 *
 * Allocates or grows the array held in @p array_value. On success the element
 * at @p index is returned and zero-initialized if newly created.
 *
 * @param[in,out] array_value Value whose type must be METADATA_TREE_ARRAY.
 * @param[in]     index       Zero-based index to access.
 * @return Pointer to the element slot on success, or NULL on OOM or type mismatch.
 */
metadata_tree_value_t *metadata_tree_array_ensure_slot(metadata_tree_value_t *array_value,
                                                       size_t index);

/**
 * @brief Pretty-print a metadata map for debugging.
 *
 * @param[in] map     Root map to print.
 * @param[in] indent  Initial indentation (spaces).
 * @param[in] stream  Output stream (stderr if NULL).
 *
 * Does not modify the map. Best-effort; ignores NULL @p map.
 */
void metadata_tree_print_map(const metadata_tree_map_t *map, int indent, FILE *stream);

/**
 * @brief Convenience wrapper to print a root map with zero indent.
 *
 * @param[in] map    Root map to print.
 * @param[in] stream Output stream (stderr if NULL).
 */
void metadata_tree_print(const metadata_tree_map_t *map, FILE *stream);

#endif /* PIADINA_COMMON_METADATA_TREE_H */
