/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata.c
 * @brief Azdora metadata representation and parsing.
 */
#include "metadata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "common/metadata_core.h"

/* ------------------------------------------------------------------------- */
/* Helpers forward declarations                                             */
/* ------------------------------------------------------------------------- */
static azdora_metadata_result_t parse_hex_bytes(const char *hex,
                                                size_t expected_bytes,
                                                uint8_t *out,
                                                const char **error_msg);
static azdora_metadata_result_t parse_base64(const char *in, uint8_t **out, size_t *out_len);
static bool env_key_shell_safe(const char *key, size_t len);
static azdora_meta_value_t *map_put_bytes(azdora_meta_map_t *map,
                                          const char *key,
                                          size_t key_len,
                                          const uint8_t *bytes,
                                          size_t len,
                                          const char **error_msg);
static azdora_meta_value_t *map_put_uint(azdora_meta_map_t *map,
                                         const char *key,
                                         size_t key_len,
                                         uint64_t value,
                                         const char **error_msg);
static azdora_meta_value_t *map_get_or_create(azdora_meta_map_t *map,
                                              const char *key,
                                              size_t key_len,
                                              bool *created,
                                              const char **error_msg);
static azdora_meta_value_t *ensure_array_slot(azdora_meta_value_t *array_value,
                                              size_t index,
                                              const char **error_msg);
static azdora_metadata_result_t set_scalar_value(azdora_meta_value_t *value,
                                                 azdora_meta_type_t type,
                                                 const char *str_value,
                                                 const char **error_msg);
static void value_reset(azdora_meta_value_t *value);
static void value_destroy(azdora_meta_value_t *value);
static void map_destroy(azdora_meta_map_t *map);
static void array_destroy(azdora_meta_array_t *array);
static azdora_meta_value_t *value_new(void);
static azdora_meta_value_t *map_put_scalar(azdora_meta_map_t *map,
                                           const char *key,
                                           size_t key_len,
                                           azdora_meta_type_t type,
                                           const char *str_value,
                                           const char **error_msg);
static azdora_metadata_result_t ensure_required_defaults(azdora_metadata_t *metadata,
                                                         const char **error_msg);
static azdora_meta_value_t *map_find(const azdora_meta_map_t *map,
                                     const char *key,
                                     size_t key_len);
static azdora_metadata_result_t enforce_scalar_kind(metadata_core_expected_kind_t expected,
                                                    azdora_meta_type_t actual,
                                                    const char **error_msg);
static void metadata_print_indent(int indent, FILE *stream);
static void metadata_print_value(const azdora_meta_value_t *val, int indent, FILE *stream);
static void metadata_print_map(const azdora_meta_map_t *map, int indent, FILE *stream);

void azdora_metadata_init(azdora_metadata_t *metadata)
{
    if (!metadata) {
        return;
    }
    memset(metadata, 0, sizeof(*metadata));
    metadata->root.count = 0;
    metadata->root.capacity = 0;
    metadata->root.entries = NULL;
}

void azdora_metadata_destroy(azdora_metadata_t *metadata)
{
    if (!metadata) {
        return;
    }
    map_destroy(&metadata->root);
}

azdora_metadata_result_t azdora_metadata_apply_meta(azdora_metadata_t *metadata,
                                                    const char *entry,
                                                    const char **error_msg)
{
    if (!metadata || !entry) {
        if (error_msg) {
            *error_msg = "invalid metadata arguments";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }

    const char *eq = strchr(entry, '=');
    if (!eq || eq == entry || *(eq + 1) == '\0') {
        if (error_msg) {
            *error_msg = "meta entry must be PATH=VALUE";
        }
        return AZDORA_METADATA_ERR_PARSE;
    }

    size_t path_len = (size_t)(eq - entry);
    const char *path = entry;
    const char *value_str = eq + 1;

    /* Split map path (MAP.KEY) if present */
    const char *dot = memchr(path, '.', path_len);
    const char *bracket = memchr(path, '[', path_len);

    /* Validate identifiers before brackets/dots */
    size_t first_len = dot ? (size_t)(dot - path) : (bracket ? (size_t)(bracket - path) : path_len);
    if (!metadata_core_identifier_valid(path, first_len)) {
        if (error_msg) {
            *error_msg = "invalid metadata key";
        }
        return AZDORA_METADATA_ERR_PARSE;
    }

    /* Determine value type from prefix */
    azdora_meta_type_t val_type = AZDORA_META_STRING;
    const char *typed_value = value_str;
    if (strncmp(value_str, "u:", 2) == 0) {
        val_type = AZDORA_META_UINT;
        typed_value += 2;
    } else if (strncmp(value_str, "b:", 2) == 0) {
        val_type = AZDORA_META_BOOL;
        typed_value += 2;
    } else if (strncmp(value_str, "hex:", 4) == 0) {
        val_type = AZDORA_META_BYTES;
        typed_value += 4;
    } else if (strncmp(value_str, "b64:", 4) == 0) {
        val_type = AZDORA_META_BYTES;
        typed_value += 4;
    }

    /* Known field expectations */
    metadata_core_field_t known_field = METADATA_FIELD_UNKNOWN;
    bool is_known = metadata_core_field_lookup(path, first_len, &known_field);
    metadata_core_expected_kind_t expected_kind =
        is_known ? metadata_core_expected_kind(known_field) : METADATA_EXPECT_ANY;

    /* VERSION cannot be overridden */
    if (!dot && !bracket && known_field == METADATA_FIELD_VERSION) {
        if (error_msg) {
            *error_msg = "VERSION is set by Azdora and cannot be overridden";
        }
        return AZDORA_METADATA_ERR_UNSUPPORTED_KEY;
    }
    /* Hashes cannot be provided by user */
    if (!dot && !bracket &&
        (known_field == METADATA_FIELD_PAYLOAD_HASH || known_field == METADATA_FIELD_ARCHIVE_HASH)) {
        if (error_msg) {
            *error_msg = "hashes are computed by Azdora and cannot be set";
        }
        return AZDORA_METADATA_ERR_UNSUPPORTED_KEY;
    }

    /* Handle array syntax on top-level key */
    if (bracket && (!dot || bracket < dot)) {
        const char *after_bracket = bracket + 1;
        bool append = false;
        size_t index = 0;
        if (*after_bracket == ']') {
            append = true;
        } else {
            char *endptr = NULL;
            index = (size_t)strtoul(after_bracket, &endptr, 10);
            if (!endptr || *endptr != ']') {
                if (error_msg) {
                    *error_msg = "invalid array index";
                }
                return AZDORA_METADATA_ERR_PARSE;
            }
        }

        size_t base_len = (size_t)(bracket - path);
        if (!metadata_core_identifier_valid(path, base_len)) {
            if (error_msg) {
                *error_msg = "invalid array name";
            }
            return AZDORA_METADATA_ERR_PARSE;
        }

        if (is_known && expected_kind != METADATA_EXPECT_ARRAY_STRING) {
            if (error_msg) {
                *error_msg = "field is not an array";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }

        bool created = false;
        azdora_meta_value_t *arr_val = map_get_or_create(&metadata->root, path, base_len, &created, error_msg);
        if (!arr_val) {
            return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
        }
        if (!created && arr_val->type != AZDORA_META_ARRAY) {
            if (error_msg) {
                *error_msg = "array path used for non-array";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        if (created) {
            arr_val->type = AZDORA_META_ARRAY;
            arr_val->as.array.count = 0;
            arr_val->as.array.capacity = 0;
            arr_val->as.array.items = NULL;
        }

        if (expected_kind == METADATA_EXPECT_ARRAY_STRING && val_type != AZDORA_META_STRING) {
            if (error_msg) {
                *error_msg = "array elements must be strings";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }

        size_t target_index = append ? arr_val->as.array.count : index;
        if (!append && target_index > arr_val->as.array.count) {
            if (error_msg) {
                *error_msg = "array indices must be dense";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }

        azdora_meta_value_t *slot = ensure_array_slot(arr_val, target_index, error_msg);
        if (!slot) {
            return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
        }

        return set_scalar_value(slot, val_type, typed_value, error_msg);
    }

    /* Handle map entry (MAP.KEY) */
    if (dot) {
        size_t map_name_len = (size_t)(dot - path);
        const char *map_name = path;
        const char *leaf = dot + 1;
        size_t leaf_len = path_len - (size_t)(leaf - path);
        if (!metadata_core_identifier_valid(leaf, leaf_len)) {
            if (error_msg) {
                *error_msg = "invalid map key";
            }
            return AZDORA_METADATA_ERR_PARSE;
        }

        metadata_core_field_t map_field = METADATA_FIELD_UNKNOWN;
        bool map_known = metadata_core_field_lookup(map_name, map_name_len, &map_field);
        metadata_core_expected_kind_t map_expected =
            map_known ? metadata_core_expected_kind(map_field) : METADATA_EXPECT_ANY;
        if (map_known && map_expected != METADATA_EXPECT_MAP_STRING) {
            if (error_msg) {
                *error_msg = "field is not a map";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        if (map_field == METADATA_FIELD_ENV && !env_key_shell_safe(leaf, leaf_len)) {
            if (error_msg) {
                *error_msg = "ENV keys must match [A-Za-z_][A-Za-z0-9_]*";
            }
            return AZDORA_METADATA_ERR_PARSE;
        }
        if (map_known && map_expected == METADATA_EXPECT_MAP_STRING && val_type != AZDORA_META_STRING) {
            if (error_msg) {
                *error_msg = (map_field == METADATA_FIELD_ENV)
                                 ? "ENV entries must be strings"
                                 : "map entries must be strings";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }

        bool created = false;
        azdora_meta_value_t *map_val = map_get_or_create(&metadata->root, map_name, map_name_len, &created, error_msg);
        if (!map_val) {
            return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
        }
        if (!created && map_val->type != AZDORA_META_MAP) {
            if (error_msg) {
                *error_msg = "map path used for non-map";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        if (created) {
            map_val->type = AZDORA_META_MAP;
            map_val->as.map.count = 0;
            map_val->as.map.capacity = 0;
            map_val->as.map.entries = NULL;
        }

        azdora_meta_value_t *leaf_val = map_put_scalar(&map_val->as.map, leaf, leaf_len, val_type, typed_value, error_msg);
        if (!leaf_val) {
            return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
        }
        return AZDORA_METADATA_OK;
    }

    /* Top-level scalar (with validations for known keys) */
    if (!dot && !bracket && strncmp(path, "PAYLOAD_HASH", path_len) == 0) {
        if (error_msg) {
            *error_msg = "PAYLOAD_HASH is computed by Azdora";
        }
        return AZDORA_METADATA_ERR_UNSUPPORTED_KEY;
    } else if (!dot && !bracket && strncmp(path, "ARCHIVE_HASH", path_len) == 0) {
        if (error_msg) {
            *error_msg = "ARCHIVE_HASH is computed by Azdora";
        }
        return AZDORA_METADATA_ERR_UNSUPPORTED_KEY;
    }

    if (!dot && !bracket && is_known) {
        if (expected_kind == METADATA_EXPECT_ARRAY_STRING) {
            if (error_msg) {
                *error_msg = "field is an array";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        } else if (expected_kind == METADATA_EXPECT_MAP_STRING) {
            if (error_msg) {
                *error_msg = "field is a map";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        azdora_metadata_result_t kind_rc = enforce_scalar_kind(expected_kind, val_type, error_msg);
        if (kind_rc != AZDORA_METADATA_OK) {
            return kind_rc;
        }
    }

    azdora_meta_value_t *val = map_put_scalar(&metadata->root, path, path_len, val_type, typed_value, error_msg);
    if (!val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }

    return AZDORA_METADATA_OK;
}

azdora_metadata_result_t azdora_metadata_finalize(azdora_metadata_t *metadata,
                                                  const char **error_msg)
{
    if (!metadata) {
        if (error_msg) {
            *error_msg = "invalid metadata";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }

    /* Set defaults and validate required fields */
    return ensure_required_defaults(metadata, error_msg);
}

/* ------------------------------------------------------------------------- */
/* Accessors                                                                 */
/* ------------------------------------------------------------------------- */

const azdora_meta_map_t *azdora_metadata_root(const azdora_metadata_t *metadata)
{
    return metadata ? &metadata->root : NULL;
}

static azdora_meta_value_t *find_field_value(const azdora_metadata_t *metadata,
                                             metadata_core_field_t field)
{
    if (!metadata) {
        return NULL;
    }
    const char *key = metadata_core_field_name(field);
    if (!key) {
        return NULL;
    }
    return map_find(&metadata->root, key, strlen(key));
}

azdora_metadata_result_t azdora_metadata_get_string(const azdora_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    const char **out,
                                                    const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const azdora_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != AZDORA_META_STRING) {
        if (error_msg) {
            *error_msg = "field not present or not a string";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.str;
    return AZDORA_METADATA_OK;
}

azdora_metadata_result_t azdora_metadata_get_bool(const azdora_metadata_t *metadata,
                                                  metadata_core_field_t field,
                                                  bool *out,
                                                  const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const azdora_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != AZDORA_META_BOOL) {
        if (error_msg) {
            *error_msg = "field not present or not a bool";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.bool_val;
    return AZDORA_METADATA_OK;
}

azdora_metadata_result_t azdora_metadata_get_uint(const azdora_metadata_t *metadata,
                                                  metadata_core_field_t field,
                                                  uint64_t *out,
                                                  const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const azdora_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != AZDORA_META_UINT) {
        if (error_msg) {
            *error_msg = "field not present or not a uint";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.uint_val;
    return AZDORA_METADATA_OK;
}

azdora_metadata_result_t azdora_metadata_get_bytes(const azdora_metadata_t *metadata,
                                                   metadata_core_field_t field,
                                                   const uint8_t **out,
                                                   size_t *len_out,
                                                   const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const azdora_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != AZDORA_META_BYTES) {
        if (error_msg) {
            *error_msg = "field not present or not bytes";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.bytes.data;
    if (len_out) {
        *len_out = val->as.bytes.len;
    }
    return AZDORA_METADATA_OK;
}

void azdora_metadata_print(const azdora_metadata_t *metadata, FILE *stream)
{
    if (!stream) {
        stream = stderr;
    }
    const azdora_meta_map_t *root = azdora_metadata_root(metadata);
    if (!root) {
        return;
    }
    metadata_print_map(root, 0, stream);
}

/* Typed setters built on top of the generic map */
azdora_metadata_result_t azdora_metadata_set_field_string(azdora_metadata_t *metadata,
                                                          metadata_core_field_t field,
                                                          const char *value,
                                                          const char **error_msg)
{
    if (!metadata || !value) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const char *key = metadata_core_field_name(field);
    if (!key) {
        if (error_msg) {
            *error_msg = "unknown field";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    if (metadata_core_expected_kind(field) != METADATA_EXPECT_STRING &&
        metadata_core_expected_kind(field) != METADATA_EXPECT_ANY) {
        if (error_msg) {
            *error_msg = "field not string-typed";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    bool created = false;
    azdora_meta_value_t *val = map_get_or_create(&metadata->root, key, strlen(key), &created, error_msg);
    if (!val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    if (created) {
        val->type = AZDORA_META_STRING;
    }
    return set_scalar_value(val, AZDORA_META_STRING, value, error_msg);
}

azdora_metadata_result_t azdora_metadata_set_field_bool(azdora_metadata_t *metadata,
                                                        metadata_core_field_t field,
                                                        bool value,
                                                        const char **error_msg)
{
    if (!metadata) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const char *key = metadata_core_field_name(field);
    if (!key) {
        if (error_msg) {
            *error_msg = "unknown field";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    if (metadata_core_expected_kind(field) != METADATA_EXPECT_BOOL &&
        metadata_core_expected_kind(field) != METADATA_EXPECT_ANY) {
        if (error_msg) {
            *error_msg = "field not bool-typed";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    bool created = false;
    azdora_meta_value_t *val = map_get_or_create(&metadata->root, key, strlen(key), &created, error_msg);
    if (!val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    if (created) {
        val->type = AZDORA_META_BOOL;
    }
    return set_scalar_value(val, AZDORA_META_BOOL, value ? "true" : "false", error_msg);
}

azdora_metadata_result_t azdora_metadata_set_field_uint(azdora_metadata_t *metadata,
                                                        metadata_core_field_t field,
                                                        uint64_t value,
                                                        const char **error_msg)
{
    if (!metadata) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const char *key = metadata_core_field_name(field);
    if (!key) {
        if (error_msg) {
            *error_msg = "unknown field";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    metadata_core_expected_kind_t expect = metadata_core_expected_kind(field);
    if (expect != METADATA_EXPECT_UINT && expect != METADATA_EXPECT_ANY) {
        if (error_msg) {
            *error_msg = "field not uint-typed";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    azdora_meta_value_t *val = map_put_uint(&metadata->root, key, strlen(key), value, error_msg);
    if (!val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    return AZDORA_METADATA_OK;
}

azdora_metadata_result_t azdora_metadata_set_field_bytes(azdora_metadata_t *metadata,
                                                         metadata_core_field_t field,
                                                         const uint8_t *data,
                                                         size_t len,
                                                         const char **error_msg)
{
    if (!metadata) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const char *key = metadata_core_field_name(field);
    if (!key) {
        if (error_msg) {
            *error_msg = "unknown field";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    metadata_core_expected_kind_t expect = metadata_core_expected_kind(field);
    if (expect != METADATA_EXPECT_BYTES && expect != METADATA_EXPECT_ANY) {
        if (error_msg) {
            *error_msg = "field not bytes-typed";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    azdora_meta_value_t *val = map_put_bytes(&metadata->root, key, strlen(key), data, len, error_msg);
    if (!val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    return AZDORA_METADATA_OK;
}

azdora_metadata_result_t azdora_metadata_add_array_string(azdora_metadata_t *metadata,
                                                          metadata_core_field_t field,
                                                          size_t index,
                                                          bool append,
                                                          const char *value,
                                                          const char **error_msg)
{
    if (!metadata || !value) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    if (metadata_core_expected_kind(field) != METADATA_EXPECT_ARRAY_STRING) {
        if (error_msg) {
            *error_msg = "field is not an array of strings";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    const char *key = metadata_core_field_name(field);
    if (!key) {
        if (error_msg) {
            *error_msg = "unknown field";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    bool created = false;
    azdora_meta_value_t *arr_val = map_get_or_create(&metadata->root, key, strlen(key), &created, error_msg);
    if (!arr_val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    if (!created && arr_val->type != AZDORA_META_ARRAY) {
        if (error_msg) {
            *error_msg = "field already set to non-array";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    if (created) {
        arr_val->type = AZDORA_META_ARRAY;
        arr_val->as.array.count = 0;
        arr_val->as.array.capacity = 0;
        arr_val->as.array.items = NULL;
    }
    size_t target_index = append ? arr_val->as.array.count : index;
    if (!append && target_index > arr_val->as.array.count) {
        if (error_msg) {
            *error_msg = "array indices must be dense";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    azdora_meta_value_t *slot = ensure_array_slot(arr_val, target_index, error_msg);
    if (!slot) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    return set_scalar_value(slot, AZDORA_META_STRING, value, error_msg);
}

azdora_metadata_result_t azdora_metadata_set_map_entry_string(azdora_metadata_t *metadata,
                                                              metadata_core_field_t field,
                                                              const char *key,
                                                              const char *value,
                                                              const char **error_msg)
{
    if (!metadata || !key || !value) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    if (metadata_core_expected_kind(field) != METADATA_EXPECT_MAP_STRING) {
        if (error_msg) {
            *error_msg = "field is not a string map";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    const char *map_name = metadata_core_field_name(field);
    if (!map_name) {
        if (error_msg) {
            *error_msg = "unknown field";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    if (!metadata_core_identifier_valid(key, strlen(key))) {
        if (error_msg) {
            *error_msg = "invalid map key";
        }
        return AZDORA_METADATA_ERR_PARSE;
    }

    bool created = false;
    azdora_meta_value_t *map_val = map_get_or_create(&metadata->root, map_name, strlen(map_name), &created, error_msg);
    if (!map_val) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    if (!created && map_val->type != AZDORA_META_MAP) {
        if (error_msg) {
            *error_msg = "field already set to non-map";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }
    if (created) {
        map_val->type = AZDORA_META_MAP;
        map_val->as.map.count = 0;
        map_val->as.map.capacity = 0;
        map_val->as.map.entries = NULL;
    }

    azdora_meta_value_t *leaf = map_put_scalar(&map_val->as.map, key, strlen(key), AZDORA_META_STRING, value, error_msg);
    if (!leaf) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    return AZDORA_METADATA_OK;
}

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static azdora_metadata_result_t parse_hex_bytes(const char *hex,
                                                size_t expected_bytes,
                                                uint8_t *out,
                                                const char **error_msg)
{
    if (!hex || !out) {
        if (error_msg) {
            *error_msg = "invalid hex input";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    size_t hex_len = strlen(hex);
    if (hex_len != expected_bytes * 2) {
        if (error_msg) {
            *error_msg = "hex length mismatch";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    }

    for (size_t i = 0; i < expected_bytes; ++i) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            if (error_msg) {
                *error_msg = "hex contains non-hex characters";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return AZDORA_METADATA_OK;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2; /* padding */
    return -1;
}

static azdora_metadata_result_t parse_base64(const char *in, uint8_t **out, size_t *out_len)
{
    size_t len = strlen(in);
    if (len == 0) {
        *out = NULL;
        *out_len = 0;
        return AZDORA_METADATA_OK;
    }
    size_t blocks = len / 4;
    uint8_t *buf = malloc(blocks * 3);
    if (!buf) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }
    size_t o = 0;
    for (size_t i = 0; i < blocks; ++i) {
        int v0 = b64_val(in[i * 4 + 0]);
        int v1 = b64_val(in[i * 4 + 1]);
        int v2 = b64_val(in[i * 4 + 2]);
        int v3 = b64_val(in[i * 4 + 3]);
        if (v0 < 0 || v1 < 0 || v2 == -1 || v3 == -1) {
            free(buf);
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        uint32_t triple = ((uint32_t)(v0 & 0x3F) << 18) |
                          ((uint32_t)(v1 & 0x3F) << 12) |
                          ((uint32_t)((v2 < 0 ? 0 : v2) & 0x3F) << 6) |
                          ((uint32_t)((v3 < 0 ? 0 : v3) & 0x3F));
        buf[o++] = (triple >> 16) & 0xFF;
        if (v2 != -2) {
            buf[o++] = (triple >> 8) & 0xFF;
        }
        if (v3 != -2) {
            buf[o++] = triple & 0xFF;
        }
        if (v2 == -2 || v3 == -2) {
            break;
        }
    }
    *out = buf;
    *out_len = o;
    return AZDORA_METADATA_OK;
}

static azdora_meta_value_t *value_new(void)
{
    azdora_meta_value_t *v = calloc(1, sizeof(*v));
    return v;
}

static void value_reset(azdora_meta_value_t *value)
{
    if (!value) {
        return;
    }
    switch (value->type) {
    case AZDORA_META_STRING:
        free(value->as.str);
        break;
    case AZDORA_META_BYTES:
        free(value->as.bytes.data);
        break;
    case AZDORA_META_ARRAY:
        array_destroy(&value->as.array);
        break;
    case AZDORA_META_MAP:
        map_destroy(&value->as.map);
        break;
    case AZDORA_META_UINT:
    case AZDORA_META_BOOL:
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

static void value_destroy(azdora_meta_value_t *value)
{
    if (!value) {
        return;
    }
    value_reset(value);
    free(value);
}

static void map_destroy(azdora_meta_map_t *map)
{
    if (!map || !map->entries) {
        return;
    }
    for (size_t i = 0; i < map->count; ++i) {
        free(map->entries[i].key);
        value_destroy(map->entries[i].value);
    }
    free(map->entries);
    map->entries = NULL;
    map->count = 0;
    map->capacity = 0;
}

static void array_destroy(azdora_meta_array_t *array)
{
    if (!array || !array->items) {
        return;
    }
    for (size_t i = 0; i < array->count; ++i) {
        value_reset(&array->items[i]);
    }
    free(array->items);
    array->items = NULL;
    array->count = 0;
    array->capacity = 0;
}

static azdora_meta_value_t *map_find(const azdora_meta_map_t *map,
                                     const char *key,
                                     size_t key_len)
{
    if (!map) {
        return NULL;
    }
    for (size_t i = 0; i < map->count; ++i) {
        if (strlen(map->entries[i].key) == key_len &&
            strncmp(map->entries[i].key, key, key_len) == 0) {
            return map->entries[i].value;
        }
    }
    return NULL;
}

static azdora_metadata_result_t enforce_scalar_kind(metadata_core_expected_kind_t expected,
                                                    azdora_meta_type_t actual,
                                                    const char **error_msg)
{
    switch (expected) {
    case METADATA_EXPECT_ANY:
        return AZDORA_METADATA_OK;
    case METADATA_EXPECT_STRING:
        if (actual != AZDORA_META_STRING) {
            if (error_msg) {
                *error_msg = "field must be a string";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        return AZDORA_METADATA_OK;
    case METADATA_EXPECT_UINT:
        if (actual != AZDORA_META_UINT) {
            if (error_msg) {
                *error_msg = "field must be an unsigned integer";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        return AZDORA_METADATA_OK;
    case METADATA_EXPECT_BOOL:
        if (actual != AZDORA_META_BOOL) {
            if (error_msg) {
                *error_msg = "field must be a boolean";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        return AZDORA_METADATA_OK;
    case METADATA_EXPECT_BYTES:
        if (actual != AZDORA_META_BYTES) {
            if (error_msg) {
                *error_msg = "field must be binary data";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        return AZDORA_METADATA_OK;
    case METADATA_EXPECT_ARRAY_STRING:
        if (error_msg) {
            *error_msg = "field is an array, not a scalar";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    case METADATA_EXPECT_MAP_STRING:
        if (error_msg) {
            *error_msg = "field is a map, not a scalar";
        }
        return AZDORA_METADATA_ERR_BAD_VALUE;
    default:
        return AZDORA_METADATA_OK;
    }
}

static void metadata_print_indent(int indent, FILE *stream)
{
    for (int i = 0; i < indent; ++i) {
        fputc(' ', stream);
    }
}

static void metadata_print_value(const azdora_meta_value_t *val, int indent, FILE *stream)
{
    switch (val->type) {
    case AZDORA_META_STRING:
        fprintf(stream, "\"%s\"", val->as.str ? val->as.str : "");
        break;
    case AZDORA_META_UINT:
        fprintf(stream, "%llu", (unsigned long long)val->as.uint_val);
        break;
    case AZDORA_META_BOOL:
        fprintf(stream, "%s", val->as.bool_val ? "true" : "false");
        break;
    case AZDORA_META_BYTES:
        fprintf(stream, "hex:");
        for (size_t i = 0; i < val->as.bytes.len; ++i) {
            fprintf(stream, "%02x", val->as.bytes.data ? val->as.bytes.data[i] : 0);
        }
        break;
    case AZDORA_META_ARRAY:
        fprintf(stream, "[\n");
        for (size_t i = 0; i < val->as.array.count; ++i) {
            metadata_print_indent(indent + 2, stream);
            metadata_print_value(&val->as.array.items[i], indent + 2, stream);
            if (i + 1 < val->as.array.count) {
                fprintf(stream, ",");
            }
            fprintf(stream, "\n");
        }
        metadata_print_indent(indent, stream);
        fprintf(stream, "]");
        break;
    case AZDORA_META_MAP:
        fprintf(stream, "{\n");
        metadata_print_map(&val->as.map, indent + 2, stream);
        metadata_print_indent(indent, stream);
        fprintf(stream, "}");
        break;
    default:
        fprintf(stream, "<unknown>");
        break;
    }
}

static void metadata_print_map(const azdora_meta_map_t *map, int indent, FILE *stream)
{
    for (size_t i = 0; i < map->count; ++i) {
        metadata_print_indent(indent, stream);
        fprintf(stream, "%s: ", map->entries[i].key);
        metadata_print_value(map->entries[i].value, indent, stream);
        if (i + 1 < map->count) {
            fprintf(stream, ",");
        }
        fprintf(stream, "\n");
    }
}

static bool env_key_shell_safe(const char *key, size_t len)
{
    if (!key || len == 0) {
        return false;
    }
    unsigned char first = (unsigned char)key[0];
    if (!(isalpha(first) || first == '_')) {
        return false;
    }
    for (size_t i = 1; i < len; ++i) {
        unsigned char c = (unsigned char)key[i];
        if (!(isalnum(c) || c == '_')) {
            return false;
        }
    }
    return true;
}

static azdora_meta_value_t *map_put_bytes(azdora_meta_map_t *map,
                                          const char *key,
                                          size_t key_len,
                                          const uint8_t *bytes,
                                          size_t len,
                                          const char **error_msg)
{
    bool created = false;
    azdora_meta_value_t *val = map_get_or_create(map, key, key_len, &created, error_msg);
    if (!val) {
        return NULL;
    }
    value_reset(val);
    val->type = AZDORA_META_BYTES;
    if (len == 0) {
        val->as.bytes.data = NULL;
        val->as.bytes.len = 0;
        return val;
    }
    val->as.bytes.data = malloc(len);
    if (!val->as.bytes.data) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return NULL;
    }
    memcpy(val->as.bytes.data, bytes, len);
    val->as.bytes.len = len;
    return val;
}

static azdora_meta_value_t *map_get_or_create(azdora_meta_map_t *map,
                                              const char *key,
                                              size_t key_len,
                                              bool *created,
                                              const char **error_msg)
{
    azdora_meta_value_t *existing = map_find(map, key, key_len);
    if (existing) {
        if (created) {
            *created = false;
        }
        return existing;
    }

    if (map->count == map->capacity) {
        size_t new_cap = map->capacity ? map->capacity * 2 : 4;
        azdora_meta_map_entry_t *new_entries = realloc(map->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return NULL;
        }
        map->entries = new_entries;
        map->capacity = new_cap;
    }

    azdora_meta_value_t *val = value_new();
    if (!val) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return NULL;
    }
    map->entries[map->count].key = strndup(key, key_len);
    if (!map->entries[map->count].key) {
        value_destroy(val);
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return NULL;
    }
    map->entries[map->count].value = val;
    map->count += 1;
    if (created) {
        *created = true;
    }
    return val;
}

static azdora_meta_value_t *ensure_array_slot(azdora_meta_value_t *array_value,
                                              size_t index,
                                              const char **error_msg)
{
    if (!array_value || array_value->type != AZDORA_META_ARRAY) {
        if (error_msg) {
            *error_msg = "not an array";
        }
        return NULL;
    }
    azdora_meta_array_t *arr = &array_value->as.array;
    if (index >= arr->capacity) {
        size_t new_cap = arr->capacity ? arr->capacity : 4;
        while (new_cap <= index) {
            new_cap *= 2;
        }
        azdora_meta_value_t *new_items = realloc(arr->items, new_cap * sizeof(*new_items));
        if (!new_items) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return NULL;
        }
        /* Initialize new slots */
        for (size_t i = arr->capacity; i < new_cap; ++i) {
            memset(&new_items[i], 0, sizeof(new_items[i]));
        }
        arr->items = new_items;
        arr->capacity = new_cap;
    }
    if (index >= arr->count) {
        arr->count = index + 1;
    }
    return &arr->items[index];
}

static azdora_metadata_result_t set_scalar_value(azdora_meta_value_t *value,
                                                 azdora_meta_type_t type,
                                                 const char *str_value,
                                                 const char **error_msg)
{
    if (!value) {
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }

    /* Clean previous content */
    value_reset(value);

    value->type = type;
    switch (type) {
    case AZDORA_META_STRING:
        value->as.str = strdup(str_value ? str_value : "");
        if (!value->as.str) {
            return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
        }
        break;
    case AZDORA_META_UINT: {
        char *endptr = NULL;
        value->as.uint_val = strtoull(str_value, &endptr, 10);
        if (!endptr || *endptr != '\0') {
            if (error_msg) {
                *error_msg = "invalid unsigned integer";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        break;
    }
    case AZDORA_META_BOOL:
        if (strcmp(str_value, "true") == 0 || strcmp(str_value, "1") == 0) {
            value->as.bool_val = true;
        } else if (strcmp(str_value, "false") == 0 || strcmp(str_value, "0") == 0) {
            value->as.bool_val = false;
        } else {
            if (error_msg) {
                *error_msg = "invalid boolean (use true/false)";
            }
            return AZDORA_METADATA_ERR_BAD_VALUE;
        }
        break;
    case AZDORA_META_BYTES: {
        /* Decide between hex and base64 based on prefix already stripped */
        size_t len = strlen(str_value);
        azdora_metadata_result_t rc;
        if (strstr(str_value, "+") || strstr(str_value, "/") || strstr(str_value, "=")) {
            uint8_t *buf = NULL;
            size_t out_len = 0;
            rc = parse_base64(str_value, &buf, &out_len);
            if (rc != AZDORA_METADATA_OK) {
                if (error_msg) {
                    *error_msg = "invalid base64 value";
                }
                return rc;
            }
            value->as.bytes.data = buf;
            value->as.bytes.len = out_len;
        } else {
            if (len % 2 != 0) {
                if (error_msg) {
                    *error_msg = "hex length must be even";
                }
                return AZDORA_METADATA_ERR_BAD_VALUE;
            }
            uint8_t *buf = malloc(len / 2);
            if (!buf) {
                return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
            }
            rc = parse_hex_bytes(str_value, len / 2, buf, error_msg);
            if (rc != AZDORA_METADATA_OK) {
                free(buf);
                return rc;
            }
            value->as.bytes.data = buf;
            value->as.bytes.len = len / 2;
        }
        break;
    }
    case AZDORA_META_ARRAY:
    case AZDORA_META_MAP:
    default:
        if (error_msg) {
            *error_msg = "invalid scalar type";
        }
        return AZDORA_METADATA_ERR_INVALID_ARGUMENT;
    }
    return AZDORA_METADATA_OK;
}

static azdora_meta_value_t *map_put_scalar(azdora_meta_map_t *map,
                                           const char *key,
                                           size_t key_len,
                                           azdora_meta_type_t type,
                                           const char *str_value,
                                           const char **error_msg)
{
    bool created = false;
    azdora_meta_value_t *val = map_get_or_create(map, key, key_len, &created, error_msg);
    if (!val) {
        return NULL;
    }
    azdora_metadata_result_t rc = set_scalar_value(val, type, str_value, error_msg);
    if (rc != AZDORA_METADATA_OK) {
        return NULL;
    }
    return val;
}

static azdora_meta_value_t *map_put_uint(azdora_meta_map_t *map,
                                         const char *key,
                                         size_t key_len,
                                         uint64_t value,
                                         const char **error_msg)
{
    bool created = false;
    azdora_meta_value_t *val = map_get_or_create(map, key, key_len, &created, error_msg);
    if (!val) {
        return NULL;
    }
    value_reset(val);
    val->type = AZDORA_META_UINT;
    val->as.uint_val = value;
    return val;
}

static azdora_metadata_result_t ensure_required_defaults(azdora_metadata_t *metadata,
                                                         const char **error_msg)
{
    /* VERSION defaults to 1 */
    azdora_meta_value_t *version =
        map_put_uint(&metadata->root, "VERSION", strlen("VERSION"),
                     METADATA_CORE_SCHEMA_VERSION, error_msg);
    if (!version) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }

    /* ENTRY_POINT required */
    azdora_meta_value_t *entry = map_find(&metadata->root, "ENTRY_POINT", strlen("ENTRY_POINT"));
    if (!entry || entry->type != AZDORA_META_STRING) {
        if (error_msg) {
            *error_msg = "ENTRY_POINT is required and must be text";
        }
        return AZDORA_METADATA_ERR_MISSING_REQUIRED;
    }

    /* PAYLOAD_HASH default to zeros */
    static const uint8_t zero_hash[32] = {0};
    if (!map_put_bytes(&metadata->root, "PAYLOAD_HASH", strlen("PAYLOAD_HASH"),
                       zero_hash, sizeof(zero_hash), error_msg)) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }

    /* ARCHIVE_HASH default zeros (bytes) */
    if (!map_put_bytes(&metadata->root, "ARCHIVE_HASH", strlen("ARCHIVE_HASH"),
                       zero_hash, sizeof(zero_hash), error_msg)) {
        return AZDORA_METADATA_ERR_OUT_OF_MEMORY;
    }

    return AZDORA_METADATA_OK;
}
