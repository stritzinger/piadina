/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata.c
 * @brief Piadina launcher metadata representation and CBOR decoding.
 */
#include "metadata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "common/cbor_core.h"
#include "common/metadata_core.h"

static char g_error_buf[256];

/* ------------------------------------------------------------------------- */
/* Helpers forward declarations                                             */
/* ------------------------------------------------------------------------- */
static bool env_key_shell_safe(const char *key, size_t len);
static void value_reset(piadina_meta_value_t *value);
static void value_destroy(piadina_meta_value_t *value);
static void map_destroy(piadina_meta_map_t *map);
static void array_destroy(piadina_meta_array_t *array);
static piadina_meta_value_t *map_get_or_create(piadina_meta_map_t *map,
                                               const char *key,
                                               size_t key_len,
                                               bool *created);
static piadina_meta_value_t *map_put_string(piadina_meta_map_t *map,
                                            const char *key,
                                            size_t key_len,
                                            const char *value);
static piadina_meta_value_t *map_put_uint(piadina_meta_map_t *map,
                                         const char *key,
                                         size_t key_len,
                                         uint64_t value);
static piadina_meta_value_t *map_put_bool(piadina_meta_map_t *map,
                                          const char *key,
                                          size_t key_len,
                                          bool value);
static piadina_meta_value_t *map_put_bytes(piadina_meta_map_t *map,
                                           const char *key,
                                           size_t key_len,
                                           const uint8_t *data,
                                           size_t len);
static piadina_meta_value_t *map_find(const piadina_meta_map_t *map,
                                      const char *key,
                                      size_t key_len);
static piadina_meta_value_t *ensure_array_slot(piadina_meta_value_t *array_value,
                                               size_t index);
static piadina_metadata_result_t set_default_string_if_missing(piadina_metadata_t *metadata,
                                                               const char *key,
                                                               const char *default_value,
                                                               const char **error_msg);
static piadina_metadata_result_t set_default_bool_if_missing(piadina_metadata_t *metadata,
                                                             const char *key,
                                                             bool default_value,
                                                             const char **error_msg);
static piadina_metadata_result_t decode_value_into(piadina_meta_value_t *out,
                                                   metadata_core_expected_kind_t expected,
                                                   const cbor_core_value_t *value,
                                                   const char *key_name,
                                                   const char **error_msg);
static piadina_metadata_result_t decode_map_entries(piadina_meta_map_t *map,
                                                    const cbor_core_value_t *map_val,
                                                    bool enforce_env_rules,
                                                    const char **error_msg);
static piadina_metadata_result_t ensure_required_defaults(piadina_metadata_t *metadata,
                                                          const char **error_msg);
static piadina_metadata_result_t validate_required_fields(piadina_metadata_t *metadata,
                                                          const char **error_msg);

/* ------------------------------------------------------------------------- */
/* Public API                                                                */
/* ------------------------------------------------------------------------- */

const char *piadina_metadata_result_to_string(piadina_metadata_result_t rc)
{
    switch (rc) {
    case PIADINA_METADATA_OK:
        return "ok";
    case PIADINA_METADATA_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case PIADINA_METADATA_ERR_DECODE:
        return "decode error";
    case PIADINA_METADATA_ERR_UNSUPPORTED_KEY:
        return "unsupported key";
    case PIADINA_METADATA_ERR_MISSING_REQUIRED:
        return "missing required field";
    case PIADINA_METADATA_ERR_BAD_VALUE:
        return "bad field value";
    case PIADINA_METADATA_ERR_OUT_OF_MEMORY:
        return "out of memory";
    case PIADINA_METADATA_ERR_UNSUPPORTED_VERSION:
        return "unsupported version";
    default:
        return "unknown error";
    }
}

void piadina_metadata_init(piadina_metadata_t *metadata)
{
    if (!metadata) {
        return;
    }
    metadata_tree_map_init(&metadata->root);
}

void piadina_metadata_destroy(piadina_metadata_t *metadata)
{
    if (!metadata) {
        return;
    }
    metadata_tree_map_destroy(&metadata->root);
}

piadina_metadata_result_t piadina_metadata_apply_overrides(piadina_metadata_t *metadata,
                                                           const char *cache_root,
                                                           const char *cleanup,
                                                           int validate,
                                                           const char **error_msg)
{
    if (!metadata) {
        if (error_msg) {
            *error_msg = "invalid metadata arguments";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }

    /* CACHE_ROOT */
    if (cache_root) {
        if (!map_put_string(&metadata->root, "CACHE_ROOT", strlen("CACHE_ROOT"), cache_root)) {
            if (error_msg) {
                *error_msg = "failed to apply CACHE_ROOT override";
            }
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
    }

    /* CLEANUP_POLICY */
    if (cleanup) {
        if (metadata_core_cleanup_policy_from_string(cleanup) == METADATA_CLEANUP_INVALID) {
            if (error_msg) {
                *error_msg = "invalid cleanup policy override";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        if (!map_put_string(&metadata->root, "CLEANUP_POLICY", strlen("CLEANUP_POLICY"), cleanup)) {
            if (error_msg) {
                *error_msg = "failed to apply CLEANUP_POLICY override";
            }
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
    }

    /* VALIDATE */
    if (validate == 0 || validate == 1) {
        if (!map_put_bool(&metadata->root, "VALIDATE", strlen("VALIDATE"), validate == 1)) {
            if (error_msg) {
                *error_msg = "failed to apply VALIDATE override";
            }
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
    }

    return PIADINA_METADATA_OK;
}

piadina_metadata_result_t piadina_metadata_decode(const uint8_t *data,
                                                  size_t size,
                                                  piadina_metadata_t *metadata,
                                                  const char **error_msg)
{
    if (!data || size == 0 || !metadata) {
        if (error_msg) {
            *error_msg = "invalid metadata buffer";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }

    cbor_core_decoder_t *decoder = cbor_core_decoder_new(data, size);
    if (!decoder) {
        if (error_msg) {
            *error_msg = "failed to create CBOR decoder";
        }
        return PIADINA_METADATA_ERR_DECODE;
    }

    cbor_core_value_t root_val = {0};
    cbor_core_result_t rc = cbor_core_decoder_root(decoder, &root_val);
    if (rc != CBOR_CORE_OK || cbor_core_value_type(&root_val) != CBOR_CORE_TYPE_MAP) {
        if (error_msg) {
            *error_msg = "metadata root must be a map";
        }
        cbor_core_decoder_destroy(decoder);
        return PIADINA_METADATA_ERR_DECODE;
    }

    size_t pairs = cbor_core_map_size(&root_val);
    for (size_t i = 0; i < pairs; ++i) {
        cbor_core_value_t key = {0};
        cbor_core_value_t val = {0};
        if (cbor_core_map_get(&root_val, i, &key, &val) != CBOR_CORE_OK) {
            if (error_msg) {
                *error_msg = "failed to read metadata entry";
            }
            cbor_core_decoder_destroy(decoder);
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (cbor_core_value_type(&key) != CBOR_CORE_TYPE_TEXT) {
            if (error_msg) {
                *error_msg = "metadata keys must be text";
            }
            cbor_core_decoder_destroy(decoder);
            return PIADINA_METADATA_ERR_DECODE;
        }
        const char *key_str = NULL;
        size_t key_len = 0;
        if (cbor_core_value_get_text(&key, &key_str, &key_len) != CBOR_CORE_OK) {
            if (error_msg) {
                *error_msg = "failed to read metadata key";
            }
            cbor_core_decoder_destroy(decoder);
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (!metadata_core_identifier_valid(key_str, key_len)) {
            if (error_msg) {
                *error_msg = "invalid metadata key";
            }
            cbor_core_decoder_destroy(decoder);
            return PIADINA_METADATA_ERR_DECODE;
        }

        metadata_core_field_t field = METADATA_FIELD_UNKNOWN;
        bool known = metadata_core_field_lookup(key_str, key_len, &field);
        metadata_core_expected_kind_t expected_kind =
            known ? metadata_core_expected_kind(field) : METADATA_EXPECT_ANY;

        /* Decode into a fresh value then store */
        piadina_meta_value_t *stored = map_get_or_create(&metadata->root, key_str, key_len, NULL);
        if (!stored) {
            cbor_core_decoder_destroy(decoder);
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
        piadina_metadata_result_t decode_rc =
            decode_value_into(stored, expected_kind, &val, key_str, error_msg);
        if (decode_rc != PIADINA_METADATA_OK) {
            cbor_core_decoder_destroy(decoder);
            return decode_rc;
        }

        if (field == METADATA_FIELD_ENV && stored->type == PIADINA_META_MAP) {
            piadina_metadata_result_t env_rc =
                decode_map_entries(&stored->as.map, &val, true, error_msg);
            if (env_rc != PIADINA_METADATA_OK) {
                cbor_core_decoder_destroy(decoder);
                return env_rc;
            }
        } else if (stored->type == PIADINA_META_MAP) {
            piadina_metadata_result_t map_rc =
                decode_map_entries(&stored->as.map, &val, false, error_msg);
            if (map_rc != PIADINA_METADATA_OK) {
                cbor_core_decoder_destroy(decoder);
                return map_rc;
            }
        } else if (stored->type == PIADINA_META_ARRAY) {
            /* Already decoded in decode_value_into */
        }
    }

    cbor_core_decoder_destroy(decoder);

    /* Post-decode validations and defaults */
    piadina_metadata_result_t vr = validate_required_fields(metadata, error_msg);
    if (vr != PIADINA_METADATA_OK) {
        return vr;
    }
    return ensure_required_defaults(metadata, error_msg);
}

const piadina_meta_map_t *piadina_metadata_root(const piadina_metadata_t *metadata)
{
    return metadata ? &metadata->root : NULL;
}

static piadina_meta_value_t *find_field_value(const piadina_metadata_t *metadata,
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

piadina_metadata_result_t piadina_metadata_get_string(const piadina_metadata_t *metadata,
                                                      metadata_core_field_t field,
                                                      const char **out,
                                                      const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const piadina_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != PIADINA_META_STRING) {
        if (error_msg) {
            const char *fname = metadata_core_field_name(field);
            snprintf(g_error_buf, sizeof(g_error_buf),
                     "field '%s' not present or not a string", fname ? fname : "?");
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.str;
    return PIADINA_METADATA_OK;
}

piadina_metadata_result_t piadina_metadata_get_bool(const piadina_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    bool *out,
                                                    const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const piadina_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != PIADINA_META_BOOL) {
        if (error_msg) {
            const char *fname = metadata_core_field_name(field);
            snprintf(g_error_buf, sizeof(g_error_buf),
                     "field '%s' not present or not a bool", fname ? fname : "?");
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.bool_val;
    return PIADINA_METADATA_OK;
}

piadina_metadata_result_t piadina_metadata_get_uint(const piadina_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    uint64_t *out,
                                                    const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const piadina_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != PIADINA_META_UINT) {
        if (error_msg) {
            const char *fname = metadata_core_field_name(field);
            snprintf(g_error_buf, sizeof(g_error_buf),
                     "field '%s' not present or not a uint", fname ? fname : "?");
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.uint_val;
    return PIADINA_METADATA_OK;
}

piadina_metadata_result_t piadina_metadata_get_bytes(const piadina_metadata_t *metadata,
                                                     metadata_core_field_t field,
                                                     const uint8_t **out,
                                                     size_t *len_out,
                                                     const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const piadina_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != PIADINA_META_BYTES) {
        if (error_msg) {
            const char *fname = metadata_core_field_name(field);
            snprintf(g_error_buf, sizeof(g_error_buf),
                     "field '%s' not present or not bytes", fname ? fname : "?");
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    *out = val->as.bytes.data;
    if (len_out) {
        *len_out = val->as.bytes.len;
    }
    return PIADINA_METADATA_OK;
}

piadina_metadata_result_t piadina_metadata_get_array(const piadina_metadata_t *metadata,
                                                     metadata_core_field_t field,
                                                     const piadina_meta_array_t **out,
                                                     const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const piadina_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != PIADINA_META_ARRAY) {
        if (error_msg) {
            const char *fname = metadata_core_field_name(field);
            snprintf(g_error_buf, sizeof(g_error_buf),
                     "field '%s' not present or not an array", fname ? fname : "?");
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    *out = &val->as.array;
    return PIADINA_METADATA_OK;
}

piadina_metadata_result_t piadina_metadata_get_map(const piadina_metadata_t *metadata,
                                                   metadata_core_field_t field,
                                                   const piadina_meta_map_t **out,
                                                   const char **error_msg)
{
    if (!metadata || !out) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    const piadina_meta_value_t *val = find_field_value(metadata, field);
    if (!val || val->type != PIADINA_META_MAP) {
        if (error_msg) {
            const char *fname = metadata_core_field_name(field);
            snprintf(g_error_buf, sizeof(g_error_buf),
                     "field '%s' not present or not a map", fname ? fname : "?");
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    *out = &val->as.map;
    return PIADINA_METADATA_OK;
}

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

static bool env_key_shell_safe(const char *key, size_t len)
{
    if (!key || len == 0) {
        return false;
    }
    if (!(isalpha((unsigned char)key[0]) || key[0] == '_')) {
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

static void value_reset(piadina_meta_value_t *value)
{
    if (!value) {
        return;
    }
    switch (value->type) {
    case PIADINA_META_STRING:
        free(value->as.str);
        break;
    case PIADINA_META_BYTES:
        free(value->as.bytes.data);
        break;
    case PIADINA_META_ARRAY:
        array_destroy(&value->as.array);
        break;
    case PIADINA_META_MAP:
        map_destroy(&value->as.map);
        break;
    case PIADINA_META_UINT:
    case PIADINA_META_BOOL:
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

static void value_destroy(piadina_meta_value_t *value)
{
    if (!value) {
        return;
    }
    value_reset(value);
    free(value);
}

static void map_destroy(piadina_meta_map_t *map)
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

static void array_destroy(piadina_meta_array_t *array)
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

static piadina_meta_value_t *map_find(const piadina_meta_map_t *map,
                                      const char *key,
                                      size_t key_len)
{
    if (!map || !key) {
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

static piadina_meta_value_t *map_get_or_create(piadina_meta_map_t *map,
                                               const char *key,
                                               size_t key_len,
                                               bool *created)
{
    return metadata_tree_map_get_or_create(map, key, key_len, created);
}

static piadina_meta_value_t *map_put_string(piadina_meta_map_t *map,
                                            const char *key,
                                            size_t key_len,
                                            const char *value)
{
    return metadata_tree_map_put_string(map, key, key_len, value);
}

static piadina_meta_value_t *map_put_uint(piadina_meta_map_t *map,
                                         const char *key,
                                         size_t key_len,
                                         uint64_t value)
{
    return metadata_tree_map_put_uint(map, key, key_len, value);
}

static piadina_meta_value_t *map_put_bool(piadina_meta_map_t *map,
                                          const char *key,
                                          size_t key_len,
                                          bool value)
{
    return metadata_tree_map_put_bool(map, key, key_len, value);
}

static piadina_meta_value_t *map_put_bytes(piadina_meta_map_t *map,
                                           const char *key,
                                           size_t key_len,
                                           const uint8_t *data,
                                           size_t len)
{
    return metadata_tree_map_put_bytes(map, key, key_len, data, len);
}

static piadina_meta_value_t *ensure_array_slot(piadina_meta_value_t *array_value,
                                               size_t index)
{
    return metadata_tree_array_ensure_slot(array_value, index);
}

static piadina_metadata_result_t set_default_string_if_missing(piadina_metadata_t *metadata,
                                                               const char *key,
                                                               const char *default_value,
                                                               const char **error_msg)
{
    if (!metadata || !key || !default_value) {
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    piadina_meta_value_t *existing = map_find(&metadata->root, key, strlen(key));
    if (existing) {
        return PIADINA_METADATA_OK;
    }
    return map_put_string(&metadata->root, key, strlen(key), default_value)
               ? PIADINA_METADATA_OK
               : PIADINA_METADATA_ERR_OUT_OF_MEMORY;
}

static piadina_metadata_result_t set_default_bool_if_missing(piadina_metadata_t *metadata,
                                                             const char *key,
                                                             bool default_value,
                                                             const char **error_msg)
{
    (void)error_msg;
    if (!metadata || !key) {
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }
    piadina_meta_value_t *existing = map_find(&metadata->root, key, strlen(key));
    if (existing) {
        return PIADINA_METADATA_OK;
    }
    return map_put_bool(&metadata->root, key, strlen(key), default_value)
               ? PIADINA_METADATA_OK
               : PIADINA_METADATA_ERR_OUT_OF_MEMORY;
}

static piadina_metadata_result_t decode_array(piadina_meta_value_t *out,
                                              const cbor_core_value_t *value,
                                              const char **error_msg)
{
    size_t len = cbor_core_array_size(value);
    out->type = PIADINA_META_ARRAY;
    out->as.array.count = 0;
    out->as.array.capacity = 0;
    out->as.array.items = NULL;

    for (size_t i = 0; i < len; ++i) {
        cbor_core_value_t elem = {0};
        if (cbor_core_array_get(value, i, &elem) != CBOR_CORE_OK) {
            if (error_msg) {
                *error_msg = "failed to decode array element";
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (cbor_core_value_type(&elem) != CBOR_CORE_TYPE_TEXT) {
            if (error_msg) {
                *error_msg = "array elements must be text";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        const char *str = NULL;
        size_t slen = 0;
        if (cbor_core_value_get_text(&elem, &str, &slen) != CBOR_CORE_OK) {
            if (error_msg) {
                *error_msg = "failed to read array element";
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        piadina_meta_value_t *slot = ensure_array_slot(out, i);
        if (!slot) {
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
        value_reset(slot);
        slot->type = PIADINA_META_STRING;
        slot->as.str = strndup(str, slen);
        if (!slot->as.str) {
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
    }
    return PIADINA_METADATA_OK;
}

static piadina_metadata_result_t decode_value_into(piadina_meta_value_t *out,
                                                   metadata_core_expected_kind_t expected,
                                                   const cbor_core_value_t *value,
                                                   const char *key_name,
                                                   const char **error_msg)
{
    cbor_core_type_t type = cbor_core_value_type(value);
    switch (type) {
    case CBOR_CORE_TYPE_TEXT: {
        const char *str = NULL;
        size_t len = 0;
        if (cbor_core_value_get_text(value, &str, &len) != CBOR_CORE_OK) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s': failed to read text value", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (expected == METADATA_EXPECT_ARRAY_STRING || expected == METADATA_EXPECT_MAP_STRING) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s' is not a scalar", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        value_reset(out);
        out->type = PIADINA_META_STRING;
        out->as.str = strndup(str, len);
        if (!out->as.str) {
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
        return PIADINA_METADATA_OK;
    }
    case CBOR_CORE_TYPE_UINT: {
        uint64_t v = 0;
        if (cbor_core_value_get_uint(value, &v) != CBOR_CORE_OK) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s': failed to read uint", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (expected != METADATA_EXPECT_UINT && expected != METADATA_EXPECT_ANY) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s' must be uint", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        value_reset(out);
        out->type = PIADINA_META_UINT;
        out->as.uint_val = v;
        return PIADINA_METADATA_OK;
    }
    case CBOR_CORE_TYPE_BOOL: {
        bool v = false;
        if (cbor_core_value_get_bool(value, &v) != CBOR_CORE_OK) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s': failed to read bool", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (expected != METADATA_EXPECT_BOOL && expected != METADATA_EXPECT_ANY) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s' must be bool", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        value_reset(out);
        out->type = PIADINA_META_BOOL;
        out->as.bool_val = v;
        return PIADINA_METADATA_OK;
    }
    case CBOR_CORE_TYPE_BYTES: {
        const uint8_t *buf = NULL;
        size_t len = 0;
        if (cbor_core_value_get_bytes(value, &buf, &len) != CBOR_CORE_OK) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s': failed to read bytes", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (expected != METADATA_EXPECT_BYTES && expected != METADATA_EXPECT_ANY) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s' must be bytes", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        value_reset(out);
        out->type = PIADINA_META_BYTES;
        if (len > 0) {
            out->as.bytes.data = malloc(len);
            if (!out->as.bytes.data) {
                return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
            }
            memcpy(out->as.bytes.data, buf, len);
        } else {
            out->as.bytes.data = NULL;
        }
        out->as.bytes.len = len;
        return PIADINA_METADATA_OK;
    }
    case CBOR_CORE_TYPE_ARRAY: {
        if (expected != METADATA_EXPECT_ARRAY_STRING && expected != METADATA_EXPECT_ANY) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s' must be an array of text", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        value_reset(out);
        return decode_array(out, value, error_msg);
    }
    case CBOR_CORE_TYPE_MAP: {
        if (expected != METADATA_EXPECT_MAP_STRING && expected != METADATA_EXPECT_ANY) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "field '%s' must be a map", key_name);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        value_reset(out);
        out->type = PIADINA_META_MAP;
        out->as.map.count = 0;
        out->as.map.capacity = 0;
        out->as.map.entries = NULL;
        return PIADINA_METADATA_OK;
    }
    default:
        if (error_msg) {
            snprintf(g_error_buf, sizeof(g_error_buf), "field '%s': unsupported CBOR type", key_name);
            *error_msg = g_error_buf;
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
}

static piadina_metadata_result_t decode_map_entries(piadina_meta_map_t *map,
                                                    const cbor_core_value_t *map_val,
                                                    bool enforce_env_rules,
                                                    const char **error_msg)
{
    size_t count = cbor_core_map_size(map_val);
    for (size_t i = 0; i < count; ++i) {
        cbor_core_value_t k = {0};
        cbor_core_value_t v = {0};
        if (cbor_core_map_get(map_val, i, &k, &v) != CBOR_CORE_OK) {
            if (error_msg) {
                *error_msg = "failed to read map entry";
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (cbor_core_value_type(&k) != CBOR_CORE_TYPE_TEXT ||
            cbor_core_value_type(&v) != CBOR_CORE_TYPE_TEXT) {
            if (error_msg) {
                *error_msg = "map keys and values must be text";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        const char *kstr = NULL;
        size_t klen = 0;
        const char *vstr = NULL;
        size_t vlen = 0;
        if (cbor_core_value_get_text(&k, &kstr, &klen) != CBOR_CORE_OK ||
            cbor_core_value_get_text(&v, &vstr, &vlen) != CBOR_CORE_OK) {
            if (error_msg) {
                *error_msg = "failed to read map text";
            }
            return PIADINA_METADATA_ERR_DECODE;
        }
        if (!metadata_core_identifier_valid(kstr, klen)) {
            if (error_msg) {
                *error_msg = "invalid map key";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        if (enforce_env_rules && !env_key_shell_safe(kstr, klen)) {
            if (error_msg) {
                *error_msg = "ENV keys must match [A-Za-z_][A-Za-z0-9_]*";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        if (!map_put_string(map, kstr, klen, vstr)) {
            if (error_msg) {
                *error_msg = "out of memory writing map entry";
            }
            return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
        }
    }
    return PIADINA_METADATA_OK;
}

static piadina_metadata_result_t validate_required_fields(piadina_metadata_t *metadata,
                                                          const char **error_msg)
{
    /* VERSION must exist and match */
    piadina_meta_value_t *version = map_find(&metadata->root, "VERSION", strlen("VERSION"));
    if (!version || version->type != PIADINA_META_UINT) {
        if (error_msg) {
            *error_msg = "VERSION is required";
        }
        return PIADINA_METADATA_ERR_MISSING_REQUIRED;
    }
    if (version->as.uint_val != METADATA_CORE_SCHEMA_VERSION) {
        if (error_msg) {
            *error_msg = "unsupported metadata VERSION";
        }
        return PIADINA_METADATA_ERR_UNSUPPORTED_VERSION;
    }

    /* ENTRY_POINT required */
    piadina_meta_value_t *entry = map_find(&metadata->root, "ENTRY_POINT", strlen("ENTRY_POINT"));
    if (!entry || entry->type != PIADINA_META_STRING) {
        if (error_msg) {
            *error_msg = "ENTRY_POINT is required and must be text";
        }
        return PIADINA_METADATA_ERR_MISSING_REQUIRED;
    }
    if (entry->as.str && entry->as.str[0] == '/') {
        if (error_msg) {
            *error_msg = "ENTRY_POINT must be relative to the payload root";
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }
    if (entry->as.str && entry->as.str[0] == '\0') {
        if (error_msg) {
            *error_msg = "ENTRY_POINT cannot be empty";
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }

    /* ARCHIVE_HASH and PAYLOAD_HASH must exist and be bytes (32 bytes expected) */
    piadina_meta_value_t *archive_hash = map_find(&metadata->root, "ARCHIVE_HASH", strlen("ARCHIVE_HASH"));
    piadina_meta_value_t *payload_hash = map_find(&metadata->root, "PAYLOAD_HASH", strlen("PAYLOAD_HASH"));
    if (!archive_hash || archive_hash->type != PIADINA_META_BYTES ||
        !payload_hash || payload_hash->type != PIADINA_META_BYTES) {
        if (error_msg) {
            *error_msg = "ARCHIVE_HASH and PAYLOAD_HASH are required (bytes)";
        }
        return PIADINA_METADATA_ERR_MISSING_REQUIRED;
    }
    if (archive_hash->as.bytes.len != 32 || payload_hash->as.bytes.len != 32) {
        if (error_msg) {
            *error_msg = "hash fields must be 32 bytes";
        }
        return PIADINA_METADATA_ERR_BAD_VALUE;
    }

    return PIADINA_METADATA_OK;
}

static piadina_metadata_result_t ensure_required_defaults(piadina_metadata_t *metadata,
                                                          const char **error_msg)
{
    /* ARCHIVE_FORMAT default + validation */
    piadina_meta_value_t *archive_fmt = map_find(&metadata->root, "ARCHIVE_FORMAT", strlen("ARCHIVE_FORMAT"));
    if (!archive_fmt) {
        piadina_metadata_result_t rc =
            set_default_string_if_missing(metadata, "ARCHIVE_FORMAT",
                                          metadata_core_archive_format_default(), error_msg);
        if (rc != PIADINA_METADATA_OK) {
            return rc;
        }
        archive_fmt = map_find(&metadata->root, "ARCHIVE_FORMAT", strlen("ARCHIVE_FORMAT"));
    }
    if (archive_fmt) {
        if (archive_fmt->type != PIADINA_META_STRING) {
            if (error_msg) {
                *error_msg = "ARCHIVE_FORMAT must be text";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        if (!metadata_core_archive_format_supported(archive_fmt->as.str)) {
            if (error_msg) {
                snprintf(g_error_buf, sizeof(g_error_buf), "unsupported archive format %s", archive_fmt->as.str);
                *error_msg = g_error_buf;
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
    }

    /* CACHE_ROOT and PAYLOAD_ROOT defaults */
    piadina_metadata_result_t rc = set_default_string_if_missing(metadata, "CACHE_ROOT",
                                                                metadata_core_field_default_string(METADATA_FIELD_CACHE_ROOT),
                                                                error_msg);
    if (rc != PIADINA_METADATA_OK) {
        return rc;
    }
    rc = set_default_string_if_missing(metadata, "PAYLOAD_ROOT",
                                       metadata_core_field_default_string(METADATA_FIELD_PAYLOAD_ROOT),
                                       error_msg);
    if (rc != PIADINA_METADATA_OK) {
        return rc;
    }

    /* CLEANUP_POLICY default + validation */
    piadina_meta_value_t *cleanup = map_find(&metadata->root, "CLEANUP_POLICY", strlen("CLEANUP_POLICY"));
    if (!cleanup) {
        rc = set_default_string_if_missing(metadata, "CLEANUP_POLICY",
                                           metadata_core_cleanup_policy_to_string(metadata_core_cleanup_policy_default()),
                                           error_msg);
        if (rc != PIADINA_METADATA_OK) {
            return rc;
        }
        cleanup = map_find(&metadata->root, "CLEANUP_POLICY", strlen("CLEANUP_POLICY"));
    }
    if (cleanup) {
        if (cleanup->type != PIADINA_META_STRING) {
            if (error_msg) {
                *error_msg = "CLEANUP_POLICY must be text";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        if (metadata_core_cleanup_policy_from_string(cleanup->as.str) == METADATA_CLEANUP_INVALID) {
            if (error_msg) {
                *error_msg = "invalid cleanup policy (expected never|oncrash|always)";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
    }

    /* VALIDATE default */
    rc = set_default_bool_if_missing(metadata, "VALIDATE",
                                     metadata_core_validate_default(), error_msg);
    if (rc != PIADINA_METADATA_OK) {
        return rc;
    }

    return PIADINA_METADATA_OK;
}

void piadina_metadata_print(const piadina_metadata_t *metadata, FILE *stream)
{
    if (!stream) {
        stream = stderr;
    }
    const piadina_meta_map_t *root = piadina_metadata_root(metadata);
    if (!root) {
        return;
    }
    metadata_tree_print_map(root, 0, stream);
}
