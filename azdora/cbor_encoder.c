/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file cbor_encoder.c
 * @brief CBOR encoding for Azdora metadata.
 */
#include "cbor_encoder.h"

#include <stdlib.h>
#include <string.h>

#include "common/cbor_core.h"

static cbor_core_result_t encode_value(cbor_core_encoder_t *enc, const azdora_meta_value_t *val);
static cbor_core_result_t encode_map(cbor_core_encoder_t *enc, const azdora_meta_map_t *map);
static cbor_core_result_t encode_array(cbor_core_encoder_t *enc, const azdora_meta_array_t *array);

azdora_cbor_result_t azdora_cbor_encode_metadata(const azdora_metadata_t *metadata,
                                                 uint8_t **out_data,
                                                 size_t *out_size)
{
    if (!metadata || !out_data || !out_size) {
        return AZDORA_CBOR_ERR_INVALID_ARGUMENT;
    }

    const azdora_meta_map_t *root = azdora_metadata_root(metadata);
    if (!root) {
        return AZDORA_CBOR_ERR_INVALID_ARGUMENT;
    }

    cbor_core_encoder_t *enc = cbor_core_encoder_new();
    if (!enc) {
        return AZDORA_CBOR_ERR_OOM;
    }

    cbor_core_result_t rc = encode_map(enc, root);
    if (rc != CBOR_CORE_OK) {
        cbor_core_encoder_destroy(enc);
        return AZDORA_CBOR_ERR_ENCODE;
    }

    const uint8_t *buffer = cbor_core_encoder_buffer(enc, out_size);
    if (!buffer) {
        cbor_core_encoder_destroy(enc);
        return AZDORA_CBOR_ERR_ENCODE;
    }

    uint8_t *copy = malloc(*out_size);
    if (!copy) {
        cbor_core_encoder_destroy(enc);
        return AZDORA_CBOR_ERR_OOM;
    }
    memcpy(copy, buffer, *out_size);
    *out_data = copy;

    cbor_core_encoder_destroy(enc);
    return AZDORA_CBOR_OK;
}

/* ------------------------------------------------------------------------- */
/* Internal encoding helpers                                                */
/* ------------------------------------------------------------------------- */

static cbor_core_result_t encode_map(cbor_core_encoder_t *enc, const azdora_meta_map_t *map)
{
    if (!map) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (map->count > 0 && !map->entries) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    cbor_core_result_t rc = cbor_core_encode_map_start(enc, map->count);
    if (rc != CBOR_CORE_OK) {
        return rc;
    }
    for (size_t i = 0; i < map->count; ++i) {
        const azdora_meta_map_entry_t *entry = &map->entries[i];
        rc = cbor_core_encode_text(enc, entry->key, strlen(entry->key));
        if (rc != CBOR_CORE_OK) {
            return rc;
        }
        rc = encode_value(enc, entry->value);
        if (rc != CBOR_CORE_OK) {
            return rc;
        }
    }
    return CBOR_CORE_OK;
}

static cbor_core_result_t encode_array(cbor_core_encoder_t *enc, const azdora_meta_array_t *array)
{
    if (!array) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (array->count > 0 && !array->items) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    cbor_core_result_t rc = cbor_core_encode_array_start(enc, array->count);
    if (rc != CBOR_CORE_OK) {
        return rc;
    }
    for (size_t i = 0; i < array->count; ++i) {
        rc = encode_value(enc, &array->items[i]);
        if (rc != CBOR_CORE_OK) {
            return rc;
        }
    }
    return CBOR_CORE_OK;
}

static cbor_core_result_t encode_value(cbor_core_encoder_t *enc, const azdora_meta_value_t *val)
{
    switch (val->type) {
    case AZDORA_META_STRING:
        return cbor_core_encode_text(enc, val->as.str ? val->as.str : "", val->as.str ? strlen(val->as.str) : 0);
    case AZDORA_META_UINT:
        return cbor_core_encode_uint(enc, val->as.uint_val);
    case AZDORA_META_BOOL:
        return cbor_core_encode_bool(enc, val->as.bool_val);
    case AZDORA_META_BYTES:
        if (val->as.bytes.len > 0 && !val->as.bytes.data) {
            return CBOR_CORE_ERR_INVALID_ARGUMENT;
        }
        return cbor_core_encode_bytes(enc, val->as.bytes.data, val->as.bytes.len);
    case AZDORA_META_ARRAY:
        return encode_array(enc, &val->as.array);
    case AZDORA_META_MAP:
        return encode_map(enc, &val->as.map);
    default:
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
}
