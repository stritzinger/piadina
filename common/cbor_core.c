/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file cbor_core.c
 * @brief Core CBOR abstraction implementation.
 */
#include "cbor_core.h"

#include <cbor.h>
#include <stdlib.h>
#include <string.h>

struct cbor_core_encoder {
    unsigned char *buffer;
    size_t length;
    size_t capacity;
};

struct cbor_core_decoder {
    cbor_item_t *root;
};

static cbor_core_result_t encoder_reserve(cbor_core_encoder_t *encoder, size_t extra);
static cbor_core_result_t encoder_append(cbor_core_encoder_t *encoder, const unsigned char *data, size_t len);
static cbor_core_result_t append_header(cbor_core_encoder_t *encoder,
                                        size_t (*encode_fn)(size_t, unsigned char *, size_t),
                                        size_t length);
static cbor_item_t *value_item(const cbor_core_value_t *value);

cbor_core_encoder_t *cbor_core_encoder_new(void)
{
    cbor_core_encoder_t *enc = calloc(1, sizeof(*enc));
    if (!enc) {
        return NULL;
    }
    enc->capacity = 256;
    enc->buffer = malloc(enc->capacity);
    if (!enc->buffer) {
        free(enc);
        return NULL;
    }
    return enc;
}

void cbor_core_encoder_destroy(cbor_core_encoder_t *encoder)
{
    if (!encoder) {
        return;
    }
    free(encoder->buffer);
    free(encoder);
}

cbor_core_result_t cbor_core_encode_uint(cbor_core_encoder_t *encoder, uint64_t value)
{
    if (!encoder) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    unsigned char tmp[9];
    size_t written = cbor_encode_uint(value, tmp, sizeof(tmp));
    if (written == 0) {
        return CBOR_CORE_ERR_ENCODE;
    }
    return encoder_append(encoder, tmp, written);
}

cbor_core_result_t cbor_core_encode_bool(cbor_core_encoder_t *encoder, bool value)
{
    if (!encoder) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    unsigned char tmp[1];
    size_t written = cbor_encode_bool(value, tmp, sizeof(tmp));
    if (written == 0) {
        return CBOR_CORE_ERR_ENCODE;
    }
    return encoder_append(encoder, tmp, written);
}

cbor_core_result_t cbor_core_encode_text(cbor_core_encoder_t *encoder, const char *str, size_t len)
{
    if (!encoder || (!str && len > 0)) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    cbor_core_result_t rc = append_header(encoder, cbor_encode_string_start, len);
    if (rc != CBOR_CORE_OK) {
        return rc;
    }
    if (len == 0) {
        return CBOR_CORE_OK;
    }
    return encoder_append(encoder, (const unsigned char *)str, len);
}

cbor_core_result_t cbor_core_encode_bytes(cbor_core_encoder_t *encoder, const uint8_t *data, size_t len)
{
    if (!encoder || (!data && len > 0)) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    cbor_core_result_t rc = append_header(encoder, cbor_encode_bytestring_start, len);
    if (rc != CBOR_CORE_OK) {
        return rc;
    }
    if (len == 0) {
        return CBOR_CORE_OK;
    }
    return encoder_append(encoder, data, len);
}

cbor_core_result_t cbor_core_encode_array_start(cbor_core_encoder_t *encoder, size_t length)
{
    if (!encoder) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    return append_header(encoder, cbor_encode_array_start, length);
}

cbor_core_result_t cbor_core_encode_map_start(cbor_core_encoder_t *encoder, size_t length)
{
    if (!encoder) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    return append_header(encoder, cbor_encode_map_start, length);
}

const uint8_t *cbor_core_encoder_buffer(const cbor_core_encoder_t *encoder, size_t *size_out)
{
    if (!encoder || !size_out) {
        return NULL;
    }
    *size_out = encoder->length;
    return encoder->buffer;
}

cbor_core_decoder_t *cbor_core_decoder_new(const uint8_t *data, size_t size)
{
    if (!data && size > 0) {
        return NULL;
    }
    cbor_core_decoder_t *dec = calloc(1, sizeof(*dec));
    if (!dec) {
        return NULL;
    }
    struct cbor_load_result result = {0};
    dec->root = cbor_load(data, size, &result);
    if (!dec->root) {
        free(dec);
        return NULL;
    }
    return dec;
}

void cbor_core_decoder_destroy(cbor_core_decoder_t *decoder)
{
    if (!decoder) {
        return;
    }
    if (decoder->root) {
        cbor_decref(&decoder->root);
    }
    free(decoder);
}

cbor_core_result_t cbor_core_decoder_root(const cbor_core_decoder_t *decoder, cbor_core_value_t *out)
{
    if (!decoder || !out || !decoder->root) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    out->impl = decoder->root;
    return CBOR_CORE_OK;
}

cbor_core_type_t cbor_core_value_type(const cbor_core_value_t *value)
{
    cbor_item_t *item = value_item(value);
    if (!item) {
        return CBOR_CORE_TYPE_UNKNOWN;
    }
    switch (cbor_typeof(item)) {
    case CBOR_TYPE_UINT:
        return CBOR_CORE_TYPE_UINT;
    case CBOR_TYPE_NEGINT:
        return CBOR_CORE_TYPE_NEGINT;
    case CBOR_TYPE_BYTESTRING:
        return CBOR_CORE_TYPE_BYTES;
    case CBOR_TYPE_STRING:
        return CBOR_CORE_TYPE_TEXT;
    case CBOR_TYPE_ARRAY:
        return CBOR_CORE_TYPE_ARRAY;
    case CBOR_TYPE_MAP:
        return CBOR_CORE_TYPE_MAP;
    case CBOR_TYPE_TAG:
        return CBOR_CORE_TYPE_UNKNOWN;
    case CBOR_TYPE_FLOAT_CTRL:
        return cbor_is_bool(item) ? CBOR_CORE_TYPE_BOOL : CBOR_CORE_TYPE_UNKNOWN;
    default:
        return CBOR_CORE_TYPE_UNKNOWN;
    }
}

size_t cbor_core_array_size(const cbor_core_value_t *value)
{
    cbor_item_t *item = value_item(value);
    if (!item || !cbor_isa_array(item)) {
        return 0;
    }
    return cbor_array_size(item);
}

cbor_core_result_t cbor_core_array_get(const cbor_core_value_t *array, size_t index, cbor_core_value_t *out)
{
    cbor_item_t *item = value_item(array);
    if (!item || !out || !cbor_isa_array(item)) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (index >= cbor_array_size(item)) {
        return CBOR_CORE_ERR_END_OF_CONTAINER;
    }
    out->impl = cbor_array_handle(item)[index];
    return CBOR_CORE_OK;
}

size_t cbor_core_map_size(const cbor_core_value_t *value)
{
    cbor_item_t *item = value_item(value);
    if (!item || !cbor_isa_map(item)) {
        return 0;
    }
    return cbor_map_size(item);
}

cbor_core_result_t cbor_core_map_get(const cbor_core_value_t *map, size_t index, cbor_core_value_t *key_out, cbor_core_value_t *value_out)
{
    cbor_item_t *item = value_item(map);
    if (!item || !cbor_isa_map(item) || !key_out || !value_out) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (index >= cbor_map_size(item)) {
        return CBOR_CORE_ERR_END_OF_CONTAINER;
    }
    struct cbor_pair *pairs = cbor_map_handle(item);
    key_out->impl = pairs[index].key;
    value_out->impl = pairs[index].value;
    return CBOR_CORE_OK;
}

cbor_core_result_t cbor_core_map_find_string(const cbor_core_value_t *map, const char *key, size_t key_len, cbor_core_value_t *value_out)
{
    if (!map || !key || !value_out) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    cbor_item_t *item = value_item(map);
    if (!item || !cbor_isa_map(item)) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    size_t count = cbor_map_size(item);
    struct cbor_pair *pairs = cbor_map_handle(item);
    for (size_t i = 0; i < count; ++i) {
        cbor_item_t *key_item = pairs[i].key;
        if (!cbor_isa_string(key_item)) {
            continue;
        }
        size_t len = cbor_string_length(key_item);
        if (len == key_len) {
            const char *data = (const char *)cbor_string_handle(key_item);
            if (memcmp(data, key, len) == 0) {
                value_out->impl = pairs[i].value;
                return CBOR_CORE_OK;
            }
        }
    }
    return CBOR_CORE_ERR_DECODE;
}

cbor_core_result_t cbor_core_value_get_uint(const cbor_core_value_t *value, uint64_t *out)
{
    if (!value || !value->impl || !out) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (!cbor_isa_uint(value_item(value))) {
        return CBOR_CORE_ERR_UNSUPPORTED_TYPE;
    }
    *out = cbor_get_uint64(value_item(value));
    return CBOR_CORE_OK;
}

cbor_core_result_t cbor_core_value_get_bool(const cbor_core_value_t *value, bool *out)
{
    cbor_item_t *item = value_item(value);
    if (!item || !out) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (!cbor_isa_float_ctrl(item) || !cbor_is_bool(item)) {
        return CBOR_CORE_ERR_UNSUPPORTED_TYPE;
    }
    *out = cbor_get_bool(item);
    return CBOR_CORE_OK;
}

cbor_core_result_t cbor_core_value_get_text(const cbor_core_value_t *value, const char **str_out, size_t *len_out)
{
    cbor_item_t *item = value_item(value);
    if (!item || !str_out || !len_out) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (!cbor_isa_string(item)) {
        return CBOR_CORE_ERR_UNSUPPORTED_TYPE;
    }
    *len_out = cbor_string_length(item);
    *str_out = (const char *)cbor_string_handle(item);
    return CBOR_CORE_OK;
}

cbor_core_result_t cbor_core_value_get_bytes(const cbor_core_value_t *value, const uint8_t **data_out, size_t *len_out)
{
    cbor_item_t *item = value_item(value);
    if (!item || !data_out || !len_out) {
        return CBOR_CORE_ERR_INVALID_ARGUMENT;
    }
    if (!cbor_isa_bytestring(item)) {
        return CBOR_CORE_ERR_UNSUPPORTED_TYPE;
    }
    *len_out = cbor_bytestring_length(item);
    *data_out = cbor_bytestring_handle(item);
    return CBOR_CORE_OK;
}

/* Internal Functions */

static cbor_core_result_t encoder_reserve(cbor_core_encoder_t *encoder, size_t extra)
{
    if (encoder->length + extra <= encoder->capacity) {
        return CBOR_CORE_OK;
    }
    size_t new_capacity = encoder->capacity ? encoder->capacity : 256;
    while (new_capacity < encoder->length + extra) {
        new_capacity *= 2;
    }
    unsigned char *new_buffer = realloc(encoder->buffer, new_capacity);
    if (!new_buffer) {
        return CBOR_CORE_ERR_OOM;
    }
    encoder->buffer = new_buffer;
    encoder->capacity = new_capacity;
    return CBOR_CORE_OK;
}

static cbor_core_result_t encoder_append(cbor_core_encoder_t *encoder, const unsigned char *data, size_t len)
{
    cbor_core_result_t rc = encoder_reserve(encoder, len);
    if (rc != CBOR_CORE_OK) {
        return rc;
    }
    memcpy(encoder->buffer + encoder->length, data, len);
    encoder->length += len;
    return CBOR_CORE_OK;
}

static cbor_core_result_t append_header(cbor_core_encoder_t *encoder,
                                        size_t (*encode_fn)(size_t, unsigned char *, size_t),
                                        size_t length)
{
    unsigned char tmp[9];
    size_t written = encode_fn(length, tmp, sizeof(tmp));
    if (written == 0) {
        return CBOR_CORE_ERR_ENCODE;
    }
    return encoder_append(encoder, tmp, written);
}

static cbor_item_t *value_item(const cbor_core_value_t *value)
{
    return value ? (cbor_item_t *)value->impl : NULL;
}
