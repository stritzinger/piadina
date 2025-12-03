#ifndef PIADINA_COMMON_CBOR_CORE_H
#define PIADINA_COMMON_CBOR_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    CBOR_CORE_OK = 0,
    CBOR_CORE_ERR_INVALID_ARGUMENT,
    CBOR_CORE_ERR_UNSUPPORTED_TYPE,
    CBOR_CORE_ERR_DECODE,
    CBOR_CORE_ERR_ENCODE,
    CBOR_CORE_ERR_END_OF_CONTAINER,
    CBOR_CORE_ERR_OOM
} cbor_core_result_t;

typedef enum {
    CBOR_CORE_TYPE_UINT,
    CBOR_CORE_TYPE_NEGINT,
    CBOR_CORE_TYPE_BYTES,
    CBOR_CORE_TYPE_TEXT,
    CBOR_CORE_TYPE_ARRAY,
    CBOR_CORE_TYPE_MAP,
    CBOR_CORE_TYPE_BOOL,
    CBOR_CORE_TYPE_UNKNOWN
} cbor_core_type_t;

typedef struct cbor_core_encoder cbor_core_encoder_t;
typedef struct cbor_core_decoder cbor_core_decoder_t;
typedef struct {
    void *impl;
} cbor_core_value_t;

/**
 * Allocate a new encoder with its own growable buffer. Caller owns the encoder
 * and must destroy it via `cbor_core_encoder_destroy`. No additional buffers
 * need to be provided.
 */
cbor_core_encoder_t *cbor_core_encoder_new(void);

/**
 * Destroy an encoder created via `cbor_core_encoder_new`. Frees all internal
 * memory but does not free user-provided strings or byte buffers passed into
 * encode helpers.
 */
void cbor_core_encoder_destroy(cbor_core_encoder_t *encoder);

/**
 * Append primitive/compound values to the encoder. These functions do not take
 * ownership of input data; callers may free their buffers immediately after the
 * call returns.
 */
cbor_core_result_t cbor_core_encode_uint(cbor_core_encoder_t *encoder, uint64_t value);
cbor_core_result_t cbor_core_encode_bool(cbor_core_encoder_t *encoder, bool value);
cbor_core_result_t cbor_core_encode_text(cbor_core_encoder_t *encoder, const char *str, size_t len);
cbor_core_result_t cbor_core_encode_bytes(cbor_core_encoder_t *encoder, const uint8_t *data, size_t len);
cbor_core_result_t cbor_core_encode_array_start(cbor_core_encoder_t *encoder, size_t length);
cbor_core_result_t cbor_core_encode_map_start(cbor_core_encoder_t *encoder, size_t length);

/**
 * Retrieve the internal buffer and its length. The returned pointer is owned by
 * the encoder; callers must not free it and must copy the contents if they need
 * to keep it beyond the encoder’s lifetime.
 */
const uint8_t *cbor_core_encoder_buffer(const cbor_core_encoder_t *encoder, size_t *size_out);

/**
 * Create/destroy decoders that borrow the caller-provided CBOR buffer. The
 * decoder keeps pointers into the buffer but never takes ownership of it, so
 * the caller must retain the buffer for as long as the decoder is alive.
 */
cbor_core_decoder_t *cbor_core_decoder_new(const uint8_t *data, size_t size);
void cbor_core_decoder_destroy(cbor_core_decoder_t *decoder);

/**
 * Obtain a handle to the root CBOR value. The returned `cbor_core_value_t`
 * points into decoder-owned storage; it becomes invalid once the decoder is
 * destroyed.
 */
cbor_core_result_t cbor_core_decoder_root(const cbor_core_decoder_t *decoder, cbor_core_value_t *out);

/**
 * Inspection helpers for decoded values. These functions never allocate; they
 * simply expose information about decoder-owned items.
 */
cbor_core_type_t cbor_core_value_type(const cbor_core_value_t *value);
size_t cbor_core_array_size(const cbor_core_value_t *value);
cbor_core_result_t cbor_core_array_get(const cbor_core_value_t *array, size_t index, cbor_core_value_t *out);
size_t cbor_core_map_size(const cbor_core_value_t *value);
cbor_core_result_t cbor_core_map_get(const cbor_core_value_t *map, size_t index, cbor_core_value_t *key_out, cbor_core_value_t *value_out);
cbor_core_result_t cbor_core_map_find_string(const cbor_core_value_t *map, const char *key, size_t key_len, cbor_core_value_t *value_out);

/**
 * Extract typed data from a value. Returned pointers (`str_out`, `data_out`)
 * reference decoder-owned buffers; callers must copy them if they need to keep
 * the data beyond the decoder’s lifetime.
 */
cbor_core_result_t cbor_core_value_get_uint(const cbor_core_value_t *value, uint64_t *out);
cbor_core_result_t cbor_core_value_get_bool(const cbor_core_value_t *value, bool *out);
cbor_core_result_t cbor_core_value_get_text(const cbor_core_value_t *value, const char **str_out, size_t *len_out);
cbor_core_result_t cbor_core_value_get_bytes(const cbor_core_value_t *value, const uint8_t **data_out, size_t *len_out);
#endif /* PIADINA_COMMON_CBOR_CORE_H */
