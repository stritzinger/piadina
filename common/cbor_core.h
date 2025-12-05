/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file cbor_core.h
 * @brief Core CBOR abstraction layer (types, encoder, decoder).
 */
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
 * @brief Allocate a new encoder with its own growable buffer.
 *
 * @return Pointer to the new encoder, or NULL on failure.
 *
 * @note Memory Management:
 *       Caller owns the encoder and must destroy it via `cbor_core_encoder_destroy`.
 *       No additional buffers need to be provided.
 */
cbor_core_encoder_t *cbor_core_encoder_new(void);

/**
 * @brief Destroy an encoder.
 *
 * @param[in] encoder  The encoder to destroy.
 *
 * @note Memory Management:
 *       Frees all internal memory. Does not free user-provided strings or byte
 *       buffers passed into encode helpers (those were borrowed).
 */
void cbor_core_encoder_destroy(cbor_core_encoder_t *encoder);

/**
 * @brief Encode an unsigned integer.
 *
 * @param[in] encoder  The encoder instance.
 * @param[in] value    The value to encode.
 * @return             CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Does not take ownership of inputs.
 */
cbor_core_result_t cbor_core_encode_uint(cbor_core_encoder_t *encoder, uint64_t value);

/**
 * @brief Encode a boolean value.
 *
 * @param[in] encoder  The encoder instance.
 * @param[in] value    The boolean value.
 * @return             CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Does not take ownership of inputs.
 */
cbor_core_result_t cbor_core_encode_bool(cbor_core_encoder_t *encoder, bool value);

/**
 * @brief Encode a text string.
 *
 * @param[in] encoder  The encoder instance.
 * @param[in] str      Pointer to the string.
 * @param[in] len      Length of the string.
 * @return             CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Caller retains ownership of @p str. The encoder copies the data.
 */
cbor_core_result_t cbor_core_encode_text(cbor_core_encoder_t *encoder, const char *str, size_t len);

/**
 * @brief Encode a byte string.
 *
 * @param[in] encoder  The encoder instance.
 * @param[in] data     Pointer to the bytes.
 * @param[in] len      Length of the byte string.
 * @return             CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Caller retains ownership of @p data. The encoder copies the data.
 */
cbor_core_result_t cbor_core_encode_bytes(cbor_core_encoder_t *encoder, const uint8_t *data, size_t len);

/**
 * @brief Start encoding an array.
 *
 * @param[in] encoder  The encoder instance.
 * @param[in] length   Number of elements in the array.
 * @return             CBOR_CORE_OK on success.
 */
cbor_core_result_t cbor_core_encode_array_start(cbor_core_encoder_t *encoder, size_t length);

/**
 * @brief Start encoding a map.
 *
 * @param[in] encoder  The encoder instance.
 * @param[in] length   Number of pairs in the map.
 * @return             CBOR_CORE_OK on success.
 */
cbor_core_result_t cbor_core_encode_map_start(cbor_core_encoder_t *encoder, size_t length);

/**
 * @brief Retrieve the internal encoder buffer.
 *
 * @param[in]  encoder   The encoder instance.
 * @param[out] size_out  Pointer to store the buffer size.
 * @return               Pointer to the internal buffer.
 *
 * @note Memory Management:
 *       The returned pointer is owned by the encoder. Callers must NOT free it
 *       and must copy the contents if needed beyond the encoder's lifetime.
 */
const uint8_t *cbor_core_encoder_buffer(const cbor_core_encoder_t *encoder, size_t *size_out);

/**
 * @brief Create a decoder that borrows a CBOR buffer.
 *
 * @param[in] data  Pointer to the CBOR data.
 * @param[in] size  Size of the data.
 * @return          Pointer to a new decoder, or NULL on failure.
 *
 * @note Memory Management:
 *       The decoder keeps pointers into @p data but never takes ownership of it.
 *       The caller must retain the buffer for as long as the decoder is alive.
 *       Caller owns the returned decoder and must free it via `cbor_core_decoder_destroy`.
 */
cbor_core_decoder_t *cbor_core_decoder_new(const uint8_t *data, size_t size);

/**
 * @brief Destroy a decoder.
 *
 * @param[in] decoder  The decoder to destroy.
 */
void cbor_core_decoder_destroy(cbor_core_decoder_t *decoder);

/**
 * @brief Obtain a handle to the root CBOR value.
 *
 * @param[in]  decoder  The decoder instance.
 * @param[out] out      Buffer to store the value handle.
 * @return              CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       The returned handle points into decoder-owned storage; it becomes invalid
 *       once the decoder is destroyed. No allocation occurs.
 */
cbor_core_result_t cbor_core_decoder_root(const cbor_core_decoder_t *decoder, cbor_core_value_t *out);

/**
 * @brief Get the type of a CBOR value.
 *
 * @param[in] value  The value to inspect.
 * @return           The CBOR type enum.
 *
 * @note Memory Management:
 *       No allocation.
 */
cbor_core_type_t cbor_core_value_type(const cbor_core_value_t *value);

/**
 * @brief Get the size of an array value.
 *
 * @param[in] value  The array value.
 * @return           Number of elements.
 */
size_t cbor_core_array_size(const cbor_core_value_t *value);

/**
 * @brief Get an element from an array by index.
 *
 * @param[in]  array  The array value.
 * @param[in]  index  The index to retrieve.
 * @param[out] out    Buffer to store the element handle.
 * @return            CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Returned handle is borrowed from the decoder.
 */
cbor_core_result_t cbor_core_array_get(const cbor_core_value_t *array, size_t index, cbor_core_value_t *out);

/**
 * @brief Get the size of a map value.
 *
 * @param[in] value  The map value.
 * @return           Number of pairs.
 */
size_t cbor_core_map_size(const cbor_core_value_t *value);

/**
 * @brief Get a key-value pair from a map by index.
 *
 * @param[in]  map        The map value.
 * @param[in]  index      The index to retrieve.
 * @param[out] key_out    Buffer to store the key handle.
 * @param[out] value_out  Buffer to store the value handle.
 * @return                CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Returned handles are borrowed from the decoder.
 */
cbor_core_result_t cbor_core_map_get(const cbor_core_value_t *map, size_t index, cbor_core_value_t *key_out, cbor_core_value_t *value_out);

/**
 * @brief Find a value in a map by string key.
 *
 * @param[in]  map        The map value.
 * @param[in]  key        Key string to search for.
 * @param[in]  key_len    Length of the key string.
 * @param[out] value_out  Buffer to store the found value handle.
 * @return                CBOR_CORE_OK on success, or error if not found.
 *
 * @note Memory Management:
 *       Returned handle is borrowed from the decoder.
 */
cbor_core_result_t cbor_core_map_find_string(const cbor_core_value_t *map, const char *key, size_t key_len, cbor_core_value_t *value_out);

/**
 * @brief Get an unsigned integer value.
 *
 * @param[in]  value  The value handle.
 * @param[out] out    Pointer to store the result.
 * @return            CBOR_CORE_OK on success.
 */
cbor_core_result_t cbor_core_value_get_uint(const cbor_core_value_t *value, uint64_t *out);

/**
 * @brief Get a boolean value.
 *
 * @param[in]  value  The value handle.
 * @param[out] out    Pointer to store the result.
 * @return            CBOR_CORE_OK on success.
 */
cbor_core_result_t cbor_core_value_get_bool(const cbor_core_value_t *value, bool *out);

/**
 * @brief Get a text string value.
 *
 * @param[in]  value    The value handle.
 * @param[out] str_out  Pointer to store the string pointer.
 * @param[out] len_out  Pointer to store the length.
 * @return              CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Returned pointer references decoder-owned buffers. Callers must copy if
 *       needed beyond the decoder's lifetime.
 */
cbor_core_result_t cbor_core_value_get_text(const cbor_core_value_t *value, const char **str_out, size_t *len_out);

/**
 * @brief Get a byte string value.
 *
 * @param[in]  value     The value handle.
 * @param[out] data_out  Pointer to store the data pointer.
 * @param[out] len_out   Pointer to store the length.
 * @return               CBOR_CORE_OK on success.
 *
 * @note Memory Management:
 *       Returned pointer references decoder-owned buffers. Callers must copy if
 *       needed beyond the decoder's lifetime.
 */
cbor_core_result_t cbor_core_value_get_bytes(const cbor_core_value_t *value, const uint8_t **data_out, size_t *len_out);

#endif /* PIADINA_COMMON_CBOR_CORE_H */
