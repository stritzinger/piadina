/**
 * @file cbor_encoder.h
 * @brief CBOR encoding helpers for Azdora metadata.
 *
 * Ownership: the encoder does not take ownership of metadata; callers own the
 * returned buffer from azdora_cbor_encode_metadata and must free it.
 */
#ifndef AZDORA_CBOR_ENCODER_H
#define AZDORA_CBOR_ENCODER_H

#include <stddef.h>
#include <stdint.h>

#include "metadata.h"

typedef enum {
    AZDORA_CBOR_OK = 0,
    AZDORA_CBOR_ERR_INVALID_ARGUMENT,
    AZDORA_CBOR_ERR_ENCODE,
    AZDORA_CBOR_ERR_OOM
} azdora_cbor_result_t;

/**
 * Encode the provided metadata tree into a newly allocated CBOR buffer.
 *
 * @param metadata  Borrowed pointer to metadata tree.
 * @param out_data  Output buffer (malloc'd on success, caller frees with free()).
 * @param out_size  Output buffer length in bytes (not set on failure).
 *
 * The function never takes ownership of the metadata input. The returned buffer
 * is a fresh allocation owned by the caller.
 */
azdora_cbor_result_t azdora_cbor_encode_metadata(const azdora_metadata_t *metadata,
                                                 uint8_t **out_data,
                                                 size_t *out_size);

#endif /* AZDORA_CBOR_ENCODER_H */
