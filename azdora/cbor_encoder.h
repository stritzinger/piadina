/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file cbor_encoder.h
 * @brief CBOR encoding helpers for Azdora metadata.
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
 * @brief Encode the provided metadata tree into a newly allocated CBOR buffer.
 *
 * @param[in]  metadata  Borrowed pointer to metadata tree.
 * @param[out] out_data  Pointer to store the allocated buffer.
 * @param[out] out_size  Pointer to store the buffer size.
 * @return               AZDORA_CBOR_OK on success.
 *
 * @note Memory Management:
 *       The encoder does not take ownership of @p metadata.
 *       The returned buffer in @p out_data is a fresh allocation owned by the caller,
 *       who must free it using free().
 */
azdora_cbor_result_t azdora_cbor_encode_metadata(const azdora_metadata_t *metadata,
                                                 uint8_t **out_data,
                                                 size_t *out_size);

#endif /* AZDORA_CBOR_ENCODER_H */
