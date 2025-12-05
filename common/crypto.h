/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file crypto.h
 * @brief Minimal SHA-256 implementation.
 *
 * Used to avoid external crypto dependencies.
 */
#ifndef COMMON_CRYPTO_H
#define COMMON_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bitcount; /* Number of message bits processed */
    uint8_t buffer[64];
} crypto_sha256_ctx;

/**
 * @brief Initialize the SHA-256 context.
 *
 * @param[out] ctx  Pointer to the context structure.
 *
 * @note Memory Management:
 *       Caller provides storage for @p ctx. No allocation occurs.
 */
void crypto_sha256_init(crypto_sha256_ctx *ctx);

/**
 * @brief Update the hash with new data.
 *
 * @param[in,out] ctx   Pointer to the context.
 * @param[in]     data  Pointer to the input data.
 * @param[in]     len   Length of the input data.
 * @return              true on success, false on error (e.g. null args).
 *
 * @note Memory Management:
 *       Does not take ownership of @p data.
 */
bool crypto_sha256_update(crypto_sha256_ctx *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize the hash computation.
 *
 * @param[in,out] ctx  Pointer to the context.
 * @param[out]    out  Buffer to store the 32-byte hash.
 * @return             true on success.
 *
 * @note Memory Management:
 *       Caller owns @p out and must ensure it is at least 32 bytes.
 */
bool crypto_sha256_final(crypto_sha256_ctx *ctx, uint8_t out[32]);

/**
 * @brief Compute SHA-256 hash in one shot.
 *
 * @param[in]  data  Pointer to the input data.
 * @param[in]  len   Length of the input data.
 * @param[out] out   Buffer to store the 32-byte hash.
 * @return           true on success.
 *
 * @note Memory Management:
 *       Caller owns @p out and must ensure it is at least 32 bytes.
 *       Does not take ownership of @p data.
 */
bool crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif /* COMMON_CRYPTO_H */
