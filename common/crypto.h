/*
 * Minimal SHA-256 implementation used to avoid external crypto dependencies.
 * Provides a small init/update/final API plus a convenience one-shot helper.
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

void crypto_sha256_init(crypto_sha256_ctx *ctx);
bool crypto_sha256_update(crypto_sha256_ctx *ctx, const uint8_t *data, size_t len);
bool crypto_sha256_final(crypto_sha256_ctx *ctx, uint8_t out[32]);
bool crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif /* COMMON_CRYPTO_H */
