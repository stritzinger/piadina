/*
 * Minimal SHA-256 implementation.
 * Based on FIPS 180-4 and kept dependency-free for static builds.
 */
#include "crypto.h"

#include <string.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR32((x), 2) ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define BSIG1(x) (ROTR32((x), 6) ^ ROTR32((x), 11) ^ ROTR32((x), 25))
#define SSIG0(x) (ROTR32((x), 7) ^ ROTR32((x), 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul, 0x3956c25bul,
    0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul, 0xd807aa98ul, 0x12835b01ul,
    0x243185beul, 0x550c7dc3ul, 0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul,
    0xc19bf174ul, 0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
    0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul, 0x983e5152ul,
    0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul, 0xc6e00bf3ul, 0xd5a79147ul,
    0x06ca6351ul, 0x14292967ul, 0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul,
    0x53380d13ul, 0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
    0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul, 0xd192e819ul,
    0xd6990624ul, 0xf40e3585ul, 0x106aa070ul, 0x19a4c116ul, 0x1e376c08ul,
    0x2748774cul, 0x34b0bcb5ul, 0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful,
    0x682e6ff3ul, 0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
    0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul,
};

static void crypto_sha256_transform(crypto_sha256_ctx *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    for (size_t t = 0; t < 16; ++t) {
        w[t] = ((uint32_t)block[t * 4] << 24) | ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) | ((uint32_t)block[t * 4 + 3]);
    }
    for (size_t t = 16; t < 64; ++t) {
        w[t] = SSIG1(w[t - 2]) + w[t - 7] + SSIG0(w[t - 15]) + w[t - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (size_t t = 0; t < 64; ++t) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + k[t] + w[t];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void crypto_sha256_init(crypto_sha256_ctx *ctx)
{
    if (!ctx) {
        return;
    }
    ctx->state[0] = 0x6a09e667ul;
    ctx->state[1] = 0xbb67ae85ul;
    ctx->state[2] = 0x3c6ef372ul;
    ctx->state[3] = 0xa54ff53aul;
    ctx->state[4] = 0x510e527ful;
    ctx->state[5] = 0x9b05688cul;
    ctx->state[6] = 0x1f83d9abul;
    ctx->state[7] = 0x5be0cd19ul;
    ctx->bitcount = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

bool crypto_sha256_update(crypto_sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    if (!ctx || (!data && len > 0)) {
        return false;
    }

    size_t buffer_bytes = (size_t)((ctx->bitcount >> 3) & 0x3f);
    ctx->bitcount += (uint64_t)len * 8;

    size_t offset = 0;
    if (buffer_bytes > 0) {
        size_t to_copy = (len < (64 - buffer_bytes)) ? len : (64 - buffer_bytes);
        memcpy(ctx->buffer + buffer_bytes, data, to_copy);
        buffer_bytes += to_copy;
        offset += to_copy;
        if (buffer_bytes == 64) {
            crypto_sha256_transform(ctx, ctx->buffer);
            buffer_bytes = 0;
        }
    }

    while (offset + 64 <= len) {
        crypto_sha256_transform(ctx, data + offset);
        offset += 64;
    }

    if (offset < len) {
        memcpy(ctx->buffer, data + offset, len - offset);
    }

    return true;
}

bool crypto_sha256_final(crypto_sha256_ctx *ctx, uint8_t out[32])
{
    if (!ctx || !out) {
        return false;
    }

    uint64_t bitcount = ctx->bitcount;
    uint8_t length_bytes[8];
    for (size_t i = 0; i < 8; ++i) {
        length_bytes[7 - i] = (uint8_t)(bitcount >> (i * 8));
    }

    size_t buffer_bytes = (size_t)((bitcount >> 3) & 0x3f);
    size_t pad_len = (buffer_bytes < 56) ? (56 - buffer_bytes) : (120 - buffer_bytes);

    static const uint8_t pad[64] = {0x80};
    if (!crypto_sha256_update(ctx, pad, pad_len)) {
        return false;
    }
    if (!crypto_sha256_update(ctx, length_bytes, sizeof(length_bytes))) {
        return false;
    }

    for (size_t i = 0; i < 8; ++i) {
        out[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    return true;
}

bool crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    crypto_sha256_ctx ctx;
    crypto_sha256_init(&ctx);
    if (!crypto_sha256_update(&ctx, data, len)) {
        return false;
    }
    return crypto_sha256_final(&ctx, out);
}
