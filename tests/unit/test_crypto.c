/**
 * @file test_crypto.c
 * @brief Golden-vector tests for the internal SHA-256 implementation.
 */

#include <string.h>

#include "unity.h"
#include "common/crypto.h"

void setUp(void) {}
void tearDown(void) {}

static void assert_digest_equals(const uint8_t *expected, const uint8_t *actual)
{
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, 32);
}

static void test_sha256_empty(void)
{
    static const uint8_t expected[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
        0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
        0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

    uint8_t out[32];
    TEST_ASSERT_TRUE(crypto_sha256((const uint8_t *)"", 0, out));
    assert_digest_equals(expected, out);
}

static void test_sha256_abc(void)
{
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
        0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
        0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    uint8_t out[32];
    TEST_ASSERT_TRUE(crypto_sha256((const uint8_t *)"abc", 3, out));
    assert_digest_equals(expected, out);
}

static void test_sha256_streaming_standard_message(void)
{
    static const char *msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const uint8_t expected[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26,
        0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff,
        0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};

    crypto_sha256_ctx ctx;
    crypto_sha256_init(&ctx);

    /* Feed the message in uneven chunks to exercise buffering. */
    TEST_ASSERT_TRUE(crypto_sha256_update(&ctx, (const uint8_t *)msg, 3));
    TEST_ASSERT_TRUE(crypto_sha256_update(&ctx, (const uint8_t *)msg + 3, 10));
    size_t remaining = strlen(msg) - 13;
    TEST_ASSERT_TRUE(
        crypto_sha256_update(&ctx, (const uint8_t *)msg + 13, remaining));

    uint8_t out[32];
    TEST_ASSERT_TRUE(crypto_sha256_final(&ctx, out));
    assert_digest_equals(expected, out);
}

static void test_sha256_million_a(void)
{
    static const uint8_t expected[32] = {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7,
        0xe2, 0x84, 0xd7, 0x3e, 0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97,
        0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0};

    crypto_sha256_ctx ctx;
    crypto_sha256_init(&ctx);

    uint8_t chunk[1000];
    memset(chunk, 'a', sizeof(chunk));

    for (int i = 0; i < 1000; ++i) {
        TEST_ASSERT_TRUE(crypto_sha256_update(&ctx, chunk, sizeof(chunk)));
    }

    uint8_t out[32];
    TEST_ASSERT_TRUE(crypto_sha256_final(&ctx, out));
    assert_digest_equals(expected, out);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_sha256_empty);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_streaming_standard_message);
    RUN_TEST(test_sha256_million_a);
    return UNITY_END();
}
