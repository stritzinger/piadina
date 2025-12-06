/**
 * @file test_piadina_metadata.c
 * @brief Unit tests for piadina/metadata.{c,h}
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "piadina/metadata.h"
#include "common/cbor_core.h"
#include "common/metadata_core.h"
#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void build_minimal_cbor(uint8_t **out_buf, size_t *out_len, const char *entry_point, uint64_t version)
{
    cbor_core_encoder_t *enc = cbor_core_encoder_new();
    TEST_ASSERT_NOT_NULL(enc);

    /* map with 4 keys */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_map_start(enc, 4));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "VERSION", 7));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_uint(enc, version));

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ENTRY_POINT", 11));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, entry_point, strlen(entry_point)));

    uint8_t zeros[32] = {0};
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ARCHIVE_HASH", 12));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, zeros, sizeof(zeros)));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "PAYLOAD_HASH", 12));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, zeros, sizeof(zeros)));

    const uint8_t *buf = cbor_core_encoder_buffer(enc, out_len);
    TEST_ASSERT_NOT_NULL(buf);
    *out_buf = malloc(*out_len);
    TEST_ASSERT_NOT_NULL(*out_buf);
    memcpy(*out_buf, buf, *out_len);
    cbor_core_encoder_destroy(enc);
}

static void test_decode_minimal_metadata(void)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    build_minimal_cbor(&buf, &len, "bin/app", METADATA_CORE_SCHEMA_VERSION);

    piadina_metadata_t md;
    piadina_metadata_init(&md);
    const char *error = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_decode(buf, len, &md, &error));

    const char *entry = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_get_string(&md, METADATA_FIELD_ENTRY_POINT, &entry, &error));
    TEST_ASSERT_EQUAL_STRING("bin/app", entry);

    const uint8_t *hash = NULL;
    size_t hash_len = 0;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_get_bytes(&md, METADATA_FIELD_ARCHIVE_HASH, &hash, &hash_len, &error));
    TEST_ASSERT_EQUAL(32u, hash_len);

    /* Defaults applied for optional fields */
    const char *cache_root = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_get_string(&md, METADATA_FIELD_CACHE_ROOT, &cache_root, &error));
    TEST_ASSERT_NOT_NULL(cache_root);

    piadina_metadata_destroy(&md);
    free(buf);
}

static void test_reject_unsupported_version(void)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    build_minimal_cbor(&buf, &len, "bin/app", METADATA_CORE_SCHEMA_VERSION + 1);

    piadina_metadata_t md;
    piadina_metadata_init(&md);
    const char *error = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_ERR_UNSUPPORTED_VERSION,
                      piadina_metadata_decode(buf, len, &md, &error));
    piadina_metadata_destroy(&md);
    free(buf);
}

static void test_reject_absolute_entry_point(void)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    build_minimal_cbor(&buf, &len, "/bin/app", METADATA_CORE_SCHEMA_VERSION);

    piadina_metadata_t md;
    piadina_metadata_init(&md);
    const char *error = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_ERR_BAD_VALUE,
                      piadina_metadata_decode(buf, len, &md, &error));
    piadina_metadata_destroy(&md);
    free(buf);
}

static void test_apply_overrides_allows_permitted_fields(void)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    build_minimal_cbor(&buf, &len, "bin/app", METADATA_CORE_SCHEMA_VERSION);

    piadina_metadata_t md;
    piadina_metadata_init(&md);
    const char *error = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_decode(buf, len, &md, &error));

    /* Apply overrides: cache root, cleanup policy, validate */
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_apply_overrides(&md,
                                                       "/custom/cache",
                                                       "always",
                                                       0,
                                                       &error));

    const char *cache_root = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_get_string(&md, METADATA_FIELD_CACHE_ROOT, &cache_root, &error));
    TEST_ASSERT_EQUAL_STRING("/custom/cache", cache_root);

    const char *cleanup = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_get_string(&md, METADATA_FIELD_CLEANUP_POLICY, &cleanup, &error));
    TEST_ASSERT_EQUAL_STRING("always", cleanup);

    bool validate = true;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_get_bool(&md, METADATA_FIELD_VALIDATE, &validate, &error));
    TEST_ASSERT_FALSE(validate);

    piadina_metadata_destroy(&md);
    free(buf);
}

static void test_apply_overrides_rejects_bad_cleanup(void)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    build_minimal_cbor(&buf, &len, "bin/app", METADATA_CORE_SCHEMA_VERSION);

    piadina_metadata_t md;
    piadina_metadata_init(&md);
    const char *error = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_decode(buf, len, &md, &error));

    TEST_ASSERT_EQUAL(PIADINA_METADATA_ERR_BAD_VALUE,
                      piadina_metadata_apply_overrides(&md,
                                                       NULL,
                                                       "sometimes",
                                                       -1,
                                                       &error));

    piadina_metadata_destroy(&md);
    free(buf);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_decode_minimal_metadata);
    RUN_TEST(test_reject_unsupported_version);
    RUN_TEST(test_reject_absolute_entry_point);
    RUN_TEST(test_apply_overrides_allows_permitted_fields);
    RUN_TEST(test_apply_overrides_rejects_bad_cleanup);
    return UNITY_END();
}
