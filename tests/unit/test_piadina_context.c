/**
 * @file test_piadina_context.c
 * @brief Unit tests for piadina/context.{c,h}
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "piadina/context.h"
#include "common/cbor_core.h"
#include "common/metadata_core.h"
#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void build_cbor_with_templates(uint8_t **out_buf, size_t *out_len)
{
    cbor_core_encoder_t *enc = cbor_core_encoder_new();
    TEST_ASSERT_NOT_NULL(enc);

    /* map with 9 keys */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_map_start(enc, 9));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "VERSION", 7));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_uint(enc, METADATA_CORE_SCHEMA_VERSION));

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ENTRY_POINT", 11));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "bin/app", 7));

    uint8_t zeros[32] = {0};
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ARCHIVE_HASH", 12));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, zeros, sizeof(zeros)));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "PAYLOAD_HASH", 12));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, zeros, sizeof(zeros)));

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "CACHE_ROOT", 10));
    const char *cache_tpl = "{HOME}/.piadina/cache";
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, cache_tpl, strlen(cache_tpl)));

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "PAYLOAD_ROOT", 12));
    const char *payload_tpl = "{CACHE_ROOT}/{ARCHIVE_HASH}";
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, payload_tpl, strlen(payload_tpl)));

    /* ENTRY_ARGS */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ENTRY_ARGS", 10));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_array_start(enc, 2));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "--foo", 5));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "--bar", 5));

    /* ENTRY_ARGS_POST */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ENTRY_ARGS_POST", 15));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_array_start(enc, 1));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "--post", 6));

    /* ENV map */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ENV", 3));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_map_start(enc, 1));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "FOO", 3));
    const char *env_tpl = "{PAYLOAD_ROOT}";
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, env_tpl, strlen(env_tpl)));

    const uint8_t *buf = cbor_core_encoder_buffer(enc, out_len);
    TEST_ASSERT_NOT_NULL(buf);
    *out_buf = malloc(*out_len);
    TEST_ASSERT_NOT_NULL(*out_buf);
    memcpy(*out_buf, buf, *out_len);
    cbor_core_encoder_destroy(enc);
}

static void test_context_resolve_resolves_templates(void)
{
    setenv("HOME", "/tmp/home", 1);

    /* Start from minimal metadata then add templated fields */
    uint8_t *buf = NULL;
    size_t len = 0;
    cbor_core_encoder_t *enc = cbor_core_encoder_new();
    TEST_ASSERT_NOT_NULL(enc);
    uint8_t zeros[32] = {0};
    /* minimal map with required fields */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_map_start(enc, 4));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "VERSION", 7));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_uint(enc, METADATA_CORE_SCHEMA_VERSION));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ENTRY_POINT", 11));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "bin/app", 7));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "ARCHIVE_HASH", 12));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, zeros, sizeof(zeros)));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "PAYLOAD_HASH", 12));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, zeros, sizeof(zeros)));
    const uint8_t *buf_ro = cbor_core_encoder_buffer(enc, &len);
    buf = malloc(len);
    TEST_ASSERT_NOT_NULL(buf);
    memcpy(buf, buf_ro, len);
    cbor_core_encoder_destroy(enc);

    piadina_metadata_t md;
    piadina_metadata_init(&md);
    const char *error = NULL;
    TEST_ASSERT_EQUAL(PIADINA_METADATA_OK,
                      piadina_metadata_decode(buf, len, &md, &error));

    /* Add templated fields via API */
    piadina_metadata_apply_overrides(&md,
                                     "{HOME}/.piadina/cache",
                                     NULL,
                                     -1,
                                     &error);
    metadata_tree_map_put_string(&md.root, "PAYLOAD_ROOT", strlen("PAYLOAD_ROOT"),
                                 "{CACHE_ROOT}/{ARCHIVE_HASH}");
    piadina_meta_value_t *args_val =
        metadata_tree_map_get_or_create(&md.root, "ENTRY_ARGS", strlen("ENTRY_ARGS"), NULL);
    TEST_ASSERT_NOT_NULL(args_val);
    memset(args_val, 0, sizeof(*args_val));
    args_val->type = PIADINA_META_ARRAY;
    metadata_tree_array_ensure_slot(args_val, 1);
    args_val->as.array.count = 2;
    args_val->as.array.items[0].type = PIADINA_META_STRING;
    args_val->as.array.items[0].as.str = strdup("{HOME}/--foo");
    args_val->as.array.items[1].type = PIADINA_META_STRING;
    args_val->as.array.items[1].as.str = strdup("{CACHE_ROOT}/--bar");

    piadina_meta_value_t *args_post_val =
        metadata_tree_map_get_or_create(&md.root, "ENTRY_ARGS_POST", strlen("ENTRY_ARGS_POST"), NULL);
    TEST_ASSERT_NOT_NULL(args_post_val);
    memset(args_post_val, 0, sizeof(*args_post_val));
    args_post_val->type = PIADINA_META_ARRAY;
    metadata_tree_array_ensure_slot(args_post_val, 0);
    args_post_val->as.array.count = 1;
    args_post_val->as.array.items[0].type = PIADINA_META_STRING;
    args_post_val->as.array.items[0].as.str = strdup("{PAYLOAD_ROOT}/--post");

    piadina_meta_value_t *env_val =
        metadata_tree_map_get_or_create(&md.root, "ENV", strlen("ENV"), NULL);
    TEST_ASSERT_NOT_NULL(env_val);
    memset(env_val, 0, sizeof(*env_val));
    env_val->type = PIADINA_META_MAP;
    metadata_tree_map_put_string(&env_val->as.map, "FOO", strlen("FOO"), "{PAYLOAD_ROOT}");

    piadina_context_t ctx;
    piadina_context_init(&ctx);

    piadina_context_result_t rc_ctx =
        piadina_context_resolve(&md, &ctx, &error);
    if (rc_ctx != PIADINA_CONTEXT_OK) {
        TEST_FAIL_MESSAGE(error ? error : "context resolve failed");
    }

    TEST_ASSERT_EQUAL_STRING("/tmp/home/.piadina/cache", ctx.cache_root);
    TEST_ASSERT_TRUE(strstr(ctx.payload_root, "/tmp/home/.piadina/cache") == ctx.payload_root);
    TEST_ASSERT_TRUE(strstr(ctx.entry_path, ctx.payload_root) == ctx.entry_path);
    /* Args */
    TEST_ASSERT_EQUAL(2u, ctx.entry_args_count);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/--foo", ctx.entry_args[0]);
    TEST_ASSERT_TRUE(strstr(ctx.entry_args[1], "/tmp/home/.piadina/cache") == ctx.entry_args[1]);
    TEST_ASSERT_EQUAL(1u, ctx.entry_args_post_count);
    TEST_ASSERT_TRUE(strstr(ctx.entry_args_post[0], ctx.payload_root) == ctx.entry_args_post[0]);

    TEST_ASSERT_NOT_NULL(ctx.env);
    TEST_ASSERT_EQUAL(1u, ctx.env_count);
    TEST_ASSERT_EQUAL_STRING("FOO", ctx.env[0].key);
    TEST_ASSERT_EQUAL_STRING(ctx.payload_root, ctx.env[0].value);

    piadina_context_destroy(&ctx);
    piadina_metadata_destroy(&md);
    free(buf);
}

static void test_context_resolve_recursive_and_custom(void)
{
    /* Set environment used by templates */
    setenv("HOME", "/tmp/home", 1);
    setenv("ENV_VAR", "zzz", 1);

    piadina_metadata_t md;
    const char *error = NULL;
    piadina_metadata_init(&md);

    /* Populate required hashes */
    piadina_meta_value_t *payload_hash =
        metadata_tree_map_get_or_create(&md.root, "PAYLOAD_HASH", strlen("PAYLOAD_HASH"), NULL);
    piadina_meta_value_t *archive_hash =
        metadata_tree_map_get_or_create(&md.root, "ARCHIVE_HASH", strlen("ARCHIVE_HASH"), NULL);
    TEST_ASSERT_NOT_NULL(payload_hash);
    TEST_ASSERT_NOT_NULL(archive_hash);
    memset(payload_hash, 0, sizeof(*payload_hash));
    memset(archive_hash, 0, sizeof(*archive_hash));
    payload_hash->type = PIADINA_META_BYTES;
    archive_hash->type = PIADINA_META_BYTES;
    payload_hash->as.bytes.data = (uint8_t *)malloc(2);
    archive_hash->as.bytes.data = (uint8_t *)malloc(2);
    TEST_ASSERT_NOT_NULL(payload_hash->as.bytes.data);
    TEST_ASSERT_NOT_NULL(archive_hash->as.bytes.data);
    payload_hash->as.bytes.len = 2;
    archive_hash->as.bytes.len = 2;
    payload_hash->as.bytes.data[0] = 0x01;
    payload_hash->as.bytes.data[1] = 0x02;
    archive_hash->as.bytes.data[0] = 0x0a;
    archive_hash->as.bytes.data[1] = 0x0b;

    /* Core fields with nested templates */
    metadata_tree_map_put_string(&md.root, "CACHE_ROOT", strlen("CACHE_ROOT"), "{HOME}/cache");
    metadata_tree_map_put_string(&md.root, "PAYLOAD_ROOT", strlen("PAYLOAD_ROOT"), "{CACHE_ROOT}/{ARCHIVE_HASH}");
    metadata_tree_map_put_string(&md.root, "ENTRY_POINT", strlen("ENTRY_POINT"), "bin/{PAYLOAD_HASH}");

    piadina_meta_value_t *args_val =
        metadata_tree_map_get_or_create(&md.root, "ENTRY_ARGS", strlen("ENTRY_ARGS"), NULL);
    TEST_ASSERT_NOT_NULL(args_val);
    memset(args_val, 0, sizeof(*args_val));
    args_val->type = PIADINA_META_ARRAY;
    metadata_tree_array_ensure_slot(args_val, 1);
    args_val->as.array.count = 2;
    args_val->as.array.items[0].type = PIADINA_META_STRING;
    args_val->as.array.items[0].as.str = strdup("{PAYLOAD_ROOT}/app");
    args_val->as.array.items[1].type = PIADINA_META_STRING;
    args_val->as.array.items[1].as.str = strdup("{ENV_VAR}");

    piadina_meta_value_t *args_post_val =
        metadata_tree_map_get_or_create(&md.root, "ENTRY_ARGS_POST", strlen("ENTRY_ARGS_POST"), NULL);
    TEST_ASSERT_NOT_NULL(args_post_val);
    memset(args_post_val, 0, sizeof(*args_post_val));
    args_post_val->type = PIADINA_META_ARRAY;
    metadata_tree_array_ensure_slot(args_post_val, 0);
    args_post_val->as.array.count = 1;
    args_post_val->as.array.items[0].type = PIADINA_META_STRING;
    args_post_val->as.array.items[0].as.str = strdup("{CACHE_ROOT}/post");

    piadina_meta_value_t *env_val =
        metadata_tree_map_get_or_create(&md.root, "ENV", strlen("ENV"), NULL);
    TEST_ASSERT_NOT_NULL(env_val);
    memset(env_val, 0, sizeof(*env_val));
    env_val->type = PIADINA_META_MAP;
    metadata_tree_map_put_string(&env_val->as.map, "FOO", strlen("FOO"), "{CACHE_ROOT}");
    metadata_tree_map_put_string(&env_val->as.map, "BAR", strlen("BAR"), "{PAYLOAD_ROOT}");

    /* Custom fields */
    metadata_tree_map_put_string(&md.root, "CUSTOM1", strlen("CUSTOM1"), "{PAYLOAD_ROOT}/custom");
    piadina_meta_value_t *custom_map =
        metadata_tree_map_get_or_create(&md.root, "CUSTOM_MAP", strlen("CUSTOM_MAP"), NULL);
    TEST_ASSERT_NOT_NULL(custom_map);
    memset(custom_map, 0, sizeof(*custom_map));
    custom_map->type = PIADINA_META_MAP;
    metadata_tree_map_put_string(&custom_map->as.map, "PATH", strlen("PATH"), "{CACHE_ROOT}/x");

    piadina_meta_value_t *custom_arr =
        metadata_tree_map_get_or_create(&md.root, "CUSTOM_ARR", strlen("CUSTOM_ARR"), NULL);
    TEST_ASSERT_NOT_NULL(custom_arr);
    memset(custom_arr, 0, sizeof(*custom_arr));
    custom_arr->type = PIADINA_META_ARRAY;
    metadata_tree_array_ensure_slot(custom_arr, 0);
    custom_arr->as.array.count = 1;
    custom_arr->as.array.items[0].type = PIADINA_META_STRING;
    custom_arr->as.array.items[0].as.str = strdup("{PAYLOAD_HASH}");

    piadina_context_t ctx;
    piadina_context_init(&ctx);

    piadina_context_result_t rc_ctx =
        piadina_context_resolve(&md, &ctx, &error);
    if (rc_ctx != PIADINA_CONTEXT_OK) {
        TEST_FAIL_MESSAGE(error ? error : "context resolve failed");
    }

    /* Check resolved context fields */
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache", ctx.cache_root);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache/0a0b", ctx.payload_root);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache/0a0b/bin/{PAYLOAD_HASH}", ctx.entry_path);

    TEST_ASSERT_EQUAL(2u, ctx.entry_args_count);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache/0a0b/app", ctx.entry_args[0]);
    TEST_ASSERT_EQUAL_STRING("zzz", ctx.entry_args[1]);

    TEST_ASSERT_EQUAL(1u, ctx.entry_args_post_count);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache/post", ctx.entry_args_post[0]);

    TEST_ASSERT_EQUAL(2u, ctx.env_count);
    TEST_ASSERT_EQUAL_STRING("FOO", ctx.env[0].key);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache", ctx.env[0].value);
    TEST_ASSERT_EQUAL_STRING("BAR", ctx.env[1].key);
    TEST_ASSERT_EQUAL_STRING("/tmp/home/cache/0a0b", ctx.env[1].value);

    /* Custom fields are not expanded */
    piadina_meta_value_t *custom1 =
        metadata_tree_map_find(&md.root, "CUSTOM1", strlen("CUSTOM1"));
    TEST_ASSERT_NOT_NULL(custom1);
    TEST_ASSERT_EQUAL(PIADINA_META_STRING, custom1->type);
    TEST_ASSERT_EQUAL_STRING("{PAYLOAD_ROOT}/custom", custom1->as.str);

    piadina_context_destroy(&ctx);
    piadina_metadata_destroy(&md);
}

static void test_context_resolve_rejects_cycle(void)
{
    /* Set environment used by templates */
    setenv("HOME", "/tmp/home", 1);

    piadina_metadata_t md;
    const char *error = NULL;
    piadina_metadata_init(&md);

    /* Required hashes */
    piadina_meta_value_t *payload_hash =
        metadata_tree_map_get_or_create(&md.root, "PAYLOAD_HASH", strlen("PAYLOAD_HASH"), NULL);
    piadina_meta_value_t *archive_hash =
        metadata_tree_map_get_or_create(&md.root, "ARCHIVE_HASH", strlen("ARCHIVE_HASH"), NULL);
    TEST_ASSERT_NOT_NULL(payload_hash);
    TEST_ASSERT_NOT_NULL(archive_hash);
    memset(payload_hash, 0, sizeof(*payload_hash));
    memset(archive_hash, 0, sizeof(*archive_hash));
    payload_hash->type = PIADINA_META_BYTES;
    archive_hash->type = PIADINA_META_BYTES;
    payload_hash->as.bytes.data = (uint8_t *)malloc(1);
    archive_hash->as.bytes.data = (uint8_t *)malloc(1);
    TEST_ASSERT_NOT_NULL(payload_hash->as.bytes.data);
    TEST_ASSERT_NOT_NULL(archive_hash->as.bytes.data);
    payload_hash->as.bytes.len = archive_hash->as.bytes.len = 1;
    payload_hash->as.bytes.data[0] = 0x01;
    archive_hash->as.bytes.data[0] = 0x02;

    /* Core fields */
    metadata_tree_map_put_string(&md.root, "CACHE_ROOT", strlen("CACHE_ROOT"), "{A}");
    metadata_tree_map_put_string(&md.root, "PAYLOAD_ROOT", strlen("PAYLOAD_ROOT"), "{CACHE_ROOT}");
    metadata_tree_map_put_string(&md.root, "ENTRY_POINT", strlen("ENTRY_POINT"), "app");

    /* Create a cycle A -> B -> A */
    metadata_tree_map_put_string(&md.root, "A", strlen("A"), "{B}");
    metadata_tree_map_put_string(&md.root, "B", strlen("B"), "{A}");

    piadina_context_t ctx;
    piadina_context_init(&ctx);
    piadina_context_result_t rc_ctx =
        piadina_context_resolve(&md, &ctx, &error);

    TEST_ASSERT_NOT_EQUAL(PIADINA_CONTEXT_OK, rc_ctx);
    TEST_ASSERT_NOT_NULL(error);

    piadina_context_destroy(&ctx);
    piadina_metadata_destroy(&md);
}
int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_context_resolve_resolves_templates);
    RUN_TEST(test_context_resolve_recursive_and_custom);
    RUN_TEST(test_context_resolve_rejects_cycle);
    return UNITY_END();
}
