/**
 * @file test_azdora_metadata.c
 * @brief Unit tests for azdora/metadata.{c,h}
 */
#include <string.h>

#include "unity.h"

#include "azdora/metadata.h"

void setUp(void) {}
void tearDown(void) {}

static azdora_meta_value_t *find_entry(const azdora_meta_map_t *root, const char *key)
{
    if (!root) {
        return NULL;
    }
    for (size_t i = 0; i < root->count; ++i) {
        if (strcmp(root->entries[i].key, key) == 0) {
            return root->entries[i].value;
        }
    }
    return NULL;
}

static void test_metadata_finalize_sets_defaults(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, azdora_metadata_finalize(&md, &error));

    const azdora_meta_map_t *root = azdora_metadata_root(&md);
    TEST_ASSERT_NOT_NULL(root);

    azdora_meta_value_t *version = find_entry(root, "VERSION");
    TEST_ASSERT_NOT_NULL(version);
    TEST_ASSERT_EQUAL(AZDORA_META_UINT, version->type);
    TEST_ASSERT_EQUAL_UINT64(METADATA_CORE_SCHEMA_VERSION, version->as.uint_val);

    azdora_meta_value_t *payload_hash = find_entry(root, "PAYLOAD_HASH");
    TEST_ASSERT_NOT_NULL(payload_hash);
    TEST_ASSERT_EQUAL(AZDORA_META_BYTES, payload_hash->type);
    TEST_ASSERT_EQUAL(32u, payload_hash->as.bytes.len);
    for (size_t i = 0; i < payload_hash->as.bytes.len; ++i) {
        TEST_ASSERT_EQUAL_UINT8(0, payload_hash->as.bytes.data[i]);
    }

    azdora_meta_value_t *archive_hash = find_entry(root, "ARCHIVE_HASH");
    TEST_ASSERT_NOT_NULL(archive_hash);
    TEST_ASSERT_EQUAL(AZDORA_META_BYTES, archive_hash->type);
    TEST_ASSERT_EQUAL(32u, archive_hash->as.bytes.len);

    azdora_metadata_destroy(&md);
}

static void test_metadata_reject_version_override(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    azdora_metadata_result_t rc = azdora_metadata_apply_meta(&md, "VERSION=2", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_UNSUPPORTED_KEY, rc);
    TEST_ASSERT_NOT_NULL(error);

    azdora_metadata_destroy(&md);
}

static void test_metadata_missing_entry_point(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    azdora_metadata_result_t rc = azdora_metadata_finalize(&md, &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_MISSING_REQUIRED, rc);
    TEST_ASSERT_NOT_NULL(error);

    azdora_metadata_destroy(&md);
}

static void test_metadata_reject_hash_override(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_UNSUPPORTED_KEY,
                      azdora_metadata_apply_meta(&md,
                                                 "PAYLOAD_HASH=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                                                 &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_UNSUPPORTED_KEY,
                      azdora_metadata_apply_meta(&md,
                                                 "ARCHIVE_HASH=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                                                 &error));

    azdora_metadata_destroy(&md);
}

static void test_metadata_env_validation(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    azdora_metadata_result_t rc = azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, rc);

    rc = azdora_metadata_apply_meta(&md, "ENV.DB=postgres", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, rc);

    rc = azdora_metadata_apply_meta(&md, "ENV.COUNT=b:1", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE, rc);
    TEST_ASSERT_NOT_NULL(error);

    rc = azdora_metadata_apply_meta(&md, "ENV.BAD=hex:aaaa", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE, rc);

    rc = azdora_metadata_apply_meta(&md, "ENV.1BAD=foo", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_PARSE, rc);
    TEST_ASSERT_NOT_NULL(error);

    rc = azdora_metadata_apply_meta(&md, "ENV.BAD-KEY=foo", &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_PARSE, rc);
    TEST_ASSERT_NOT_NULL(error);

    azdora_metadata_destroy(&md);
}

static void test_metadata_entry_args_append_and_indexed(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_ARGS[]=one", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_ARGS[1]=two", &error));

    const azdora_meta_map_t *root = azdora_metadata_root(&md);
    azdora_meta_value_t *args = find_entry(root, "ENTRY_ARGS");
    TEST_ASSERT_NOT_NULL(args);
    TEST_ASSERT_EQUAL(AZDORA_META_ARRAY, args->type);
    TEST_ASSERT_EQUAL(2u, args->as.array.count);
    TEST_ASSERT_EQUAL(AZDORA_META_STRING, args->as.array.items[0].type);
    TEST_ASSERT_EQUAL_STRING("one", args->as.array.items[0].as.str);
    TEST_ASSERT_EQUAL_STRING("two", args->as.array.items[1].as.str);

    azdora_metadata_destroy(&md);
}

static void test_metadata_entry_args_sparse_index_rejected(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE,
                      azdora_metadata_apply_meta(&md, "ENTRY_ARGS[2]=late", &error));

    azdora_metadata_destroy(&md);
}

static void test_metadata_entry_args_non_string_rejected(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE,
                      azdora_metadata_apply_meta(&md, "ENTRY_ARGS[]=b:true", &error));

    azdora_metadata_destroy(&md);
}

static void test_metadata_scalar_type_enforcement(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));

    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE,
                      azdora_metadata_apply_meta(&md, "APP_VER=u:1", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE,
                      azdora_metadata_apply_meta(&md, "VALIDATE=true", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "VALIDATE=b:true", &error));

    azdora_metadata_result_t rc = azdora_metadata_finalize(&md, &error);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, rc);

    azdora_metadata_destroy(&md);
}

static void test_metadata_programmatic_setters(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    /* Finalize to populate required defaults */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, azdora_metadata_finalize(&md, &error));

    /* Override VERSION via uint setter */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_set_field_uint(&md, METADATA_FIELD_VERSION, 2, &error));

    const uint8_t custom_hash[32] = {1, 2, 3, 4};
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_set_field_bytes(&md, METADATA_FIELD_ARCHIVE_HASH,
                                                      custom_hash, sizeof(custom_hash), &error));

    /* Type mismatch should fail */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_ERR_BAD_VALUE,
                      azdora_metadata_set_field_uint(&md, METADATA_FIELD_APP_VER, 5, &error));

    /* Verify getters reflect programmatic sets */
    uint64_t version = 0;
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_get_uint(&md, METADATA_FIELD_VERSION, &version, &error));
    TEST_ASSERT_EQUAL_UINT64(2u, version);

    const uint8_t *hash_bytes = NULL;
    size_t hash_len = 0;
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_get_bytes(&md, METADATA_FIELD_ARCHIVE_HASH,
                                                &hash_bytes, &hash_len, &error));
    TEST_ASSERT_EQUAL(32u, hash_len);
    TEST_ASSERT_EQUAL_UINT8(1, hash_bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(2, hash_bytes[1]);
    TEST_ASSERT_EQUAL_UINT8(3, hash_bytes[2]);
    TEST_ASSERT_EQUAL_UINT8(4, hash_bytes[3]);

    azdora_metadata_destroy(&md);
}

static void test_metadata_custom_fields_all_types(void)
{
    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;

    /* Required entry point */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "ENTRY_POINT=bin/app", &error));

    /* Custom scalars */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_STRING=hello", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_UINT=u:42", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_BOOL=b:true", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_BYTES=hex:0a0b", &error));

    /* Custom map with mixed value types (keys allow dash/underscore) */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_MAP.key-1=val", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_MAP.num=u:7", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_MAP.flag=b:false", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_MAP.bytes=hex:0c0d", &error));

    /* Custom array with mixed element types */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_ARR[]=text", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_ARR[]=u:3", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_ARR[]=b:true", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, "CUSTOM_ARR[]=hex:0102", &error));

    /* Finalize should still succeed */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, azdora_metadata_finalize(&md, &error));

    /* Inspect custom scalars, map, and array */
    const azdora_meta_map_t *root = azdora_metadata_root(&md);
    azdora_meta_value_t *custom_string = find_entry(root, "CUSTOM_STRING");
    TEST_ASSERT_NOT_NULL(custom_string);
    TEST_ASSERT_EQUAL(AZDORA_META_STRING, custom_string->type);
    TEST_ASSERT_EQUAL_STRING("hello", custom_string->as.str);

    azdora_meta_value_t *custom_uint = find_entry(root, "CUSTOM_UINT");
    TEST_ASSERT_NOT_NULL(custom_uint);
    TEST_ASSERT_EQUAL(AZDORA_META_UINT, custom_uint->type);
    TEST_ASSERT_EQUAL_UINT64(42u, custom_uint->as.uint_val);

    azdora_meta_value_t *custom_bool = find_entry(root, "CUSTOM_BOOL");
    TEST_ASSERT_NOT_NULL(custom_bool);
    TEST_ASSERT_EQUAL(AZDORA_META_BOOL, custom_bool->type);
    TEST_ASSERT_TRUE(custom_bool->as.bool_val);

    azdora_meta_value_t *custom_bytes = find_entry(root, "CUSTOM_BYTES");
    TEST_ASSERT_NOT_NULL(custom_bytes);
    TEST_ASSERT_EQUAL(AZDORA_META_BYTES, custom_bytes->type);
    TEST_ASSERT_EQUAL(2u, custom_bytes->as.bytes.len);
    TEST_ASSERT_EQUAL_UINT8(0x0a, custom_bytes->as.bytes.data[0]);
    TEST_ASSERT_EQUAL_UINT8(0x0b, custom_bytes->as.bytes.data[1]);

    azdora_meta_value_t *map_val = find_entry(root, "CUSTOM_MAP");
    TEST_ASSERT_NOT_NULL(map_val);
    TEST_ASSERT_EQUAL(AZDORA_META_MAP, map_val->type);
    azdora_meta_value_t *arr_val = find_entry(root, "CUSTOM_ARR");
    TEST_ASSERT_NOT_NULL(arr_val);
    TEST_ASSERT_EQUAL(AZDORA_META_ARRAY, arr_val->type);
    TEST_ASSERT_EQUAL(4u, arr_val->as.array.count);
    TEST_ASSERT_EQUAL(AZDORA_META_STRING, arr_val->as.array.items[0].type);
    TEST_ASSERT_EQUAL_STRING("text", arr_val->as.array.items[0].as.str);
    TEST_ASSERT_EQUAL(AZDORA_META_UINT, arr_val->as.array.items[1].type);
    TEST_ASSERT_EQUAL_UINT64(3u, arr_val->as.array.items[1].as.uint_val);
    TEST_ASSERT_EQUAL(AZDORA_META_BOOL, arr_val->as.array.items[2].type);
    TEST_ASSERT_TRUE(arr_val->as.array.items[2].as.bool_val);
    TEST_ASSERT_EQUAL(AZDORA_META_BYTES, arr_val->as.array.items[3].type);
    TEST_ASSERT_EQUAL(2u, arr_val->as.array.items[3].as.bytes.len);
    TEST_ASSERT_EQUAL_UINT8(0x01, arr_val->as.array.items[3].as.bytes.data[0]);
    TEST_ASSERT_EQUAL_UINT8(0x02, arr_val->as.array.items[3].as.bytes.data[1]);

    /* Verify map entries */
    azdora_meta_value_t *map_entry = find_entry(&map_val->as.map, "key-1");
    TEST_ASSERT_NOT_NULL(map_entry);
    TEST_ASSERT_EQUAL(AZDORA_META_STRING, map_entry->type);
    TEST_ASSERT_EQUAL_STRING("val", map_entry->as.str);
    map_entry = find_entry(&map_val->as.map, "num");
    TEST_ASSERT_NOT_NULL(map_entry);
    TEST_ASSERT_EQUAL(AZDORA_META_UINT, map_entry->type);
    TEST_ASSERT_EQUAL_UINT64(7u, map_entry->as.uint_val);
    map_entry = find_entry(&map_val->as.map, "flag");
    TEST_ASSERT_NOT_NULL(map_entry);
    TEST_ASSERT_EQUAL(AZDORA_META_BOOL, map_entry->type);
    TEST_ASSERT_FALSE(map_entry->as.bool_val);
    map_entry = find_entry(&map_val->as.map, "bytes");
    TEST_ASSERT_NOT_NULL(map_entry);
    TEST_ASSERT_EQUAL(AZDORA_META_BYTES, map_entry->type);
    TEST_ASSERT_EQUAL(2u, map_entry->as.bytes.len);
    TEST_ASSERT_EQUAL_UINT8(0x0c, map_entry->as.bytes.data[0]);
    TEST_ASSERT_EQUAL_UINT8(0x0d, map_entry->as.bytes.data[1]);

    azdora_metadata_destroy(&md);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_metadata_finalize_sets_defaults);
    RUN_TEST(test_metadata_reject_version_override);
    RUN_TEST(test_metadata_missing_entry_point);
    RUN_TEST(test_metadata_reject_hash_override);
    RUN_TEST(test_metadata_env_validation);
    RUN_TEST(test_metadata_entry_args_append_and_indexed);
    RUN_TEST(test_metadata_entry_args_sparse_index_rejected);
    RUN_TEST(test_metadata_entry_args_non_string_rejected);
    RUN_TEST(test_metadata_scalar_type_enforcement);
    RUN_TEST(test_metadata_programmatic_setters);
    RUN_TEST(test_metadata_custom_fields_all_types);
    return UNITY_END();
}
