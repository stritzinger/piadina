/**
 * @file test_azdora_cbor_encode.c
 * @brief Unit tests for azdora/cbor_encode.{c,h}
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "azdora/cbor_encoder.h"
#include "common/cbor_core.h"

void setUp(void) {}
void tearDown(void) {}

static void fill_metadata(azdora_metadata_t *md)
{
    const char *error = NULL;
    azdora_metadata_init(md);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "APP_NAME=myapp", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "APP_VER=1.2.3", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "ENTRY_ARGS[]=one", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "ENTRY_ARGS[1]=two", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "ENTRY_ARGS_POST[]=post", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "ENV.DB_HOST=localhost", &error));
    /* Custom scalars */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_STRING=hello", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_UINT=u:42", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_BOOL=b:true", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_BYTES=hex:0a0b", &error));
    /* Custom map (mixed types) */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_MAP.key-1=val", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_MAP.num=u:7", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_MAP.flag=b:false", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_MAP.bytes=hex:0c0d", &error));
    /* Custom array (mixed types) */
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_ARR[]=text", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_ARR[]=u:3", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_ARR[]=b:true", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "CUSTOM_ARR[]=hex:0102", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, azdora_metadata_finalize(md, &error));
}

static void test_cbor_encode_round_trip(void)
{
    azdora_metadata_t md;
    fill_metadata(&md);

    uint8_t *buf = NULL;
    size_t buf_size = 0;
    azdora_cbor_result_t rc = azdora_cbor_encode_metadata(&md, &buf, &buf_size);
    TEST_ASSERT_EQUAL(AZDORA_CBOR_OK, rc);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_TRUE(buf_size > 0);

    cbor_core_decoder_t *dec = cbor_core_decoder_new(buf, buf_size);
    TEST_ASSERT_NOT_NULL(dec);

    cbor_core_value_t root;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_decoder_root(dec, &root));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_MAP, cbor_core_value_type(&root));

    /* Check VERSION */
    cbor_core_value_t value;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "VERSION", strlen("VERSION"), &value));
    uint64_t version = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_uint(&value, &version));
    TEST_ASSERT_EQUAL_UINT64(METADATA_CORE_SCHEMA_VERSION, version);

    /* Check ENTRY_POINT */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "ENTRY_POINT", strlen("ENTRY_POINT"), &value));
    const char *entry = NULL;
    size_t entry_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&value, &entry, &entry_len));
    TEST_ASSERT_EQUAL_STRING_LEN("bin/app", entry, entry_len);

    /* Check PAYLOAD_HASH length */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "PAYLOAD_HASH", strlen("PAYLOAD_HASH"), &value));
    const uint8_t *payload_bytes = NULL;
    size_t payload_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bytes(&value, &payload_bytes, &payload_len));
    TEST_ASSERT_EQUAL(32u, payload_len);

    /* Check ARCHIVE_HASH bytes */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "ARCHIVE_HASH", strlen("ARCHIVE_HASH"), &value));
    const uint8_t *archive_hash = NULL;
    size_t archive_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bytes(&value, &archive_hash, &archive_len));
    TEST_ASSERT_EQUAL(32u, archive_len);

    /* ENTRY_ARGS array */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "ENTRY_ARGS", strlen("ENTRY_ARGS"), &value));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_ARRAY, cbor_core_value_type(&value));
    TEST_ASSERT_EQUAL(2u, cbor_core_array_size(&value));
    cbor_core_value_t arg0;
    cbor_core_value_t arg1;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 0, &arg0));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 1, &arg1));
    const char *arg_text = NULL;
    size_t arg_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&arg0, &arg_text, &arg_len));
    TEST_ASSERT_EQUAL_STRING_LEN("one", arg_text, arg_len);
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&arg1, &arg_text, &arg_len));
    TEST_ASSERT_EQUAL_STRING_LEN("two", arg_text, arg_len);

    /* ENTRY_ARGS_POST */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "ENTRY_ARGS_POST", strlen("ENTRY_ARGS_POST"), &value));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_ARRAY, cbor_core_value_type(&value));
    TEST_ASSERT_EQUAL(1u, cbor_core_array_size(&value));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 0, &arg0));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&arg0, &arg_text, &arg_len));
    TEST_ASSERT_EQUAL_STRING_LEN("post", arg_text, arg_len);

    /* ENV map */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "ENV", strlen("ENV"), &value));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_MAP, cbor_core_value_type(&value));
    cbor_core_value_t env_val;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&value, "DB_HOST", strlen("DB_HOST"), &env_val));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_TEXT, cbor_core_value_type(&env_val));
    const char *env_str = NULL;
    size_t env_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&env_val, &env_str, &env_len));
    TEST_ASSERT_EQUAL_STRING_LEN("localhost", env_str, env_len);

    /* Custom scalars */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "CUSTOM_STRING", strlen("CUSTOM_STRING"), &value));
    const char *custom_str = NULL;
    size_t custom_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&value, &custom_str, &custom_len));
    TEST_ASSERT_EQUAL_STRING_LEN("hello", custom_str, custom_len);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "CUSTOM_UINT", strlen("CUSTOM_UINT"), &value));
    uint64_t custom_uint = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_uint(&value, &custom_uint));
    TEST_ASSERT_EQUAL_UINT64(42u, custom_uint);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "CUSTOM_BOOL", strlen("CUSTOM_BOOL"), &value));
    bool custom_bool = false;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bool(&value, &custom_bool));
    TEST_ASSERT_TRUE(custom_bool);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "CUSTOM_BYTES", strlen("CUSTOM_BYTES"), &value));
    const uint8_t *custom_bytes = NULL;
    size_t custom_bytes_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bytes(&value, &custom_bytes, &custom_bytes_len));
    TEST_ASSERT_EQUAL(2u, custom_bytes_len);
    TEST_ASSERT_EQUAL_UINT8(0x0a, custom_bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(0x0b, custom_bytes[1]);

    /* Custom map */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "CUSTOM_MAP", strlen("CUSTOM_MAP"), &value));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_MAP, cbor_core_value_type(&value));
    cbor_core_value_t map_entry;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&value, "key-1", strlen("key-1"), &map_entry));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_TEXT, cbor_core_value_type(&map_entry));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&map_entry, &custom_str, &custom_len));
    TEST_ASSERT_EQUAL_STRING_LEN("val", custom_str, custom_len);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&value, "num", strlen("num"), &map_entry));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_uint(&map_entry, &custom_uint));
    TEST_ASSERT_EQUAL_UINT64(7u, custom_uint);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&value, "flag", strlen("flag"), &map_entry));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bool(&map_entry, &custom_bool));
    TEST_ASSERT_FALSE(custom_bool);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&value, "bytes", strlen("bytes"), &map_entry));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bytes(&map_entry, &custom_bytes, &custom_bytes_len));
    TEST_ASSERT_EQUAL(2u, custom_bytes_len);
    TEST_ASSERT_EQUAL_UINT8(0x0c, custom_bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(0x0d, custom_bytes[1]);

    /* Custom array */
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "CUSTOM_ARR", strlen("CUSTOM_ARR"), &value));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_ARRAY, cbor_core_value_type(&value));
    TEST_ASSERT_EQUAL(4u, cbor_core_array_size(&value));
    cbor_core_value_t arr_item;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 0, &arr_item));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&arr_item, &custom_str, &custom_len));
    TEST_ASSERT_EQUAL_STRING_LEN("text", custom_str, custom_len);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 1, &arr_item));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_uint(&arr_item, &custom_uint));
    TEST_ASSERT_EQUAL_UINT64(3u, custom_uint);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 2, &arr_item));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bool(&arr_item, &custom_bool));
    TEST_ASSERT_TRUE(custom_bool);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&value, 3, &arr_item));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bytes(&arr_item, &custom_bytes, &custom_bytes_len));
    TEST_ASSERT_EQUAL(2u, custom_bytes_len);
    TEST_ASSERT_EQUAL_UINT8(0x01, custom_bytes[0]);
    TEST_ASSERT_EQUAL_UINT8(0x02, custom_bytes[1]);

    free(buf);
    cbor_core_decoder_destroy(dec);
    azdora_metadata_destroy(&md);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cbor_encode_round_trip);
    return UNITY_END();
}
