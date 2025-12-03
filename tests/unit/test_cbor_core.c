#include <stdint.h>
#include <string.h>

#include "unity.h"

#include "common/cbor_core.h"

void setUp(void) {}
void tearDown(void) {}

static void test_cbor_core_round_trip_map(void)
{
    cbor_core_encoder_t *enc = cbor_core_encoder_new();
    TEST_ASSERT_NOT_NULL(enc);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_map_start(enc, 2));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "foo", 3));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_uint(enc, 42));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "bar", 3));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bool(enc, true));

    size_t encoded_len = 0;
    const uint8_t *buffer = cbor_core_encoder_buffer(enc, &encoded_len);
    TEST_ASSERT_TRUE(encoded_len > 0);

    cbor_core_decoder_t *dec = cbor_core_decoder_new(buffer, encoded_len);
    TEST_ASSERT_NOT_NULL(dec);

    cbor_core_value_t root;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_decoder_root(dec, &root));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_MAP, cbor_core_value_type(&root));
    TEST_ASSERT_EQUAL(2u, cbor_core_map_size(&root));

    cbor_core_value_t value;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_map_find_string(&root, "foo", 3, &value));
    uint64_t number = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_uint(&value, &number));
    TEST_ASSERT_EQUAL_UINT64(42, number);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_map_find_string(&root, "bar", 3, &value));
    bool flag = false;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bool(&value, &flag));
    TEST_ASSERT_TRUE(flag);

    cbor_core_decoder_destroy(dec);
    cbor_core_encoder_destroy(enc);
}

static void test_cbor_core_array_bytes(void)
{
    cbor_core_encoder_t *enc = cbor_core_encoder_new();
    TEST_ASSERT_NOT_NULL(enc);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_array_start(enc, 2));
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_text(enc, "hello", 5));
    const uint8_t bytes[] = {0xde, 0xad, 0xbe, 0xef};
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_encode_bytes(enc, bytes, sizeof(bytes)));

    size_t encoded_len = 0;
    const uint8_t *buffer = cbor_core_encoder_buffer(enc, &encoded_len);

    cbor_core_decoder_t *dec = cbor_core_decoder_new(buffer, encoded_len);
    TEST_ASSERT_NOT_NULL(dec);

    cbor_core_value_t root;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_decoder_root(dec, &root));
    TEST_ASSERT_EQUAL(CBOR_CORE_TYPE_ARRAY, cbor_core_value_type(&root));
    TEST_ASSERT_EQUAL(2u, cbor_core_array_size(&root));

    cbor_core_value_t elem;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&root, 0, &elem));
    const char *str = NULL;
    size_t len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&elem, &str, &len));
    TEST_ASSERT_EQUAL(5u, len);
    TEST_ASSERT_EQUAL_STRING_LEN("hello", str, len);

    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_array_get(&root, 1, &elem));
    const uint8_t *out_bytes = NULL;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_bytes(&elem, &out_bytes, &len));
    TEST_ASSERT_EQUAL(sizeof(bytes), len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(bytes, out_bytes, len);

    cbor_core_decoder_destroy(dec);
    cbor_core_encoder_destroy(enc);
}

static void test_cbor_core_decoder_rejects_invalid(void)
{
    const uint8_t bad_data[] = {0xff, 0xff};
    cbor_core_decoder_t *dec = cbor_core_decoder_new(bad_data, sizeof(bad_data));
    TEST_ASSERT_NULL(dec);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_cbor_core_round_trip_map);
    RUN_TEST(test_cbor_core_array_bytes);
    RUN_TEST(test_cbor_core_decoder_rejects_invalid);
    return UNITY_END();
}
