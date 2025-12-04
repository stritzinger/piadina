#include "unity.h"

#include "common/metadata_core.h"

void setUp(void) {}
void tearDown(void) {}

static void test_identifier_validation(void)
{
    TEST_ASSERT_TRUE(metadata_core_identifier_valid("APP_NAME", 8));
    TEST_ASSERT_TRUE(metadata_core_identifier_valid("foo-bar_123", 11));
    TEST_ASSERT_FALSE(metadata_core_identifier_valid("1INVALID", 8));
    TEST_ASSERT_FALSE(metadata_core_identifier_valid("bad space", 9));
}

static void test_field_lookup_and_required(void)
{
    metadata_core_field_t field = METADATA_FIELD_UNKNOWN;
    TEST_ASSERT_TRUE(metadata_core_field_lookup("VERSION", 7, &field));
    TEST_ASSERT_EQUAL(METADATA_FIELD_VERSION, field);
    TEST_ASSERT_TRUE(metadata_core_field_required(field));

    TEST_ASSERT_TRUE(metadata_core_field_lookup("LOG_LEVEL", 9, &field));
    TEST_ASSERT_FALSE(metadata_core_field_required(field));

    TEST_ASSERT_FALSE(metadata_core_field_lookup("missing", 7, &field));
    TEST_ASSERT_EQUAL(METADATA_FIELD_UNKNOWN, field);
}

static void test_cleanup_policy_helpers(void)
{
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_ONCRASH, metadata_core_cleanup_policy_default());
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_NEVER,
                      metadata_core_cleanup_policy_from_string("never"));
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_ALWAYS,
                      metadata_core_cleanup_policy_from_string("always"));
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_INVALID,
                      metadata_core_cleanup_policy_from_string("nope"));
    TEST_ASSERT_EQUAL_STRING("oncrash",
                             metadata_core_cleanup_policy_to_string(METADATA_CLEANUP_ONCRASH));
}

static void test_archive_defaults(void)
{
    TEST_ASSERT_TRUE(metadata_core_archive_format_supported("tar+gzip"));
    TEST_ASSERT_FALSE(metadata_core_archive_format_supported("zip"));
    TEST_ASSERT_EQUAL_STRING("tar+gzip", metadata_core_archive_format_default());
    TEST_ASSERT_FALSE(metadata_core_validate_default());
}

static void test_field_default_strings(void)
{
    TEST_ASSERT_EQUAL_STRING("tar+gzip",
                             metadata_core_field_default_string(METADATA_FIELD_ARCHIVE_FORMAT));
    TEST_ASSERT_EQUAL_STRING("{HOME}/.piadina/cache",
                             metadata_core_field_default_string(METADATA_FIELD_CACHE_ROOT));
    TEST_ASSERT_EQUAL_STRING("{CACHE_ROOT}/{PAYLOAD_HASH}",
                             metadata_core_field_default_string(METADATA_FIELD_PAYLOAD_ROOT));
    TEST_ASSERT_EQUAL_STRING("oncrash",
                             metadata_core_field_default_string(METADATA_FIELD_CLEANUP_POLICY));
    TEST_ASSERT_EQUAL_STRING("false",
                             metadata_core_field_default_string(METADATA_FIELD_VALIDATE));
    TEST_ASSERT_EQUAL_STRING("info",
                             metadata_core_field_default_string(METADATA_FIELD_LOG_LEVEL));
    TEST_ASSERT_EQUAL_PTR(NULL,
                          metadata_core_field_default_string(METADATA_FIELD_ENV));
    TEST_ASSERT_EQUAL_PTR(NULL,
                          metadata_core_field_default_string(METADATA_FIELD_VERSION));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_identifier_validation);
    RUN_TEST(test_field_lookup_and_required);
    RUN_TEST(test_cleanup_policy_helpers);
    RUN_TEST(test_archive_defaults);
    RUN_TEST(test_field_default_strings);
    return UNITY_END();
}
