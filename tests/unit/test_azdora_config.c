/**
 * @file test_azdora_config.c
 * @brief Unit tests for azdora/config.{c,h}
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "azdora/config.h"

void setUp(void) {}
void tearDown(void) {}

static void test_config_minimal_ok(void)
{
    azdora_config_t cfg;
    azdora_config_init(&cfg);

    char *argv[] = {
        "azdora",
        "--launcher", "/tmp/launcher",
        "--payload", "/tmp/payload",
        "--meta", "ENTRY_POINT=bin/app"
    };
    const char *error = NULL;

    azdora_config_result_t rc = azdora_config_parse_args(&cfg,
                                                         (int)(sizeof(argv) / sizeof(argv[0])),
                                                         argv,
                                                         &error);
    TEST_ASSERT_EQUAL(AZDORA_CONFIG_OK, rc);
    TEST_ASSERT_NOT_NULL(cfg.launcher_path);
    TEST_ASSERT_NOT_NULL(cfg.payload_dir);
    TEST_ASSERT_NOT_NULL(cfg.output_path);
    TEST_ASSERT_EQUAL(1, cfg.meta_count);
    TEST_ASSERT_NOT_NULL(cfg.meta_entries);

    azdora_config_destroy(&cfg);
}

static void test_config_output_override(void)
{
    azdora_config_t cfg;
    azdora_config_init(&cfg);

    char *argv[] = {
        "azdora",
        "-l", "/tmp/l",
        "-p", "/tmp/p",
        "-o", "/tmp/out.bin"
    };
    const char *error = NULL;

    azdora_config_result_t rc = azdora_config_parse_args(&cfg, 7, argv, &error);
    TEST_ASSERT_EQUAL(AZDORA_CONFIG_OK, rc);
    TEST_ASSERT_EQUAL_STRING("/tmp/out.bin", cfg.output_path);

    azdora_config_destroy(&cfg);
}

static void test_config_unknown_option(void)
{
    azdora_config_t cfg;
    azdora_config_init(&cfg);

    char *argv[] = { "azdora", "--unknown" };
    const char *error = NULL;

    azdora_config_result_t rc = azdora_config_parse_args(&cfg, 2, argv, &error);
    TEST_ASSERT_EQUAL(AZDORA_CONFIG_ERR_UNKNOWN_OPTION, rc);
    TEST_ASSERT_NOT_NULL(error);

    azdora_config_destroy(&cfg);
}

static void test_config_missing_required(void)
{
    azdora_config_t cfg;
    azdora_config_init(&cfg);
    const char *error = NULL;

    /* Only launcher provided */
    char *argv[] = { "azdora", "--launcher", "/tmp/l" };
    azdora_config_result_t rc = azdora_config_parse_args(&cfg, 3, argv, &error);
    TEST_ASSERT_EQUAL(AZDORA_CONFIG_ERR_MISSING_REQUIRED, rc);
    TEST_ASSERT_NOT_NULL(error);

    azdora_config_destroy(&cfg);
}

static void test_config_missing_value(void)
{
    azdora_config_t cfg;
    azdora_config_init(&cfg);
    const char *error = NULL;

    char *argv[] = { "azdora", "--launcher" };
    azdora_config_result_t rc = azdora_config_parse_args(&cfg, 2, argv, &error);
    TEST_ASSERT_EQUAL(AZDORA_CONFIG_ERR_MISSING_VALUE, rc);
    TEST_ASSERT_NOT_NULL(error);

    azdora_config_destroy(&cfg);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_config_minimal_ok);
    RUN_TEST(test_config_output_override);
    RUN_TEST(test_config_unknown_option);
    RUN_TEST(test_config_missing_required);
    RUN_TEST(test_config_missing_value);
    return UNITY_END();
}
