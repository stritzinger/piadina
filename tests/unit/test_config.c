/**
 * @file test_config.c
 * @brief Unit tests for piadina/config.{c,h}
 */
#include <stdlib.h>
#include <string.h>

#include "unity.h"

/* Include piadina config module - need proper include path */
#include "piadina/config.h"


void setUp(void)
{
    /* Clear any environment variables that might interfere */
    unsetenv("PIADINA_CACHE_ROOT");
    unsetenv("PIADINA_CLEANUP_POLICY");
    unsetenv("PIADINA_LOG_LEVEL");
    unsetenv("PIADINA_VALIDATE");
    unsetenv("PIADINA_FORCE_EXTRACT");
}


void tearDown(void) {}


/* ========================================================================== */
/*  Initialization tests                                                      */
/* ========================================================================== */

static void test_config_init_sets_defaults(void)
{
    piadina_config_t config;
    config_init(&config);

    TEST_ASSERT_EQUAL(CONFIG_ACTION_RUN, config.action);
    TEST_ASSERT_NULL(config.cache_root);  /* NULL means use metadata default */
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_ONCRASH, config.cleanup_policy);
    TEST_ASSERT_EQUAL(LOG_LEVEL_INFO, config.log_level);
    TEST_ASSERT_FALSE(config.validate);
    TEST_ASSERT_FALSE(config.force_extract);
    TEST_ASSERT_EQUAL(0, config.app_argc);
    TEST_ASSERT_NULL(config.app_argv);

    config_destroy(&config);
}


static void test_config_destroy_handles_null(void)
{
    /* Should not crash */
    config_destroy(NULL);
}


/* ========================================================================== */
/*  CLI parsing tests                                                         */
/* ========================================================================== */

static void test_config_parse_help(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-help" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(CONFIG_ACTION_HELP, config.action);

    config_destroy(&config);
}


static void test_config_parse_version(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-version" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(CONFIG_ACTION_VERSION, config.action);

    config_destroy(&config);
}


static void test_config_parse_print_footer(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-print-footer" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(CONFIG_ACTION_PRINT_FOOTER, config.action);

    config_destroy(&config);
}


static void test_config_parse_print_metadata(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-print-metadata" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(CONFIG_ACTION_PRINT_METADATA, config.action);

    config_destroy(&config);
}


static void test_config_parse_verbose(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-verbose" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(LOG_LEVEL_DEBUG, config.log_level);

    config_destroy(&config);
}


static void test_config_parse_cache_root_equals(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-cache-root=/tmp/cache" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_NOT_NULL(config.cache_root);
    TEST_ASSERT_EQUAL_STRING("/tmp/cache", config.cache_root);

    config_destroy(&config);
}


static void test_config_parse_cache_root_space(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-cache-root", "/tmp/cache2" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 3, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_NOT_NULL(config.cache_root);
    TEST_ASSERT_EQUAL_STRING("/tmp/cache2", config.cache_root);

    config_destroy(&config);
}


static void test_config_parse_cleanup_policy(void)
{
    piadina_config_t config;
    const char *error = NULL;

    /* Test "never" */
    config_init(&config);
    char *argv1[] = { "piadina", "--launcher-cleanup=never" };
    config_result_t result = config_parse_args(&config, 2, argv1, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_NEVER, config.cleanup_policy);
    config_destroy(&config);

    /* Test "oncrash" */
    config_init(&config);
    char *argv2[] = { "piadina", "--launcher-cleanup=oncrash" };
    result = config_parse_args(&config, 2, argv2, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_ONCRASH, config.cleanup_policy);
    config_destroy(&config);

    /* Test "always" */
    config_init(&config);
    char *argv3[] = { "piadina", "--launcher-cleanup=always" };
    result = config_parse_args(&config, 2, argv3, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_ALWAYS, config.cleanup_policy);
    config_destroy(&config);
}


static void test_config_parse_log_level(void)
{
    piadina_config_t config;
    const char *error = NULL;

    /* Test each log level */
    const struct { const char *name; log_level_t level; } levels[] = {
        { "debug", LOG_LEVEL_DEBUG },
        { "info", LOG_LEVEL_INFO },
        { "warn", LOG_LEVEL_WARN },
        { "error", LOG_LEVEL_ERROR }
    };

    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        config_init(&config);
        char opt[64];
        snprintf(opt, sizeof(opt), "--launcher-log-level=%s", levels[i].name);
        char *argv[] = { "piadina", opt };
        config_result_t result = config_parse_args(&config, 2, argv, &error);
        TEST_ASSERT_EQUAL_MESSAGE(CONFIG_OK, result, levels[i].name);
        TEST_ASSERT_EQUAL_MESSAGE(levels[i].level, config.log_level, levels[i].name);
        config_destroy(&config);
    }
}


static void test_config_parse_validate_true(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-validate" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(1, config.validate);

    config_destroy(&config);
}


static void test_config_parse_validate_explicit(void)
{
    piadina_config_t config;
    const char *error = NULL;

    /* Test explicit true */
    config_init(&config);
    char *argv1[] = { "piadina", "--launcher-validate=true" };
    config_result_t result = config_parse_args(&config, 2, argv1, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(1, config.validate);
    config_destroy(&config);

    /* Test explicit false */
    config_init(&config);
    char *argv2[] = { "piadina", "--launcher-validate=false" };
    result = config_parse_args(&config, 2, argv2, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(0, config.validate);
    config_destroy(&config);
}


static void test_config_parse_validate_space_false(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-validate", "false" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 3, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_FALSE(config.validate);

    config_destroy(&config);
}


static void test_config_parse_validate_invalid_value(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-validate=maybe" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_ERR_INVALID_VALUE, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


static void test_config_parse_boolean_flags_interspersed(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = {
        "piadina",
        "--launcher-validate",
        "-f",
        "--foobar",
        "XXX",
        "--launcher-force-extract",
        "--",
        "--lonely"
    };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config,
                                               (int)(sizeof(argv) / sizeof(argv[0])),
                                               argv,
                                               &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_TRUE(config.validate);
    TEST_ASSERT_TRUE(config.force_extract);
    TEST_ASSERT_EQUAL(4, config.app_argc);
    TEST_ASSERT_NOT_NULL(config.app_argv);
    TEST_ASSERT_EQUAL_STRING("-f", config.app_argv[0]);
    TEST_ASSERT_EQUAL_STRING("--foobar", config.app_argv[1]);
    TEST_ASSERT_EQUAL_STRING("XXX", config.app_argv[2]);
    TEST_ASSERT_EQUAL_STRING("--lonely", config.app_argv[3]);

    config_destroy(&config);
}


static void test_config_parse_force_extract(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-force-extract" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(1, config.force_extract);

    config_destroy(&config);
}


static void test_config_parse_force_extract_space_false(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-force-extract", "false" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 3, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_FALSE(config.force_extract);

    config_destroy(&config);
}


static void test_config_parse_force_extract_invalid_value(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-force-extract=maybe" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_ERR_INVALID_VALUE, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


static void test_config_parse_separator(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-verbose", "--", "arg1", "arg2", "arg3" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 6, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(LOG_LEVEL_DEBUG, config.log_level);
    TEST_ASSERT_EQUAL(3, config.app_argc);
    TEST_ASSERT_NOT_NULL(config.app_argv);
    TEST_ASSERT_EQUAL_STRING("arg1", config.app_argv[0]);
    TEST_ASSERT_EQUAL_STRING("arg2", config.app_argv[1]);
    TEST_ASSERT_EQUAL_STRING("arg3", config.app_argv[2]);

    config_destroy(&config);
}


static void test_config_parse_interspersed_args(void)
{
    piadina_config_t config;
    config_init(&config);

    /* --foo --launcher-verbose --bar -- --buz
     * Should pass --foo --bar --buz to the app */
    char *argv[] = { "piadina", "--foo", "--launcher-verbose", "--bar", "--", "--buz" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 6, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(LOG_LEVEL_DEBUG, config.log_level);
    TEST_ASSERT_EQUAL(3, config.app_argc);
    TEST_ASSERT_NOT_NULL(config.app_argv);
    TEST_ASSERT_EQUAL_STRING("--foo", config.app_argv[0]);
    TEST_ASSERT_EQUAL_STRING("--bar", config.app_argv[1]);
    TEST_ASSERT_EQUAL_STRING("--buz", config.app_argv[2]);

    config_destroy(&config);
}


static void test_config_parse_pass_launcher_like_after_separator(void)
{
    piadina_config_t config;
    config_init(&config);

    /* After --, even --launcher-help should be passed through */
    char *argv[] = { "piadina", "--", "--launcher-help", "--launcher-version" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 4, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(CONFIG_ACTION_RUN, config.action);  /* Not help action */
    TEST_ASSERT_EQUAL(2, config.app_argc);
    TEST_ASSERT_NOT_NULL(config.app_argv);
    TEST_ASSERT_EQUAL_STRING("--launcher-help", config.app_argv[0]);
    TEST_ASSERT_EQUAL_STRING("--launcher-version", config.app_argv[1]);

    config_destroy(&config);
}


static void test_config_parse_non_launcher_args_before_separator(void)
{
    piadina_config_t config;
    config_init(&config);

    /* Arguments not starting with --launcher- are passed through */
    char *argv[] = { "piadina", "-v", "start", "--config=/etc/app.conf" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 4, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(3, config.app_argc);
    TEST_ASSERT_NOT_NULL(config.app_argv);
    TEST_ASSERT_EQUAL_STRING("-v", config.app_argv[0]);
    TEST_ASSERT_EQUAL_STRING("start", config.app_argv[1]);
    TEST_ASSERT_EQUAL_STRING("--config=/etc/app.conf", config.app_argv[2]);

    config_destroy(&config);
}


static void test_config_parse_unknown_option_error(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-unknown" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_ERR_UNKNOWN_OPTION, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


static void test_config_parse_invalid_cleanup_error(void)
{
    piadina_config_t config;
    config_init(&config);

    char *argv[] = { "piadina", "--launcher-cleanup=invalid" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_ERR_INVALID_VALUE, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


static void test_config_parse_missing_value_error(void)
{
    piadina_config_t config;
    config_init(&config);

    /* --launcher-cache-root without a value at end of args */
    char *argv[] = { "piadina", "--launcher-cache-root" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 2, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_ERR_MISSING_VALUE, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


/* ========================================================================== */
/*  Environment variable tests                                                */
/* ========================================================================== */

static void test_config_env_cache_root(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_CACHE_ROOT", "/env/cache", 1);

    char *argv[] = { "piadina" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 1, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    result = config_apply_env(&config, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_NOT_NULL(config.cache_root);
    TEST_ASSERT_EQUAL_STRING("/env/cache", config.cache_root);

    config_destroy(&config);
}


static void test_config_env_cleanup_policy(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_CLEANUP_POLICY", "always", 1);

    char *argv[] = { "piadina" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 1, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    result = config_apply_env(&config, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_ALWAYS, config.cleanup_policy);

    config_destroy(&config);
}


static void test_config_env_validate(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_VALIDATE", "true", 1);

    char *argv[] = { "piadina" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 1, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    result = config_apply_env(&config, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(1, config.validate);

    config_destroy(&config);
}


static void test_config_env_log_level(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_LOG_LEVEL", "warn", 1);

    char *argv[] = { "piadina" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 1, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    result = config_apply_env(&config, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_EQUAL(LOG_LEVEL_WARN, config.log_level);

    config_destroy(&config);
}


static void test_config_env_force_extract(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_FORCE_EXTRACT", "true", 1);

    char *argv[] = { "piadina" };
    const char *error = NULL;

    config_result_t result = config_parse_args(&config, 1, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    result = config_apply_env(&config, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);
    TEST_ASSERT_TRUE(config.force_extract);

    config_destroy(&config);
}


static void test_config_env_invalid_validate(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_VALIDATE", "maybe", 1);

    const char *error = NULL;
    config_result_t result = config_apply_env(&config, &error);

    TEST_ASSERT_EQUAL(CONFIG_ERR_INVALID_VALUE, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


static void test_config_env_invalid_force_extract(void)
{
    piadina_config_t config;
    config_init(&config);

    setenv("PIADINA_FORCE_EXTRACT", "sometimes", 1);

    const char *error = NULL;
    config_result_t result = config_apply_env(&config, &error);

    TEST_ASSERT_EQUAL(CONFIG_ERR_INVALID_VALUE, result);
    TEST_ASSERT_NOT_NULL(error);

    config_destroy(&config);
}


/* ========================================================================== */
/*  Precedence tests (CLI > env)                                              */
/* ========================================================================== */

static void test_config_cli_overrides_env(void)
{
    piadina_config_t config;
    config_init(&config);

    /* Set environment */
    setenv("PIADINA_CACHE_ROOT", "/env/cache", 1);
    setenv("PIADINA_CLEANUP_POLICY", "always", 1);
    setenv("PIADINA_VALIDATE", "true", 1);

    /* Apply environment first (overrides defaults) */
    const char *error = NULL;
    config_result_t result = config_apply_env(&config, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    /* Then CLI (overrides everything) */
    char *argv[] = {
        "piadina",
        "--launcher-cache-root=/cli/cache",
        "--launcher-cleanup=never",
        "--launcher-validate=false"
    };

    result = config_parse_args(&config, 4, argv, &error);
    TEST_ASSERT_EQUAL(CONFIG_OK, result);

    /* CLI values should take precedence */
    TEST_ASSERT_EQUAL_STRING("/cli/cache", config.cache_root);
    TEST_ASSERT_EQUAL(METADATA_CLEANUP_NEVER, config.cleanup_policy);
    TEST_ASSERT_FALSE(config.validate);

    config_destroy(&config);
}


/* ========================================================================== */
/*  Main test runner                                                          */
/* ========================================================================== */

int main(void)
{
    UNITY_BEGIN();

    /* Initialization tests */
    RUN_TEST(test_config_init_sets_defaults);
    RUN_TEST(test_config_destroy_handles_null);

    /* CLI parsing tests */
    RUN_TEST(test_config_parse_help);
    RUN_TEST(test_config_parse_version);
    RUN_TEST(test_config_parse_print_footer);
    RUN_TEST(test_config_parse_print_metadata);
    RUN_TEST(test_config_parse_verbose);
    RUN_TEST(test_config_parse_cache_root_equals);
    RUN_TEST(test_config_parse_cache_root_space);
    RUN_TEST(test_config_parse_cleanup_policy);
    RUN_TEST(test_config_parse_log_level);
    RUN_TEST(test_config_parse_validate_true);
    RUN_TEST(test_config_parse_validate_explicit);
    RUN_TEST(test_config_parse_validate_space_false);
    RUN_TEST(test_config_parse_validate_invalid_value);
    RUN_TEST(test_config_parse_force_extract);
    RUN_TEST(test_config_parse_force_extract_space_false);
    RUN_TEST(test_config_parse_force_extract_invalid_value);
    RUN_TEST(test_config_parse_boolean_flags_interspersed);
    RUN_TEST(test_config_parse_separator);
    RUN_TEST(test_config_parse_interspersed_args);
    RUN_TEST(test_config_parse_pass_launcher_like_after_separator);
    RUN_TEST(test_config_parse_non_launcher_args_before_separator);
    RUN_TEST(test_config_parse_unknown_option_error);
    RUN_TEST(test_config_parse_invalid_cleanup_error);
    RUN_TEST(test_config_parse_missing_value_error);

    /* Environment variable tests */
    RUN_TEST(test_config_env_cache_root);
    RUN_TEST(test_config_env_cleanup_policy);
    RUN_TEST(test_config_env_validate);
    RUN_TEST(test_config_env_log_level);
    RUN_TEST(test_config_env_force_extract);
    RUN_TEST(test_config_env_invalid_validate);
    RUN_TEST(test_config_env_invalid_force_extract);

    /* Precedence tests */
    RUN_TEST(test_config_cli_overrides_env);

    return UNITY_END();
}
