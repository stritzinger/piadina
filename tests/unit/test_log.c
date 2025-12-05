#include <stdio.h>
#include <string.h>

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "common/log.h"

static void read_stream(FILE *stream, char *buffer, size_t buffer_size)
{
    fflush(stream);
    rewind(stream);
    size_t nread = fread(buffer, 1, buffer_size - 1, stream);
    buffer[nread] = '\0';
    rewind(stream);
}

void setUp(void)
{
    log_set_level(LOG_LEVEL_INFO);
    log_set_stream(NULL);
}

void tearDown(void) {}

static void test_log_default_level_is_info(void)
{
    TEST_ASSERT_EQUAL(LOG_LEVEL_INFO, log_get_level());
}

static void test_log_filters_below_level(void)
{
    FILE *stream = tmpfile();
    TEST_ASSERT_NOT_NULL(stream);

    log_set_stream(stream);
    log_set_level(LOG_LEVEL_WARN);

    log_info("info message");
    log_error("error message");

    char buffer[256];
    read_stream(stream, buffer, sizeof(buffer));

    TEST_ASSERT_NULL(strstr(buffer, "info message"));
    TEST_ASSERT_NOT_NULL(strstr(buffer, "error message"));

    fclose(stream);
}

static void test_log_emits_debug_when_enabled(void)
{
    FILE *stream = tmpfile();
    TEST_ASSERT_NOT_NULL(stream);

    log_set_stream(stream);
    log_set_level(LOG_LEVEL_DEBUG);

    log_debug("debug %d", 42);

    char buffer[256];
    read_stream(stream, buffer, sizeof(buffer));

    TEST_ASSERT_NOT_NULL(strstr(buffer, "[DEBUG]"));
    TEST_ASSERT_NOT_NULL(strstr(buffer, "debug 42"));

    fclose(stream);
}

static void test_log_level_from_string(void)
{
    TEST_ASSERT_EQUAL(LOG_LEVEL_DEBUG, log_level_from_string("debug"));
    TEST_ASSERT_EQUAL(LOG_LEVEL_INFO, log_level_from_string("info"));
    TEST_ASSERT_EQUAL(LOG_LEVEL_WARN, log_level_from_string("warn"));
    TEST_ASSERT_EQUAL(LOG_LEVEL_ERROR, log_level_from_string("error"));
    TEST_ASSERT_EQUAL(LOG_LEVEL_INVALID, log_level_from_string("verbose"));
    TEST_ASSERT_EQUAL(LOG_LEVEL_INVALID, log_level_from_string(NULL));
    TEST_ASSERT_EQUAL(LOG_LEVEL_INVALID, log_level_from_string(""));
}

static void test_log_level_default(void)
{
    TEST_ASSERT_EQUAL(LOG_LEVEL_INFO, log_level_default());
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_log_default_level_is_info);
    RUN_TEST(test_log_filters_below_level);
    RUN_TEST(test_log_emits_debug_when_enabled);
    RUN_TEST(test_log_level_from_string);
    RUN_TEST(test_log_level_default);
    return UNITY_END();
}
