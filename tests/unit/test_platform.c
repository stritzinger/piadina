#include <limits.h>
#include <string.h>

#ifdef __linux__
#include <unistd.h>
#endif

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "common/platform.h"

void setUp(void) {}
void tearDown(void) {}

static void test_platform_self_path(void)
{
    char buffer[PATH_MAX];
    platform_result_t rc = platform_get_self_exe_path(buffer, sizeof(buffer));

#ifdef __linux__
    TEST_ASSERT_EQUAL(PLATFORM_OK, rc);

    char expected[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", expected, sizeof(expected) - 1);
    TEST_ASSERT_TRUE(len > 0);
    expected[len] = '\0';

    TEST_ASSERT_EQUAL_STRING(expected, buffer);
#else
    TEST_ASSERT_EQUAL(PLATFORM_ERR_NOT_IMPLEMENTED, rc);
#endif
}

static void test_platform_buffer_too_small(void)
{
    char buffer[1];
    platform_result_t rc = platform_get_self_exe_path(buffer, sizeof(buffer));

#ifdef __linux__
    TEST_ASSERT_EQUAL(PLATFORM_ERR_BUFFER_TOO_SMALL, rc);
#else
    TEST_ASSERT_EQUAL(PLATFORM_ERR_NOT_IMPLEMENTED, rc);
#endif
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_platform_self_path);
    RUN_TEST(test_platform_buffer_too_small);
    return UNITY_END();
}
