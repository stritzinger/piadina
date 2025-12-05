/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"
#include "piadina_config.h"

void setUp(void) {}
void tearDown(void) {}

static void test_version_macro_is_populated(void)
{
    TEST_ASSERT_TRUE(PACKAGE_VERSION[0] != '\0');
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_version_macro_is_populated);
    return UNITY_END();
}
