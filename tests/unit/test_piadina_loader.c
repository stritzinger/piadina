/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include <string.h>

#include "../unity/unity.h"
#include "../../piadina/loader.h"

static void test_extract_rejects_uninitialized(void)
{
    piadina_loader_t loader;
    memset(&loader, 0, sizeof(loader));
    loader.fd = -1;
    char out_dir[32] = {0};
    const char *err = NULL;

    piadina_loader_result_t rc = piadina_loader_extract(&loader, NULL, out_dir, sizeof(out_dir), &err);
    TEST_ASSERT_EQUAL(PIADINA_LOADER_ERR_IO, rc);
    TEST_ASSERT_NOT_NULL(err);
}

static void test_extract_rejects_missing_payload(void)
{
    piadina_loader_t loader;
    memset(&loader, 0, sizeof(loader));
    loader.fd = 0; /* not actually used because archive_size == 0 */
    loader.footer_loaded = true;
    loader.footer.archive_size = 0;

    char out_dir[32] = {0};
    const char *err = NULL;

    piadina_loader_result_t rc = piadina_loader_extract(&loader, NULL, out_dir, sizeof(out_dir), &err);
    TEST_ASSERT_EQUAL(PIADINA_LOADER_ERR_EXTRACT, rc);
    TEST_ASSERT_NOT_NULL(err);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_extract_rejects_uninitialized);
    RUN_TEST(test_extract_rejects_missing_payload);
    return UNITY_END();
}
