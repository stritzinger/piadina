/**
 * @file test_metadata_tree.c
 * @brief Unit tests for common/metadata_tree.{c,h}
 */

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include <stdlib.h>
#include <string.h>

#include "common/metadata_tree.h"

void setUp(void) {}
void tearDown(void) {}

static void test_map_put_and_find(void)
{
    metadata_tree_map_t map;
    metadata_tree_map_init(&map);

    metadata_tree_value_t *s = metadata_tree_map_put_string(&map, "S", 1, "text");
    TEST_ASSERT_NOT_NULL(s);
    metadata_tree_value_t *u = metadata_tree_map_put_uint(&map, "U", 1, 42);
    TEST_ASSERT_NOT_NULL(u);
    metadata_tree_value_t *b = metadata_tree_map_put_bool(&map, "B", 1, true);
    TEST_ASSERT_NOT_NULL(b);
    uint8_t bytes[2] = {0x01, 0x02};
    metadata_tree_value_t *y = metadata_tree_map_put_bytes(&map, "Y", 1, bytes, sizeof(bytes));
    TEST_ASSERT_NOT_NULL(y);

    metadata_tree_value_t *f = metadata_tree_map_find(&map, "S", 1);
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL(METADATA_TREE_STRING, f->type);
    TEST_ASSERT_EQUAL_STRING("text", f->as.str);

    f = metadata_tree_map_find(&map, "U", 1);
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL(METADATA_TREE_UINT, f->type);
    TEST_ASSERT_EQUAL_UINT64(42, f->as.uint_val);

    f = metadata_tree_map_find(&map, "B", 1);
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL(METADATA_TREE_BOOL, f->type);
    TEST_ASSERT_TRUE(f->as.bool_val);

    f = metadata_tree_map_find(&map, "Y", 1);
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL(METADATA_TREE_BYTES, f->type);
    TEST_ASSERT_EQUAL(2u, f->as.bytes.len);
    TEST_ASSERT_EQUAL_UINT8(0x01, f->as.bytes.data[0]);
    TEST_ASSERT_EQUAL_UINT8(0x02, f->as.bytes.data[1]);

    metadata_tree_map_destroy(&map);
}

static void test_array_slot_and_types(void)
{
    metadata_tree_map_t map;
    metadata_tree_map_init(&map);

    metadata_tree_value_t *arr_val = metadata_tree_map_get_or_create(&map, "ARR", 3, NULL);
    TEST_ASSERT_NOT_NULL(arr_val);
    arr_val->type = METADATA_TREE_ARRAY;
    arr_val->as.array.count = 0;
    arr_val->as.array.capacity = 0;
    arr_val->as.array.items = NULL;

    metadata_tree_value_t *slot0 = metadata_tree_array_ensure_slot(arr_val, 0);
    TEST_ASSERT_NOT_NULL(slot0);
    slot0->type = METADATA_TREE_STRING;
    slot0->as.str = strdup("zero");

    metadata_tree_value_t *slot2 = metadata_tree_array_ensure_slot(arr_val, 2);
    TEST_ASSERT_NOT_NULL(slot2);
    slot2->type = METADATA_TREE_UINT;
    slot2->as.uint_val = 99;

    TEST_ASSERT_EQUAL(3u, arr_val->as.array.count);
    TEST_ASSERT_EQUAL_STRING("zero", arr_val->as.array.items[0].as.str);
    TEST_ASSERT_EQUAL(METADATA_TREE_UINT, arr_val->as.array.items[2].type);
    TEST_ASSERT_EQUAL_UINT64(99, arr_val->as.array.items[2].as.uint_val);

    metadata_tree_map_destroy(&map);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_map_put_and_find);
    RUN_TEST(test_array_slot_and_types);
    return UNITY_END();
}
