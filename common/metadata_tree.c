/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata_tree.c
 * @brief Shared metadata tree representation (maps/arrays/scalars).
 */

#include "metadata_tree.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Internal Prototypes */

static metadata_tree_value_t *value_new(void);
static void value_reset(metadata_tree_value_t *value);
static void value_destroy(metadata_tree_value_t *value);
static void map_destroy(metadata_tree_map_t *map);
static void array_destroy(metadata_tree_array_t *array);
static void metadata_print_indent(int indent, FILE *stream);
static void metadata_print_value(const metadata_tree_value_t *val, int indent, FILE *stream);
static void metadata_print_map_internal(const metadata_tree_map_t *map, int indent, FILE *stream);

/* Exported Functions */

void metadata_tree_map_init(metadata_tree_map_t *map)
{
    if (!map) {
        return;
    }
    memset(map, 0, sizeof(*map));
}

void metadata_tree_map_destroy(metadata_tree_map_t *map)
{
    map_destroy(map);
}

metadata_tree_value_t *metadata_tree_map_find(const metadata_tree_map_t *map,
                                              const char *key,
                                              size_t key_len)
{
    if (!map || !key) {
        return NULL;
    }
    for (size_t i = 0; i < map->count; ++i) {
        if (strlen(map->entries[i].key) == key_len &&
            strncmp(map->entries[i].key, key, key_len) == 0) {
            return map->entries[i].value;
        }
    }
    return NULL;
}

metadata_tree_value_t *metadata_tree_map_get_or_create(metadata_tree_map_t *map,
                                                       const char *key,
                                                       size_t key_len,
                                                       bool *created)
{
    if (created) {
        *created = false;
    }
    if (!map || !key) {
        return NULL;
    }
    metadata_tree_value_t *found = metadata_tree_map_find(map, key, key_len);
    if (found) {
        return found;
    }
    if (map->count == map->capacity) {
        size_t new_cap = map->capacity == 0 ? 4 : map->capacity * 2;
        metadata_tree_map_entry_t *new_entries =
            realloc(map->entries, new_cap * sizeof(*new_entries));
        if (!new_entries) {
            return NULL;
        }
        map->entries = new_entries;
        map->capacity = new_cap;
    }
    metadata_tree_value_t *val = value_new();
    if (!val) {
        return NULL;
    }
    char *dup_key = strndup(key, key_len);
    if (!dup_key) {
        value_destroy(val);
        return NULL;
    }
    map->entries[map->count].key = dup_key;
    map->entries[map->count].value = val;
    map->count += 1;
    if (created) {
        *created = true;
    }
    return val;
}

metadata_tree_value_t *metadata_tree_map_put_string(metadata_tree_map_t *map,
                                                    const char *key,
                                                    size_t key_len,
                                                    const char *value)
{
    bool created = false;
    metadata_tree_value_t *val = metadata_tree_map_get_or_create(map, key, key_len, &created);
    if (!val) {
        return NULL;
    }
    value_reset(val);
    val->type = METADATA_TREE_STRING;
    val->as.str = strdup(value ? value : "");
    if (!val->as.str) {
        return NULL;
    }
    return val;
}

metadata_tree_value_t *metadata_tree_map_put_uint(metadata_tree_map_t *map,
                                                  const char *key,
                                                  size_t key_len,
                                                  uint64_t value)
{
    bool created = false;
    metadata_tree_value_t *val = metadata_tree_map_get_or_create(map, key, key_len, &created);
    if (!val) {
        return NULL;
    }
    value_reset(val);
    val->type = METADATA_TREE_UINT;
    val->as.uint_val = value;
    return val;
}

metadata_tree_value_t *metadata_tree_map_put_bool(metadata_tree_map_t *map,
                                                  const char *key,
                                                  size_t key_len,
                                                  bool value)
{
    bool created = false;
    metadata_tree_value_t *val = metadata_tree_map_get_or_create(map, key, key_len, &created);
    if (!val) {
        return NULL;
    }
    value_reset(val);
    val->type = METADATA_TREE_BOOL;
    val->as.bool_val = value;
    return val;
}

metadata_tree_value_t *metadata_tree_map_put_bytes(metadata_tree_map_t *map,
                                                   const char *key,
                                                   size_t key_len,
                                                   const uint8_t *data,
                                                   size_t len)
{
    bool created = false;
    metadata_tree_value_t *val = metadata_tree_map_get_or_create(map, key, key_len, &created);
    if (!val) {
        return NULL;
    }
    value_reset(val);
    val->type = METADATA_TREE_BYTES;
    if (len > 0) {
        val->as.bytes.data = malloc(len);
        if (!val->as.bytes.data) {
            return NULL;
        }
        memcpy(val->as.bytes.data, data, len);
    } else {
        val->as.bytes.data = NULL;
    }
    val->as.bytes.len = len;
    return val;
}

metadata_tree_value_t *metadata_tree_array_ensure_slot(metadata_tree_value_t *array_value,
                                                       size_t index)
{
    if (!array_value || array_value->type != METADATA_TREE_ARRAY) {
        return NULL;
    }
    metadata_tree_array_t *arr = &array_value->as.array;
    if (index >= arr->count) {
        if (index >= arr->capacity) {
            size_t new_cap = arr->capacity == 0 ? 4 : arr->capacity * 2;
            while (new_cap <= index) {
                new_cap *= 2;
            }
            metadata_tree_value_t *new_items =
                realloc(arr->items, new_cap * sizeof(*new_items));
            if (!new_items) {
                return NULL;
            }
            for (size_t i = arr->capacity; i < new_cap; ++i) {
                memset(&new_items[i], 0, sizeof(new_items[i]));
            }
            arr->items = new_items;
            arr->capacity = new_cap;
        }
        arr->count = index + 1;
    }
    return &arr->items[index];
}

void metadata_tree_print(const metadata_tree_map_t *map, FILE *stream)
{
    metadata_tree_print_map(map, 0, stream);
}

void metadata_tree_print_map(const metadata_tree_map_t *map, int indent, FILE *stream)
{
    if (!stream) {
        stream = stderr;
    }
    if (!map) {
        return;
    }
    metadata_print_indent(indent, stream);
    fprintf(stream, "{\n");
    metadata_print_map_internal(map, indent + 2, stream);
    metadata_print_indent(indent, stream);
    fprintf(stream, "}\n");
}

/* Internal Functions */

static metadata_tree_value_t *value_new(void)
{
    metadata_tree_value_t *v = calloc(1, sizeof(*v));
    return v;
}

static void value_reset(metadata_tree_value_t *value)
{
    if (!value) {
        return;
    }
    switch (value->type) {
    case METADATA_TREE_STRING:
        free(value->as.str);
        break;
    case METADATA_TREE_BYTES:
        free(value->as.bytes.data);
        break;
    case METADATA_TREE_ARRAY:
        array_destroy(&value->as.array);
        break;
    case METADATA_TREE_MAP:
        map_destroy(&value->as.map);
        break;
    case METADATA_TREE_UINT:
    case METADATA_TREE_BOOL:
    default:
        break;
    }
    memset(value, 0, sizeof(*value));
}

static void value_destroy(metadata_tree_value_t *value)
{
    if (!value) {
        return;
    }
    value_reset(value);
    free(value);
}

static void map_destroy(metadata_tree_map_t *map)
{
    if (!map || !map->entries) {
        return;
    }
    for (size_t i = 0; i < map->count; ++i) {
        free(map->entries[i].key);
        value_destroy(map->entries[i].value);
    }
    free(map->entries);
    map->entries = NULL;
    map->count = 0;
    map->capacity = 0;
}

static void array_destroy(metadata_tree_array_t *array)
{
    if (!array || !array->items) {
        return;
    }
    for (size_t i = 0; i < array->count; ++i) {
        value_reset(&array->items[i]);
    }
    free(array->items);
    array->items = NULL;
    array->count = 0;
    array->capacity = 0;
}

static void metadata_print_indent(int indent, FILE *stream)
{
    for (int i = 0; i < indent; ++i) {
        fputc(' ', stream);
    }
}

static void metadata_print_value(const metadata_tree_value_t *val, int indent, FILE *stream)
{
    switch (val->type) {
    case METADATA_TREE_STRING:
        fprintf(stream, "\"%s\"", val->as.str ? val->as.str : "");
        break;
    case METADATA_TREE_UINT:
        fprintf(stream, "%llu", (unsigned long long)val->as.uint_val);
        break;
    case METADATA_TREE_BOOL:
        fprintf(stream, "%s", val->as.bool_val ? "true" : "false");
        break;
    case METADATA_TREE_BYTES:
        fprintf(stream, "bytes(%zu)", val->as.bytes.len);
        break;
    case METADATA_TREE_ARRAY:
        fprintf(stream, "[\n");
        for (size_t i = 0; i < val->as.array.count; ++i) {
            metadata_print_indent(indent + 2, stream);
            metadata_print_value(&val->as.array.items[i], indent + 2, stream);
            if (i + 1 < val->as.array.count) {
                fprintf(stream, ",");
            }
            fprintf(stream, "\n");
        }
        metadata_print_indent(indent, stream);
        fprintf(stream, "]");
        break;
    case METADATA_TREE_MAP:
        fprintf(stream, "{\n");
        metadata_print_map_internal(&val->as.map, indent + 2, stream);
        metadata_print_indent(indent, stream);
        fprintf(stream, "}");
        break;
    default:
        fprintf(stream, "<unknown>");
        break;
    }
}

static void metadata_print_map_internal(const metadata_tree_map_t *map, int indent, FILE *stream)
{
    for (size_t i = 0; i < map->count; ++i) {
        metadata_print_indent(indent, stream);
        fprintf(stream, "%s: ", map->entries[i].key);
        metadata_print_value(map->entries[i].value, indent, stream);
        if (i + 1 < map->count) {
            fprintf(stream, ",");
        }
        fprintf(stream, "\n");
    }
}
