/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file context.c
 * @brief Resolve effective launcher context (paths, args, env) from metadata.
 */

#include "context.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/metadata_core.h"

#define MAX_TEMPLATE_VARS 16

struct template_lookup {
    const char *key;
    const char *value;
};

/* Internal prototypes */

static char *dup_string(const char *s);
static char *join_path(const char *a, const char *b);
static char *bytes_to_hex(const uint8_t *data, size_t len);
static const char *lookup_var(const struct template_lookup *vars, size_t var_count,
                              const char *name, size_t len);
static piadina_metadata_result_t template_expand_string_internal(const char *input,
                                                                 const struct template_lookup *vars,
                                                                 size_t var_count,
                                                                 int depth,
                                                                 char **out,
                                                                 const char **error_msg);
static piadina_metadata_result_t template_expand_string(const char *input,
                                                        const struct template_lookup *vars,
                                                        size_t var_count,
                                                        char **out,
                                                        const char **error_msg);
static piadina_context_result_t md_to_ctx(piadina_metadata_result_t rc);
static piadina_metadata_result_t expand_value_recursive(metadata_tree_value_t *val,
                                                        const struct template_lookup *vars,
                                                        size_t var_count,
                                                        int depth,
                                                        const char **error_msg);
static char **copy_string_array(const piadina_meta_array_t *arr, size_t *count_out,
                                const struct template_lookup *vars, size_t var_count,
                                const char **error_msg);
static int copy_env_map(const piadina_meta_map_t *map,
                        char ***keys_out,
                        char ***vals_out,
                        size_t *count_out);

/* Exported Functions */

const char *piadina_context_result_to_string(piadina_context_result_t result)
{
    switch (result) {
    case PIADINA_CONTEXT_OK:
        return "ok";
    case PIADINA_CONTEXT_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case PIADINA_CONTEXT_ERR_MISSING_REQUIRED:
        return "missing required field";
    case PIADINA_CONTEXT_ERR_BAD_VALUE:
        return "bad value";
    case PIADINA_CONTEXT_ERR_OUT_OF_MEMORY:
        return "out of memory";
    default:
        return "unknown context error";
    }
}

void piadina_context_init(piadina_context_t *ctx)
{
    if (!ctx) {
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
}

void piadina_context_destroy(piadina_context_t *ctx)
{
    if (!ctx) {
        return;
    }
    free(ctx->cache_root);
    free(ctx->payload_root);
    free(ctx->entry_path);
    if (ctx->entry_args) {
        for (size_t i = 0; i < ctx->entry_args_count; ++i) {
            free(ctx->entry_args[i]);
        }
        free(ctx->entry_args);
    }
    if (ctx->entry_args_post) {
        for (size_t i = 0; i < ctx->entry_args_post_count; ++i) {
            free(ctx->entry_args_post[i]);
        }
        free(ctx->entry_args_post);
    }
    if (ctx->env) {
        for (size_t i = 0; i < ctx->env_count; ++i) {
            free(ctx->env[i].key);
            free(ctx->env[i].value);
        }
        free(ctx->env);
    }
    memset(ctx, 0, sizeof(*ctx));
}

void piadina_context_print(const piadina_context_t *ctx, FILE *stream)
{
    if (!ctx) {
        return;
    }
    FILE *out = stream ? stream : stderr;
    fprintf(out, "  cache_root:       %s\n", ctx->cache_root ? ctx->cache_root : "(null)");
    fprintf(out, "  payload_root:     %s\n", ctx->payload_root ? ctx->payload_root : "(null)");
    fprintf(out, "  entry_path:       %s\n", ctx->entry_path ? ctx->entry_path : "(null)");

    fprintf(out, "  entry_args (%zu):\n", ctx->entry_args_count);
    for (size_t i = 0; i < ctx->entry_args_count; ++i) {
        fprintf(out, "    [%zu]: %s\n", i, ctx->entry_args && ctx->entry_args[i] ? ctx->entry_args[i] : "(null)");
    }

    fprintf(out, "  entry_args_post (%zu):\n", ctx->entry_args_post_count);
    for (size_t i = 0; i < ctx->entry_args_post_count; ++i) {
        fprintf(out, "    [%zu]: %s\n", i, ctx->entry_args_post && ctx->entry_args_post[i] ? ctx->entry_args_post[i] : "(null)");
    }

    fprintf(out, "  env (%zu):\n", ctx->env_count);
    for (size_t i = 0; i < ctx->env_count; ++i) {
        const char *k = (ctx->env && ctx->env[i].key) ? ctx->env[i].key : "(null)";
        const char *v = (ctx->env && ctx->env[i].value) ? ctx->env[i].value : "(null)";
        fprintf(out, "    %s=%s\n", k, v);
    }
}

piadina_context_result_t piadina_context_resolve(const piadina_metadata_t *metadata,
                                                 piadina_context_t *ctx,
                                                 const char **error_msg)
{
    if (!metadata || !ctx) {
        if (error_msg) {
            *error_msg = "invalid context arguments";
        }
        return PIADINA_CONTEXT_ERR_INVALID_ARGUMENT;
    }

    piadina_metadata_t *mutable_md = (piadina_metadata_t *)metadata;

    /* Build hash vars */
    piadina_meta_value_t *payload_hash =
        metadata_tree_map_find(&mutable_md->root, "PAYLOAD_HASH", strlen("PAYLOAD_HASH"));
    piadina_meta_value_t *archive_hash =
        metadata_tree_map_find(&mutable_md->root, "ARCHIVE_HASH", strlen("ARCHIVE_HASH"));
    if (!payload_hash || payload_hash->type != PIADINA_META_BYTES ||
        !archive_hash || archive_hash->type != PIADINA_META_BYTES) {
        if (error_msg) {
            *error_msg = "hash fields missing";
        }
        return PIADINA_CONTEXT_ERR_MISSING_REQUIRED;
    }
    char *payload_hex = bytes_to_hex(payload_hash->as.bytes.data, payload_hash->as.bytes.len);
    char *archive_hex = bytes_to_hex(archive_hash->as.bytes.data, archive_hash->as.bytes.len);
    if (!payload_hex || !archive_hex) {
        free(payload_hex);
        free(archive_hex);
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
    }

    struct template_lookup vars[MAX_TEMPLATE_VARS];
    size_t var_count = 0;
    vars[var_count++] = (struct template_lookup){.key = "PAYLOAD_HASH", .value = payload_hex};
    vars[var_count++] = (struct template_lookup){.key = "ARCHIVE_HASH", .value = archive_hex};

    /* Resolve CACHE_ROOT */
    const char *cache_root_raw = NULL;
    piadina_metadata_result_t rc =
        piadina_metadata_get_string(metadata, METADATA_FIELD_CACHE_ROOT, &cache_root_raw, error_msg);
    if (rc != PIADINA_METADATA_OK) {
        free(payload_hex);
        free(archive_hex);
        return md_to_ctx(rc);
    }
    char *cache_root = NULL;
    rc = template_expand_string(cache_root_raw, vars, var_count, &cache_root, error_msg);
    if (rc != PIADINA_METADATA_OK) {
        free(payload_hex);
        free(archive_hex);
        return md_to_ctx(rc);
    }
    if (var_count < MAX_TEMPLATE_VARS) {
        vars[var_count++] = (struct template_lookup){.key = "CACHE_ROOT", .value = cache_root};
    }

    /* Resolve PAYLOAD_ROOT */
    const char *payload_root_raw = NULL;
    rc = piadina_metadata_get_string(metadata, METADATA_FIELD_PAYLOAD_ROOT, &payload_root_raw, error_msg);
    if (rc != PIADINA_METADATA_OK) {
        free(payload_hex);
        free(archive_hex);
        free(cache_root);
        return md_to_ctx(rc);
    }
    char *payload_root = NULL;
    rc = template_expand_string(payload_root_raw, vars, var_count, &payload_root, error_msg);
    if (rc != PIADINA_METADATA_OK) {
        free(payload_hex);
        free(archive_hex);
        free(cache_root);
        return md_to_ctx(rc);
    }
    if (var_count < MAX_TEMPLATE_VARS) {
        vars[var_count++] = (struct template_lookup){.key = "PAYLOAD_ROOT", .value = payload_root};
    }

    /* Resolve ENTRY_POINT */
    const char *entry_point_raw = NULL;
    rc = piadina_metadata_get_string(metadata, METADATA_FIELD_ENTRY_POINT, &entry_point_raw, error_msg);
    if (rc != PIADINA_METADATA_OK) {
        free(payload_hex);
        free(archive_hex);
        free(cache_root);
        free(payload_root);
        return md_to_ctx(rc);
    }
    /* Do not expand templates in ENTRY_POINT for security/correctness */
    char *entry_point = dup_string(entry_point_raw);
    if (!entry_point) {
        free(payload_hex);
        free(archive_hex);
        free(cache_root);
        free(payload_root);
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
    }

    ctx->cache_root = cache_root;
    ctx->payload_root = payload_root;
    ctx->entry_path = join_path(payload_root, entry_point);
    free(entry_point);
    free(payload_hex);
    free(archive_hex);
    if (!ctx->cache_root || !ctx->payload_root || !ctx->entry_path) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
    }

    /* ENTRY_ARGS */
    const piadina_meta_array_t *args = NULL;
    rc = piadina_metadata_get_array(metadata, METADATA_FIELD_ENTRY_ARGS, &args, error_msg);
    if (rc == PIADINA_METADATA_OK && args) {
        ctx->entry_args = copy_string_array(args, &ctx->entry_args_count, vars, var_count, error_msg);
        if (args->count > 0 && !ctx->entry_args) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
        }
    }

    /* ENTRY_ARGS_POST */
    const piadina_meta_array_t *args_post = NULL;
    rc = piadina_metadata_get_array(metadata, METADATA_FIELD_ENTRY_ARGS_POST, &args_post, error_msg);
    if (rc == PIADINA_METADATA_OK && args_post) {
        ctx->entry_args_post = copy_string_array(args_post, &ctx->entry_args_post_count, vars, var_count, error_msg);
        if (args_post->count > 0 && !ctx->entry_args_post) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
        }
    }

    /* ENV map */
    const piadina_meta_map_t *env_map = NULL;
    rc = piadina_metadata_get_map(metadata, METADATA_FIELD_ENV, &env_map, error_msg);
    if (rc == PIADINA_METADATA_OK && env_map) {
        char **keys = NULL;
        char **vals = NULL;
        size_t count = 0;
        if (copy_env_map(env_map, &keys, &vals, &count) != 0) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
        }
        if (count > 0) {
            ctx->env = calloc(count, sizeof(*ctx->env));
            if (!ctx->env) {
                for (size_t i = 0; i < count; ++i) {
                    free(keys[i]);
                    free(vals[i]);
                }
                free(keys);
                free(vals);
                if (error_msg) {
                    *error_msg = "out of memory";
                }
                return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
            }
            ctx->env_count = count;
            for (size_t i = 0; i < count; ++i) {
                /* expand values */
                char *resolved = NULL;
                if (template_expand_string(vals[i], vars, var_count, &resolved, error_msg) != PIADINA_METADATA_OK) {
                    for (size_t j = i; j < count; ++j) {
                        free(keys[j]);
                        free(vals[j]);
                    }
                    free(keys);
                    free(vals);
                    return PIADINA_CONTEXT_ERR_BAD_VALUE;
                }
                free(vals[i]);
                ctx->env[i].key = keys[i];
                ctx->env[i].value = resolved ? resolved : dup_string("");
            }
        }
        free(keys);
        free(vals);
    }

    return PIADINA_CONTEXT_OK;
}

/* Internal Functions */

static piadina_context_result_t md_to_ctx(piadina_metadata_result_t rc)
{
    switch (rc) {
    case PIADINA_METADATA_OK:
        return PIADINA_CONTEXT_OK;
    case PIADINA_METADATA_ERR_INVALID_ARGUMENT:
        return PIADINA_CONTEXT_ERR_INVALID_ARGUMENT;
    case PIADINA_METADATA_ERR_MISSING_REQUIRED:
        return PIADINA_CONTEXT_ERR_MISSING_REQUIRED;
    case PIADINA_METADATA_ERR_BAD_VALUE:
        return PIADINA_CONTEXT_ERR_BAD_VALUE;
    case PIADINA_METADATA_ERR_OUT_OF_MEMORY:
        return PIADINA_CONTEXT_ERR_OUT_OF_MEMORY;
    default:
        return PIADINA_CONTEXT_ERR_BAD_VALUE;
    }
}

static char *dup_string(const char *s)
{
    if (!s) {
        return NULL;
    }
    size_t len = strlen(s);
    char *out = malloc(len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, s, len + 1);
    return out;
}

static char *join_path(const char *a, const char *b)
{
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int need_sep = (la > 0 && b[0] != '/' && a[la - 1] != '/');
    size_t total = la + lb + (need_sep ? 1 : 0) + 1;
    char *out = malloc(total);
    if (!out) {
        return NULL;
    }
    memcpy(out, a, la);
    size_t pos = la;
    if (need_sep) {
        out[pos++] = '/';
    }
    memcpy(out + pos, b, lb);
    out[pos + lb] = '\0';
    return out;
}

static char *bytes_to_hex(const uint8_t *data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    if (!data) {
        return NULL;
    }
    char *out = malloc(len * 2 + 1);
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = hex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = hex[data[i] & 0xF];
    }
    out[len * 2] = '\0';
    return out;
}

static const char *lookup_var(const struct template_lookup *vars, size_t var_count, const char *name, size_t len)
{
    for (size_t i = 0; i < var_count; ++i) {
        if (strlen(vars[i].key) == len && strncmp(vars[i].key, name, len) == 0) {
            return vars[i].value;
        }
    }
    /* fallback to environment */
    char tmp[128];
    if (len >= sizeof(tmp)) {
        return NULL;
    }
    memcpy(tmp, name, len);
    tmp[len] = '\0';
    const char *env = getenv(tmp);
    return env;
}

static piadina_metadata_result_t template_expand_string_internal(const char *input,
                                                                 const struct template_lookup *vars,
                                                                 size_t var_count,
                                                                 int depth,
                                                                 char **out,
                                                                 const char **error_msg)
{
    if (!input || !out || depth <= 0) {
        if (error_msg) {
            *error_msg = "invalid template args";
        }
        return PIADINA_METADATA_ERR_INVALID_ARGUMENT;
    }

    size_t cap = strlen(input) + 1;
    char *buf = malloc(cap);
    if (!buf) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
    }
    size_t len = 0;

    for (const char *p = input; *p; ) {
        if (*p != '{') {
            if (len + 1 >= cap) {
                cap *= 2;
                char *nbuf = realloc(buf, cap);
                if (!nbuf) {
                    free(buf);
                    if (error_msg) {
                        *error_msg = "out of memory";
                    }
                    return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
                }
                buf = nbuf;
            }
            buf[len++] = *p++;
            continue;
        }

        /* parse {VAR} */
        const char *start = p + 1;
        const char *end = strchr(start, '}');
        if (!end) {
            free(buf);
            if (error_msg) {
                *error_msg = "unterminated template";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        size_t var_len = (size_t)(end - start);
        if (var_len == 0) {
            free(buf);
            if (error_msg) {
                *error_msg = "empty template variable";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        const char *val_raw = lookup_var(vars, var_count, start, var_len);
        if (!val_raw) {
            free(buf);
            if (error_msg) {
                *error_msg = "unknown template variable";
            }
            return PIADINA_METADATA_ERR_BAD_VALUE;
        }
        /* Resolve nested templates in the variable value */
        char *val = NULL;
        piadina_metadata_result_t nested_rc =
            template_expand_string_internal(val_raw, vars, var_count, depth - 1, &val, error_msg);
        if (nested_rc != PIADINA_METADATA_OK) {
            free(buf);
            return nested_rc;
        }
        size_t val_len = strlen(val);
        while (len + val_len + 1 >= cap) {
            cap *= 2;
            char *nbuf = realloc(buf, cap);
            if (!nbuf) {
                free(val);
                free(buf);
                if (error_msg) {
                    *error_msg = "out of memory";
                }
                return PIADINA_METADATA_ERR_OUT_OF_MEMORY;
            }
            buf = nbuf;
        }
        memcpy(buf + len, val, val_len);
        len += val_len;
        free(val);
        p = end + 1;
    }

    buf[len] = '\0';
    *out = buf;
    return PIADINA_METADATA_OK;
}

static piadina_metadata_result_t template_expand_string(const char *input,
                                                        const struct template_lookup *vars,
                                                        size_t var_count,
                                                        char **out,
                                                        const char **error_msg)
{
    /* limit recursion to prevent cycles */
    return template_expand_string_internal(input, vars, var_count, 8, out, error_msg);
}

static char **copy_string_array(const piadina_meta_array_t *arr, size_t *count_out,
                                const struct template_lookup *vars, size_t var_count,
                                const char **error_msg)
{
    if (!arr || !count_out) {
        return NULL;
    }
    char **out = NULL;
    if (arr->count == 0) {
        *count_out = 0;
        return NULL;
    }
    out = calloc(arr->count, sizeof(char *));
    if (!out) {
        return NULL;
    }
    for (size_t i = 0; i < arr->count; ++i) {
        if (arr->items[i].type != PIADINA_META_STRING || !arr->items[i].as.str) {
            /* Skip non-string entries defensively */
            continue;
        }
        char *resolved = NULL;
        piadina_metadata_result_t rc =
            template_expand_string(arr->items[i].as.str, vars, var_count, &resolved, error_msg);
        if (rc != PIADINA_METADATA_OK) {
            for (size_t j = 0; j < i; ++j) {
                free(out[j]);
            }
            free(out);
            return NULL;
        }
        out[i] = resolved;
        if (!out[i]) {
            for (size_t j = 0; j < i; ++j) {
                free(out[j]);
            }
            free(out);
            return NULL;
        }
    }
    *count_out = arr->count;
    return out;
}

static int copy_env_map(const piadina_meta_map_t *map,
                        char ***keys_out,
                        char ***vals_out,
                        size_t *count_out)
{
    if (!map || !keys_out || !vals_out || !count_out) {
        return -1;
    }
    *count_out = map->count;
    if (map->count == 0) {
        *keys_out = NULL;
        *vals_out = NULL;
        return 0;
    }
    char **keys = calloc(map->count, sizeof(char *));
    char **vals = calloc(map->count, sizeof(char *));
    if (!keys || !vals) {
        free(keys);
        free(vals);
        return -1;
    }
    for (size_t i = 0; i < map->count; ++i) {
        keys[i] = dup_string(map->entries[i].key);
        if (!keys[i]) {
            goto fail;
        }
        if (map->entries[i].value && map->entries[i].value->type == PIADINA_META_STRING) {
            vals[i] = dup_string(map->entries[i].value->as.str);
            if (!vals[i]) {
                goto fail;
            }
        } else {
            vals[i] = dup_string("");
            if (!vals[i]) {
                goto fail;
            }
        }
    }
    *keys_out = keys;
    *vals_out = vals;
    return 0;
fail:
    for (size_t j = 0; j < map->count; ++j) {
        free(keys[j]);
        free(vals[j]);
    }
    free(keys);
    free(vals);
    return -1;
}
