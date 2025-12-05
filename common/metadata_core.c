/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata_core.c
 * @brief Core metadata definitions and validation logic.
 */
#include "metadata_core.h"

#include <ctype.h>
#include <string.h>

typedef struct {
    const char *name;
    metadata_core_field_t field;
    bool required;
    const char *default_literal;
    metadata_core_expected_kind_t expect_kind;
} metadata_field_descriptor_t;

static const metadata_field_descriptor_t kFieldTable[] = {
    {"VERSION", METADATA_FIELD_VERSION, true, NULL, METADATA_EXPECT_UINT},
    {"APP_NAME", METADATA_FIELD_APP_NAME, false, NULL, METADATA_EXPECT_STRING},
    {"APP_VER", METADATA_FIELD_APP_VER, false, NULL, METADATA_EXPECT_STRING},
    {"ARCHIVE_HASH", METADATA_FIELD_ARCHIVE_HASH, true, NULL, METADATA_EXPECT_BYTES},
    {"ARCHIVE_FORMAT", METADATA_FIELD_ARCHIVE_FORMAT, false, "tar+gzip", METADATA_EXPECT_STRING},
    {"PAYLOAD_HASH", METADATA_FIELD_PAYLOAD_HASH, true, NULL, METADATA_EXPECT_BYTES},
    {"ENTRY_POINT", METADATA_FIELD_ENTRY_POINT, true, NULL, METADATA_EXPECT_STRING},
    {"ENTRY_ARGS", METADATA_FIELD_ENTRY_ARGS, false, NULL, METADATA_EXPECT_ARRAY_STRING},
    {"ENTRY_ARGS_POST", METADATA_FIELD_ENTRY_ARGS_POST, false, NULL, METADATA_EXPECT_ARRAY_STRING},
    {"CACHE_ROOT", METADATA_FIELD_CACHE_ROOT, false, "{HOME}/.piadina/cache", METADATA_EXPECT_STRING},
    {"PAYLOAD_ROOT", METADATA_FIELD_PAYLOAD_ROOT, false, "{CACHE_ROOT}/{PAYLOAD_HASH}", METADATA_EXPECT_STRING},
    {"CLEANUP_POLICY", METADATA_FIELD_CLEANUP_POLICY, false, "oncrash", METADATA_EXPECT_STRING},
    {"VALIDATE", METADATA_FIELD_VALIDATE, false, "false", METADATA_EXPECT_BOOL},
    {"LOG_LEVEL", METADATA_FIELD_LOG_LEVEL, false, "info", METADATA_EXPECT_STRING},
    {"ENV", METADATA_FIELD_ENV, false, NULL, METADATA_EXPECT_MAP_STRING},
};

_Static_assert(sizeof(kFieldTable) / sizeof(kFieldTable[0]) == METADATA_FIELD_UNKNOWN,
               "metadata field table must match enum");

typedef struct {
    const char *name;
    metadata_core_cleanup_policy_t value;
} cleanup_policy_entry_t;

static const cleanup_policy_entry_t kCleanupPolicies[] = {
    {"never", METADATA_CLEANUP_NEVER},
    {"oncrash", METADATA_CLEANUP_ONCRASH},
    {"always", METADATA_CLEANUP_ALWAYS},
};

bool metadata_core_identifier_valid(const char *key, size_t len)
{
    if (!key || len == 0) {
        return false;
    }
    char first = key[0];
    if (!(isalpha((unsigned char)first) || first == '-' || first == '_')) {
        return false;
    }
    for (size_t i = 1; i < len; ++i) {
        unsigned char c = (unsigned char)key[i];
        if (!(isalnum(c) || c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}

bool metadata_core_field_lookup(const char *key, size_t len, metadata_core_field_t *out)
{
    if (!key || len == 0 || !out) {
        return false;
    }
    for (size_t i = 0; i < sizeof(kFieldTable) / sizeof(kFieldTable[0]); ++i) {
        if (strlen(kFieldTable[i].name) == len &&
            strncmp(kFieldTable[i].name, key, len) == 0) {
            *out = kFieldTable[i].field;
            return true;
        }
    }
    *out = METADATA_FIELD_UNKNOWN;
    return false;
}

const char *metadata_core_field_name(metadata_core_field_t field)
{
    if (field < 0 || field >= METADATA_FIELD_UNKNOWN) {
        return NULL;
    }
    return kFieldTable[field].name;
}

bool metadata_core_field_required(metadata_core_field_t field)
{
    if (field < 0 || field >= METADATA_FIELD_UNKNOWN) {
        return false;
    }
    return kFieldTable[field].required;
}

const char *metadata_core_field_default_string(metadata_core_field_t field)
{
    if (field < 0 || field >= METADATA_FIELD_UNKNOWN) {
        return NULL;
    }
    return kFieldTable[field].default_literal;
}

metadata_core_expected_kind_t metadata_core_expected_kind(metadata_core_field_t field)
{
    if (field < 0 || field >= METADATA_FIELD_UNKNOWN) {
        return METADATA_EXPECT_ANY;
    }
    return kFieldTable[field].expect_kind;
}

metadata_core_cleanup_policy_t metadata_core_cleanup_policy_from_string(const char *value)
{
    if (!value) {
        return METADATA_CLEANUP_INVALID;
    }
    for (size_t i = 0; i < sizeof(kCleanupPolicies) / sizeof(kCleanupPolicies[0]); ++i) {
        if (strcmp(kCleanupPolicies[i].name, value) == 0) {
            return kCleanupPolicies[i].value;
        }
    }
    return METADATA_CLEANUP_INVALID;
}

const char *metadata_core_cleanup_policy_to_string(metadata_core_cleanup_policy_t policy)
{
    for (size_t i = 0; i < sizeof(kCleanupPolicies) / sizeof(kCleanupPolicies[0]); ++i) {
        if (kCleanupPolicies[i].value == policy) {
            return kCleanupPolicies[i].name;
        }
    }
    return NULL;
}

metadata_core_cleanup_policy_t metadata_core_cleanup_policy_default(void)
{
    return METADATA_CLEANUP_ONCRASH;
}

bool metadata_core_archive_format_supported(const char *value)
{
    if (!value) {
        return false;
    }
    return strcmp(value, "tar+gzip") == 0;
}

const char *metadata_core_archive_format_default(void)
{
    return "tar+gzip";
}

bool metadata_core_validate_default(void)
{
    return false;
}
