/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file metadata_core.h
 * @brief Core metadata definitions and validation logic.
 */
#ifndef PIADINA_COMMON_METADATA_CORE_H
#define PIADINA_COMMON_METADATA_CORE_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    METADATA_EXPECT_ANY = 0,
    METADATA_EXPECT_STRING,
    METADATA_EXPECT_UINT,
    METADATA_EXPECT_BOOL,
    METADATA_EXPECT_BYTES,
    METADATA_EXPECT_ARRAY_STRING,
    METADATA_EXPECT_MAP_STRING
} metadata_core_expected_kind_t;

#define METADATA_CORE_SCHEMA_VERSION 1

typedef enum {
    METADATA_FIELD_VERSION = 0,
    METADATA_FIELD_APP_NAME,
    METADATA_FIELD_APP_VER,
    METADATA_FIELD_ARCHIVE_HASH,
    METADATA_FIELD_ARCHIVE_FORMAT,
    METADATA_FIELD_PAYLOAD_HASH,
    METADATA_FIELD_ENTRY_POINT,
    METADATA_FIELD_ENTRY_ARGS,
    METADATA_FIELD_ENTRY_ARGS_POST,
    METADATA_FIELD_CACHE_ROOT,
    METADATA_FIELD_PAYLOAD_ROOT,
    METADATA_FIELD_CLEANUP_POLICY,
    METADATA_FIELD_VALIDATE,
    METADATA_FIELD_ENV,
    METADATA_FIELD_UNKNOWN
} metadata_core_field_t;

typedef enum {
    METADATA_CLEANUP_NEVER = 0,
    METADATA_CLEANUP_ONCRASH,
    METADATA_CLEANUP_ALWAYS,
    METADATA_CLEANUP_INVALID
} metadata_core_cleanup_policy_t;

/**
 * @brief Validate that a metadata identifier matches the allowed pattern.
 *
 * Pattern: `[a-zA-Z-_][a-zA-Z0-9-_]*`.
 *
 * @param[in] key  Pointer to the identifier string.
 * @param[in] len  Length of the identifier.
 * @return         true if valid, false otherwise.
 *
 * @note Memory Management:
 *       Callers own the string memory; this function performs no allocations.
 */
bool metadata_core_identifier_valid(const char *key, size_t len);

/**
 * @brief Look up a well-known field by name.
 *
 * @param[in]  key  Pointer to the key string.
 * @param[in]  len  Length of the key.
 * @param[out] out  Buffer to store the field enum if found.
 * @return          true if found, false for user-defined or unknown keys.
 *
 * @note Memory Management:
 *       Neither allocates nor takes ownership of the key string.
 */
bool metadata_core_field_lookup(const char *key, size_t len, metadata_core_field_t *out);

/**
 * @brief Retrieve the canonical field name for known entries.
 *
 * @param[in] field  The field enum.
 * @return           String name, or NULL for unknown fields.
 *
 * @note Memory Management:
 *       Ownership of the returned string remains with metadata_core (static constants).
 */
const char *metadata_core_field_name(metadata_core_field_t field);

/**
 * @brief Query whether a known field is required.
 *
 * @param[in] field  The field enum.
 * @return           true if required, false otherwise.
 *
 * @note Memory Management:
 *       No allocation occurs.
 */
bool metadata_core_field_required(metadata_core_field_t field);

/**
 * @brief Return the default string value (if any) associated with a known field.
 *
 * @param[in] field  The field enum.
 * @return           Default string value, or NULL if no default exists.
 *
 * @note Memory Management:
 *       The returned pointer is owned by metadata_core (static constants) and remains
 *       valid for the life of the process.
 */
const char *metadata_core_field_default_string(metadata_core_field_t field);

/**
 * @brief Parse a cleanup policy from a string.
 *
 * @param[in] value  String value.
 * @return           Enum value, or METADATA_CLEANUP_INVALID.
 *
 * @note Memory Management:
 *       No allocation.
 */
metadata_core_cleanup_policy_t metadata_core_cleanup_policy_from_string(const char *value);

/**
 * @brief Convert a cleanup policy enum to a string.
 *
 * @param[in] policy  The policy enum.
 * @return            String representation.
 *
 * @note Memory Management:
 *       Returned string is static constant.
 */
const char *metadata_core_cleanup_policy_to_string(metadata_core_cleanup_policy_t policy);

/**
 * @brief Return the default cleanup policy.
 *
 * @return METADATA_CLEANUP_ONCRASH.
 */
metadata_core_cleanup_policy_t metadata_core_cleanup_policy_default(void);

/**
 * @brief Validate if an archive format string is supported.
 *
 * @param[in] value  The format string.
 * @return           true if supported ("tar+gzip"), false otherwise.
 *
 * @note Memory Management:
 *       No allocation.
 */
bool metadata_core_archive_format_supported(const char *value);

/**
 * @brief Return the default archive format.
 *
 * @return "tar+gzip".
 *
 * @note Memory Management:
 *       Static constant string.
 */
const char *metadata_core_archive_format_default(void);

/**
 * @brief Return the default for the VALIDATE flag.
 *
 * @return false.
 */
bool metadata_core_validate_default(void);

/**
 * @brief Return the expected value kind for a well-known field.
 *
 * @param[in] field  The field enum.
 * @return           Expected kind (string, uint, bool, etc.).
 *
 * @note Memory Management:
 *       No allocation.
 */
metadata_core_expected_kind_t metadata_core_expected_kind(metadata_core_field_t field);

#endif /* PIADINA_COMMON_METADATA_CORE_H */
