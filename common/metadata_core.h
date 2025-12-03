#ifndef PIADINA_COMMON_METADATA_CORE_H
#define PIADINA_COMMON_METADATA_CORE_H

#include <stdbool.h>
#include <stddef.h>

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
    METADATA_FIELD_LOG_LEVEL,
    METADATA_FIELD_ENV,
    METADATA_FIELD_UNKNOWN
} metadata_core_field_t;

typedef enum {
    METADATA_CLEANUP_NEVER = 0,
    METADATA_CLEANUP_ONCRASH,
    METADATA_CLEANUP_ALWAYS,
    METADATA_CLEANUP_INVALID
} metadata_core_cleanup_policy_t;

typedef enum {
    METADATA_LOG_DEBUG = 0,
    METADATA_LOG_INFO,
    METADATA_LOG_WARN,
    METADATA_LOG_ERROR,
    METADATA_LOG_INVALID
} metadata_core_log_level_t;

/**
 * Validate that a metadata identifier matches the allowed pattern. Callers own
 * the string memory; this function performs no allocations.
 */
bool metadata_core_identifier_valid(const char *key, size_t len);

/**
 * Look up a well-known field by name. Returns false for user-defined keys.
 * Neither allocates nor takes ownership of the key string.
 */
bool metadata_core_field_lookup(const char *key, size_t len, metadata_core_field_t *out);

/**
 * Retrieve the canonical field name for known entries. Returns NULL for unknown
 * fields. Ownership of the returned string remains with metadata_core.
 */
const char *metadata_core_field_name(metadata_core_field_t field);

/**
 * Query whether a known field is required. No allocation occurs.
 */
bool metadata_core_field_required(metadata_core_field_t field);

/**
 * Return the default string value (if any) associated with a known field. The
 * returned pointer is owned by metadata_core and remains valid for the life of
 * the process. Returns NULL if the field has no default literal.
 */
const char *metadata_core_field_default_string(metadata_core_field_t field);

/**
 * Cleanup policy helpers. Conversion functions never allocate; returned string
 * pointers are owned by metadata_core.
 */
metadata_core_cleanup_policy_t metadata_core_cleanup_policy_from_string(const char *value);
const char *metadata_core_cleanup_policy_to_string(metadata_core_cleanup_policy_t policy);
metadata_core_cleanup_policy_t metadata_core_cleanup_policy_default(void);

/**
 * Log-level helpers. As above, returned strings are metadata_core-owned.
 */
metadata_core_log_level_t metadata_core_log_level_from_string(const char *value);
const char *metadata_core_log_level_to_string(metadata_core_log_level_t level);
metadata_core_log_level_t metadata_core_log_level_default(void);

/**
 * Archive-format helpers for validating user input; no allocation occurs.
 */
bool metadata_core_archive_format_supported(const char *value);
const char *metadata_core_archive_format_default(void);

/**
 * Default for the `VALIDATE` flag.
 */
bool metadata_core_validate_default(void);

#endif /* PIADINA_COMMON_METADATA_CORE_H */
