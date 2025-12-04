/**
 * @file metadata.h
 * @brief Azdora metadata representation and parsing.
 *
 * Ownership rules:
 *  - The metadata struct is caller-owned; init/destroy manage internal heap.
 *  - Strings/byte buffers stored in the metadata map are owned by the metadata.
 *  - Accessors returning pointers (e.g., hashes, map roots) are borrowed and
 *    remain valid until azdora_metadata_destroy() is called.
 */
#ifndef AZDORA_METADATA_H
#define AZDORA_METADATA_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "common/metadata_core.h"

typedef enum {
    AZDORA_METADATA_OK = 0,
    AZDORA_METADATA_ERR_INVALID_ARGUMENT,
    AZDORA_METADATA_ERR_PARSE,
    AZDORA_METADATA_ERR_UNSUPPORTED_KEY,
    AZDORA_METADATA_ERR_MISSING_REQUIRED,
    AZDORA_METADATA_ERR_BAD_VALUE,
    AZDORA_METADATA_ERR_OUT_OF_MEMORY
} azdora_metadata_result_t;

typedef enum {
    AZDORA_META_STRING = 0,
    AZDORA_META_UINT,
    AZDORA_META_BOOL,
    AZDORA_META_BYTES,
    AZDORA_META_ARRAY,
    AZDORA_META_MAP
} azdora_meta_type_t;

struct azdora_meta_value;

typedef struct {
    size_t count;
    size_t capacity;
    struct azdora_meta_value *items; /* owned array */
} azdora_meta_array_t;

typedef struct {
    char *key;                        /* owned */
    struct azdora_meta_value *value;  /* owned */
} azdora_meta_map_entry_t;

typedef struct {
    size_t count;
    size_t capacity;
    azdora_meta_map_entry_t *entries; /* owned array */
} azdora_meta_map_t;

typedef struct azdora_meta_value {
    azdora_meta_type_t type;
    union {
        char *str; /* owned */
        uint64_t uint_val;
        bool bool_val;
        struct {
            uint8_t *data; /* owned */
            size_t len;
        } bytes;
        azdora_meta_array_t array;
        azdora_meta_map_t map;
    } as;
} azdora_meta_value_t;

typedef struct {
    azdora_meta_map_t root; /* top-level metadata map */
} azdora_metadata_t;

/**
 * Initialize a metadata struct. Caller allocates the struct; this sets internal
 * pointers to NULL and zeroes counters.
 */
void azdora_metadata_init(azdora_metadata_t *metadata);

/**
 * Destroy all owned memory within the metadata struct. Caller retains the
 * struct storage and may re-init it afterward.
 */
void azdora_metadata_destroy(azdora_metadata_t *metadata);

/**
 * Apply a user-provided PATH=VALUE entry (e.g., ENV.DB=foo, ENTRY_ARGS[]=bar).
 * The entry string is borrowed; any stored data is duplicated.
 */
azdora_metadata_result_t azdora_metadata_apply_meta(azdora_metadata_t *metadata,
                                                    const char *entry,
                                                    const char **error_msg);

/**
 * Finalize metadata: enforce required fields, fill defaults, and normalize
 * hashes. Does not allocate beyond what is needed for defaults.
 */
azdora_metadata_result_t azdora_metadata_finalize(azdora_metadata_t *metadata,
                                                  const char **error_msg);

/* Accessors */
/**
 * Borrow the top-level metadata map. The returned pointer stays valid until
 * azdora_metadata_destroy() is called on the owning struct.
 */
const azdora_meta_map_t *azdora_metadata_root(const azdora_metadata_t *metadata);
/**
 * Set a scalar string field identified by metadata_core_field_t. The value is
 * duplicated and owned by the metadata struct. Fails if the field expects a
 * non-string type.
 */
azdora_metadata_result_t azdora_metadata_set_field_string(azdora_metadata_t *metadata,
                                                          metadata_core_field_t field,
                                                          const char *value,
                                                          const char **error_msg);
/**
 * Set a scalar boolean field identified by metadata_core_field_t. The value is
 * stored by value (no heap allocations) and owned by the metadata struct. Fails
 * if the field expects a non-boolean type.
 */
azdora_metadata_result_t azdora_metadata_set_field_bool(azdora_metadata_t *metadata,
                                                        metadata_core_field_t field,
                                                        bool value,
                                                        const char **error_msg);
/**
 * Set a scalar uint field identified by metadata_core_field_t. The value is
 * stored by value. Fails if the field expects a non-uint type.
 */
azdora_metadata_result_t azdora_metadata_set_field_uint(azdora_metadata_t *metadata,
                                                        metadata_core_field_t field,
                                                        uint64_t value,
                                                        const char **error_msg);
/**
 * Set a scalar bytes field identified by metadata_core_field_t. The buffer is
 * duplicated and owned by the metadata struct. Fails if the field expects a
 * non-bytes type.
 */
azdora_metadata_result_t azdora_metadata_set_field_bytes(azdora_metadata_t *metadata,
                                                         metadata_core_field_t field,
                                                         const uint8_t *data,
                                                         size_t len,
                                                         const char **error_msg);

/**
 * Add an element to an array field (ENTRY_ARGS, ENTRY_ARGS_POST). If append is
 * true, index is ignored and the element is appended; otherwise index must be
 * the next dense index.
 */
azdora_metadata_result_t azdora_metadata_add_array_string(azdora_metadata_t *metadata,
                                                          metadata_core_field_t field,
                                                          size_t index,
                                                          bool append,
                                                          const char *value,
                                                          const char **error_msg);

/**
 * Set a map entry (e.g., ENV.KEY) with string value. Map keys and values are
 * duplicated and owned by the metadata struct. Fails if the target field is not
 * a string-keyed/string-valued map.
 */
azdora_metadata_result_t azdora_metadata_set_map_entry_string(azdora_metadata_t *metadata,
                                                              metadata_core_field_t field,
                                                              const char *key,
                                                              const char *value,
                                                              const char **error_msg);

/**
 * Typed getters that read from the metadata map. Returned pointers are borrowed
 * and valid until azdora_metadata_destroy() is called. error_msg is optional.
 */
azdora_metadata_result_t azdora_metadata_get_string(const azdora_metadata_t *metadata,
                                                    metadata_core_field_t field,
                                                    const char **out,
                                                    const char **error_msg);
azdora_metadata_result_t azdora_metadata_get_bool(const azdora_metadata_t *metadata,
                                                  metadata_core_field_t field,
                                                  bool *out,
                                                  const char **error_msg);
azdora_metadata_result_t azdora_metadata_get_uint(const azdora_metadata_t *metadata,
                                                  metadata_core_field_t field,
                                                  uint64_t *out,
                                                  const char **error_msg);
azdora_metadata_result_t azdora_metadata_get_bytes(const azdora_metadata_t *metadata,
                                                   metadata_core_field_t field,
                                                   const uint8_t **out,
                                                   size_t *len_out,
                                                   const char **error_msg);

/**
 * Pretty-print the metadata tree to the provided stream (stderr if NULL).
 * The function does not take ownership of metadata or the stream.
 */
void azdora_metadata_print(const azdora_metadata_t *metadata, FILE *stream);

#endif /* AZDORA_METADATA_H */
