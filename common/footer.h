#ifndef PIADINA_COMMON_FOOTER_H
#define PIADINA_COMMON_FOOTER_H

#include <stdint.h>

#define PIADINA_FOOTER_MAGIC "PIADINA\0"
#define PIADINA_FOOTER_MAGIC_SIZE 8
#define PIADINA_FOOTER_LAYOUT_VERSION 1
#define PIADINA_FOOTER_SIZE 128

typedef enum {
    FOOTER_OK = 0,
    FOOTER_ERR_INVALID_ARGUMENT,
    FOOTER_ERR_FILE_TOO_SMALL,
    FOOTER_ERR_SEEK,
    FOOTER_ERR_READ,
    FOOTER_ERR_WRITE,
    FOOTER_ERR_BAD_MAGIC,
    FOOTER_ERR_BAD_VERSION,
    FOOTER_ERR_RESERVED_NONZERO,
    FOOTER_ERR_METADATA_RANGE,
    FOOTER_ERR_ARCHIVE_RANGE
} footer_result_t;

typedef struct __attribute__((packed)) {
    uint8_t magic[PIADINA_FOOTER_MAGIC_SIZE];
    uint32_t layout_version;
    uint64_t metadata_offset;
    uint64_t metadata_size;
    uint64_t archive_offset;
    uint64_t archive_size;
    uint8_t archive_hash[32];
    uint8_t footer_hash[32];
    uint8_t reserved[20];
} piadina_footer_t;

_Static_assert(sizeof(piadina_footer_t) == PIADINA_FOOTER_SIZE, "Footer struct must be packed");

/**
 * Read and validate the footer at the end of the given launcher binary.
 *
 * The caller provides @out_footer storage and retains ownership. The function
 * does not allocate memory; it simply populates the supplied struct. The file
 * descriptor is used to locate, read, and validate the footer as well as check
 * that metadata/archive offsets and sizes fall within the file contents.
 */
footer_result_t footer_read(int fd, piadina_footer_t *out_footer);

/**
 * Validate the contents of a footer previously read into caller-owned storage.
 *
 * No allocation occurs; the footer pointer remains owned by the caller for the
 * desired lifetime of the parsed data. This routine only checks structural
 * fields (magic/version/reserved) and does not perform file-size bounds checks.
 */
footer_result_t footer_validate(const piadina_footer_t *footer);

/**
 * Initialize a footer struct with defaults (magic string, layout version, zeros).
 *
 * The caller owns @footer and can mutate offsets/sizes afterward. No allocation
 * occurs; the memory is entirely caller provided.
 */
void footer_prepare(piadina_footer_t *footer);

/**
 * Append a validated footer to the end of the launcher binary.
 *
 * The caller retains ownership of @footer and must ensure the metadata and
 * archive sections already exist in the file descriptor. No memory is allocated;
 * the function validates ranges against the current file size before writing.
 */
footer_result_t footer_append(int fd, const piadina_footer_t *footer);

const char *footer_result_to_string(footer_result_t result);

#endif /* PIADINA_COMMON_FOOTER_H */
