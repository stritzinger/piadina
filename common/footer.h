/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file footer.h
 * @brief Layout and handling of the Piadina binary footer.
 */
#ifndef PIADINA_COMMON_FOOTER_H
#define PIADINA_COMMON_FOOTER_H

#include <stdint.h>
#include <stdio.h>

#define PIADINA_FOOTER_MAGIC "PIADINA\0"
#define PIADINA_FOOTER_MAGIC_SIZE 8
#define PIADINA_FOOTER_LAYOUT_VERSION 1
#define PIADINA_FOOTER_SIZE 192

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
    uint8_t metadata_hash[32];
    uint8_t archive_hash[32];
    uint8_t reserved[52];
    uint8_t footer_hash[32];
} piadina_footer_t;

_Static_assert(sizeof(piadina_footer_t) == PIADINA_FOOTER_SIZE, "Footer struct must be packed");

/**
 * @brief Read and validate the footer at the end of the given launcher binary.
 *
 * @param[in]  fd          File descriptor of the binary.
 * @param[out] out_footer  Buffer to store the read footer.
 * @return                 FOOTER_OK on success, or an error code.
 *
 * @note Memory Management:
 *       The caller provides @p out_footer storage and retains ownership.
 *       The function does not allocate memory; it simply populates the supplied struct.
 */
footer_result_t footer_read(int fd, piadina_footer_t *out_footer);

/**
 * @brief Validate the contents of a footer previously read.
 *
 * This checks structural fields (magic, version, reserved bytes).
 *
 * @param[in] footer  Pointer to the footer struct to validate.
 * @return            FOOTER_OK on success, or an error code.
 *
 * @note Memory Management:
 *       No allocation occurs; the footer pointer remains owned by the caller.
 */
footer_result_t footer_validate(const piadina_footer_t *footer);

/**
 * @brief Initialize a footer struct with defaults.
 *
 * Sets magic, layout version, and zeroes other fields.
 *
 * @param[out] footer  Pointer to the footer struct to initialize.
 *
 * @note Memory Management:
 *       The caller owns @p footer. No allocation occurs.
 */
void footer_prepare(piadina_footer_t *footer);

/**
 * @brief Append a validated footer to the end of the launcher binary.
 *
 * @param[in] fd      File descriptor open for writing.
 * @param[in] footer  Pointer to the footer to write.
 * @return            FOOTER_OK on success, or an error code.
 *
 * @note Memory Management:
 *       The caller retains ownership of @p footer. No memory is allocated.
 */
footer_result_t footer_append(int fd, const piadina_footer_t *footer);

/**
 * @brief Convert a footer result code to a string.
 *
 * @param[in] result  The result code.
 * @return            String description of the result.
 *
 * @note Memory Management:
 *       Returns a pointer to static string constants. Caller must not free it.
 */
const char *footer_result_to_string(footer_result_t result);

/**
 * @brief Print footer information to a FILE stream in human-readable format.
 *
 * @param[in] footer  Pointer to the footer to print.
 * @param[in] stream  Stream to print to (defaults to stderr if NULL).
 *
 * @note Memory Management:
 *       The caller retains ownership of @p footer and @p stream. No allocation occurs.
 */
void footer_print(const piadina_footer_t *footer, FILE *stream);

#endif /* PIADINA_COMMON_FOOTER_H */
