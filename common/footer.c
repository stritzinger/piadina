/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file footer.c
 * @brief Layout and handling of the Piadina binary footer.
 */
#include "footer.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef SEEK_END
#define SEEK_END 2
#endif

static bool add_overflow(uint64_t a, uint64_t b, uint64_t *out);
static footer_result_t footer_validate_ranges(const piadina_footer_t *footer,
                                              uint64_t content_size,
                                              bool require_archive_exact);

footer_result_t footer_read(int fd, piadina_footer_t *out_footer)
{
    if (fd < 0 || out_footer == NULL) {
        return FOOTER_ERR_INVALID_ARGUMENT;
    }

    off_t end = lseek(fd, 0, SEEK_END);
    if (end == (off_t)-1) {
        return FOOTER_ERR_SEEK;
    }

    if (end < PIADINA_FOOTER_SIZE) {
        return FOOTER_ERR_FILE_TOO_SMALL;
    }

    if (lseek(fd, -((off_t)PIADINA_FOOTER_SIZE), SEEK_END) == (off_t)-1) {
        return FOOTER_ERR_SEEK;
    }

    ssize_t read_bytes = read(fd, out_footer, PIADINA_FOOTER_SIZE);
    if (read_bytes != PIADINA_FOOTER_SIZE) {
        return FOOTER_ERR_READ;
    }

    footer_result_t rc = footer_validate(out_footer);
    if (rc != FOOTER_OK) {
        return rc;
    }

    uint64_t content_size = (uint64_t)end - PIADINA_FOOTER_SIZE;
    return footer_validate_ranges(out_footer, content_size, false);
}

footer_result_t footer_validate(const piadina_footer_t *footer)
{
    if (!footer) {
        return FOOTER_ERR_INVALID_ARGUMENT;
    }

    if (memcmp(footer->magic, PIADINA_FOOTER_MAGIC, PIADINA_FOOTER_MAGIC_SIZE) != 0) {
        return FOOTER_ERR_BAD_MAGIC;
    }

    if (footer->layout_version != PIADINA_FOOTER_LAYOUT_VERSION) {
        return FOOTER_ERR_BAD_VERSION;
    }

    for (size_t i = 0; i < sizeof(footer->reserved); ++i) {
        if (footer->reserved[i] != 0) {
            return FOOTER_ERR_RESERVED_NONZERO;
        }
    }

    return FOOTER_OK;
}

footer_result_t footer_append(int fd, const piadina_footer_t *footer)
{
    if (fd < 0 || footer == NULL) {
        return FOOTER_ERR_INVALID_ARGUMENT;
    }

    off_t end = lseek(fd, 0, SEEK_END);
    if (end == (off_t)-1) {
        return FOOTER_ERR_SEEK;
    }

    footer_result_t rc = footer_validate(footer);
    if (rc != FOOTER_OK) {
        return rc;
    }

    rc = footer_validate_ranges(footer, (uint64_t)end, true);
    if (rc != FOOTER_OK) {
        return rc;
    }

    ssize_t written = write(fd, footer, PIADINA_FOOTER_SIZE);
    if (written != PIADINA_FOOTER_SIZE) {
        return FOOTER_ERR_WRITE;
    }

    return FOOTER_OK;
}

const char *footer_result_to_string(footer_result_t result)
{
    switch (result) {
    case FOOTER_OK:
        return "ok";
    case FOOTER_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case FOOTER_ERR_FILE_TOO_SMALL:
        return "file too small for footer";
    case FOOTER_ERR_SEEK:
        return "seek failed";
    case FOOTER_ERR_READ:
        return "read failed";
    case FOOTER_ERR_BAD_MAGIC:
        return "bad footer magic";
    case FOOTER_ERR_BAD_VERSION:
        return "unsupported footer version";
    case FOOTER_ERR_RESERVED_NONZERO:
        return "reserved bytes not zero";
    case FOOTER_ERR_METADATA_RANGE:
        return "metadata section outside file";
    case FOOTER_ERR_ARCHIVE_RANGE:
        return "archive section outside file";
    case FOOTER_ERR_WRITE:
        return "footer write failed";
    default:
        return "unknown footer error";
    }
}

void footer_prepare(piadina_footer_t *footer)
{
    if (!footer) {
        return;
    }

    memset(footer, 0, sizeof(*footer));
    memcpy(footer->magic, PIADINA_FOOTER_MAGIC, PIADINA_FOOTER_MAGIC_SIZE);
    footer->layout_version = PIADINA_FOOTER_LAYOUT_VERSION;
}

void footer_print(const piadina_footer_t *footer, FILE *stream)
{
    if (!footer) {
        return;
    }
    if (!stream) {
        stream = stderr;
    }

    fprintf(stream, "  Layout version:    %u\n", footer->layout_version);
    fprintf(stream, "  Metadata offset:   %lu\n", (unsigned long)footer->metadata_offset);
    fprintf(stream, "  Metadata size:     %lu\n", (unsigned long)footer->metadata_size);
    fprintf(stream, "  Archive offset:    %lu\n", (unsigned long)footer->archive_offset);
    fprintf(stream, "  Archive size:      %lu\n", (unsigned long)footer->archive_size);

    /* Metadata hash as hex */
    fprintf(stream, "  Metadata hash:     ");
    for (int i = 0; i < 32; i++) {
        fprintf(stream, "%02x", footer->metadata_hash[i]);
    }
    fprintf(stream, "\n");

    /* Print archive hash as hex */
    fprintf(stream, "  Archive hash:      ");
    for (int i = 0; i < 32; i++) {
        fprintf(stream, "%02x", footer->archive_hash[i]);
    }
    fprintf(stream, "\n");

    /* Footer hash as hex */
    fprintf(stream, "  Footer hash:       ");
    for (int i = 0; i < 32; i++) {
        fprintf(stream, "%02x", footer->footer_hash[i]);
    }
    fprintf(stream, "\n");
}

/* Internal Functions */

static bool add_overflow(uint64_t a, uint64_t b, uint64_t *out)
{
    uint64_t sum = a + b;
    if (sum < a) {
        return true;
    }
    *out = sum;
    return false;
}

static footer_result_t footer_validate_ranges(const piadina_footer_t *footer,
                                              uint64_t content_size,
                                              bool require_archive_exact)
{
    uint64_t archive_end = 0;
    if (add_overflow(footer->archive_offset, footer->archive_size, &archive_end)) {
        return FOOTER_ERR_ARCHIVE_RANGE;
    }

    if (archive_end > content_size) {
        return FOOTER_ERR_ARCHIVE_RANGE;
    }

    if (archive_end > footer->metadata_offset) {
        return FOOTER_ERR_ARCHIVE_RANGE;
    }

    uint64_t metadata_end = 0;
    if (add_overflow(footer->metadata_offset, footer->metadata_size, &metadata_end)) {
        return FOOTER_ERR_METADATA_RANGE;
    }

    if (metadata_end > content_size) {
        return FOOTER_ERR_METADATA_RANGE;
    }

    if (require_archive_exact && metadata_end != content_size) {
        return FOOTER_ERR_METADATA_RANGE;
    }

    return FOOTER_OK;
}
