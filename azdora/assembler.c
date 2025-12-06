/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file assembler.c
 * @brief Assemble launcher + metadata into a self-contained binary (placeholder archive).
 */
#include "assembler.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cbor_encoder.h"
#include "common/crypto.h"
#include "common/footer.h"
#include "metadata.h"
#include "packer_tar_gzip.h"

#define COPY_BUFFER_SIZE 4096

/* Internal Prototypes */

static int copy_fd(int src_fd, int dst_fd);
static azdora_assembler_result_t write_metadata_block(int out_fd,
                                                      const azdora_metadata_t *metadata,
                                                      bool verbose,
                                                      uint64_t *metadata_size_out,
                                                      uint8_t metadata_hash_out[32]);
static azdora_assembler_result_t write_footer_block(int out_fd,
                                                    uint64_t launcher_size,
                                                    uint64_t metadata_size,
                                                    uint64_t archive_size,
                                                    const uint8_t archive_hash[32],
                                                    const uint8_t metadata_hash[32],
                                                    bool verbose);
static bool compute_hash_region(int fd, uint64_t offset, uint64_t size, uint8_t out_hash[32]);
azdora_assembler_result_t normalize_entry_point(const azdora_config_t *config,
                                                azdora_metadata_t *metadata);

/* Exported Functions */

azdora_assembler_result_t azdora_assembler_build(const azdora_config_t *config,
                                                 const azdora_metadata_t *metadata)
{
    if (!config || !metadata || !config->launcher_path || !config->output_path) {
        return AZDORA_ASSEMBLER_ERR_INVALID_ARGUMENT;
    }

    int in_fd = -1;
    int out_fd = -1;
    struct stat st;

    in_fd = open(config->launcher_path, O_RDONLY);
    if (in_fd < 0) {
        return AZDORA_ASSEMBLER_ERR_OPEN_LAUNCHER;
    }

    if (fstat(in_fd, &st) != 0) {
        close(in_fd);
        return AZDORA_ASSEMBLER_ERR_READ_LAUNCHER;
    }

    out_fd = open(config->output_path, O_CREAT | O_TRUNC | O_RDWR, 0755);
    if (out_fd < 0) {
        close(in_fd);
        return AZDORA_ASSEMBLER_ERR_OPEN_OUTPUT;
    }

    if (config->verbose) {
        fprintf(stderr, "[azdora] writing launcher from %s\n", config->launcher_path);
    }

    if (copy_fd(in_fd, out_fd) != 0) {
        close(in_fd);
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_WRITE_OUTPUT;
    }

    close(in_fd);

    uint64_t archive_size = 0;
    off_t archive_offset = lseek(out_fd, 0, SEEK_END);
    if (config->verbose) {
        fprintf(stderr, "[azdora] packing archive from %s\n", config->payload_dir);
    }

    packer_tar_gzip_result_t pack_rc =
        packer_tar_gzip_write(config->payload_dir, out_fd, &archive_size,
                              config->verbose, config->quiet);
    if (pack_rc != PACKER_TGZ_OK) {
        fprintf(stderr, "[azdora] tar+gzip pack failed: %s\n",
                packer_tar_gzip_result_to_string(pack_rc));
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_PACK_ARCHIVE;
    }

    if (config->verbose) {
        fprintf(stderr, "[azdora] packing completed\n");
    }

    off_t archive_end = lseek(out_fd, 0, SEEK_END);
    if (archive_size == 0 && archive_end != (off_t)-1 && archive_offset != (off_t)-1) {
        archive_size = (uint64_t)(archive_end - archive_offset);
    }
    if (archive_size == 0 || archive_offset < 0) {
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_PACK_ARCHIVE;
    }

    uint8_t archive_hash[32];
    if (!compute_hash_region(out_fd, (uint64_t)archive_offset, archive_size, archive_hash)) {
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_PACK_ARCHIVE;
    }

    if (lseek(out_fd, 0, SEEK_END) < 0) {
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_PACK_ARCHIVE;
    }

    azdora_metadata_t mutable_md = *metadata;
    const char *set_err = NULL;

    azdora_assembler_result_t norm_rc = normalize_entry_point(config, &mutable_md);
    if (norm_rc != AZDORA_ASSEMBLER_OK) {
        close(out_fd);
        unlink(config->output_path);
        return norm_rc;
    }

    azdora_metadata_result_t set_rc = azdora_metadata_set_field_bytes(&mutable_md,
                                                                      METADATA_FIELD_ARCHIVE_HASH,
                                                                      archive_hash,
                                                                      sizeof(archive_hash),
                                                                      &set_err);
    if (set_rc != AZDORA_METADATA_OK) {
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    uint64_t metadata_size = 0;
    uint8_t metadata_hash[32];

    azdora_assembler_result_t rc = write_metadata_block(out_fd,
                                                        &mutable_md,
                                                        config->verbose,
                                                        &metadata_size,
                                                        metadata_hash);
    if (rc != AZDORA_ASSEMBLER_OK) {
        close(out_fd);
        unlink(config->output_path);
        return rc;
    }

    rc = write_footer_block(out_fd,
                            (uint64_t)st.st_size,
                            metadata_size,
                            archive_size,
                            archive_hash,
                            metadata_hash,
                            config->verbose);
    close(out_fd);

    if (rc != AZDORA_ASSEMBLER_OK) {
        unlink(config->output_path);
        return rc;
    }

    return AZDORA_ASSEMBLER_OK;
}

const char *azdora_assembler_result_to_string(azdora_assembler_result_t result)
{
    switch (result) {
    case AZDORA_ASSEMBLER_OK:
        return "ok";
    case AZDORA_ASSEMBLER_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case AZDORA_ASSEMBLER_ERR_OPEN_LAUNCHER:
        return "failed to open launcher";
    case AZDORA_ASSEMBLER_ERR_READ_LAUNCHER:
        return "failed to read launcher";
    case AZDORA_ASSEMBLER_ERR_OPEN_OUTPUT:
        return "failed to open output";
    case AZDORA_ASSEMBLER_ERR_WRITE_OUTPUT:
        return "failed to write output";
    case AZDORA_ASSEMBLER_ERR_METADATA_ENCODE:
        return "metadata encode failed";
    case AZDORA_ASSEMBLER_ERR_PACK_ARCHIVE:
        return "archive packing failed";
    case AZDORA_ASSEMBLER_ERR_FOOTER:
        return "footer append failed";
    default:
        return "unknown error";
    }
}

/* Internal Functions */

static int copy_fd(int src_fd, int dst_fd)
{
    char buffer[COPY_BUFFER_SIZE];
    ssize_t n;
    while ((n = read(src_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t written = 0;
        while (written < n) {
            ssize_t w = write(dst_fd, buffer + written, (size_t)(n - written));
            if (w < 0) {
                return -1;
            }
            written += w;
        }
    }
    return (n < 0) ? -1 : 0;
}

static azdora_assembler_result_t write_metadata_block(int out_fd,
                                                      const azdora_metadata_t *metadata,
                                                      bool verbose,
                                                      uint64_t *metadata_size_out,
                                                      uint8_t metadata_hash_out[32])
{
    if (verbose) {
        fprintf(stderr, "[azdora] writing metadata:\n");
        azdora_metadata_print(metadata, stderr);
    }

    uint8_t *metadata_buf = NULL;
    size_t metadata_size = 0;

    azdora_cbor_result_t cbor_rc = azdora_cbor_encode_metadata(metadata,
                                                               &metadata_buf,
                                                               &metadata_size);
    if (cbor_rc != AZDORA_CBOR_OK) {
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    if (!crypto_sha256(metadata_buf, metadata_size, metadata_hash_out)) {
        free(metadata_buf);
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    ssize_t written = write(out_fd, metadata_buf, metadata_size);
    free(metadata_buf);
    if (written < 0 || (size_t)written != metadata_size) {
        return AZDORA_ASSEMBLER_ERR_WRITE_OUTPUT;
    }

    if (metadata_size_out) {
        *metadata_size_out = (uint64_t)metadata_size;
    }
    return AZDORA_ASSEMBLER_OK;
}

static azdora_assembler_result_t write_footer_block(int out_fd,
                                                    uint64_t launcher_size,
                                                    uint64_t metadata_size,
                                                    uint64_t archive_size,
                                                    const uint8_t archive_hash[32],
                                                    const uint8_t metadata_hash[32],
                                                    bool verbose)
{
    piadina_footer_t footer;
    footer_prepare(&footer);
    footer.archive_offset = launcher_size;
    footer.archive_size = archive_size;
    footer.metadata_offset = launcher_size + archive_size;
    footer.metadata_size = metadata_size;
    memcpy(footer.metadata_hash, metadata_hash, 32);

    if (archive_hash) {
        memcpy(footer.archive_hash, archive_hash, sizeof(footer.archive_hash));
    } else {
        memset(footer.archive_hash, 0, sizeof(footer.archive_hash));
    }

    piadina_footer_t footer_for_hash = footer;
    memset(footer_for_hash.footer_hash, 0, sizeof(footer_for_hash.footer_hash));
    if (!crypto_sha256((const uint8_t *)&footer_for_hash,
                       sizeof(footer_for_hash),
                       footer.footer_hash)) {
        return AZDORA_ASSEMBLER_ERR_FOOTER;
    }

    if (verbose) {
        fprintf(stderr, "[azdora] writing footer:\n");
        footer_print(&footer, stderr);
    }

    footer_result_t footer_rc = footer_append(out_fd, &footer);
    if (footer_rc != FOOTER_OK) {
        return AZDORA_ASSEMBLER_ERR_FOOTER;
    }

    return AZDORA_ASSEMBLER_OK;
}

static bool compute_hash_region(int fd, uint64_t offset, uint64_t size, uint8_t out_hash[32])
{
    if (fd < 0 || !out_hash) {
        return false;
    }
    off_t rc = lseek(fd, (off_t)offset, SEEK_SET);
    if (rc < 0) {
        return false;
    }

    crypto_sha256_ctx ctx;
    crypto_sha256_init(&ctx);
    uint8_t buffer[COPY_BUFFER_SIZE];
    uint64_t remaining = size;
    while (remaining > 0) {
        size_t to_read = remaining < sizeof(buffer) ? (size_t)remaining : sizeof(buffer);
        ssize_t n = read(fd, buffer, to_read);
        if (n <= 0) {
            return false;
        }
        if (!crypto_sha256_update(&ctx, buffer, (size_t)n)) {
            return false;
        }
        remaining -= (uint64_t)n;
    }

    return crypto_sha256_final(&ctx, out_hash);
}

azdora_assembler_result_t normalize_entry_point(const azdora_config_t *config,
                                                azdora_metadata_t *metadata)
{
    const char *entry_point = NULL;
    const char *err = NULL;
    azdora_metadata_result_t rc = azdora_metadata_get_string(metadata,
                                                             METADATA_FIELD_ENTRY_POINT,
                                                             &entry_point,
                                                             &err);
    if (rc != AZDORA_METADATA_OK || !entry_point) {
        fprintf(stderr, "[azdora] missing ENTRY_POINT: %s\n", err ? err : "unknown error");
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    if (entry_point[0] != '/') {
        return AZDORA_ASSEMBLER_OK;
    }

    if (!config->payload_dir) {
        fprintf(stderr, "[azdora] absolute ENTRY_POINT requires payload_dir\n");
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    char payload_real[PATH_MAX];
    char entry_real[PATH_MAX];

    if (!realpath(config->payload_dir, payload_real)) {
        fprintf(stderr, "[azdora] failed to resolve payload dir: %s\n", strerror(errno));
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }
    if (!realpath(entry_point, entry_real)) {
        fprintf(stderr, "[azdora] failed to resolve ENTRY_POINT: %s\n", strerror(errno));
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    size_t prefix_len = strlen(payload_real);
    if (strncmp(entry_real, payload_real, prefix_len) != 0 ||
        (entry_real[prefix_len] != '/' && entry_real[prefix_len] != '\0')) {
        fprintf(stderr, "[azdora] ENTRY_POINT must reside within payload root (%s)\n", payload_real);
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    const char *relative = entry_real + prefix_len;
    if (*relative == '/') {
        relative++;
    }
    if (*relative == '\0') {
        fprintf(stderr, "[azdora] ENTRY_POINT cannot be the payload root itself\n");
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    rc = azdora_metadata_set_field_string(metadata, METADATA_FIELD_ENTRY_POINT, relative, &err);
    if (rc != AZDORA_METADATA_OK) {
        fprintf(stderr, "[azdora] failed to normalize ENTRY_POINT: %s\n", err ? err : "unknown error");
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    if (config->verbose) {
        fprintf(stderr, "[azdora] normalized ENTRY_POINT to %s\n", relative);
    }
    return AZDORA_ASSEMBLER_OK;
}
