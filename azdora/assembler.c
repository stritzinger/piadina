/**
 * @file assembler.c
 * @brief Assemble launcher + metadata into a self-contained binary (placeholder archive).
 */
#include "assembler.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cbor_encoder.h"
#include "common/crypto.h"
#include "common/footer.h"
#include "metadata.h"

#define COPY_BUFFER_SIZE 4096

static int copy_fd(int src_fd, int dst_fd);
static azdora_assembler_result_t write_metadata_and_footer(int out_fd,
                                                           uint64_t launcher_size,
                                                           const azdora_metadata_t *metadata,
                                                           bool verbose);

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

    out_fd = open(config->output_path, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    if (out_fd < 0) {
        close(in_fd);
        return AZDORA_ASSEMBLER_ERR_OPEN_OUTPUT;
    }

    if (copy_fd(in_fd, out_fd) != 0) {
        close(in_fd);
        close(out_fd);
        unlink(config->output_path);
        return AZDORA_ASSEMBLER_ERR_WRITE_OUTPUT;
    }

    close(in_fd);

    azdora_assembler_result_t rc = write_metadata_and_footer(out_fd,
                                                             (uint64_t)st.st_size,
                                                             metadata,
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
    case AZDORA_ASSEMBLER_ERR_FOOTER:
        return "footer append failed";
    default:
        return "unknown error";
    }
}

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

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

static azdora_assembler_result_t write_metadata_and_footer(int out_fd,
                                                           uint64_t launcher_size,
                                                           const azdora_metadata_t *metadata,
                                                           bool verbose)
{
    if (verbose) {
        fprintf(stderr, "[azdora] metadata:\n");
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

    uint8_t metadata_hash[32];
    if (!crypto_sha256(metadata_buf, metadata_size, metadata_hash)) {
        free(metadata_buf);
        return AZDORA_ASSEMBLER_ERR_METADATA_ENCODE;
    }

    /* Write metadata block */
    ssize_t written = write(out_fd, metadata_buf, metadata_size);
    if (written < 0 || (size_t)written != metadata_size) {
        free(metadata_buf);
        return AZDORA_ASSEMBLER_ERR_WRITE_OUTPUT;
    }
    free(metadata_buf);

    /* Prepare footer */
    piadina_footer_t footer;
    footer_prepare(&footer);
    footer.metadata_offset = launcher_size;
    footer.metadata_size = (uint64_t)metadata_size;
    footer.archive_offset = footer.metadata_offset + footer.metadata_size;
    footer.archive_size = 0; /* Placeholder archive */
    memcpy(footer.metadata_hash, metadata_hash, sizeof(metadata_hash));

    /* Set archive hash (bytes) from metadata */
    size_t hash_len = 0;
    const uint8_t *hash_bytes = NULL;
    azdora_metadata_result_t hash_rc = azdora_metadata_get_bytes(metadata,
                                                                 METADATA_FIELD_ARCHIVE_HASH,
                                                                 &hash_bytes,
                                                                 &hash_len,
                                                                 NULL);
    if (hash_rc == AZDORA_METADATA_OK && hash_bytes && hash_len >= sizeof(footer.archive_hash)) {
        memcpy(footer.archive_hash, hash_bytes, sizeof(footer.archive_hash));
    } else {
        memset(footer.archive_hash, 0, sizeof(footer.archive_hash));
    }

    /* Compute footer hash (covers entire footer with footer_hash zeroed) */
    piadina_footer_t footer_for_hash = footer;
    memset(footer_for_hash.footer_hash, 0, sizeof(footer_for_hash.footer_hash));
    if (!crypto_sha256((const uint8_t *)&footer_for_hash,
                       sizeof(footer_for_hash),
                       footer.footer_hash)) {
        return AZDORA_ASSEMBLER_ERR_FOOTER;
    }

    if (verbose) {
        fprintf(stderr, "[azdora] footer:\n");
        footer_print(&footer, stderr);
    }

    footer_result_t footer_rc = footer_append(out_fd, &footer);
    if (footer_rc != FOOTER_OK) {
        return AZDORA_ASSEMBLER_ERR_FOOTER;
    }

    return AZDORA_ASSEMBLER_OK;
}
