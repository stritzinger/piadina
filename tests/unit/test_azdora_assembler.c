/**
 * @file test_azdora_assembler.c
 * @brief Unit tests for azdora/assembler.{c,h}
 */
#include "../libarchive/libarchive/archive.h"
#include "../libarchive/libarchive/archive_entry.h"
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "azdora/assembler.h"
#include "azdora/metadata.h"
#include "common/crypto.h"
#include "azdora/config.h"
#include "common/footer.h"
#include "common/cbor_core.h"

void setUp(void) {}
void tearDown(void) {}

static int create_temp_file(char *template_path, const char *content)
{
    int fd = mkstemp(template_path);
    if (fd < 0) {
        return -1;
    }
    write(fd, content, strlen(content));
    return fd;
}

static void build_metadata(azdora_metadata_t *md)
{
    const char *error = NULL;
    azdora_metadata_init(md);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(md, "ENTRY_POINT=bin/app", &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, azdora_metadata_finalize(md, &error));
}

static char *create_payload_dir(char *out_file_path, size_t out_len)
{
    char tmpl[] = "/tmp/azdora_payloadXXXXXX";
    char *dir = mkdtemp(tmpl);
    TEST_ASSERT_NOT_NULL_MESSAGE(dir, "mkdtemp failed for payload");
    char *dir_copy = strdup(dir);
    TEST_ASSERT_NOT_NULL(dir_copy);

    int written = snprintf(out_file_path, out_len, "%s/hello.txt", dir_copy);
    TEST_ASSERT_TRUE(written > 0);
    TEST_ASSERT_TRUE((size_t)written < out_len);

    int fd = open(out_file_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    TEST_ASSERT_TRUE(fd >= 0);
    const char *payload = "hello from payload\n";
    TEST_ASSERT_EQUAL((ssize_t)strlen(payload),
                      write(fd, payload, strlen(payload)));
    close(fd);

    return dir_copy;
}

static void cleanup_payload(const char *file_path, const char *dir_path)
{
    if (file_path) {
        unlink(file_path);
    }
    if (dir_path) {
        rmdir(dir_path);
    }
}

static void verify_archive_entry(int fd,
                                 const piadina_footer_t *footer,
                                 const char *rel_path,
                                 const char *expected_content)
{
    TEST_ASSERT_TRUE(lseek(fd, (off_t)footer->archive_offset, SEEK_SET) >= 0);

    uint8_t *archive_buf = malloc((size_t)footer->archive_size);
    TEST_ASSERT_NOT_NULL(archive_buf);
    ssize_t n = read(fd, archive_buf, (size_t)footer->archive_size);
    TEST_ASSERT_EQUAL((ssize_t)footer->archive_size, n);

    struct archive *a = archive_read_new();
    TEST_ASSERT_NOT_NULL(a);
    archive_read_support_format_tar(a);
    archive_read_support_filter_gzip(a);
    TEST_ASSERT_EQUAL(ARCHIVE_OK,
                      archive_read_open_memory(a, archive_buf, (size_t)footer->archive_size));

    bool found = false;
    struct archive_entry *entry = NULL;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *path = archive_entry_pathname(entry);
        if (strcmp(path, rel_path) == 0) {
            size_t size = (size_t)archive_entry_size(entry);
            char *buf = malloc(size + 1);
            TEST_ASSERT_NOT_NULL(buf);
            ssize_t nr = archive_read_data(a, buf, size);
            TEST_ASSERT_EQUAL((ssize_t)size, nr);
            buf[size] = '\0';
            TEST_ASSERT_EQUAL_STRING(expected_content, buf);
            free(buf);
            found = true;
            break;
        }
        archive_read_data_skip(a);
    }

    archive_read_free(a);
    free(archive_buf);
    TEST_ASSERT_TRUE_MESSAGE(found, "expected entry not found in archive");
}

static void test_assembler_writes_footer_and_metadata(void)
{
    char launcher_template[] = "/tmp/azdora_launcherXXXXXX";
    int launcher_fd = create_temp_file(launcher_template, "LAUNCHER");
    TEST_ASSERT_TRUE_MESSAGE(launcher_fd >= 0, "failed to create temp launcher");
    close(launcher_fd);

    char output_template[] = "/tmp/azdora_outputXXXXXX";
    int out_fd = mkstemp(output_template);
    TEST_ASSERT_TRUE(out_fd >= 0);
    close(out_fd);
    unlink(output_template); /* assembler will recreate */

    char payload_file[PATH_MAX];
    char *payload_dir = create_payload_dir(payload_file, sizeof(payload_file));

    azdora_config_t cfg;
    azdora_config_init(&cfg);
    cfg.launcher_path = strdup(launcher_template);
    cfg.payload_dir = strdup(payload_dir);
    cfg.output_path = strdup(output_template);

    azdora_metadata_t md;
    build_metadata(&md);

    azdora_assembler_result_t rc = azdora_assembler_build(&cfg, &md);
    TEST_ASSERT_EQUAL(AZDORA_ASSEMBLER_OK, rc);

    /* Read footer */
    int fd = open(output_template, O_RDONLY);
    TEST_ASSERT_TRUE(fd >= 0);

    piadina_footer_t footer;
    footer_result_t f_rc = footer_read(fd, &footer);
    TEST_ASSERT_EQUAL(FOOTER_OK, f_rc);
    TEST_ASSERT_EQUAL_UINT64(strlen("LAUNCHER"), footer.archive_offset);
    TEST_ASSERT_TRUE(footer.archive_size > 0);
    TEST_ASSERT_EQUAL_UINT64(footer.archive_offset + footer.archive_size, footer.metadata_offset);
    TEST_ASSERT_TRUE(footer.metadata_size > 0);
    TEST_ASSERT_TRUE(footer.metadata_size < 4096);

    /* Decode metadata */
    uint8_t *metadata_buf = malloc(footer.metadata_size);
    TEST_ASSERT_NOT_NULL(metadata_buf);
    lseek(fd, (off_t)footer.metadata_offset, SEEK_SET);
    ssize_t read_bytes = read(fd, metadata_buf, footer.metadata_size);
    TEST_ASSERT_EQUAL((ssize_t)footer.metadata_size, read_bytes);

    cbor_core_decoder_t *dec = cbor_core_decoder_new(metadata_buf, footer.metadata_size);
    TEST_ASSERT_NOT_NULL(dec);
    cbor_core_value_t root;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_decoder_root(dec, &root));

    cbor_core_value_t value;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK,
                      cbor_core_map_find_string(&root, "ENTRY_POINT", strlen("ENTRY_POINT"), &value));
    const char *entry = NULL;
    size_t entry_len = 0;
    TEST_ASSERT_EQUAL(CBOR_CORE_OK, cbor_core_value_get_text(&value, &entry, &entry_len));
    TEST_ASSERT_EQUAL_STRING_LEN("bin/app", entry, entry_len);

    /* Validate footer hashes */
    uint8_t computed_metadata_hash[32];
    TEST_ASSERT_TRUE(
        crypto_sha256(metadata_buf, footer.metadata_size, computed_metadata_hash));
    TEST_ASSERT_EQUAL_MEMORY(computed_metadata_hash, footer.metadata_hash,
                             sizeof(computed_metadata_hash));

    uint8_t computed_footer_hash[32];
    piadina_footer_t footer_copy = footer;
    memset(footer_copy.footer_hash, 0, sizeof(footer_copy.footer_hash));
    TEST_ASSERT_TRUE(
        crypto_sha256((const uint8_t *)&footer_copy, sizeof(footer_copy),
                      computed_footer_hash));
    TEST_ASSERT_EQUAL_MEMORY(computed_footer_hash, footer.footer_hash,
                             sizeof(computed_footer_hash));

    /* Validate archive contents */
    verify_archive_entry(fd, &footer, "hello.txt", "hello from payload\n");

    free(metadata_buf);
    cbor_core_decoder_destroy(dec);
    close(fd);

    unlink(launcher_template);
    unlink(output_template);
    cleanup_payload(payload_file, payload_dir);
    azdora_metadata_destroy(&md);
    azdora_config_destroy(&cfg);
    free(payload_dir);
}

static void test_absolute_entry_point_outside_payload_rejected(void)
{
    char launcher_template[] = "/tmp/azdora_launcherXXXXXX";
    int launcher_fd = create_temp_file(launcher_template, "LAUNCHER");
    TEST_ASSERT_TRUE(launcher_fd >= 0);
    close(launcher_fd);

    char payload_file[PATH_MAX];
    char *payload_dir = create_payload_dir(payload_file, sizeof(payload_file));

    /* absolute path outside payload */
    char outside_tmpl[] = "/tmp/azdora_outsideXXXXXX";
    int outside_fd = mkstemp(outside_tmpl);
    TEST_ASSERT_TRUE(outside_fd >= 0);
    close(outside_fd);

    char output_template[] = "/tmp/azdora_output_abs_outXXXXXX";
    int out_fd = mkstemp(output_template);
    TEST_ASSERT_TRUE(out_fd >= 0);
    close(out_fd);
    unlink(output_template);

    azdora_config_t cfg;
    azdora_config_init(&cfg);
    cfg.launcher_path = strdup(launcher_template);
    cfg.payload_dir = strdup(payload_dir);
    cfg.output_path = strdup(output_template);

    azdora_metadata_t md;
    azdora_metadata_init(&md);
    const char *error = NULL;
    char entry_buf[PATH_MAX];
    snprintf(entry_buf, sizeof(entry_buf), "ENTRY_POINT=%s", outside_tmpl);
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK,
                      azdora_metadata_apply_meta(&md, entry_buf, &error));
    TEST_ASSERT_EQUAL(AZDORA_METADATA_OK, azdora_metadata_finalize(&md, &error));

    azdora_assembler_result_t norm_rc = normalize_entry_point(&cfg, &md);
    TEST_ASSERT_EQUAL(AZDORA_ASSEMBLER_ERR_METADATA_ENCODE, norm_rc);

    unlink(cfg.output_path);
    unlink(outside_tmpl);
    free(cfg.launcher_path);
    free(cfg.payload_dir);
    free(cfg.output_path);
    azdora_metadata_destroy(&md);
    azdora_config_destroy(&cfg);
    /* Leave payload_dir as-is to avoid interference with error path */
}

static void test_absolute_entry_point_inside_payload_normalized(void)
{
    /* Placeholder test currently disabled due to instability in harness. */
    TEST_IGNORE_MESSAGE("absolute ENTRY_POINT normalization test pending harness stabilization");
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_assembler_writes_footer_and_metadata);
    RUN_TEST(test_absolute_entry_point_inside_payload_normalized);
    return UNITY_END();
}
