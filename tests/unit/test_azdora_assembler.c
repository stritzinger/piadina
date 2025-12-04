/**
 * @file test_azdora_assembler.c
 * @brief Unit tests for azdora/assembler.{c,h}
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

    azdora_config_t cfg;
    azdora_config_init(&cfg);
    cfg.launcher_path = strdup(launcher_template);
    cfg.payload_dir = strdup("/tmp/payload");
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
    TEST_ASSERT_EQUAL_UINT64(strlen("LAUNCHER"), footer.metadata_offset);
    TEST_ASSERT_EQUAL_UINT64(footer.metadata_offset + footer.metadata_size, footer.archive_offset);
    TEST_ASSERT_EQUAL_UINT64(0, footer.archive_size);
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

    free(metadata_buf);
    cbor_core_decoder_destroy(dec);
    close(fd);

    unlink(launcher_template);
    unlink(output_template);
    azdora_metadata_destroy(&md);
    azdora_config_destroy(&cfg);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_assembler_writes_footer_and_metadata);
    return UNITY_END();
}
