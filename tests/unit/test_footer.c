#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "common/footer.h"

static piadina_footer_t make_valid_footer(void)
{
    piadina_footer_t footer;
    footer_prepare(&footer);
    footer.metadata_offset = 16;
    footer.metadata_size = 32;
    footer.archive_offset = footer.metadata_offset + footer.metadata_size;
    footer.archive_size = 64;
    return footer;
}

static int create_temp_file(void)
{
    char path[] = "/tmp/piadina_footerXXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT_TRUE(fd >= 0);
    unlink(path);
    return fd;
}

static void write_or_fail(int fd, const void *data, size_t size)
{
    ssize_t written = write(fd, data, size);
    TEST_ASSERT_EQUAL_size_t(size, (size_t)written);
}

static void ensure_data_region(int fd, uint64_t size)
{
    TEST_ASSERT_EQUAL(0, ftruncate(fd, (off_t)size));
    TEST_ASSERT_EQUAL((off_t)size, lseek(fd, 0, SEEK_END));
}

void setUp(void) {}
void tearDown(void) {}

static void test_footer_read_and_validate_success(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();

    uint64_t data_size = footer.archive_offset + footer.archive_size;
    ensure_data_region(fd, data_size);
    TEST_ASSERT_EQUAL(FOOTER_OK, footer_append(fd, &footer));

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_OK, footer_read(fd, &out));

    close(fd);
}

static void test_footer_detects_bad_magic(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();
    footer.magic[0] = 'X';

    uint64_t data_size = footer.archive_offset + footer.archive_size;
    ensure_data_region(fd, data_size);
    write_or_fail(fd, &footer, sizeof(footer));

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_ERR_BAD_MAGIC, footer_read(fd, &out));

    close(fd);
}

static void test_footer_detects_bad_version(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();
    footer.layout_version = 999; /* unsupported version */

    uint64_t data_size = footer.archive_offset + footer.archive_size;
    ensure_data_region(fd, data_size);
    write_or_fail(fd, &footer, sizeof(footer));

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_ERR_BAD_VERSION, footer_read(fd, &out));

    close(fd);
}

static void test_footer_detects_reserved_nonzero(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();
    footer.reserved[0] = 0xFF; /* non-zero reserved byte */

    uint64_t data_size = footer.archive_offset + footer.archive_size;
    ensure_data_region(fd, data_size);
    write_or_fail(fd, &footer, sizeof(footer));

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_ERR_RESERVED_NONZERO, footer_read(fd, &out));

    close(fd);
}

static void test_footer_file_too_small(void)
{
    int fd = create_temp_file();

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_ERR_FILE_TOO_SMALL, footer_read(fd, &out));

    close(fd);
}

static void test_footer_metadata_range_invalid(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();
    footer.metadata_size = footer.archive_offset - footer.metadata_offset + 1; /* overlaps archive */

    uint64_t data_size = footer.archive_offset + footer.archive_size;
    ensure_data_region(fd, data_size);
    write_or_fail(fd, &footer, sizeof(footer));

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_ERR_METADATA_RANGE, footer_read(fd, &out));

    close(fd);
}

static void test_footer_archive_out_of_bounds(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();

    uint64_t data_size = footer.archive_offset + footer.archive_size - 1; /* truncate archive */
    ensure_data_region(fd, data_size);
    write_or_fail(fd, &footer, sizeof(footer));

    piadina_footer_t out;
    TEST_ASSERT_EQUAL(FOOTER_ERR_ARCHIVE_RANGE, footer_read(fd, &out));

    close(fd);
}

static void test_footer_append_fails_when_file_too_small(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();

    uint64_t data_size = footer.archive_offset + footer.archive_size - 1;
    ensure_data_region(fd, data_size);

    TEST_ASSERT_EQUAL(FOOTER_ERR_ARCHIVE_RANGE, footer_append(fd, &footer));

    close(fd);
}

static void test_footer_append_validates_structural_issues(void)
{
    int fd = create_temp_file();
    piadina_footer_t footer = make_valid_footer();
    footer.magic[0] = 'X';

    uint64_t data_size = footer.archive_offset + footer.archive_size;
    ensure_data_region(fd, data_size);

    TEST_ASSERT_EQUAL(FOOTER_ERR_BAD_MAGIC, footer_append(fd, &footer));

    close(fd);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_footer_read_and_validate_success);
    RUN_TEST(test_footer_detects_bad_magic);
    RUN_TEST(test_footer_detects_bad_version);
    RUN_TEST(test_footer_detects_reserved_nonzero);
    RUN_TEST(test_footer_file_too_small);
    RUN_TEST(test_footer_metadata_range_invalid);
    RUN_TEST(test_footer_archive_out_of_bounds);
    RUN_TEST(test_footer_append_fails_when_file_too_small);
    RUN_TEST(test_footer_append_validates_structural_issues);
    return UNITY_END();
}
