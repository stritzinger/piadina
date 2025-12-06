/**
 * @file test_tar_gzip.c
 * @brief Unit tests for libarchive-backed tar+gzip packer/extractor.
 */
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "unity.h"

#include "azdora/packer_tar_gzip.h"
#include "piadina/extractor_tar_gzip.h"

typedef struct {
    char dir[PATH_MAX];
    char file[PATH_MAX];
    char nested_dir[PATH_MAX];
    char nested_file[PATH_MAX];
    char symlink_path[PATH_MAX];
    mode_t file_mode;
    mode_t nested_mode;
} payload_paths_t;

static void create_payload_dir(payload_paths_t *paths, const char *symlink_target)
{
    char tmpl[] = "/tmp/tgz_payloadXXXXXX";
    char *dir = mkdtemp(tmpl);
    TEST_ASSERT_NOT_NULL_MESSAGE(dir, "mkdtemp failed");

    snprintf(paths->dir, sizeof(paths->dir), "%s", dir);
    snprintf(paths->file, sizeof(paths->file), "%s/file.txt", dir);
    snprintf(paths->nested_dir, sizeof(paths->nested_dir), "%s/sub", dir);
    snprintf(paths->nested_file, sizeof(paths->nested_file), "%s/sub/nested.txt", dir);
    snprintf(paths->symlink_path, sizeof(paths->symlink_path), "%s/link_to_nested", dir);

    TEST_ASSERT_EQUAL(0, mkdir(paths->nested_dir, 0755));

    int fd = open(paths->file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    TEST_ASSERT_TRUE(fd >= 0);
    const char *payload = "tar round-trip\n";
    TEST_ASSERT_EQUAL((ssize_t)strlen(payload), write(fd, payload, strlen(payload)));
    close(fd);
    paths->file_mode = 0644;

    int nfd = open(paths->nested_file, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    TEST_ASSERT_TRUE(nfd >= 0);
    const char *nested_payload = "nested content\n";
    TEST_ASSERT_EQUAL((ssize_t)strlen(nested_payload),
                      write(nfd, nested_payload, strlen(nested_payload)));
    close(nfd);
    paths->nested_mode = 0600;

    const char *link_target = symlink_target ? symlink_target : "sub/nested.txt";
    TEST_ASSERT_EQUAL(0, symlink(link_target, paths->symlink_path));
}

static void cleanup_payload(const payload_paths_t *paths)
{
    unlink(paths->symlink_path);
    unlink(paths->nested_file);
    rmdir(paths->nested_dir);
    unlink(paths->file);
    rmdir(paths->dir);
}

static void cleanup_extract_dir(const payload_paths_t *paths)
{
    unlink(paths->symlink_path);
    unlink(paths->nested_file);
    rmdir(paths->nested_dir);
    unlink(paths->file);
    rmdir(paths->dir);
}

static int run_tar_cmd(const char *cmd)
{
    int rc = system(cmd);
    return rc;
}

static int compare_file_contents(const char *path1, const char *path2)
{
    FILE *f1 = fopen(path1, "rb");
    FILE *f2 = fopen(path2, "rb");
    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        return -1;
    }

    int result = 0;
    int c1, c2;
    do {
        c1 = fgetc(f1);
        c2 = fgetc(f2);
        if (c1 != c2) {
            result = -1;
            break;
        }
    } while (c1 != EOF && c2 != EOF);

    fclose(f1);
    fclose(f2);
    return result;
}

static int compare_symlink_target(const char *path, const char *expected_target)
{
    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len < 0) {
        return -1;
    }
    buf[len] = '\0';
    return strcmp(buf, expected_target);
}

static int compare_mode(const char *path, mode_t expected)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }
    return ((st.st_mode & 0777) == expected) ? 0 : -1;
}

/* Unity requires these symbols even if unused in a test file */
void setUp(void) {}
void tearDown(void) {}

static void test_packer_and_extractor_round_trip(void)
{
    payload_paths_t payload = {0};
    create_payload_dir(&payload, "sub/nested.txt");

    char archive_template[] = "/tmp/tgz_archiveXXXXXX";
    int archive_fd = mkstemp(archive_template);
    TEST_ASSERT_TRUE(archive_fd >= 0);
    ftruncate(archive_fd, 0);

    uint64_t archive_size = 0;
    packer_tar_gzip_result_t pack_rc =
        packer_tar_gzip_write(payload.dir, archive_fd, &archive_size, false, false);
    TEST_ASSERT_EQUAL(PACKER_TGZ_OK, pack_rc);
    TEST_ASSERT_TRUE(archive_size > 0);

    /* Extract into a fresh directory */
    char extract_tmpl[] = "/tmp/tgz_extractXXXXXX";
    char *extract_dir = mkdtemp(extract_tmpl);
    TEST_ASSERT_NOT_NULL(extract_dir);

    payload_paths_t extracted = {0};
    snprintf(extracted.dir, sizeof(extracted.dir), "%s", extract_dir);
    snprintf(extracted.file, sizeof(extracted.file), "%s/file.txt", extract_dir);
    snprintf(extracted.nested_dir, sizeof(extracted.nested_dir), "%s/sub", extract_dir);
    snprintf(extracted.nested_file, sizeof(extracted.nested_file), "%s/sub/nested.txt", extract_dir);
    snprintf(extracted.symlink_path, sizeof(extracted.symlink_path), "%s/link_to_nested", extract_dir);

    TEST_ASSERT_TRUE(lseek(archive_fd, 0, SEEK_SET) >= 0);
    tar_result_t ext_rc = extractor_tar_gzip_extract(archive_fd,
                                                     0,
                                                     archive_size,
                                                     extract_dir,
                                                     NULL);
    TEST_ASSERT_EQUAL(TAR_RESULT_OK, ext_rc);

    TEST_ASSERT_EQUAL(0, compare_file_contents(payload.file, extracted.file));
    TEST_ASSERT_EQUAL(0, compare_file_contents(payload.nested_file, extracted.nested_file));
    TEST_ASSERT_EQUAL(0, compare_symlink_target(extracted.symlink_path, "sub/nested.txt"));
    TEST_ASSERT_EQUAL(0, compare_mode(extracted.file, payload.file_mode));
    TEST_ASSERT_EQUAL(0, compare_mode(extracted.nested_file, payload.nested_mode));

    close(archive_fd);
    unlink(archive_template);
    cleanup_payload(&payload);
    cleanup_extract_dir(&extracted);
}

static void test_packer_archive_extractable_with_system_tar(void)
{
    payload_paths_t payload = {0};
    create_payload_dir(&payload, "sub/nested.txt");

    char archive_template[] = "/tmp/tgz_archive_tarXXXXXX";
    int archive_fd = mkstemp(archive_template);
    TEST_ASSERT_TRUE(archive_fd >= 0);
    ftruncate(archive_fd, 0);

    uint64_t archive_size = 0;
    TEST_ASSERT_EQUAL(PACKER_TGZ_OK,
                      packer_tar_gzip_write(payload.dir, archive_fd, &archive_size, false, false));
    TEST_ASSERT_TRUE(archive_size > 0);
    close(archive_fd);

    char extract_tmpl[] = "/tmp/tgz_ext_tarXXXXXX";
    char *extract_dir = mkdtemp(extract_tmpl);
    TEST_ASSERT_NOT_NULL(extract_dir);

    payload_paths_t extracted = {0};
    snprintf(extracted.dir, sizeof(extracted.dir), "%s", extract_dir);
    snprintf(extracted.file, sizeof(extracted.file), "%s/file.txt", extract_dir);
    snprintf(extracted.nested_dir, sizeof(extracted.nested_dir), "%s/sub", extract_dir);
    snprintf(extracted.nested_file, sizeof(extracted.nested_file), "%s/sub/nested.txt", extract_dir);
    snprintf(extracted.symlink_path, sizeof(extracted.symlink_path), "%s/link_to_nested", extract_dir);

    char cmd[PATH_MAX * 2];
    snprintf(cmd, sizeof(cmd), "tar -xzf %s -C %s", archive_template, extract_dir);
    TEST_ASSERT_EQUAL(0, run_tar_cmd(cmd));

    TEST_ASSERT_EQUAL(0, compare_file_contents(payload.file, extracted.file));
    TEST_ASSERT_EQUAL(0, compare_file_contents(payload.nested_file, extracted.nested_file));
    TEST_ASSERT_EQUAL(0, compare_symlink_target(extracted.symlink_path, "sub/nested.txt"));
    TEST_ASSERT_EQUAL(0, compare_mode(extracted.file, payload.file_mode));
    TEST_ASSERT_EQUAL(0, compare_mode(extracted.nested_file, payload.nested_mode));

    unlink(archive_template);
    cleanup_payload(&payload);
    cleanup_extract_dir(&extracted);
}

static void test_extractor_accepts_system_tar_archive(void)
{
    payload_paths_t payload = {0};
    create_payload_dir(&payload, "sub/nested.txt");

    char archive_template[] = "/tmp/tgz_archive_sysXXXXXX";
    int archive_fd = mkstemp(archive_template);
    TEST_ASSERT_TRUE(archive_fd >= 0);
    close(archive_fd);

    char cmd[PATH_MAX * 3];
    snprintf(cmd, sizeof(cmd), "tar -czf %s -C %s .", archive_template, payload.dir);
    TEST_ASSERT_EQUAL(0, run_tar_cmd(cmd));

    struct stat st;
    TEST_ASSERT_EQUAL(0, stat(archive_template, &st));
    int fd = open(archive_template, O_RDONLY);
    TEST_ASSERT_TRUE(fd >= 0);

    char extract_tmpl[] = "/tmp/tgz_ext_sysXXXXXX";
    char *extract_dir = mkdtemp(extract_tmpl);
    TEST_ASSERT_NOT_NULL(extract_dir);

    payload_paths_t extracted = {0};
    snprintf(extracted.dir, sizeof(extracted.dir), "%s", extract_dir);
    snprintf(extracted.file, sizeof(extracted.file), "%s/file.txt", extract_dir);
    snprintf(extracted.nested_dir, sizeof(extracted.nested_dir), "%s/sub", extract_dir);
    snprintf(extracted.nested_file, sizeof(extracted.nested_file), "%s/sub/nested.txt", extract_dir);
    snprintf(extracted.symlink_path, sizeof(extracted.symlink_path), "%s/link_to_nested", extract_dir);

    TEST_ASSERT_EQUAL(TAR_RESULT_OK,
                      extractor_tar_gzip_extract(fd, 0, (uint64_t)st.st_size, extract_dir, NULL));

    TEST_ASSERT_EQUAL(0, compare_file_contents(payload.file, extracted.file));
    TEST_ASSERT_EQUAL(0, compare_file_contents(payload.nested_file, extracted.nested_file));
    TEST_ASSERT_EQUAL(0, compare_symlink_target(extracted.symlink_path, "sub/nested.txt"));
    TEST_ASSERT_EQUAL(0, compare_mode(extracted.file, payload.file_mode));
    TEST_ASSERT_EQUAL(0, compare_mode(extracted.nested_file, payload.nested_mode));

    close(fd);
    unlink(archive_template);
    cleanup_payload(&payload);
    cleanup_extract_dir(&extracted);
}

static void test_packer_rejects_out_of_root_symlink(void)
{
    payload_paths_t payload = {0};
    create_payload_dir(&payload, "../outside");

    char archive_template[] = "/tmp/tgz_archive_badlinkXXXXXX";
    int archive_fd = mkstemp(archive_template);
    TEST_ASSERT_TRUE(archive_fd >= 0);
    ftruncate(archive_fd, 0);

    uint64_t archive_size = 0;
    packer_tar_gzip_result_t pack_rc =
        packer_tar_gzip_write(payload.dir, archive_fd, &archive_size, false, false);
    TEST_ASSERT_EQUAL(PACKER_TGZ_ERR_SYMLINK, pack_rc);

    close(archive_fd);
    unlink(archive_template);
    cleanup_payload(&payload);
}

static void test_packer_rejects_absolute_symlink_even_in_root(void)
{
    payload_paths_t payload = {0};
    /* Absolute target that still points inside the payload dir should be rejected at this stage */
    char abs_target[PATH_MAX * 2];
    snprintf(abs_target, sizeof(abs_target), "%s/sub/nested.txt", "/tmp"); /* placeholder; will overwrite below */

    create_payload_dir(&payload, "sub/nested.txt");
    /* Rewrite symlink to absolute path inside payload dir */
    unlink(payload.symlink_path);
    snprintf(abs_target, sizeof(abs_target), "%s/sub/nested.txt", payload.dir);
    TEST_ASSERT_EQUAL(0, symlink(abs_target, payload.symlink_path));

    char archive_template[] = "/tmp/tgz_archive_abslinkXXXXXX";
    int archive_fd = mkstemp(archive_template);
    TEST_ASSERT_TRUE(archive_fd >= 0);
    ftruncate(archive_fd, 0);

    uint64_t archive_size = 0;
    packer_tar_gzip_result_t pack_rc =
        packer_tar_gzip_write(payload.dir, archive_fd, &archive_size, false, false);
    TEST_ASSERT_EQUAL(PACKER_TGZ_ERR_SYMLINK, pack_rc);

    close(archive_fd);
    unlink(archive_template);
    cleanup_payload(&payload);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_packer_and_extractor_round_trip);
    RUN_TEST(test_packer_archive_extractable_with_system_tar);
    RUN_TEST(test_extractor_accepts_system_tar_archive);
    RUN_TEST(test_packer_rejects_out_of_root_symlink);
    RUN_TEST(test_packer_rejects_absolute_symlink_even_in_root);
    return UNITY_END();
}
