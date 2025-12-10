/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "unity.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "piadina/patchref.h"

static char *make_temp_path(void)
{
    char tmpl[] = "/tmp/patchrefXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd >= 0) {
        close(fd);
        unlink(tmpl);
        return strdup(tmpl);
    }
    return NULL;
}

static int write_fake_elf64(const char *path, const char *interp, size_t slot)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0700);
    if (fd < 0) {
        return -1;
    }

    Elf64_Ehdr eh = {0};
    memcpy(eh.e_ident, ELFMAG, SELFMAG);
    eh.e_ident[EI_CLASS] = ELFCLASS64;
    eh.e_ident[EI_DATA] = ELFDATA2LSB;
    eh.e_ident[EI_VERSION] = EV_CURRENT;
    eh.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    eh.e_type = ET_DYN;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_ehsize = sizeof(Elf64_Ehdr);
    eh.e_phoff = sizeof(Elf64_Ehdr);
    eh.e_phentsize = sizeof(Elf64_Phdr);
    eh.e_phnum = 1;
    eh.e_shoff = 0; /* no sections */

    Elf64_Phdr ph = {0};
    ph.p_type = PT_INTERP;
    ph.p_offset = 0x200;
    ph.p_vaddr = 0x400200;
    ph.p_paddr = ph.p_vaddr;
    ph.p_filesz = slot;
    ph.p_memsz = slot;
    ph.p_align = 1;

    size_t file_size = ph.p_offset + slot;
    unsigned char *buf = calloc(1, file_size);
    if (!buf) {
        close(fd);
        return -1;
    }
    memcpy(buf, &eh, sizeof(eh));
    memcpy(buf + eh.e_phoff, &ph, sizeof(ph));
    strncpy((char *)(buf + ph.p_offset), interp, slot);

    ssize_t w = write(fd, buf, file_size);
    free(buf);
    close(fd);
    return (w == (ssize_t)file_size) ? 0 : -1;
}

static void read_interp(const char *path, Elf64_Off off, size_t len, char *out)
{
    int fd = open(path, O_RDONLY);
    TEST_ASSERT_TRUE(fd >= 0);
    ssize_t n = pread(fd, out, len, off);
    close(fd);
    TEST_ASSERT_EQUAL_INT64((ssize_t)len, n);
    out[len - 1] = '\0';
}

static Elf64_Phdr read_phdr64(const char *path)
{
    Elf64_Phdr ph = {0};
    Elf64_Ehdr eh = {0};
    int fd = open(path, O_RDONLY);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT64((ssize_t)sizeof(eh), pread(fd, &eh, sizeof(eh), 0));
    TEST_ASSERT_EQUAL_INT64((ssize_t)sizeof(ph), pread(fd, &ph, sizeof(ph), eh.e_phoff));
    close(fd);
    return ph;
}

static void test_inplace_shorter(void)
{
    char *path = make_temp_path();
    TEST_ASSERT_NOT_NULL(path);

    const char *orig = "/lib64/ld-linux-x86-64.so.2";
    const char *newi = "/lib/ld.so";
    size_t slot = 64;
    TEST_ASSERT_EQUAL_INT(0, write_fake_elf64(path, orig, slot));

    patchref_result_t rc = patchref_set_interpreter(path, newi);
    TEST_ASSERT_EQUAL_INT(PATCHREF_OK, rc);

    char buf[64] = {0};
    read_interp(path, 0x200, slot, buf);
    TEST_ASSERT_EQUAL_STRING(newi, buf);

    unlink(path);
    free(path);
}

static void test_already_set_same_length(void)
{
    char *path = make_temp_path();
    TEST_ASSERT_NOT_NULL(path);

    const char *orig = "/lib64/ld-linux-x86-64.so.2";
    size_t slot = 64;
    TEST_ASSERT_EQUAL_INT(0, write_fake_elf64(path, orig, slot));

    patchref_result_t rc = patchref_set_interpreter(path, orig);
    TEST_ASSERT_EQUAL_INT(PATCHREF_ALREADY_SET, rc);

    char buf[64] = {0};
    read_interp(path, 0x200, slot, buf);
    TEST_ASSERT_EQUAL_STRING(orig, buf);

    unlink(path);
    free(path);
}

static void test_grow_longer(void)
{
    char *path = make_temp_path();
    TEST_ASSERT_NOT_NULL(path);

    const char *orig = "/ld.so";
    const char *longi = "/tmp/very/long/path/that/exceeds/the/original/interp/string/ld-linux-x86-64.so.2";
    size_t slot = 8; /* smaller than replacement */
    TEST_ASSERT_EQUAL_INT(0, write_fake_elf64(path, orig, slot));

    patchref_result_t rc = patchref_set_interpreter(path, longi);
    TEST_ASSERT_EQUAL_INT(PATCHREF_OK, rc);

    Elf64_Phdr ph = read_phdr64(path);
    /* New offset should be at previous file end (0x200 + slot) */
    TEST_ASSERT_EQUAL_UINT64(0x200 + slot, ph.p_offset);
    TEST_ASSERT_EQUAL_UINT64(strlen(longi) + 1, ph.p_filesz);
    char *buf = calloc(1, ph.p_filesz);
    TEST_ASSERT_NOT_NULL(buf);
    read_interp(path, ph.p_offset, ph.p_filesz, buf);
    TEST_ASSERT_EQUAL_STRING(longi, buf);
    free(buf);

    unlink(path);
    free(path);
}

void setUp(void) {}
void tearDown(void) {}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_inplace_shorter);
    RUN_TEST(test_already_set_same_length);
    RUN_TEST(test_grow_longer);
    return UNITY_END();
}
