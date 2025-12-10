/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#include "patchref.h"

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static patchref_result_t set_interp32(int fd, const Elf32_Ehdr *ehdr, const char *interpreter);
static patchref_result_t set_interp64(int fd, const Elf64_Ehdr *ehdr, const char *interpreter);
static patchref_result_t grow_interp32(int fd,
                                       const Elf32_Ehdr *ehdr,
                                       Elf32_Phdr *phdr,
                                       Elf32_Half ph_index,
                                       const char *interpreter);
static patchref_result_t grow_interp64(int fd,
                                       const Elf64_Ehdr *ehdr,
                                       Elf64_Phdr *phdr,
                                       Elf64_Half ph_index,
                                       const char *interpreter);

static bool is_supported_type(uint16_t type)
{
    return type == ET_EXEC || type == ET_DYN;
}

patchref_result_t patchref_set_interpreter(const char *path, const char *interpreter)
{
    if (!path || !interpreter || interpreter[0] == '\0') {
        return PATCHREF_ERR_INVALID_ARGUMENT;
    }

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return PATCHREF_ERR_IO;
    }

    unsigned char ident[EI_NIDENT] = {0};
    ssize_t n = pread(fd, ident, sizeof(ident), 0);
    if (n != (ssize_t)sizeof(ident) || memcmp(ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return PATCHREF_ERR_NOT_ELF;
    }

    patchref_result_t rc = PATCHREF_ERR_UNSUPPORTED_CLASS;
    if (ident[EI_CLASS] == ELFCLASS32) {
        Elf32_Ehdr ehdr32;
        if (pread(fd, &ehdr32, sizeof(ehdr32), 0) != (ssize_t)sizeof(ehdr32)) {
            rc = PATCHREF_ERR_IO;
        } else if (!is_supported_type(ehdr32.e_type)) {
            rc = PATCHREF_ERR_UNSUPPORTED_TYPE;
        } else {
            rc = set_interp32(fd, &ehdr32, interpreter);
        }
    } else if (ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr ehdr64;
        if (pread(fd, &ehdr64, sizeof(ehdr64), 0) != (ssize_t)sizeof(ehdr64)) {
            rc = PATCHREF_ERR_IO;
        } else if (!is_supported_type(ehdr64.e_type)) {
            rc = PATCHREF_ERR_UNSUPPORTED_TYPE;
        } else {
            rc = set_interp64(fd, &ehdr64, interpreter);
        }
    }

    close(fd);
    return rc;
}

const char *patchref_result_to_string(patchref_result_t rc)
{
    switch (rc) {
    case PATCHREF_OK:
        return "ok";
    case PATCHREF_ALREADY_SET:
        return "interpreter already set";
    case PATCHREF_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case PATCHREF_ERR_NOT_ELF:
        return "not an ELF binary";
    case PATCHREF_ERR_UNSUPPORTED_CLASS:
        return "unsupported ELF class";
    case PATCHREF_ERR_UNSUPPORTED_TYPE:
        return "unsupported ELF type";
    case PATCHREF_ERR_NO_INTERP:
        return "no PT_INTERP segment";
    case PATCHREF_ERR_TOO_LONG:
        return ".interp section too small for requested interpreter";
    case PATCHREF_ERR_IO:
    default:
        return "i/o error";
    }
}

static patchref_result_t write_interpreter(int fd,
                                           off_t offset,
                                           size_t slot_size,
                                           const char *interpreter,
                                           const char *current,
                                           size_t current_len)
{
    size_t new_len = strlen(interpreter);
    if (new_len + 1 > slot_size) {
        return PATCHREF_ERR_TOO_LONG;
    }

    if (current && current_len > 0 && new_len == current_len &&
        strncmp(interpreter, current, new_len) == 0) {
        return PATCHREF_ALREADY_SET;
    }

    char *buf = calloc(slot_size, 1);
    if (!buf) {
        return PATCHREF_ERR_IO;
    }
    memcpy(buf, interpreter, new_len);
    ssize_t w = pwrite(fd, buf, slot_size, offset);
    free(buf);
    if (w != (ssize_t)slot_size) {
        return PATCHREF_ERR_IO;
    }
    return PATCHREF_OK;
}

static patchref_result_t set_interp32(int fd, const Elf32_Ehdr *ehdr, const char *interpreter)
{
    Elf32_Half phnum = ehdr->e_phnum;
    Elf32_Off phoff = ehdr->e_phoff;
    Elf32_Half phentsize = ehdr->e_phentsize;
    if (phentsize != sizeof(Elf32_Phdr) || phnum == 0) {
        return PATCHREF_ERR_NO_INTERP;
    }

    Elf32_Phdr phdr = {0};
    for (Elf32_Half i = 0; i < phnum; ++i) {
        off_t pos = (off_t)phoff + (off_t)i * phentsize;
        if (pread(fd, &phdr, sizeof(phdr), pos) != (ssize_t)sizeof(phdr)) {
            return PATCHREF_ERR_IO;
        }
        if (phdr.p_type != PT_INTERP) {
            continue;
        }
        if (phdr.p_filesz == 0) {
            return PATCHREF_ERR_NO_INTERP;
        }
        char *current = calloc(phdr.p_filesz + 1, 1);
        if (!current) {
            return PATCHREF_ERR_IO;
        }
        if (pread(fd, current, phdr.p_filesz, phdr.p_offset) != (ssize_t)phdr.p_filesz) {
            free(current);
            return PATCHREF_ERR_IO;
        }
        size_t cur_len = strnlen(current, phdr.p_filesz);
        patchref_result_t rc;
        size_t new_len = strlen(interpreter);
        if (new_len + 1 <= (size_t)phdr.p_filesz) {
            rc = write_interpreter(fd, phdr.p_offset, (size_t)phdr.p_filesz, interpreter, current, cur_len);
        } else {
            rc = grow_interp32(fd, ehdr, &phdr, i, interpreter);
        }
        free(current);
        return rc;
    }
    return PATCHREF_ERR_NO_INTERP;
}

static patchref_result_t set_interp64(int fd, const Elf64_Ehdr *ehdr, const char *interpreter)
{
    Elf64_Half phnum = ehdr->e_phnum;
    Elf64_Off phoff = ehdr->e_phoff;
    Elf64_Half phentsize = ehdr->e_phentsize;
    if (phentsize != sizeof(Elf64_Phdr) || phnum == 0) {
        return PATCHREF_ERR_NO_INTERP;
    }

    Elf64_Phdr phdr = {0};
    for (Elf64_Half i = 0; i < phnum; ++i) {
        off_t pos = (off_t)phoff + (off_t)i * phentsize;
        if (pread(fd, &phdr, sizeof(phdr), pos) != (ssize_t)sizeof(phdr)) {
            return PATCHREF_ERR_IO;
        }
        if (phdr.p_type != PT_INTERP) {
            continue;
        }
        if (phdr.p_filesz == 0) {
            return PATCHREF_ERR_NO_INTERP;
        }
        char *current = calloc(phdr.p_filesz + 1, 1);
        if (!current) {
            return PATCHREF_ERR_IO;
        }
        if (pread(fd, current, phdr.p_filesz, phdr.p_offset) != (ssize_t)phdr.p_filesz) {
            free(current);
            return PATCHREF_ERR_IO;
        }
        size_t cur_len = strnlen(current, phdr.p_filesz);
        patchref_result_t rc;
        size_t new_len = strlen(interpreter);
        if (new_len + 1 <= (size_t)phdr.p_filesz) {
            rc = write_interpreter(fd, phdr.p_offset, (size_t)phdr.p_filesz, interpreter, current, cur_len);
        } else {
            rc = grow_interp64(fd, ehdr, &phdr, i, interpreter);
        }
        free(current);
        return rc;
    }
    return PATCHREF_ERR_NO_INTERP;
}

static patchref_result_t grow_interp32(int fd,
                                       const Elf32_Ehdr *ehdr,
                                       Elf32_Phdr *phdr,
                                       Elf32_Half ph_index,
                                       const char *interpreter)
{
    size_t new_len = strlen(interpreter) + 1;
    off_t file_end = lseek(fd, 0, SEEK_END);
    if (file_end < 0) {
        return PATCHREF_ERR_IO;
    }

    /* Append new interpreter */
    if (pwrite(fd, interpreter, new_len, file_end) != (ssize_t)new_len) {
        return PATCHREF_ERR_IO;
    }

    Elf32_Addr delta = phdr->p_vaddr - phdr->p_offset;
    phdr->p_offset = (Elf32_Off)file_end;
    phdr->p_vaddr = phdr->p_paddr = phdr->p_offset + delta;
    phdr->p_filesz = phdr->p_memsz = (Elf32_Word)new_len;
    if (phdr->p_align == 0) {
        phdr->p_align = 1;
    }

    off_t ph_pos = (off_t)ehdr->e_phoff + (off_t)ph_index * ehdr->e_phentsize;
    if (pwrite(fd, phdr, sizeof(*phdr), ph_pos) != (ssize_t)sizeof(*phdr)) {
        return PATCHREF_ERR_IO;
    }

    /* Update section header for .interp if present */
    if (ehdr->e_shoff != 0 && ehdr->e_shentsize == sizeof(Elf32_Shdr) && ehdr->e_shnum > 0) {
        Elf32_Shdr shstr;
        off_t shstr_off = (off_t)ehdr->e_shoff + (off_t)ehdr->e_shstrndx * ehdr->e_shentsize;
        if (pread(fd, &shstr, sizeof(shstr), shstr_off) == (ssize_t)sizeof(shstr)) {
            char *strtab = malloc(shstr.sh_size);
            if (strtab && pread(fd, strtab, shstr.sh_size, shstr.sh_offset) == (ssize_t)shstr.sh_size) {
                for (Elf32_Half i = 0; i < ehdr->e_shnum; ++i) {
                    Elf32_Shdr sh;
                    off_t s_off = (off_t)ehdr->e_shoff + (off_t)i * ehdr->e_shentsize;
                    if (pread(fd, &sh, sizeof(sh), s_off) != (ssize_t)sizeof(sh)) {
                        continue;
                    }
                    const char *name = sh.sh_name < shstr.sh_size ? (strtab + sh.sh_name) : NULL;
                    if (name && strcmp(name, ".interp") == 0) {
                        Elf32_Addr delta_sec = sh.sh_addr - sh.sh_offset;
                        sh.sh_offset = (Elf32_Off)file_end;
                        sh.sh_addr = sh.sh_offset + delta_sec;
                        sh.sh_size = (Elf32_Word)new_len;
                        if (sh.sh_addralign == 0) {
                            sh.sh_addralign = 1;
                        }
                        (void)pwrite(fd, &sh, sizeof(sh), s_off);
                        break;
                    }
                }
            }
            free(strtab);
        }
    }

    return PATCHREF_OK;
}

static patchref_result_t grow_interp64(int fd,
                                       const Elf64_Ehdr *ehdr,
                                       Elf64_Phdr *phdr,
                                       Elf64_Half ph_index,
                                       const char *interpreter)
{
    size_t new_len = strlen(interpreter) + 1;
    off_t file_end = lseek(fd, 0, SEEK_END);
    if (file_end < 0) {
        return PATCHREF_ERR_IO;
    }

    /* Append new interpreter */
    if (pwrite(fd, interpreter, new_len, file_end) != (ssize_t)new_len) {
        return PATCHREF_ERR_IO;
    }

    Elf64_Addr delta = phdr->p_vaddr - phdr->p_offset;
    phdr->p_offset = (Elf64_Off)file_end;
    phdr->p_vaddr = phdr->p_paddr = phdr->p_offset + delta;
    phdr->p_filesz = phdr->p_memsz = (Elf64_Xword)new_len;
    if (phdr->p_align == 0) {
        phdr->p_align = 1;
    }

    off_t ph_pos = (off_t)ehdr->e_phoff + (off_t)ph_index * ehdr->e_phentsize;
    if (pwrite(fd, phdr, sizeof(*phdr), ph_pos) != (ssize_t)sizeof(*phdr)) {
        return PATCHREF_ERR_IO;
    }

    /* Update section header for .interp if present */
    if (ehdr->e_shoff != 0 && ehdr->e_shentsize == sizeof(Elf64_Shdr) && ehdr->e_shnum > 0) {
        Elf64_Shdr shstr;
        off_t shstr_off = (off_t)ehdr->e_shoff + (off_t)ehdr->e_shstrndx * ehdr->e_shentsize;
        if (pread(fd, &shstr, sizeof(shstr), shstr_off) == (ssize_t)sizeof(shstr)) {
            char *strtab = malloc(shstr.sh_size);
            if (strtab && pread(fd, strtab, shstr.sh_size, shstr.sh_offset) == (ssize_t)shstr.sh_size) {
                for (Elf64_Half i = 0; i < ehdr->e_shnum; ++i) {
                    Elf64_Shdr sh;
                    off_t s_off = (off_t)ehdr->e_shoff + (off_t)i * ehdr->e_shentsize;
                    if (pread(fd, &sh, sizeof(sh), s_off) != (ssize_t)sizeof(sh)) {
                        continue;
                    }
                    const char *name = sh.sh_name < shstr.sh_size ? (strtab + sh.sh_name) : NULL;
                    if (name && strcmp(name, ".interp") == 0) {
                        Elf64_Addr delta_sec = sh.sh_addr - sh.sh_offset;
                        sh.sh_offset = (Elf64_Off)file_end;
                        sh.sh_addr = sh.sh_offset + delta_sec;
                        sh.sh_size = (Elf64_Xword)new_len;
                        if (sh.sh_addralign == 0) {
                            sh.sh_addralign = 1;
                        }
                        (void)pwrite(fd, &sh, sizeof(sh), s_off);
                        break;
                    }
                }
            }
            free(strtab);
        }
    }

    return PATCHREF_OK;
}
