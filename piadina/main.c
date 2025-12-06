/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file main.c
 * @brief Piadina launcher entry point.
 *
 * This is the main entry point for the Piadina self-extracting launcher.
 * It orchestrates configuration parsing, footer/metadata reading,
 * extraction, and process launching.
 */
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "piadina_config.h"
#include "config.h"
#include "archive.h"
#include "common/footer.h"
#include "common/log.h"
#include "common/platform.h"


/* Maximum path length for self exe path */
#define MAX_PATH_SIZE 4096

static int launch_test_process(const piadina_config_t *config);
static int extract_archive_from_footer(int fd,
                                       const piadina_footer_t *footer,
                                       char *out_dir,
                                       size_t out_dir_len);
static void debug_log_metadata(int fd, const piadina_footer_t *footer);

/**
 * Print version information.
 */
static void print_version(void)
{
    fprintf(stderr, "Piadina launcher v%s\n", PACKAGE_VERSION);
    fprintf(stderr, "Footer layout version: %d\n", PIADINA_FOOTER_LAYOUT_VERSION);
}

static void debug_log_metadata(int fd, const piadina_footer_t *footer)
{
    if (!footer || footer->metadata_size == 0) {
        return;
    }

    uint8_t buf[256];
    off_t rc = lseek(fd, (off_t)footer->metadata_offset, SEEK_SET);
    if (rc < 0) {
        log_debug("metadata: seek failed for debug dump");
        return;
    }

    size_t dump_len = footer->metadata_size < sizeof(buf) ? (size_t)footer->metadata_size : sizeof(buf);
    ssize_t n = read(fd, buf, dump_len);
    if (n <= 0) {
        log_debug("metadata: read failed for debug dump");
        return;
    }

    log_debug("metadata: size=%" PRIu64 " bytes, showing first %zd bytes",
              footer->metadata_size, n);
    char line[3 * 16 + 1];
    size_t offset = 0;
    while (offset < (size_t)n) {
        size_t chunk = ((size_t)n - offset) < 16 ? ((size_t)n - offset) : 16;
        char *p = line;
        for (size_t i = 0; i < chunk; ++i) {
            p += sprintf(p, "%02x ", buf[offset + i]);
        }
        *p = '\0';
        log_debug("  %04zx: %s", offset, line);
        offset += chunk;
    }
}


static int extract_archive_from_footer(int fd,
                                       const piadina_footer_t *footer,
                                       char *out_dir,
                                       size_t out_dir_len)
{
    if (!footer || footer->archive_size == 0) {
        log_error("no archive payload present");
        return PIADINA_EXIT_EXTRACTION_ERROR;
    }

    if (out_dir_len < sizeof("/tmp/piadina_payload_XXXXXX")) {
        log_error("extraction path buffer too small");
        return PIADINA_EXIT_EXTRACTION_ERROR;
    }

    char tmpl[] = "/tmp/piadina_payload_XXXXXX";
    char *dir = mkdtemp(tmpl);
    if (!dir) {
        log_error("failed to create extraction directory: %s", strerror(errno));
        return PIADINA_EXIT_EXTRACTION_ERROR;
    }

    snprintf(out_dir, out_dir_len, "%s", dir);
    log_info("extracting archive to %s (offset=%" PRIu64 ", size=%" PRIu64 ")",
             out_dir, footer->archive_offset, footer->archive_size);

    piadina_archive_result_t arc_rc = piadina_archive_extract("tar+gzip",
                                                              fd,
                                                              footer->archive_offset,
                                                              footer->archive_size,
                                                              out_dir);
    if (arc_rc != PIADINA_ARCHIVE_OK) {
        log_error("archive extraction failed: %s",
                  piadina_archive_result_to_string(arc_rc));
        return PIADINA_EXIT_EXTRACTION_ERROR;
    }

    log_info("extraction completed");
    return PIADINA_EXIT_SUCCESS;
}

/**
 * Launch a child process and wait for it to complete.
 *
 * For milestone 5/7 test mode, this launches a hard-coded /bin/echo to
 * validate process launch infrastructure when no payload/footer exists.
 */
static int launch_test_process(const piadina_config_t *config)
{
    const char *entry_point = "/bin/echo";
    const char *test_args[] = {
        "echo",
        "Piadina: test process launched successfully!",
        NULL
    };

    log_debug("launching test process: %s", entry_point);

    pid_t pid = fork();
    if (pid < 0) {
        log_error("fork failed: %s", strerror(errno));
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    if (pid == 0) {
        if (config->app_argc > 0) {
            log_debug("child: ignoring %d app args for test", config->app_argc);
        }
        execv(entry_point, (char * const *)test_args);
        log_error("execv failed: %s", strerror(errno));
        _exit(PIADINA_EXIT_LAUNCH_ERROR);
    }

    int status;
    pid_t waited_pid;
    do {
        waited_pid = waitpid(pid, &status, 0);
    } while (waited_pid < 0 && errno == EINTR);

    if (waited_pid < 0) {
        log_error("waitpid failed: %s", strerror(errno));
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        log_debug("child exited with code %d", exit_code);
        return exit_code;
    }

    if (WIFSIGNALED(status)) {
        int signum = WTERMSIG(status);
        log_info("child terminated by signal %d", signum);
        return 128 + signum;
    }

    log_warn("unexpected child termination status: 0x%x", status);
    return PIADINA_EXIT_LAUNCH_ERROR;
}


int main(int argc, char **argv)
{
    int result = PIADINA_EXIT_SUCCESS;
    piadina_config_t config;
    char self_path[MAX_PATH_SIZE];
    piadina_footer_t footer;
    int fd = -1;
    const char *error_msg = NULL;
    config_result_t cfg_result;
    char extract_dir[MAX_PATH_SIZE] = {0};

    /* Initialize configuration with defaults */
    config_init(&config);

    /* Apply environment variable overrides */
    cfg_result = config_apply_env(&config, &error_msg);
    if (cfg_result != CONFIG_OK) {
        log_error("%s", error_msg ? error_msg : config_result_to_string(cfg_result));
        config_print_help(argv[0]);
        result = PIADINA_EXIT_USAGE_ERROR;
        goto cleanup;
    }

    /* Parse command-line arguments (overrides environment) */
    cfg_result = config_parse_args(&config, argc, argv, &error_msg);
    if (cfg_result != CONFIG_OK) {
        log_error("%s", error_msg ? error_msg : config_result_to_string(cfg_result));
        config_print_help(argv[0]);
        result = PIADINA_EXIT_USAGE_ERROR;
        goto cleanup;
    }

    /* Set log level based on configuration */
    log_set_level(config.log_level);

    /* Handle special actions */
    switch (config.action) {
        case CONFIG_ACTION_HELP:
            config_print_help(argv[0]);
            result = PIADINA_EXIT_SUCCESS;
            goto cleanup;

        case CONFIG_ACTION_VERSION:
            print_version();
            result = PIADINA_EXIT_SUCCESS;
            goto cleanup;

        case CONFIG_ACTION_PRINT_FOOTER:
        case CONFIG_ACTION_PRINT_METADATA:
        case CONFIG_ACTION_RUN:
            /* Continue with normal processing */
            break;
    }

    /* Resolve path to our own executable */
    platform_result_t plat_result = platform_get_self_exe_path(self_path, sizeof(self_path));
    if (plat_result != PLATFORM_OK) {
        log_error("failed to resolve self executable path");
        result = PIADINA_EXIT_FOOTER_ERROR;
        goto cleanup;
    }

    log_debug("self path: %s", self_path);

    /* Open the launcher binary for reading */
    fd = open(self_path, O_RDONLY);
    if (fd < 0) {
        log_error("failed to open self: %s", strerror(errno));
        result = PIADINA_EXIT_FOOTER_ERROR;
        goto cleanup;
    }

    /* Read and validate footer */
    footer_result_t footer_result = footer_read(fd, &footer);
    if (footer_result != FOOTER_OK) {
        if (config.action == CONFIG_ACTION_PRINT_FOOTER ||
            config.action == CONFIG_ACTION_PRINT_METADATA) {
            log_error("no valid footer found: %s",
                      footer_result_to_string(footer_result));
            result = PIADINA_EXIT_FOOTER_ERROR;
            goto cleanup;
        }

        log_warn("no valid footer found: %s (running in test mode)",
                 footer_result_to_string(footer_result));
        result = launch_test_process(&config);
        goto cleanup;
    }

    if (log_get_level() == LOG_LEVEL_DEBUG) {
        log_debug("footer:");
        footer_print(&footer, stderr);
        debug_log_metadata(fd, &footer);
    }

    /* Handle print-footer action */
    if (config.action == CONFIG_ACTION_PRINT_FOOTER) {
        fprintf(stderr, "Footer Information:\n");
        footer_print(&footer, stderr);
        result = PIADINA_EXIT_SUCCESS;
        goto cleanup;
    }

    /* Handle print-metadata action */
    if (config.action == CONFIG_ACTION_PRINT_METADATA) {
        fprintf(stderr, "Metadata block at offset %lu, size %lu bytes\n",
                (unsigned long)footer.metadata_offset,
                (unsigned long)footer.metadata_size);
        debug_log_metadata(fd, &footer);
        fprintf(stderr, "(Full metadata decoding not yet implemented)\n");
        result = PIADINA_EXIT_SUCCESS;
        goto cleanup;
    }

    /*
     * Normal operation (CONFIG_ACTION_RUN):
     * Milestone 7: extract the embedded tar+gzip archive to a temp directory.
     * Future milestones will decode metadata, resolve context, and launch.
     */
    result = extract_archive_from_footer(fd, &footer, extract_dir, sizeof(extract_dir));

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    config_destroy(&config);
    return result;
}
