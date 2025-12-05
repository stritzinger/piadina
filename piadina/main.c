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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "piadina_config.h"
#include "config.h"
#include "common/footer.h"
#include "common/log.h"
#include "common/platform.h"


/* Maximum path length for self exe path */
#define MAX_PATH_SIZE 4096


/**
 * Print version information.
 */
static void print_version(void)
{
    fprintf(stderr, "Piadina launcher v%s\n", PACKAGE_VERSION);
    fprintf(stderr, "Footer layout version: %d\n", PIADINA_FOOTER_LAYOUT_VERSION);
}


/**
 * Launch a child process and wait for it to complete.
 *
 * For milestone 5, this is a temporary implementation that launches a
 * hard-coded test command (/bin/echo) to validate the process launch
 * infrastructure. In later milestones, this will be replaced with the
 * real entry point from metadata.
 *
 * @param config    Parsed launcher configuration
 * @return Child exit code, or launcher error code on failure
 */
static int launch_test_process(const piadina_config_t *config)
{
    /*
     * For milestone 5, we use a hard-coded test entry point.
     * This validates the fork+execve infrastructure.
     */
    const char *entry_point = "/bin/echo";
    const char *test_args[] = {
        "echo",  /* argv[0] = basename of entry point */
        "Piadina: test process launched successfully!",
        NULL
    };

    log_debug("launching test process: %s", entry_point);

    pid_t pid = fork();

    if (pid < 0) {
        /* Fork failed */
        log_error("fork failed: %s", strerror(errno));
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    if (pid == 0) {
        /* Child process */
        
        /* Add application arguments if any */
        if (config->app_argc > 0) {
            log_debug("child: ignoring %d app args for test", config->app_argc);
        }

        /*
         * Execute the test program.
         * In later milestones, this will use the real entry point and
         * properly constructed argv/envp.
         */
        execv(entry_point, (char * const *)test_args);

        /* execv only returns on error */
        log_error("execv failed: %s", strerror(errno));
        _exit(PIADINA_EXIT_LAUNCH_ERROR);
    }

    /* Parent process - wait for child */
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

    /* Should not reach here under normal circumstances */
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
        /*
         * For a plain launcher binary without embedded payload,
         * we expect footer_read to fail (bad magic).
         * In milestone 5, we treat this as acceptable for testing
         * the process launch infrastructure.
         */
        if (config.action == CONFIG_ACTION_PRINT_FOOTER ||
            config.action == CONFIG_ACTION_PRINT_METADATA) {
            log_error("no valid footer found: %s",
                      footer_result_to_string(footer_result));
            result = PIADINA_EXIT_FOOTER_ERROR;
            goto cleanup;
        }

        log_warn("no valid footer found: %s (running in test mode)",
                 footer_result_to_string(footer_result));

        /*
         * For milestone 5 testing: proceed with test process launch
         * even without a valid footer. This allows testing the
         * launcher skeleton before Azdora produces real binaries.
         */
        result = launch_test_process(&config);
        goto cleanup;
    }

    log_info("footer read successfully (layout version %u)", footer.layout_version);

    /* Handle print-footer action */
    if (config.action == CONFIG_ACTION_PRINT_FOOTER) {
        fprintf(stderr, "Footer Information:\n");
        footer_print(&footer, stderr);
        result = PIADINA_EXIT_SUCCESS;
        goto cleanup;
    }

    /* Handle print-metadata action */
    if (config.action == CONFIG_ACTION_PRINT_METADATA) {
        /*
         * TODO: In milestone 8, implement metadata decoding and printing.
         * For now, just print basic info.
         */
        fprintf(stderr, "Metadata block at offset %lu, size %lu bytes\n",
                (unsigned long)footer.metadata_offset,
                (unsigned long)footer.metadata_size);
        fprintf(stderr, "(Full metadata decoding not yet implemented)\n");
        result = PIADINA_EXIT_SUCCESS;
        goto cleanup;
    }

    /*
     * Normal operation (CONFIG_ACTION_RUN):
     * In later milestones, this will:
     * 1. Decode metadata
     * 2. Resolve context (cache root, payload root, etc.)
     * 3. Extract payload if needed
     * 4. Launch the entry point
     *
     * For milestone 5, we launch a test process to validate the
     * process launch infrastructure.
     */
    result = launch_test_process(&config);

cleanup:
    if (fd >= 0) {
        close(fd);
    }
    config_destroy(&config);
    return result;
}
