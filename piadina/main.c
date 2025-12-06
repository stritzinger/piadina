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
#include <stdbool.h>
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
#include "metadata.h"
#include "context.h"
#include "loader.h"

/* Internal Prototypes */

static void print_version(void);
static int launch_test_process(const piadina_config_t *config);

/* Exported Functions */

int main(int argc, char **argv)
{
    int result = PIADINA_EXIT_SUCCESS;
    piadina_config_t config;
    const char *error_msg = NULL;
    config_result_t cfg_result;
    char extract_dir[PLATFORM_PATH_MAX] = {0};
    piadina_loader_t loader;

    /* Initialize configuration with defaults */
    config_init(&config);
    piadina_loader_init(&loader);

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

    /* Load footer/metadata via loader */
    piadina_loader_result_t load_rc = piadina_loader_load(&config, &loader, &error_msg);
    if (load_rc != PIADINA_LOADER_OK) {
        if (load_rc == PIADINA_LOADER_ERR_FOOTER &&
            config.action != CONFIG_ACTION_PRINT_FOOTER &&
            config.action != CONFIG_ACTION_PRINT_METADATA) {
            log_warn("no valid footer found: %s (running in test mode)",
                     error_msg ? error_msg : piadina_loader_result_to_string(load_rc));
            result = launch_test_process(&config);
            goto cleanup;
        }

        log_error("loader failed: %s",
                  error_msg ? error_msg : piadina_loader_result_to_string(load_rc));
        result = (load_rc == PIADINA_LOADER_ERR_METADATA || load_rc == PIADINA_LOADER_ERR_OVERRIDES)
                     ? PIADINA_EXIT_METADATA_ERROR
                     : PIADINA_EXIT_FOOTER_ERROR;
        goto cleanup;
    }

    /* Handle print-footer action (no metadata needed) */
    if (config.action == CONFIG_ACTION_PRINT_FOOTER) {
        fprintf(stderr, "footer:\n");
        footer_print(&loader.footer, stderr);
        result = PIADINA_EXIT_SUCCESS;
        goto cleanup;
    }

    /* Handle print-metadata action */
    if (config.action == CONFIG_ACTION_PRINT_METADATA) {
        piadina_metadata_print(&loader.metadata, stderr);
        result = PIADINA_EXIT_SUCCESS;
        goto cleanup;
    }

    /* Resolve runtime context */
    log_info("resolving context");
    piadina_context_t ctx;
    bool ctx_initialized = false;
    piadina_context_init(&ctx);
    piadina_context_result_t ctx_rc =
        piadina_context_resolve(&loader.metadata, &ctx, &error_msg);
    if (ctx_rc != PIADINA_CONTEXT_OK) {
        log_error("context resolution failed: %s",
                  error_msg ? error_msg : piadina_context_result_to_string(ctx_rc));
        result = PIADINA_EXIT_METADATA_ERROR;
        goto cleanup;
    }
    ctx_initialized = true;
    if (log_get_level() == LOG_LEVEL_DEBUG) {
        piadina_context_print(&ctx, stderr);
    }

    /*
     * Normal operation (CONFIG_ACTION_RUN):
     * Milestone 7: extract the embedded tar+gzip archive to a temp directory.
     * Milestone 8+: resolve context and launch.
     */
    load_rc = piadina_loader_extract(&loader,
                                     ctx.payload_root,
                                     extract_dir,
                                     sizeof(extract_dir),
                                     &error_msg);
    if (load_rc != PIADINA_LOADER_OK) {
        log_error("extraction failed: %s",
                  error_msg ? error_msg : piadina_loader_result_to_string(load_rc));
        result = PIADINA_EXIT_EXTRACTION_ERROR;
        goto cleanup;
    }

cleanup:
    if (ctx_initialized) {
        piadina_context_destroy(&ctx);
    }
    piadina_loader_destroy(&loader);
    config_destroy(&config);
    return result;
}

/* Internal Functions */

static void print_version(void)
{
    fprintf(stderr, "Piadina launcher v%s\n", PACKAGE_VERSION);
    fprintf(stderr, "Footer layout version: %d\n", PIADINA_FOOTER_LAYOUT_VERSION);
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
