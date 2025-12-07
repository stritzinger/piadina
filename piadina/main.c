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
#include <ctype.h>
#include <inttypes.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
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
static bool path_is_dir(const char *path);
static int mkdir_p_local(const char *path);
static int ensure_parent_dir(const char *path);
static int remove_recursive(const char *path);
static int launch_payload(const piadina_context_t *ctx, const piadina_config_t *config);
static void log_launch_command(const piadina_context_t *ctx, char *const *argv, size_t argc);
static void log_launch_debug(const piadina_context_t *ctx, char *const *argv, size_t argc);

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
        const char *msg = error_msg ? error_msg : piadina_loader_result_to_string(load_rc);
        if (load_rc == PIADINA_LOADER_ERR_FOOTER) {
            log_error("no valid footer found: %s", msg);
            log_error("piadina is a launcher and must be used as part of a self-extracting binary.");
            log_error("use azdora to produce a self-extracting binary that embeds piadina and a payload.");
            result = PIADINA_EXIT_FOOTER_ERROR;
        } else {
            log_error("loader failed: %s", msg);
            result = (load_rc == PIADINA_LOADER_ERR_METADATA || load_rc == PIADINA_LOADER_ERR_OVERRIDES)
                         ? PIADINA_EXIT_METADATA_ERROR
                         : PIADINA_EXIT_FOOTER_ERROR;
        }
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

    /* Basic extraction/caching: reuse if present, otherwise extract via temp dir */
    bool payload_exists = path_is_dir(ctx.payload_root);
    if (payload_exists && !config.force_extract) {
        log_info("reusing existing payload at %s", ctx.payload_root);
    } else {
        if (config.force_extract && payload_exists) {
            log_info("force extracting payload; removing existing %s", ctx.payload_root);
            if (remove_recursive(ctx.payload_root) != 0) {
                log_error("failed to remove existing payload_root %s: %s",
                          ctx.payload_root, strerror(errno));
                result = PIADINA_EXIT_EXTRACTION_ERROR;
                goto cleanup;
            }
        }

        if (remove_recursive(ctx.temp_dir) != 0) {
            log_error("failed to clean temp dir %s: %s", ctx.temp_dir, strerror(errno));
            result = PIADINA_EXIT_EXTRACTION_ERROR;
            goto cleanup;
        }
        if (mkdir_p_local(ctx.temp_dir) != 0) {
            log_error("failed to create temp dir %s: %s", ctx.temp_dir, strerror(errno));
            result = PIADINA_EXIT_EXTRACTION_ERROR;
            goto cleanup;
        }

        load_rc = piadina_loader_extract(&loader,
                                         ctx.temp_dir,
                                         extract_dir,
                                         sizeof(extract_dir),
                                         &error_msg);
        if (load_rc != PIADINA_LOADER_OK) {
            log_error("extraction failed: %s",
                      error_msg ? error_msg : piadina_loader_result_to_string(load_rc));
            result = PIADINA_EXIT_EXTRACTION_ERROR;
            goto cleanup;
        }

        if (ensure_parent_dir(ctx.payload_root) != 0) {
            log_error("failed to create parent directories for %s: %s",
                      ctx.payload_root, strerror(errno));
            result = PIADINA_EXIT_EXTRACTION_ERROR;
            goto cleanup;
        }
        if (rename(ctx.temp_dir, ctx.payload_root) != 0) {
            log_error("failed to finalize payload move %s -> %s: %s",
                      ctx.temp_dir, ctx.payload_root, strerror(errno));
            result = PIADINA_EXIT_EXTRACTION_ERROR;
            goto cleanup;
        }
        log_info("payload ready at %s", ctx.payload_root);
    }

    result = launch_payload(&ctx, &config);

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

static bool path_is_dir(const char *path)
{
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int mkdir_p_local(const char *path)
{
    if (!path || !*path) {
        return -1;
    }
    char tmp[PLATFORM_PATH_MAX];
    if (strlen(path) >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int ensure_parent_dir(const char *path)
{
    if (!path) {
        return -1;
    }
    char tmp[PLATFORM_PATH_MAX];
    if (strlen(path) >= sizeof(tmp)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(tmp, path);
    char *slash = strrchr(tmp, '/');
    if (!slash) {
        return 0;
    }
    if (slash == tmp) {
        /* root-only path */
        return 0;
    }
    *slash = '\0';
    return mkdir_p_local(tmp);
}

static int remove_recursive(const char *path)
{
    if (!path || *path == '\0') {
        return -1;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        return (errno == ENOENT) ? 0 : -1;
    }

    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            return -1;
        }
        struct dirent *ent = NULL;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            char child[PLATFORM_PATH_MAX];
            int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            if (n < 0 || (size_t)n >= sizeof(child)) {
                closedir(dir);
                errno = ENAMETOOLONG;
                return -1;
            }
            if (remove_recursive(child) != 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
        if (rmdir(path) != 0) {
            return -1;
        }
        return 0;
    }

    return unlink(path);
}

static int launch_payload(const piadina_context_t *ctx, const piadina_config_t *config)
{
    if (!ctx || !config) {
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    /* ENTRY_POINT must remain under PAYLOAD_ROOT */
    size_t root_len = strlen(ctx->payload_root);
    if (strncmp(ctx->entry_path, ctx->payload_root, root_len) != 0 ||
        (ctx->entry_path[root_len] != '/' && ctx->entry_path[root_len] != '\0')) {
        log_error("ENTRY_POINT must be relative to PAYLOAD_ROOT");
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    size_t argc = 1 + ctx->entry_args_count + (size_t)config->app_argc + ctx->entry_args_post_count;
    char **argv = calloc(argc + 1, sizeof(char *));
    if (!argv) {
        log_error("out of memory building argv");
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    size_t idx = 0;
    argv[idx++] = ctx->entry_path;
    for (size_t i = 0; i < ctx->entry_args_count; ++i) {
        argv[idx++] = ctx->entry_args[i];
    }
    for (int i = 0; i < config->app_argc; ++i) {
        argv[idx++] = config->app_argv[i];
    }
    for (size_t i = 0; i < ctx->entry_args_post_count; ++i) {
        argv[idx++] = ctx->entry_args_post[i];
    }
    argv[idx] = NULL;

    log_launch_command(ctx, argv, argc);
    log_launch_debug(ctx, argv, argc);

    pid_t pid = fork();
    if (pid < 0) {
        log_error("fork failed: %s", strerror(errno));
        free(argv);
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    if (pid == 0) {
        for (size_t i = 0; i < ctx->env_count; ++i) {
            if (ctx->env[i].key && ctx->env[i].value) {
                setenv(ctx->env[i].key, ctx->env[i].value, 1);
            }
        }
        execv(ctx->entry_path, (char * const *)argv);
        log_error("execv failed: %s", strerror(errno));
        _exit(PIADINA_EXIT_LAUNCH_ERROR);
    }

    int status;
    pid_t waited_pid;
    do {
        waited_pid = waitpid(pid, &status, 0);
    } while (waited_pid < 0 && errno == EINTR);

    free(argv);

    if (waited_pid < 0) {
        log_error("waitpid failed: %s", strerror(errno));
        return PIADINA_EXIT_LAUNCH_ERROR;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        log_info("payload exited with code %d", exit_code);
        return exit_code;
    }

    if (WIFSIGNALED(status)) {
        int signum = WTERMSIG(status);
        log_info("payload terminated by signal %d", signum);
        return 128 + signum;
    }

    log_warn("unexpected payload termination status: 0x%x", status);
    return PIADINA_EXIT_LAUNCH_ERROR;
}

static void append_arg_quoted(char *buf, size_t buf_len, size_t *used, const char *arg)
{
    if (!buf || !arg || !used || *used >= buf_len) {
        return;
    }

    bool quote = false;
    for (const char *p = arg; *p; ++p) {
        if (isspace((unsigned char)*p) || *p == '"' || *p == '\'') {
            quote = true;
            break;
        }
    }

    if (quote && *used + 1 < buf_len) {
        buf[(*used)++] = '\'';
    }

    for (const char *p = arg; *p && *used + 1 < buf_len; ++p) {
        if (quote && *p == '\'') {
            if (*used + 2 < buf_len) {
                buf[(*used)++] = '\\';
                buf[(*used)++] = '\'';
            }
            continue;
        }
        buf[(*used)++] = *p;
    }

    if (quote && *used + 1 < buf_len) {
        buf[(*used)++] = '\'';
    }

    if (*used + 1 < buf_len) {
        buf[(*used)++] = ' ';
    }
    buf[*used] = '\0';
}

static void log_launch_command(const piadina_context_t *ctx, char *const *argv, size_t argc)
{
    (void)argv;
    char line[1024] = {0};
    size_t used = 0;

    if (log_get_level() > LOG_LEVEL_INFO || !ctx) {
        return;
    }

    const char *app_name = ctx->app_name ? ctx->app_name : "(unknown)";
    const char *app_ver = ctx->app_ver ? ctx->app_ver : "";
    if (app_ver[0] != '\0') {
        log_info("launching %s %s", app_name, app_ver);
    } else {
        log_info("launching %s", app_name);
    }

    append_arg_quoted(line, sizeof(line), &used, ctx->entry_point ? ctx->entry_point : ctx->entry_path);
    for (size_t i = 1; i < argc && used < sizeof(line) - 1; ++i) {
        append_arg_quoted(line, sizeof(line), &used, argv[i]);
    }
    if (used > 0 && line[used - 1] == ' ') {
        line[used - 1] = '\0';
    }
    log_info("exec %s", line);
}

static void log_launch_debug(const piadina_context_t *ctx, char *const *argv, size_t argc)
{
    if (log_get_level() != LOG_LEVEL_DEBUG || !ctx) {
        return;
    }

    log_debug("exec path: %s", ctx->entry_path);
    for (size_t i = 0; i < argc && argv; ++i) {
        log_debug("argv[%zu]: %s", i, argv[i]);
    }
    for (size_t i = 0; i < ctx->env_count; ++i) {
        if (ctx->env[i].key && ctx->env[i].value) {
            log_debug("env %s=%s", ctx->env[i].key, ctx->env[i].value);
        }
    }
}
