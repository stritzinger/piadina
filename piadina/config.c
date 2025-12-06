/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file config.c
 * @brief Piadina launcher configuration parsing implementation.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "piadina_config.h"
#include "common/log.h"


/* Environment variable names */
#define ENV_CACHE_ROOT      "PIADINA_CACHE_ROOT"
#define ENV_CLEANUP_POLICY  "PIADINA_CLEANUP_POLICY"
#define ENV_VALIDATE        "PIADINA_VALIDATE"
#define ENV_FORCE_EXTRACT   "PIADINA_FORCE_EXTRACT"
#define ENV_LOG_LEVEL       "PIADINA_LOG_LEVEL"

/* CLI option prefixes and names */
#define OPT_PREFIX          "--launcher-"
#define OPT_PREFIX_LEN      11


void config_init(piadina_config_t *config)
{
    if (!config) {
        return;
    }

    config->action = CONFIG_ACTION_RUN;
    config->cache_root = NULL;  /* NULL means use metadata default */
    config->cleanup_policy = metadata_core_cleanup_policy_default();
    config->log_level = LOG_LEVEL_WARN;
    config->validate = metadata_core_validate_default();
    config->force_extract = false;
    config->app_argc = 0;
    config->app_argv = NULL;
}


void config_destroy(piadina_config_t *config)
{
    if (!config) {
        return;
    }

    free(config->cache_root);
    config->cache_root = NULL;

    /* app_argv array is owned by us, but the strings it points to are not */
    free(config->app_argv);
    config->app_argv = NULL;
    config->app_argc = 0;
}


/**
 * Parse a boolean value from a string.
 * Returns 0 for false, 1 for true, -1 for invalid.
 */
static int parse_bool(const char *value)
{
    if (!value) {
        return -1;
    }

    if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
        strcmp(value, "yes") == 0) {
        return 1;
    }

    if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0 ||
        strcmp(value, "no") == 0) {
        return 0;
    }

    return -1;
}


/**
 * Check if an argument starts with --launcher- prefix.
 */
static bool is_launcher_option(const char *arg)
{
    return arg && strncmp(arg, OPT_PREFIX, OPT_PREFIX_LEN) == 0;
}


/**
 * Extract the option name after --launcher- prefix.
 * Returns pointer into the original string (no allocation).
 */
static const char *get_option_name(const char *arg)
{
    return arg + OPT_PREFIX_LEN;
}


/**
 * Find the value part of an --opt=value argument.
 * Returns NULL if no = found, pointer to value otherwise.
 */
static const char *find_option_value(const char *opt_name)
{
    const char *eq = strchr(opt_name, '=');
    return eq ? (eq + 1) : NULL;
}


/**
 * Get the length of the option name part (before = if present).
 */
static size_t option_name_length(const char *opt_name)
{
    const char *eq = strchr(opt_name, '=');
    return eq ? (size_t)(eq - opt_name) : strlen(opt_name);
}


/**
 * Check if option name matches a target (handling both --opt=val and --opt val).
 */
static bool option_matches(const char *opt_name, const char *target)
{
    size_t name_len = option_name_length(opt_name);
    size_t target_len = strlen(target);
    return (name_len == target_len) && (strncmp(opt_name, target, name_len) == 0);
}


/**
 * Helper to add an argument to the app_argv array.
 */
static config_result_t add_app_arg(piadina_config_t *config, char *arg,
                                   const char **error_msg)
{
    /* Grow the array if needed (we pre-allocate, so this shouldn't happen) */
    char **new_argv = realloc(config->app_argv,
                              (size_t)(config->app_argc + 1) * sizeof(char *));
    if (!new_argv) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return CONFIG_ERR_OUT_OF_MEMORY;
    }
    config->app_argv = new_argv;
    config->app_argv[config->app_argc++] = arg;
    return CONFIG_OK;
}


/**
 * Process a single launcher option.
 * Returns CONFIG_OK if processed, error code otherwise.
 * Sets *consumed_next to true if the next argv element was consumed as a value.
 */
static config_result_t process_launcher_option(piadina_config_t *config,
                                               const char *opt_name,
                                               int i, int argc, char **argv,
                                               bool *consumed_next,
                                               const char **error_msg)
{
    *consumed_next = false;
    const char *opt_value = find_option_value(opt_name);

    /* Handle options */
    if (option_matches(opt_name, "help")) {
        config->action = CONFIG_ACTION_HELP;
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "version")) {
        config->action = CONFIG_ACTION_VERSION;
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "print-footer")) {
        config->action = CONFIG_ACTION_PRINT_FOOTER;
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "print-metadata")) {
        config->action = CONFIG_ACTION_PRINT_METADATA;
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "verbose")) {
        config->log_level = LOG_LEVEL_DEBUG;
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "quiet")) {
        config->log_level = LOG_LEVEL_ERROR;
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "cache-root")) {
        if (!opt_value) {
            if (i + 1 < argc && !is_launcher_option(argv[i + 1])) {
                opt_value = argv[i + 1];
                *consumed_next = true;
            } else {
                if (error_msg) {
                    *error_msg = "--launcher-cache-root requires a value";
                }
                return CONFIG_ERR_MISSING_VALUE;
            }
        }
        free(config->cache_root);
        config->cache_root = strdup(opt_value);
        if (!config->cache_root) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return CONFIG_ERR_OUT_OF_MEMORY;
        }
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "cleanup")) {
        if (!opt_value) {
            if (i + 1 < argc && !is_launcher_option(argv[i + 1])) {
                opt_value = argv[i + 1];
                *consumed_next = true;
            } else {
                if (error_msg) {
                    *error_msg = "--launcher-cleanup requires a value";
                }
                return CONFIG_ERR_MISSING_VALUE;
            }
        }
        config->cleanup_policy = metadata_core_cleanup_policy_from_string(opt_value);
        if (config->cleanup_policy == METADATA_CLEANUP_INVALID) {
            if (error_msg) {
                *error_msg = "invalid cleanup policy (use: never, oncrash, always)";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "log-level")) {
        if (!opt_value) {
            if (i + 1 < argc && !is_launcher_option(argv[i + 1])) {
                opt_value = argv[i + 1];
                *consumed_next = true;
            } else {
                if (error_msg) {
                    *error_msg = "--launcher-log-level requires a value";
                }
                return CONFIG_ERR_MISSING_VALUE;
            }
        }
        config->log_level = log_level_from_string(opt_value);
        if (config->log_level == LOG_LEVEL_INVALID) {
            if (error_msg) {
                *error_msg = "invalid log level (use: debug, info, warn, error)";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "validate")) {
        const char *value = opt_value;

        if (!value) {
            if ((i + 1) < argc && !is_launcher_option(argv[i + 1])) {
                int parsed = parse_bool(argv[i + 1]);
                if (parsed >= 0) {
                    config->validate = (parsed == 1);
                    *consumed_next = true;
                    return CONFIG_OK;
                }
            }

            config->validate = true;
            return CONFIG_OK;
        }

        int parsed = parse_bool(value);
        if (parsed < 0) {
            if (error_msg) {
                *error_msg = "invalid validate value (use: true, false)";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        config->validate = (parsed == 1);
        return CONFIG_OK;
    }

    if (option_matches(opt_name, "force-extract")) {
        const char *value = opt_value;

        if (!value) {
            if ((i + 1) < argc && !is_launcher_option(argv[i + 1])) {
                int parsed = parse_bool(argv[i + 1]);
                if (parsed >= 0) {
                    config->force_extract = (parsed == 1);
                    *consumed_next = true;
                    return CONFIG_OK;
                }
            }

            config->force_extract = true;
            return CONFIG_OK;
        }

        int parsed = parse_bool(value);
        if (parsed < 0) {
            if (error_msg) {
                *error_msg = "invalid force-extract value (use: true, false)";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        config->force_extract = (parsed == 1);
        return CONFIG_OK;
    }

    /* Unknown --launcher- option */
    if (error_msg) {
        *error_msg = "unknown launcher option";
    }
    return CONFIG_ERR_UNKNOWN_OPTION;
}


config_result_t config_parse_args(piadina_config_t *config,
                                  int argc, char **argv,
                                  const char **error_msg)
{
    if (!config || argc < 0 || (argc > 0 && !argv)) {
        if (error_msg) {
            *error_msg = "invalid arguments";
        }
        return CONFIG_ERR_INVALID_ARGUMENT;
    }

    config_result_t result;
    bool after_separator = false;

    /* Skip argv[0] (program name) */
    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        /* After --, everything goes to the app */
        if (after_separator) {
            result = add_app_arg(config, arg, error_msg);
            if (result != CONFIG_OK) {
                return result;
            }
            continue;
        }

        /* Check for -- separator */
        if (strcmp(arg, "--") == 0) {
            after_separator = true;
            continue;
        }

        /* Check if this is a launcher option */
        if (is_launcher_option(arg)) {
            const char *opt_name = get_option_name(arg);
            bool consumed_next = false;

            result = process_launcher_option(config, opt_name, i, argc, argv,
                                             &consumed_next, error_msg);
            if (result != CONFIG_OK) {
                return result;
            }

            /* Skip next arg if it was consumed as a value */
            if (consumed_next) {
                i++;
            }

            /* Check for early exit actions */
            if (config->action != CONFIG_ACTION_RUN) {
                return CONFIG_OK;
            }
        } else {
            /* Non-launcher argument: pass through to the application */
            result = add_app_arg(config, arg, error_msg);
            if (result != CONFIG_OK) {
                return result;
            }
        }
    }

    return CONFIG_OK;
}


config_result_t config_apply_env(piadina_config_t *config,
                                 const char **error_msg)
{
    if (!config) {
        if (error_msg) {
            *error_msg = "invalid argument";
        }
        return CONFIG_ERR_INVALID_ARGUMENT;
    }

    const char *value;

    /* PIADINA_CACHE_ROOT */
    value = getenv(ENV_CACHE_ROOT);
    if (value && value[0] != '\0') {
        free(config->cache_root);
        config->cache_root = strdup(value);
        if (!config->cache_root) {
            if (error_msg) {
                *error_msg = "out of memory";
            }
            return CONFIG_ERR_OUT_OF_MEMORY;
        }
    }

    /* PIADINA_CLEANUP_POLICY */
    value = getenv(ENV_CLEANUP_POLICY);
    if (value && value[0] != '\0') {
        metadata_core_cleanup_policy_t policy = metadata_core_cleanup_policy_from_string(value);
        if (policy == METADATA_CLEANUP_INVALID) {
            if (error_msg) {
                *error_msg = "invalid PIADINA_CLEANUP_POLICY value";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        config->cleanup_policy = policy;
    }

    /* PIADINA_LOG_LEVEL */
    value = getenv(ENV_LOG_LEVEL);
    if (value && value[0] != '\0') {
        log_level_t level = log_level_from_string(value);
        if (level == LOG_LEVEL_INVALID) {
            if (error_msg) {
                *error_msg = "invalid PIADINA_LOG_LEVEL value";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        config->log_level = level;
    }

    /* PIADINA_VALIDATE */
    value = getenv(ENV_VALIDATE);
    if (value && value[0] != '\0') {
        int val = parse_bool(value);
        if (val < 0) {
            if (error_msg) {
                *error_msg = "invalid PIADINA_VALIDATE value";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        config->validate = (val == 1);
    }

    /* PIADINA_FORCE_EXTRACT */
    value = getenv(ENV_FORCE_EXTRACT);
    if (value && value[0] != '\0') {
        int val = parse_bool(value);
        if (val < 0) {
            if (error_msg) {
                *error_msg = "invalid PIADINA_FORCE_EXTRACT value";
            }
            return CONFIG_ERR_INVALID_VALUE;
        }
        config->force_extract = (val == 1);
    }

    return CONFIG_OK;
}


const char *config_result_to_string(config_result_t result)
{
    switch (result) {
        case CONFIG_OK:
            return "success";
        case CONFIG_ERR_INVALID_ARGUMENT:
            return "invalid argument";
        case CONFIG_ERR_UNKNOWN_OPTION:
            return "unknown option";
        case CONFIG_ERR_MISSING_VALUE:
            return "missing value";
        case CONFIG_ERR_INVALID_VALUE:
            return "invalid value";
        case CONFIG_ERR_OUT_OF_MEMORY:
            return "out of memory";
        default:
            return "unknown error";
    }
}


void config_print_help(const char *program_name)
{
    const char *name = program_name ? program_name : "piadina";
    
    /* Use basename (part after last '/') for cleaner output */
    const char *slash = strrchr(name, '/');
    if (slash) {
        name = slash + 1;
    }

    fprintf(stderr, "Usage: %s [options] [--] [more options]\n\n", name);
    fprintf(stderr, "Piadina Self-Extracting Launcher v%s\n\n", PACKAGE_VERSION);
    fprintf(stderr, "Launcher Options (consumed by launcher, not passed to app):\n");
    fprintf(stderr, "  --launcher-help              Show this help message and exit\n");
    fprintf(stderr, "  --launcher-version           Show version information and exit\n");
    fprintf(stderr, "  --launcher-print-footer      Print footer information and exit\n");
    fprintf(stderr, "  --launcher-print-metadata    Print embedded metadata and exit\n");
    fprintf(stderr, "  --launcher-cache-root=PATH   Override cache root directory\n");
    fprintf(stderr, "  --launcher-cleanup=POLICY    Set cleanup policy (never|oncrash|always)\n");
    fprintf(stderr, "  --launcher-log-level=LEVEL   Set log verbosity (debug|info|warn|error)\n");
    fprintf(stderr, "  --launcher-verbose           Shortcut for --launcher-log-level=debug\n");
    fprintf(stderr, "  --launcher-validate[=BOOL]   Validate cached payload against hash\n");
    fprintf(stderr, "  --launcher-force-extract[=BOOL]  Force fresh extraction\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Environment Variables:\n");
    fprintf(stderr, "  PIADINA_CACHE_ROOT           Same as --launcher-cache-root\n");
    fprintf(stderr, "  PIADINA_CLEANUP_POLICY       Same as --launcher-cleanup\n");
    fprintf(stderr, "  PIADINA_LOG_LEVEL            Same as --launcher-log-level\n");
    fprintf(stderr, "  PIADINA_VALIDATE             Same as --launcher-validate\n");
    fprintf(stderr, "  PIADINA_FORCE_EXTRACT        Same as --launcher-force-extract\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "All non-launcher arguments are passed to the embedded application.\n");
    fprintf(stderr, "Launcher options can be interspersed with application arguments.\n");
    fprintf(stderr, "Use -- to pass arguments that look like launcher options to the app.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Example: %s --foo --launcher-verbose --bar -- --launcher-help\n", name);
    fprintf(stderr, "  Passes --foo --bar --launcher-help to the application.\n");
}
