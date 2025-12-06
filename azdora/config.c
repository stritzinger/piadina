/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file config.c
 * @brief Azdora packer CLI parsing implementation.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "piadina_config.h"

#define DEFAULT_OUTPUT_PATH "output.piadina"

static azdora_config_result_t add_meta_entry(azdora_config_t *config,
                                             const char *value,
                                             const char **error_msg);
static azdora_config_result_t set_option_value(char **target,
                                               const char *value,
                                               const char **error_msg);
static const char *next_arg_value(int index, int argc, char **argv, bool *consumed);
static bool has_prefix(const char *arg, const char *prefix);

void azdora_config_init(azdora_config_t *config)
{
    if (!config) {
        return;
    }
    config->action = AZDORA_ACTION_RUN;
    config->launcher_path = NULL;
    config->payload_dir = NULL;
    config->output_path = NULL;
    config->verbose = false;
    config->quiet = false;
    config->meta_count = 0;
    config->meta_entries = NULL;
}

void azdora_config_destroy(azdora_config_t *config)
{
    if (!config) {
        return;
    }
    free(config->launcher_path);
    free(config->payload_dir);
    free(config->output_path);
    if (config->meta_entries) {
        for (size_t i = 0; i < config->meta_count; ++i) {
            free(config->meta_entries[i]);
        }
        free(config->meta_entries);
    }
    azdora_config_init(config);
}

azdora_config_result_t azdora_config_parse_args(azdora_config_t *config,
                                                int argc,
                                                char **argv,
                                                const char **error_msg)
{
    if (!config || argc < 0 || (argc > 0 && !argv)) {
        if (error_msg) {
            *error_msg = "invalid arguments";
        }
        return AZDORA_CONFIG_ERR_INVALID_ARGUMENT;
    }

    for (int i = 1; i < argc; ++i) {
        char *arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            config->action = AZDORA_ACTION_HELP;
            continue;
        }
        if (strcmp(arg, "--version") == 0) {
            config->action = AZDORA_ACTION_VERSION;
            continue;
        }
        if (strcmp(arg, "--verbose") == 0 || strcmp(arg, "-v") == 0) {
            config->verbose = true;
            config->quiet = false;
            continue;
        }
        if (strcmp(arg, "--quiet") == 0 || strcmp(arg, "-q") == 0) {
            config->quiet = true;
            config->verbose = false;
            continue;
        }

        /* --launcher / -l */
        if (has_prefix(arg, "--launcher=") || strcmp(arg, "--launcher") == 0 || strcmp(arg, "-l") == 0) {
            bool consumed = false;
            const char *value = NULL;
            if (has_prefix(arg, "--launcher=")) {
                value = arg + strlen("--launcher=");
            } else {
                value = next_arg_value(i, argc, argv, &consumed);
                if (consumed) {
                    i++;
                }
            }
            if (!value || value[0] == '\0') {
                if (error_msg) {
                    *error_msg = "--launcher requires a value";
                }
                return AZDORA_CONFIG_ERR_MISSING_VALUE;
            }
            azdora_config_result_t rc = set_option_value(&config->launcher_path, value, error_msg);
            if (rc != AZDORA_CONFIG_OK) {
                return rc;
            }
            continue;
        }

        /* --payload / -p */
        if (has_prefix(arg, "--payload=") || strcmp(arg, "--payload") == 0 || strcmp(arg, "-p") == 0) {
            bool consumed = false;
            const char *value = NULL;
            if (has_prefix(arg, "--payload=")) {
                value = arg + strlen("--payload=");
            } else {
                value = next_arg_value(i, argc, argv, &consumed);
                if (consumed) {
                    i++;
                }
            }
            if (!value || value[0] == '\0') {
                if (error_msg) {
                    *error_msg = "--payload requires a value";
                }
                return AZDORA_CONFIG_ERR_MISSING_VALUE;
            }
            azdora_config_result_t rc = set_option_value(&config->payload_dir, value, error_msg);
            if (rc != AZDORA_CONFIG_OK) {
                return rc;
            }
            continue;
        }

        /* --output / -o */
        if (has_prefix(arg, "--output=") || strcmp(arg, "--output") == 0 || strcmp(arg, "-o") == 0) {
            bool consumed = false;
            const char *value = NULL;
            if (has_prefix(arg, "--output=")) {
                value = arg + strlen("--output=");
            } else {
                value = next_arg_value(i, argc, argv, &consumed);
                if (consumed) {
                    i++;
                }
            }
            if (!value || value[0] == '\0') {
                if (error_msg) {
                    *error_msg = "--output requires a value";
                }
                return AZDORA_CONFIG_ERR_MISSING_VALUE;
            }
            azdora_config_result_t rc = set_option_value(&config->output_path, value, error_msg);
            if (rc != AZDORA_CONFIG_OK) {
                return rc;
            }
            continue;
        }

        /* --meta / -m */
        if (has_prefix(arg, "--meta=") || strcmp(arg, "--meta") == 0 || strcmp(arg, "-m") == 0) {
            bool consumed = false;
            const char *value = NULL;
            if (has_prefix(arg, "--meta=")) {
                value = arg + strlen("--meta=");
            } else {
                value = next_arg_value(i, argc, argv, &consumed);
                if (consumed) {
                    i++;
                }
            }
            if (!value || value[0] == '\0') {
                if (error_msg) {
                    *error_msg = "--meta requires a PATH=VALUE entry";
                }
                return AZDORA_CONFIG_ERR_MISSING_VALUE;
            }
            azdora_config_result_t rc = add_meta_entry(config, value, error_msg);
            if (rc != AZDORA_CONFIG_OK) {
                return rc;
            }
            continue;
        }

        /* Unknown option */
        if (error_msg) {
            *error_msg = "unknown option";
        }
        return AZDORA_CONFIG_ERR_UNKNOWN_OPTION;
    }

    /* No arguments at all: allow and let main show help */
    if (argc <= 1 && config->action == AZDORA_ACTION_RUN) {
        return AZDORA_CONFIG_OK;
    }

    /* Skip required checks for help/version actions */
    if (config->action != AZDORA_ACTION_RUN) {
        return AZDORA_CONFIG_OK;
    }

    if (!config->launcher_path) {
        if (error_msg) {
            *error_msg = "missing required --launcher";
        }
        return AZDORA_CONFIG_ERR_MISSING_REQUIRED;
    }
    if (!config->payload_dir) {
        if (error_msg) {
            *error_msg = "missing required --payload";
        }
        return AZDORA_CONFIG_ERR_MISSING_REQUIRED;
    }
    if (!config->output_path) {
        azdora_config_result_t rc = set_option_value(&config->output_path,
                                                     DEFAULT_OUTPUT_PATH,
                                                     error_msg);
        if (rc != AZDORA_CONFIG_OK) {
            return rc;
        }
    }

    return AZDORA_CONFIG_OK;
}

const char *azdora_config_result_to_string(azdora_config_result_t result)
{
    switch (result) {
    case AZDORA_CONFIG_OK:
        return "ok";
    case AZDORA_CONFIG_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case AZDORA_CONFIG_ERR_UNKNOWN_OPTION:
        return "unknown option";
    case AZDORA_CONFIG_ERR_MISSING_VALUE:
        return "missing value";
    case AZDORA_CONFIG_ERR_OUT_OF_MEMORY:
        return "out of memory";
    case AZDORA_CONFIG_ERR_MISSING_REQUIRED:
        return "missing required option";
    default:
        return "unknown error";
    }
}

void azdora_config_print_help(const char *program_name)
{
    const char *name = program_name ? program_name : "azdora";
    const char *slash = strrchr(name, '/');
    if (slash) {
        name = slash + 1;
    }

    fprintf(stderr, "Usage: %s --launcher PATH --payload DIR [options]\n\n", name);
    fprintf(stderr, "Azdora packer v%s\n\n", PACKAGE_VERSION);
    fprintf(stderr, "Required options:\n");
    fprintf(stderr, "  -l, --launcher PATH      Path to launcher binary to embed\n");
    fprintf(stderr, "  -p, --payload DIR        Path to payload directory to pack\n\n");
    fprintf(stderr, "Optional options:\n");
    fprintf(stderr, "  -o, --output PATH        Output file (default: %s)\n", DEFAULT_OUTPUT_PATH);
    fprintf(stderr, "  -m, --meta PATH=VALUE    Metadata entry (repeatable)\n");
    fprintf(stderr, "                           Scalars: VALUE (string), u:NUM, b:true|false,\n");
    fprintf(stderr, "                                    hex:BYTES, b64:BYTES\n");
    fprintf(stderr, "                           Arrays:  KEY[]=VAL (append) or KEY[IDX]=VAL\n");
    fprintf(stderr, "                           Maps:    MAP.KEY=VAL (KEY must match [A-Za-z0-9_-]+)\n");
    fprintf(stderr, "  -v, --verbose            Trace packing steps and dump metadata/footer\n");
    fprintf(stderr, "  -q, --quiet              Suppress non-error output (also disables progress)\n");
    fprintf(stderr, "  -h, --help               Show this help message\n");
    fprintf(stderr, "      --version            Show version\n");
}

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

static azdora_config_result_t set_option_value(char **target,
                                               const char *value,
                                               const char **error_msg)
{
    char *dup = strdup(value);
    if (!dup) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return AZDORA_CONFIG_ERR_OUT_OF_MEMORY;
    }
    free(*target);
    *target = dup;
    return AZDORA_CONFIG_OK;
}

static azdora_config_result_t add_meta_entry(azdora_config_t *config,
                                             const char *value,
                                             const char **error_msg)
{
    char **new_entries = realloc(config->meta_entries,
                                 (config->meta_count + 1) * sizeof(char *));
    if (!new_entries) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return AZDORA_CONFIG_ERR_OUT_OF_MEMORY;
    }
    config->meta_entries = new_entries;
    config->meta_entries[config->meta_count] = strdup(value);
    if (!config->meta_entries[config->meta_count]) {
        if (error_msg) {
            *error_msg = "out of memory";
        }
        return AZDORA_CONFIG_ERR_OUT_OF_MEMORY;
    }
    config->meta_count += 1;
    return AZDORA_CONFIG_OK;
}

static const char *next_arg_value(int index, int argc, char **argv, bool *consumed)
{
    if (consumed) {
        *consumed = false;
    }
    if (index + 1 >= argc) {
        return NULL;
    }
    if (consumed) {
        *consumed = true;
    }
    return argv[index + 1];
}

static bool has_prefix(const char *arg, const char *prefix)
{
    size_t prefix_len = strlen(prefix);
    return arg && strncmp(arg, prefix, prefix_len) == 0;
}
