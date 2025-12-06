/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file config.h
 * @brief Piadina launcher configuration parsing.
 *
 * This module parses launcher CLI arguments and environment variables into
 * a configuration struct, applying precedence rules: CLI > env > defaults.
 */
#ifndef PIADINA_CONFIG_H
#define PIADINA_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#include "common/log.h"
#include "common/metadata_core.h"


/**
 * @brief Piadina launcher exit codes.
 * Codes 111-119 are reserved for launcher internal errors.
 */
typedef enum {
    PIADINA_EXIT_SUCCESS = 0,
    PIADINA_EXIT_USAGE_ERROR = 111,
    PIADINA_EXIT_FOOTER_ERROR = 112,
    PIADINA_EXIT_METADATA_ERROR = 113,
    PIADINA_EXIT_EXTRACTION_ERROR = 114,
    PIADINA_EXIT_LAUNCH_ERROR = 115,
    PIADINA_EXIT_SIGNAL_ERROR = 116
} piadina_exit_code_t;

/**
 * @brief Result codes for config parsing operations.
 */
typedef enum {
    CONFIG_OK = 0,
    CONFIG_ERR_INVALID_ARGUMENT,
    CONFIG_ERR_UNKNOWN_OPTION,
    CONFIG_ERR_MISSING_VALUE,
    CONFIG_ERR_INVALID_VALUE,
    CONFIG_ERR_OUT_OF_MEMORY
} config_result_t;

/**
 * @brief Special action flags that cause the launcher to exit after parsing.
 */
typedef enum {
    CONFIG_ACTION_RUN = 0,       /* Normal operation: extract and launch */
    CONFIG_ACTION_HELP,          /* Print help and exit */
    CONFIG_ACTION_VERSION,       /* Print version and exit */
    CONFIG_ACTION_PRINT_FOOTER,  /* Print footer info and exit */
    CONFIG_ACTION_PRINT_METADATA /* Print metadata and exit */
} config_action_t;

/**
 * @brief Launcher configuration structure.
 */
typedef struct {
    /* Action to perform (may cause early exit) */
    config_action_t action;

    /* Configuration values (NULL cache_root means use metadata default) */
    char *cache_root;                           /* Owned, dynamically allocated */
    bool cache_root_set;
    metadata_core_cleanup_policy_t cleanup_policy;
    bool cleanup_policy_set;
    log_level_t log_level;
    bool validate;
    bool validate_set;
    bool force_extract;

    /* Application arguments (non-launcher args + args after --) */
    int app_argc;       /* Number of app arguments */
    char **app_argv;    /* Owned array of borrowed string pointers */
} piadina_config_t;

/**
 * @brief Initialize a config struct with default values.
 *
 * @param[out] config  Pointer to the config struct.
 *
 * @note Memory Management:
 *       The caller provides the struct memory. No allocation occurs during init.
 *       After init, all fields contain valid default values. The caller retains
 *       ownership of the struct.
 */
void config_init(piadina_config_t *config);

/**
 * @brief Free any dynamically allocated resources in the config struct.
 *
 * @param[in] config  Pointer to the config struct.
 *
 * @note Memory Management:
 *       Does NOT free the struct memory itself (caller-owned).
 *       Frees `cache_root` and `app_argv`.
 */
void config_destroy(piadina_config_t *config);

/**
 * @brief Apply environment variable overrides to the config.
 *
 * Reads PIADINA_* environment variables. Should be called before config_parse_args().
 *
 * @param[in,out] config     Config struct to update.
 * @param[out]    error_msg  Optional pointer to receive error message.
 * @return                   CONFIG_OK on success.
 *
 * @note Memory Management:
 *       May allocate string fields (cache_root) in @p config.
 */
config_result_t config_apply_env(piadina_config_t *config,
                                 const char **error_msg);

/**
 * @brief Parse command-line arguments into the config struct.
 *
 * Launcher options are consumed. All other arguments are collected into `app_argv`.
 * The `--` separator marks the end of launcher options.
 *
 * @param[in,out] config     Config struct to populate.
 * @param[in]     argc       Argument count.
 * @param[in]     argv       Argument vector.
 * @param[out]    error_msg  Optional pointer to receive error message.
 * @return                   CONFIG_OK on success.
 *
 * @note Memory Management:
 *       Allocated resources (cache_root, app_argv array) are owned by the config struct.
 *       @p argv is read-only and borrowed.
 */
config_result_t config_parse_args(piadina_config_t *config,
                                  int argc, char **argv,
                                  const char **error_msg);

/**
 * @brief Convert a config result code to a string.
 *
 * @param[in] result  The result code.
 * @return            String description.
 *
 * @note Memory Management:
 *       Returns static string constant.
 */
const char *config_result_to_string(config_result_t result);

/**
 * @brief Print launcher help message to stderr.
 *
 * @param[in] program_name  Name of the executable.
 */
void config_print_help(const char *program_name);

#endif /* PIADINA_CONFIG_H */
