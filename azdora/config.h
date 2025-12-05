/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file config.h
 * @brief Azdora packer CLI parsing.
 *
 * Minimal CLI for milestone 6: collects launcher path, payload dir,
 * optional output path, and raw `--meta` entries.
 */
#ifndef AZDORA_CONFIG_H
#define AZDORA_CONFIG_H

#include <stddef.h>
#include <stdbool.h>

typedef enum {
    AZDORA_CONFIG_OK = 0,
    AZDORA_CONFIG_ERR_INVALID_ARGUMENT,
    AZDORA_CONFIG_ERR_UNKNOWN_OPTION,
    AZDORA_CONFIG_ERR_MISSING_VALUE,
    AZDORA_CONFIG_ERR_OUT_OF_MEMORY,
    AZDORA_CONFIG_ERR_MISSING_REQUIRED
} azdora_config_result_t;

typedef enum {
    AZDORA_ACTION_RUN = 0,
    AZDORA_ACTION_HELP,
    AZDORA_ACTION_VERSION
} azdora_action_t;

typedef struct {
    azdora_action_t action;
    char *launcher_path;   /* Owned string */
    char *payload_dir;     /* Owned string */
    char *output_path;     /* Owned string (may be defaulted) */
    bool verbose;
    size_t meta_count;
    char **meta_entries;   /* Owned array of owned strings */
} azdora_config_t;

/**
 * @brief Initialize a config struct with defaults.
 *
 * @param[out] config  Pointer to the config struct to initialize.
 *
 * @note Memory Management:
 *       Caller owns the struct storage. No allocation occurs during init.
 */
void azdora_config_init(azdora_config_t *config);

/**
 * @brief Destroy a config struct and free its members.
 *
 * @param[in] config  Pointer to the config struct.
 *
 * @note Memory Management:
 *       Frees all dynamically allocated strings inside the struct (launcher_path, etc.).
 *       Does NOT free the struct itself (caller-owned).
 */
void azdora_config_destroy(azdora_config_t *config);

/**
 * @brief Parse command-line arguments into the config struct.
 *
 * @param[in,out] config     Config struct to populate.
 * @param[in]     argc       Argument count.
 * @param[in]     argv       Argument vector.
 * @param[out]    error_msg  Optional pointer to receive an error string.
 * @return                   AZDORA_CONFIG_OK on success.
 *
 * @note Memory Management:
 *       Allocates memory for string fields in @p config. Caller must use
 *       `azdora_config_destroy` to free them. @p argv is read-only.
 */
azdora_config_result_t azdora_config_parse_args(azdora_config_t *config,
                                                int argc,
                                                char **argv,
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
const char *azdora_config_result_to_string(azdora_config_result_t result);

/**
 * @brief Print help message to stdout/stderr.
 *
 * @param[in] program_name  Name of the executable (usually argv[0]).
 */
void azdora_config_print_help(const char *program_name);

#endif /* AZDORA_CONFIG_H */
