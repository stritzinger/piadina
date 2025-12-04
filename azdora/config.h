/**
 * @file config.h
 * @brief Azdora packer CLI parsing.
 *
 * Minimal CLI for milestone 6: collects launcher path, payload dir,
 * optional output path, and raw `--meta` entries. No environment parsing yet.
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

void azdora_config_init(azdora_config_t *config);
void azdora_config_destroy(azdora_config_t *config);

azdora_config_result_t azdora_config_parse_args(azdora_config_t *config,
                                                int argc,
                                                char **argv,
                                                const char **error_msg);

const char *azdora_config_result_to_string(azdora_config_result_t result);

void azdora_config_print_help(const char *program_name);

#endif /* AZDORA_CONFIG_H */
