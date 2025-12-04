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
 * Piadina launcher exit codes.
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
 * Result codes for config parsing operations.
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
 * Special action flags that cause the launcher to exit after parsing.
 */
typedef enum {
    CONFIG_ACTION_RUN = 0,       /* Normal operation: extract and launch */
    CONFIG_ACTION_HELP,          /* Print help and exit */
    CONFIG_ACTION_VERSION,       /* Print version and exit */
    CONFIG_ACTION_PRINT_FOOTER,  /* Print footer info and exit */
    CONFIG_ACTION_PRINT_METADATA /* Print metadata and exit */
} config_action_t;

/**
 * Launcher configuration structure.
 *
 * After config_init(), all fields contain valid default values.
 * config_apply_env() and config_parse_args() override these values.
 *
 * String fields (cache_root) are dynamically allocated when set.
 * The config_destroy() function MUST be called to release allocated memory.
 *
 * The app_argv array is dynamically allocated and contains pointers to the
 * original argv strings. It collects:
 *   - All non-launcher arguments (not starting with --launcher-)
 *   - All arguments after the -- separator
 * This allows launcher options to be interspersed with application arguments.
 */
typedef struct {
    /* Action to perform (may cause early exit) */
    config_action_t action;

    /* Configuration values (NULL cache_root means use metadata default) */
    char *cache_root;                           /* Owned, dynamically allocated */
    metadata_core_cleanup_policy_t cleanup_policy;
    log_level_t log_level;
    bool validate;
    bool force_extract;

    /* Application arguments (non-launcher args + args after --) */
    int app_argc;       /* Number of app arguments */
    char **app_argv;    /* Owned array of borrowed string pointers */
} piadina_config_t;

/**
 * Initialize a config struct with default values.
 *
 * The caller provides the struct memory. No allocation occurs during init.
 * After init, all fields contain valid default values. The caller retains
 * ownership of the struct.
 *
 * Typical usage order:
 *   1. config_init()       - set defaults
 *   2. config_apply_env()  - override with environment variables
 *   3. config_parse_args() - override with CLI arguments
 */
void config_init(piadina_config_t *config);

/**
 * Free any dynamically allocated resources in the config struct.
 *
 * After calling config_destroy(), the struct should not be used unless
 * re-initialized with config_init(). The struct memory itself is NOT freed;
 * the caller retains ownership of it.
 */
void config_destroy(piadina_config_t *config);

/**
 * Apply environment variable overrides to the config.
 *
 * Reads PIADINA_* environment variables and applies them to the config,
 * overriding defaults set by config_init(). Should be called before
 * config_parse_args() so that CLI options take final precedence.
 *
 * @param config    Config struct to update (caller-owned)
 * @param error_msg Optional pointer to receive error message on failure
 * @return CONFIG_OK on success, error code otherwise
 */
config_result_t config_apply_env(piadina_config_t *config,
                                 const char **error_msg);

/**
 * Parse command-line arguments into the config struct.
 *
 * Launcher options (--launcher-*) are consumed by the launcher. All other
 * arguments are collected into app_argv to be passed to the application.
 * The -- separator marks the end of launcher option processing; everything
 * after it is passed through verbatim.
 *
 * Example: --foo --launcher-verbose --bar -- --buz
 *   - --launcher-verbose is consumed by the launcher
 *   - --foo, --bar, --buz are passed to the application
 *
 * Unknown --launcher-* options return CONFIG_ERR_UNKNOWN_OPTION.
 *
 * On success, allocated resources (cache_root, app_argv array) are owned by
 * the config struct. On error, partial allocations are cleaned up.
 *
 * @param config    Config struct to populate (caller-owned, must be initialized)
 * @param argc      Argument count from main()
 * @param argv      Argument vector from main() (borrowed, not modified)
 * @param error_msg Optional pointer to receive error message on failure
 *                  (points to static string, not allocated)
 * @return CONFIG_OK on success, error code otherwise
 */
config_result_t config_parse_args(piadina_config_t *config,
                                  int argc, char **argv,
                                  const char **error_msg);

/**
 * Convert a config result code to a human-readable string.
 * The returned string is statically allocated and owned by the module.
 */
const char *config_result_to_string(config_result_t result);

/**
 * Print launcher help message to stderr.
 */
void config_print_help(const char *program_name);

#endif /* PIADINA_CONFIG_H */
