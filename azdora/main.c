/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file main.c
 * @brief Azdora packer entry point.
 */
#include <stdio.h>
#include <stdlib.h>

#include "piadina_config.h"
#include "config.h"
#include "metadata.h"
#include "assembler.h"
#include "common/footer.h"

int main(int argc, char **argv)
{
    int exit_code = EXIT_SUCCESS;
    const char *error = NULL;
    azdora_config_t config;
    azdora_metadata_t metadata;

    azdora_config_init(&config);
    azdora_metadata_init(&metadata);

    azdora_config_result_t cfg_rc = azdora_config_parse_args(&config, argc, argv, &error);
    if (cfg_rc != AZDORA_CONFIG_OK) {
        fprintf(stderr, "Azdora: %s\n", error ? error : azdora_config_result_to_string(cfg_rc));
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    /* No arguments: behave like help but exit 0 to satisfy basic execution check */
    if (config.action == AZDORA_ACTION_RUN &&
        !config.launcher_path && !config.payload_dir && config.meta_count == 0) {
        azdora_config_print_help(argv[0]);
        goto cleanup;
    }

    if (config.action == AZDORA_ACTION_HELP) {
        azdora_config_print_help(argv[0]);
        goto cleanup;
    }

    if (config.action == AZDORA_ACTION_VERSION) {
        printf("Azdora packer v%s\n", PACKAGE_VERSION);
        goto cleanup;
    }

    if (config.verbose) {
        fprintf(stderr, "[azdora] verbose mode enabled\n");
    }

    /* Apply metadata entries */
    for (size_t i = 0; i < config.meta_count; ++i) {
        azdora_metadata_result_t mrc = azdora_metadata_apply_meta(&metadata,
                                                                  config.meta_entries[i],
                                                                  &error);
        if (mrc != AZDORA_METADATA_OK) {
            fprintf(stderr, "Azdora metadata error: %s\n",
                    error ? error : "invalid metadata entry");
            exit_code = EXIT_FAILURE;
            goto cleanup;
        }
        if (config.verbose) {
            fprintf(stderr, "[azdora] applied metadata entry: %s\n", config.meta_entries[i]);
        }
    }

    azdora_metadata_result_t finalize_rc = azdora_metadata_finalize(&metadata, &error);
    if (finalize_rc != AZDORA_METADATA_OK) {
        fprintf(stderr, "Azdora metadata error: %s\n",
                error ? error : "metadata finalize failed");
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    azdora_assembler_result_t asm_rc = azdora_assembler_build(&config, &metadata);
    if (asm_rc != AZDORA_ASSEMBLER_OK) {
        fprintf(stderr, "Azdora assemble error: %s\n",
                azdora_assembler_result_to_string(asm_rc));
        exit_code = EXIT_FAILURE;
        goto cleanup;
    }

    if (!config.quiet) {
        printf("[azdora] wrote %s\n", config.output_path);
    }

cleanup:
    azdora_metadata_destroy(&metadata);
    azdora_config_destroy(&config);
    return exit_code;
}
