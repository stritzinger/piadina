/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

/**
 * @file assembler.h
 * @brief Assembles launcher + metadata + placeholder archive into output binary.
 */
#ifndef AZDORA_ASSEMBLER_H
#define AZDORA_ASSEMBLER_H

#include "config.h"
#include "metadata.h"

typedef enum {
    AZDORA_ASSEMBLER_OK = 0,
    AZDORA_ASSEMBLER_ERR_INVALID_ARGUMENT,
    AZDORA_ASSEMBLER_ERR_OPEN_LAUNCHER,
    AZDORA_ASSEMBLER_ERR_READ_LAUNCHER,
    AZDORA_ASSEMBLER_ERR_OPEN_OUTPUT,
    AZDORA_ASSEMBLER_ERR_WRITE_OUTPUT,
    AZDORA_ASSEMBLER_ERR_METADATA_ENCODE,
    AZDORA_ASSEMBLER_ERR_FOOTER
} azdora_assembler_result_t;

/**
 * @brief Build the self-extracting binary.
 *
 * This function reads the launcher binary, encodes the metadata, generates
 * a placeholder archive, constructs the footer, and writes
 * everything to the output path specified in the config.
 *
 * @param[in] config    Configuration struct (paths, options).
 * @param[in] metadata  Populated metadata struct.
 * @return              AZDORA_ASSEMBLER_OK on success, or an error code.
 *
 * @note Memory Management:
 *       Caller retains ownership of @p config and @p metadata.
 */
azdora_assembler_result_t azdora_assembler_build(const azdora_config_t *config,
                                                 const azdora_metadata_t *metadata);

/**
 * @brief Convert an assembler result code to a string.
 *
 * @param[in] result  The result code.
 * @return            String description.
 *
 * @note Memory Management:
 *       Returns a pointer to static string constants. Caller must not free it.
 */
const char *azdora_assembler_result_to_string(azdora_assembler_result_t result);

#endif /* AZDORA_ASSEMBLER_H */
