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

azdora_assembler_result_t azdora_assembler_build(const azdora_config_t *config,
                                                 const azdora_metadata_t *metadata);

const char *azdora_assembler_result_to_string(azdora_assembler_result_t result);

#endif /* AZDORA_ASSEMBLER_H */
