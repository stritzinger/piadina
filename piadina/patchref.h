/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Dipl.Phys. Peer Stritzinger GmbH
 */

#ifndef PIADINA_PATCHREF_H
#define PIADINA_PATCHREF_H

#include <stddef.h>

typedef enum {
    PATCHREF_OK = 0,
    PATCHREF_ALREADY_SET,
    PATCHREF_ERR_INVALID_ARGUMENT,
    PATCHREF_ERR_NOT_ELF,
    PATCHREF_ERR_UNSUPPORTED_CLASS,
    PATCHREF_ERR_UNSUPPORTED_TYPE,
    PATCHREF_ERR_NO_INTERP,
    PATCHREF_ERR_TOO_LONG,
    PATCHREF_ERR_IO
} patchref_result_t;

patchref_result_t patchref_set_interpreter(const char *path, const char *interpreter);

const char *patchref_result_to_string(patchref_result_t rc);

#endif /* PIADINA_PATCHREF_H */
