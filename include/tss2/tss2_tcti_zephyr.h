/* SPDX-License-Identifier: BSD-2-Clause */

#ifndef TCTI_ZEPHYR_H
#define TCTI_ZEPHYR_H

#include "tss2/tss2_tcti.h"

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC Tss2_Tcti_Zephyr_Init (
    TSS2_TCTI_CONTEXT *tctiContext,
    size_t *size,
    const char *conf);

#ifdef __cplusplus
}
#endif

#endif /* TCTI_ZEPHYR_H */
