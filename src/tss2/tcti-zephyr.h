/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TCTI_ZEPHYR_H
#define TCTI_ZEPHYR_H

#include <device.h>

#include "tss2-tcti/tcti-common.h"

#define TCTI_ZEPHYR_MAGIC 0xCC4D63801CF2D25EULL

typedef struct {
  TSS2_TCTI_COMMON_CONTEXT common;
  const struct device *dev;
} TSS2_TCTI_ZEPHYR_CONTEXT;

#endif /* TCTI_ZEPHYR_H */
