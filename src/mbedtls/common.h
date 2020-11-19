#pragma once

#include <tss2/tss2_esys.h>

#define goto_error(r, v, msg, label, ...) { \
  r = v;                                    \
  LOG_ERR(msg, ## __VA_ARGS__);             \
  goto label;                               \
}

int tpm_esys_initialize(ESYS_CONTEXT **esys_ctx);

int tpm_esys_finalize(ESYS_CONTEXT **esys_ctx);
