#include <stdlib.h>

#include <tpm-tis-spi.h>

#include "tss2-tcti/tctildr.h"
#include "tss2-tcti/tcti-common.h"

static TSS2_RC
tcti_device_transmit(TSS2_TCTI_CONTEXT *tctiContext,
                    size_t command_size,
                    const uint8_t *command_buffer)
{
  //TODO Move somehow into Tss2_TctiLdr_Initialize
  struct device *dev = device_get_binding("tpm");
  if (dev == NULL) {
    return TSS2_TCTI_RC_NO_CONNECTION;
  }

  if(tpm_device_transmit(dev, command_size, command_buffer) < 0) {
    return TSS2_BASE_RC_IO_ERROR;
  } else {
    return TSS2_RC_SUCCESS;
  }
}

static TSS2_RC
tcti_device_receive(TSS2_TCTI_CONTEXT *tctiContext,
                   size_t *response_size,
                   uint8_t *response_buffer,
                   int32_t timeout)
{
  //TODO Move somehow into Tss2_TctiLdr_Initialize
  struct device *dev = device_get_binding("tpm");
  if (dev == NULL) {
    return TSS2_TCTI_RC_NO_CONNECTION;
  }

  // Convert tpm2-tss timeout into k_timeout_t
  k_timeout_t k_timeout = K_FOREVER;
  if(timeout >= 0) {
    k_timeout = K_MSEC(timeout);
  }

  if(tpm_device_receive(dev, response_size, response_buffer, k_timeout) < 0) {
    return TSS2_BASE_RC_IO_ERROR;
  } else {
    return TSS2_RC_SUCCESS;
  }
}

static void
tcti_device_finalize(TSS2_TCTI_CONTEXT *tctiContext)
{
}

static TSS2_RC
tcti_device_cancel(TSS2_TCTI_CONTEXT *tctiContext)
{
  //TODO Move somehow into Tss2_TctiLdr_Initialize
  struct device *dev = device_get_binding("tpm");
  if (dev == NULL) {
    return TSS2_TCTI_RC_NO_CONNECTION;
  }

  if(tpm_device_cancel(dev) < 0) {
    return TSS2_BASE_RC_IO_ERROR;
  } else {
    return TSS2_RC_SUCCESS;
  }
}

static TSS2_RC
tcti_device_get_poll_handles(TSS2_TCTI_CONTEXT *tctiContext,
                             TSS2_TCTI_POLL_HANDLE *handles,
                             size_t *num_handles)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static TSS2_RC
tcti_device_set_locality(TSS2_TCTI_CONTEXT *tctiContext,
                         uint8_t locality)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC Tss2_TctiLdr_Initialize(const char *nameConf, TSS2_TCTI_CONTEXT **context)
{
  TSS2_TCTILDR_CONTEXT *ldr_ctx = calloc(1, sizeof(TSS2_TCTILDR_CONTEXT));

  TSS2_TCTI_MAGIC (ldr_ctx) = 0xCC4D63801CF2D25EULL;
  TSS2_TCTI_VERSION (ldr_ctx) = TCTI_VERSION;
  TSS2_TCTI_TRANSMIT (ldr_ctx) = tcti_device_transmit;
  TSS2_TCTI_RECEIVE (ldr_ctx) = tcti_device_receive;
  TSS2_TCTI_FINALIZE (ldr_ctx) = tcti_device_finalize;
  TSS2_TCTI_CANCEL (ldr_ctx) = tcti_device_cancel;
  TSS2_TCTI_GET_POLL_HANDLES (ldr_ctx) = tcti_device_get_poll_handles;
  TSS2_TCTI_SET_LOCALITY (ldr_ctx) = tcti_device_set_locality;
  TSS2_TCTI_MAKE_STICKY (ldr_ctx) = tcti_make_sticky_not_implemented;

  *context = (void*)ldr_ctx;

  return TSS2_RC_SUCCESS;
}

void Tss2_TctiLdr_Finalize(TSS2_TCTI_CONTEXT **context)
{
  if(context != NULL && *context != NULL) {
    free(*context);
    *context = NULL;
  }
}

TSS2_RC iesys_cryptossl_init()
{
  return TSS2_RC_SUCCESS;
}
