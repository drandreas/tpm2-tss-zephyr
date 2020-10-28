#include "tcti-zephyr.h"

#include <tpm-tis-spi.h>

#include "tss2-tcti/tcti-common.h"

#include <string.h>
#include <stdlib.h>

/*
 * This function wraps the "up-cast" of the opaque TCTI context type to the
 * type for the zephyr TCTI context.
 */
static TSS2_TCTI_ZEPHYR_CONTEXT*
tcti_zephyr_context_cast (TSS2_TCTI_CONTEXT *tcti_ctx)
{
  return (TSS2_TCTI_ZEPHYR_CONTEXT*)tcti_ctx;
}

/*
 * This function down-casts the zephyr TCTI context to the common context
 * defined in the tcti-common module.
 */
static TSS2_TCTI_COMMON_CONTEXT*
tcti_zephyr_down_cast (TSS2_TCTI_ZEPHYR_CONTEXT *tcti_zephyr)
{
  if (tcti_zephyr == NULL) {
    return NULL;
  }
  return &tcti_zephyr->common;
}

static TSS2_RC
tcti_zephyr_transmit(TSS2_TCTI_CONTEXT *tcti_ctx,
                     size_t command_size,
                     const uint8_t *command_buffer)
{
  TSS2_TCTI_ZEPHYR_CONTEXT *tcti_zephyr = tcti_zephyr_context_cast (tcti_ctx);

  if (tpm_device_transmit(tcti_zephyr->dev, command_size, command_buffer) < 0) {
    return TSS2_BASE_RC_IO_ERROR;
  } else {
    return TSS2_RC_SUCCESS;
  }
}

static TSS2_RC
tcti_zephyr_receive(TSS2_TCTI_CONTEXT *tcti_ctx,
                    size_t *response_size,
                    uint8_t *response_buffer,
                    int32_t timeout)
{
  TSS2_TCTI_ZEPHYR_CONTEXT *tcti_zephyr = tcti_zephyr_context_cast (tcti_ctx);

  // Convert tpm2-tss timeout into k_timeout_t
  k_timeout_t k_timeout = K_FOREVER;
  if(timeout >= 0) {
    k_timeout = K_MSEC(timeout);
  }

  if (tpm_device_receive(tcti_zephyr->dev, response_size, response_buffer, k_timeout) < 0) {
    return TSS2_BASE_RC_IO_ERROR;
  } else {
    return TSS2_RC_SUCCESS;
  }
}

static void
tcti_zephyr_finalize(TSS2_TCTI_CONTEXT *tcti_ctx)
{
}

static TSS2_RC
tcti_zephyr_cancel(TSS2_TCTI_CONTEXT *tcti_ctx)
{
  TSS2_TCTI_ZEPHYR_CONTEXT *tcti_zephyr = tcti_zephyr_context_cast (tcti_ctx);

  if (tpm_device_cancel(tcti_zephyr->dev) < 0) {
    return TSS2_BASE_RC_IO_ERROR;
  } else {
    return TSS2_RC_SUCCESS;
  }
}

static TSS2_RC
tcti_zephyr_get_poll_handles(TSS2_TCTI_CONTEXT *tcti_ctx,
                             TSS2_TCTI_POLL_HANDLE *handles,
                             size_t *num_handles)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static TSS2_RC
tcti_zephyr_set_locality(TSS2_TCTI_CONTEXT *tcti_ctx,
                         uint8_t locality)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

static void
tcti_zephyr_init_context_data (
    TSS2_TCTI_COMMON_CONTEXT *tcti_common)
{
    TSS2_TCTI_MAGIC (tcti_common) = TCTI_ZEPHYR_MAGIC;
    TSS2_TCTI_VERSION (tcti_common) = TCTI_VERSION;
    TSS2_TCTI_TRANSMIT (tcti_common) = tcti_zephyr_transmit;
    TSS2_TCTI_RECEIVE (tcti_common) = tcti_zephyr_receive;
    TSS2_TCTI_FINALIZE (tcti_common) = tcti_zephyr_finalize;
    TSS2_TCTI_CANCEL (tcti_common) = tcti_zephyr_cancel;
    TSS2_TCTI_GET_POLL_HANDLES (tcti_common) = tcti_zephyr_get_poll_handles;
    TSS2_TCTI_SET_LOCALITY (tcti_common) = tcti_zephyr_set_locality;
    TSS2_TCTI_MAKE_STICKY (tcti_common) = tcti_make_sticky_not_implemented;
    tcti_common->state = TCTI_STATE_TRANSMIT;
    tcti_common->locality = 0;
    memset (&tcti_common->header, 0, sizeof (tcti_common->header));
}

/*
 * This function is public and can be used to run the stack with a custom
 * device name. The device is resolved with device_get_binding(...)
 */ 
TSS2_RC Tss2_Tcti_Zephyr_Init (
    TSS2_TCTI_CONTEXT *tcti_ctx,
    size_t *size,
    const char *conf)
{
  TSS2_TCTI_ZEPHYR_CONTEXT *tcti_zephyr = tcti_zephyr_context_cast (tcti_ctx);
  TSS2_TCTI_COMMON_CONTEXT *tcti_common = tcti_zephyr_down_cast (tcti_zephyr);

  if (tcti_ctx == NULL) {
    *size = sizeof(TSS2_TCTI_ZEPHYR_CONTEXT);
    return TSS2_RC_SUCCESS;
  }
  
  if (conf == NULL) {
    return TSS2_TCTI_RC_BAD_VALUE;
  }

  tcti_zephyr->dev = device_get_binding(conf);
  if (tcti_zephyr->dev == NULL) {
    return TSS2_TCTI_RC_NO_CONNECTION;
  }

  tcti_zephyr_init_context_data(tcti_common);
  return TSS2_RC_SUCCESS;
}

/*
 * This function is called by Esys_Initialize if it want's the default tcti
 */
TSS2_RC Tss2_TctiLdr_Initialize(const char *nameConf, TSS2_TCTI_CONTEXT **context)
{
  TSS2_TCTI_CONTEXT *tcti_ctx = (TSS2_TCTI_CONTEXT *)calloc(1, sizeof(TSS2_TCTI_ZEPHYR_CONTEXT));
  size_t size = sizeof(TSS2_TCTI_ZEPHYR_CONTEXT);

  TSS2_RC rc = Tss2_Tcti_Zephyr_Init(tcti_ctx, &size, "tpm");
  if (rc != TSS2_RC_SUCCESS) {
    free(tcti_ctx);
    return rc;
  }

  *context = (void*)tcti_ctx;
  return TSS2_RC_SUCCESS;
}

/*
 * This function is called by Esys_Initialize and Esys_Finalize during cleanup
 */
void Tss2_TctiLdr_Finalize(TSS2_TCTI_CONTEXT **context)
{
  if(context != NULL && *context != NULL) {
    free(*context);
    *context = NULL;
  }
}
