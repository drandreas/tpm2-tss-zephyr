#include <tss2_tctildr.h>

#include <tss2-tcti/tcti-common.h>

TSS2_RC
tcti_device_transmit(TSS2_TCTI_CONTEXT *tctiContext,
                    size_t command_size,
                    const uint8_t *command_buffer)
{

  return TSS2_RC_SUCCESS;
}

TSS2_RC
tcti_device_receive(TSS2_TCTI_CONTEXT *tctiContext,
                   size_t *response_size,
                   uint8_t *response_buffer,
                   int32_t timeout)
{

  return TSS2_RC_SUCCESS;
}

void
tcti_device_finalize(TSS2_TCTI_CONTEXT *tctiContext)
{

}

TSS2_RC
tcti_device_cancel(TSS2_TCTI_CONTEXT *tctiContext)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_device_get_poll_handles(TSS2_TCTI_CONTEXT *tctiContext,
                             TSS2_TCTI_POLL_HANDLE *handles,
                             size_t *num_handles)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC
tcti_device_set_locality(TSS2_TCTI_CONTEXT *tctiContext,
                         uint8_t locality)
{
  return TSS2_TCTI_RC_NOT_IMPLEMENTED;
}

TSS2_RC Tss2_TctiLdr_Initialize(const char *nameConf, TSS2_TCTI_CONTEXT **context)
{
  *context = malloc(sizeof(TSS2_TCTI_COMMON_CONTEXT));
  TSS2_TCTI_MAGIC (context) = 0xCC4D63801CF2D25EULL;
  TSS2_TCTI_VERSION (context) = TCTI_VERSION;
  TSS2_TCTI_TRANSMIT (context) = tcti_device_transmit;
  TSS2_TCTI_RECEIVE (context) = tcti_device_receive;
  TSS2_TCTI_FINALIZE (context) = tcti_device_finalize;
  TSS2_TCTI_CANCEL (context) = tcti_device_cancel;
  TSS2_TCTI_GET_POLL_HANDLES (context) = tcti_device_get_poll_handles;
  TSS2_TCTI_SET_LOCALITY (context) = tcti_device_set_locality;
  TSS2_TCTI_MAKE_STICKY (context) = tcti_make_sticky_not_implemented;
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
