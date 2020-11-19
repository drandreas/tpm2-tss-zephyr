#include "common.h"

#include <stdlib.h>
#include <errno.h>

#include <logging/log.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/tpm-utils.h>

#include <tss2/tss2_tcti_zephyr.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>

LOG_MODULE_REGISTER(tpm_common, LOG_LEVEL_DBG);

// TPM2-TSS-Engine TPM BLOB OID "2.23.133.10.1.3"
#define OID_TSS2_BLOB "\x67\x81\x05\x0A\x01\x03"

// TPM2-TSS-Engine ASN.1-Format
// https://github.com/tpm2-software/tpm2-tools/issues/1599
//
// TPMKey ::= SEQUENCE {
//    type       OBJECT IDENTIFIER,
//    emptyAuth  [0] EXPLICIT BOOLEAN OPTIONAL,
//    parent     INTEGER,
//    pubkey     OCTET STRING,
//    privkey    OCTET STRING

// Global Variables
static const char* tpm_dev = "tpm";

void tpm_set_device_name(const char *dev) {
  if(dev == NULL) {
    tpm_dev = "tpm";
  } else {
    tpm_dev = dev;
  }
}

int tpm_esys_initialize(ESYS_CONTEXT **esys_ctx) {
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  *esys_ctx = NULL;

  size_t size = 0;
  int ret = Tss2_Tcti_Zephyr_Init(NULL, &size, NULL);
  if(ret != TPM2_RC_SUCCESS)
  {
    goto_error(ret, -EINVAL, "Faled to get allocation size for tcti", cleanup);
  }

  tcti_ctx = calloc(1, size);
  if (tcti_ctx == NULL)
  {
    goto_error(ret, -ENOMEM, "Faled to alloc space for tcti", cleanup);
  }

  ret = Tss2_Tcti_Zephyr_Init(tcti_ctx, &size, tpm_dev);
  if(ret != TSS2_RC_SUCCESS)
  {
    goto_error(ret, -EIO, "Failed to initialize tcti context", cleanup);
  }

  ret = Esys_Initialize(esys_ctx, tcti_ctx, NULL);
  if(ret != TPM2_RC_SUCCESS)
  {
    goto_error(ret, -EIO, "Failed to initialize esys context", cleanup);
  }

  return 0;

cleanup:
  free(tcti_ctx);
  return ret;
}

int tpm_esys_finalize(ESYS_CONTEXT **esys_ctx) {
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;

  Esys_GetTcti(*esys_ctx, &tcti_ctx);
  Esys_Finalize(esys_ctx);
  free(tcti_ctx);

  return 0;
}

int tpm_load_keypair_der(tpm_keypair_t *keypair, uint8_t* buf, size_t len) {
  int ret = 0;

  unsigned char* p = buf;
  unsigned char* end = p + len;

  // Verify type to be sequence and get length
  if(mbedtls_asn1_get_tag(&p, end, &len,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to get sequence length", cleanup);
  }

  // Set end pointer to sequence end (note: asn1_get_tag checks boundries)
  end = p + len;

  // Validate type (OID)
  if(mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID) != 0) {
    goto_error(ret, -EINVAL, "Failed to get type length", cleanup);
  }
  if(   (len != sizeof(OID_TSS2_BLOB))
     || (memcmp(p, OID_TSS2_BLOB, sizeof(OID_TSS2_BLOB))) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to verify type", cleanup);
  }
  p += len;

  // Get optional emptyAuth
  keypair->empty_auth = true;
  if(mbedtls_asn1_get_tag(&p, end, &len,
                          MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0) == 0)
  {
    if(mbedtls_asn1_get_bool(&p, end, &keypair->empty_auth) != 0) {
      goto_error(ret, -EINVAL, "Failed to get empty_auth", cleanup);
    }
  }

  // Get parent the hard way (asn1_get_int does not like uint32_t)
  if(mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER) != 0) {
    goto_error(ret, -EINVAL, "Failed to get parent length", cleanup);
  }

  if(len > sizeof(uint32_t)) {
    goto_error(ret, -EINVAL, "Failed to validate parent length", cleanup);
  }

  keypair->parent = 0;
  while(len-- > 0) {
    keypair->parent = (keypair->parent << 8) | *p;
    p++;
  }

  // Get public key
  if(mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
    goto_error(ret, -EINVAL, "Failed to get public key length", cleanup);
  }

  if(Tss2_MU_TPM2B_PUBLIC_Unmarshal(p, len, NULL, &keypair->pub_key) != 0) {
    goto_error(ret, -EINVAL, "Failed to unmarshal public key", cleanup);
  }
  p += len;

  // Get private key
  if(mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
    goto_error(ret, -EINVAL, "Failed to get private key length", cleanup);
  }

  if(Tss2_MU_TPM2B_PRIVATE_Unmarshal(p, len, NULL, &keypair->priv_key) != 0) {
    goto_error(ret, -EINVAL, "Failed to unmarshal private key", cleanup);
  }

cleanup:
  return ret;
}

int tpm_store_keypair_der(const tpm_keypair_t *keypair, uint8_t* buf, size_t *len) {
  int ret = 0;

  // Marshal Keypair into intermediate buffers
  uint8_t privbuf[sizeof(TPM2B_PRIVATE)];
  size_t privbuf_len = 0;
  uint8_t pubbuf[sizeof(TPM2B_PUBLIC)];
  size_t pubbuf_len = 0;

  if(Tss2_MU_TPM2B_PRIVATE_Marshal(&keypair->priv_key, &privbuf[0],
                                   sizeof(privbuf), &privbuf_len) != 0)
  {
    goto_error(ret, -EIO, "Failed to marshal private key", cleanup);
  }

  if(Tss2_MU_TPM2B_PUBLIC_Marshal(&keypair->pub_key, &pubbuf[0],
                                  sizeof(pubbuf), &pubbuf_len)!= 0)
  {
    goto_error(ret, -EIO, "Failed to marshal public key", cleanup);
  }

  // Wrap Keypair in DER (mbedTLS is doing it in inverse order for efficiency)
  unsigned char *p = buf + *len;
  *len = 0;

  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_octet_string(&p, buf, privbuf, privbuf_len));
  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_octet_string(&p, buf, pubbuf, pubbuf_len));

  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_int(&p, buf, keypair->parent));

  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_bool(&p, buf, keypair->empty_auth));
  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_len(&p, buf, 3));
  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_tag(&p, buf,
                       MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0));

  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_oid(&p, buf, OID_TSS2_BLOB, sizeof(OID_TSS2_BLOB)));

  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_len(&p, buf, *len));
  MBEDTLS_ASN1_CHK_ADD(*len, mbedtls_asn1_write_tag(&p, buf,
                       MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

  // Move data to front
  memcpy(buf, p, *len);

cleanup:
  return ret;
}

int tpm_export_pubkey(TPM2B_PUBLIC *pub_key, mbedtls_pk_context* ctx) {
  int ret = 0;

  if(mbedtls_pk_setup(ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
  {
    goto_error(ret, -EIO, "Failed to setup pubkey context", cleanup);
  }

  if(mbedtls_ecp_group_load(&mbedtls_pk_ec(*ctx)->grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
  {
    goto_error(ret, -EIO, "Failed to load ec-curve", cleanup);
  }

  if (mbedtls_mpi_read_binary(&mbedtls_pk_ec(*ctx)->Q.X,
                              &pub_key->publicArea.unique.ecc.x.buffer[0],
                              pub_key->publicArea.unique.ecc.x.size) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to read Q.x from byte buffer", cleanup);
  }

  if (mbedtls_mpi_read_binary(&mbedtls_pk_ec(*ctx)->Q.Y,
                              &pub_key->publicArea.unique.ecc.y.buffer[0],
                              pub_key->publicArea.unique.ecc.y.size) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to read Q.y from byte buffer", cleanup);
  }

  // Initialise Q.z (Q would be zero, or "at infinity", if Z == 0)
  if (mbedtls_mpi_lset(&mbedtls_pk_ec(*ctx)->Q.Z, 1) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to init Q.z to 1", cleanup);
  }

  // Validate pubkey
  if (mbedtls_ecp_check_pubkey(&mbedtls_pk_ec(*ctx)->grp,
                               &mbedtls_pk_ec(*ctx)->Q) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to validate pubkey", cleanup);
  }

cleanup:
  return ret;
}
