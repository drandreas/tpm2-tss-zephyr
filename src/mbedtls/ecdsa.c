#include <mbedtls/tpm-utils.h>

#include <errno.h>

#include <logging/log.h>
#include <tss2/tss2_mu.h>

#include "common.h"

LOG_MODULE_REGISTER(tpm_ecdsa, LOG_LEVEL_DBG);

// Global Variables
static tpm_keypair_t tpm_keypair_ecdsa;

// Templates of various TPM Structures
static const TPM2B_DIGEST ownerauth = {
  .size = 0
};

static const TPM2B_SENSITIVE_CREATE sensitive = {
  .sensitive = {
    .userAuth = {
      .size = 0,
    },
    .data = {
      .size = 0,
    }
  }
};

static const TPM2B_DATA allOutsideInfo = {
  .size = 0,
};

static const TPML_PCR_SELECTION allCreationPCR = {
  .count = 0,
};

static const TPM2B_PUBLIC primaryEccTemplate = {
  .publicArea = {
    .type = TPM2_ALG_ECC,
    .nameAlg = TPM2_ALG_SHA256,
    .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                         TPMA_OBJECT_RESTRICTED |
                         TPMA_OBJECT_DECRYPT |
                         TPMA_OBJECT_NODA |
                         TPMA_OBJECT_FIXEDTPM |
                         TPMA_OBJECT_FIXEDPARENT |
                         TPMA_OBJECT_SENSITIVEDATAORIGIN),
    .authPolicy = {
       .size = 0,
     },
    .parameters = {
      .eccDetail = {
        .symmetric = {
          .algorithm = TPM2_ALG_AES,
          .keyBits = {
            .aes = 128,
          },
          .mode = {
            .aes = TPM2_ALG_CFB,
          }
        },
        .scheme = {
          .scheme = TPM2_ALG_NULL,
          .details = {}
        },
        .curveID = TPM2_ECC_NIST_P256,
        .kdf = {
           .scheme = TPM2_ALG_NULL,
           .details = {}
        },
      },
    },
    .unique = {
      .ecc = {
        .x = {
          .size = 0,
        },
        .y = {
          .size = 0
        }
      }
    }
  }
};

static const TPM2B_PUBLIC keyEcTemplate = {
  .publicArea = {
    .type = TPM2_ALG_ECC,
    .nameAlg = TPM2_ALG_SHA256,
    .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                         TPMA_OBJECT_SIGN_ENCRYPT |
                         TPMA_OBJECT_FIXEDTPM |
                         TPMA_OBJECT_FIXEDPARENT |
                         TPMA_OBJECT_SENSITIVEDATAORIGIN |
                         TPMA_OBJECT_NODA),
    .parameters = {
      .eccDetail = {
        .symmetric = {
          .algorithm = TPM2_ALG_NULL,
          .keyBits = {
            .aes = 128,
          },
          .mode = {
            .aes = TPM2_ALG_CFB,
          }
        },
        .scheme = {
          .scheme = TPM2_ALG_NULL,
          .details = {}
        },
        .curveID = TPM2_ECC_NIST_P256,
        .kdf = {
          .scheme = TPM2_ALG_NULL,
          .details = {}
        },
      },
    },
    .unique = {
      .ecc = {
        .x = {
          .size = 0,
        },
        .y = {
          .size = 0
        }
      }
    }
  }
};

static const TPMT_TK_HASHCHECK validation = {
  .tag = TPM2_ST_HASHCHECK,
  .hierarchy = TPM2_RH_NULL,
  .digest = {
    .size = 0
  }
};

int tpm_generate_ec_keypair(tpm_keypair_t *keypair) {
  int ret = 0;

  ESYS_CONTEXT *esys_ctx = NULL;
  ESYS_TR parent = ESYS_TR_NONE;

  // Get Ready
  ret = tpm_esys_initialize(&esys_ctx);
  if(ret != 0)
  {
    goto_error(ret, ret, "Failed to connect to tpm", cleanup);
  };

  // Set OnwerAuth (empty)
  if(Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &ownerauth) != 0)
  {
    goto_error(ret, -EINVAL, "Failed to set ownerauth", cleanup);
  }

  // Re-Create Owner Key (function is deterministic)
  if(Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_OWNER,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &sensitive, &primaryEccTemplate, &allOutsideInfo,
                        &allCreationPCR,
                        &parent, NULL, NULL, NULL, NULL) != 0)
  {
    goto_error(ret, -EIO, "Failed to create primary key", cleanup);
  }

  // Create Keypair
  TPM2B_PUBLIC  *pub_key  = NULL;
  TPM2B_PRIVATE *priv_key = NULL;
  if(Esys_Create(esys_ctx, parent,
                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                  &sensitive, &keyEcTemplate, &allOutsideInfo, &allCreationPCR,
                  &priv_key, &pub_key, NULL, NULL, NULL) != 0)
  {
    goto_error(ret, -EIO, "Failed to create keypair", cleanup);
  }

  // Write Keypair into output structure
  keypair->empty_auth = 1;
  keypair->parent = ESYS_TR_RH_OWNER;
  memcpy(&keypair->pub_key, pub_key, sizeof(TPM2B_PUBLIC));
  memcpy(&keypair->priv_key, priv_key, sizeof(TPM2B_PRIVATE));

cleanup:
  if(parent != ESYS_TR_NONE) {
    Esys_FlushContext(esys_ctx, parent);
  }

  if(esys_ctx == NULL) {
    tpm_esys_finalize(&esys_ctx);
  }

  return ret;
}

void tpm_set_ec_keypair(const tpm_keypair_t *keypair) {
  memcpy(&tpm_keypair_ecdsa, keypair, sizeof(tpm_keypair_t));
}

/**
 * \brief           This function computes the ECDSA signature of a
 *                  previously-hashed message.
 * \note            If the bitlength of the message hash is larger than the
 *                  bitlength of the group order, then the hash is truncated
 *                  as defined in <em>Standards for Efficient Cryptography Group
 *                  (SECG): SEC1 Elliptic Curve Cryptography</em>, section
 *                  4.1.3, step 5.
 * \param grp       The context for the elliptic curve to use.
 *                  This must be initialized and have group parameters
 *                  set, for example through mbedtls_ecp_group_load().
 * \param r         The MPI context in which to store the first part
 *                  the signature. This must be initialized.
 * \param s         The MPI context in which to store the second part
 *                  the signature. This must be initialized.
 * \param d         The private signing key. This must be initialized.
 * \param buf       The content to be signed. This is usually the hash of
 *                  the original data to be signed. This must be a readable
 *                  buffer of length \p blen Bytes. It may be \c NULL if
 *                  \p blen is zero.
 * \param blen      The length of \p buf in Bytes.
 * \param f_rng     The RNG function. This must not be \c NULL.
 * \param p_rng     The RNG context to be passed to \p f_rng. This may be
 *                  \c NULL if \p f_rng doesn't need a context parameter.
 *
 * \return          \c 0 on success.
 * \return          An \c MBEDTLS_ERR_ECP_XXX
 *                  or \c MBEDTLS_MPI_XXX error code on failure.
 */
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp,
                       mbedtls_mpi *r, mbedtls_mpi *s,
                       const mbedtls_mpi *d,
                       const unsigned char *buf,
                       size_t blen,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng)
{
  int ret = 0;

  ESYS_CONTEXT *esys_ctx = NULL;
  ESYS_TR parent = ESYS_TR_NONE;
  ESYS_TR keyHandle = ESYS_TR_NONE;
  TPMT_SIGNATURE *outSig = NULL;

  // Check curve compatibility
  if(grp->id != MBEDTLS_ECP_DP_SECP256R1)
  {
    goto_error(ret, MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE,
               "EC-Group not supported", cleanup);
  }

  // TPM wants to know digest type, figure it out using blen
  TPMT_SIG_SCHEME inScheme;
  inScheme.scheme = TPM2_ALG_ECDSA;
  switch (blen) {
    case 20:
      inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA1;
      break;
    case 32:
      inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
      break;
    case 48:
      inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA384;
      break;
    case 64:
      inScheme.details.ecdsa.hashAlg = TPM2_ALG_SHA512;
      break;
    default:
      goto_error(ret, MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE,
                 "MD-Type not supported", cleanup);
  }

  // Copy digest into tpm structure
  TPM2B_DIGEST digest;
  digest.size = blen;
  if (digest.size > sizeof(digest.buffer)) {
      goto_error(ret, MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE,
                 "MD-Type not supported", cleanup);
  }
  memcpy(&digest.buffer[0], buf, blen);

  // Get Ready
  ret = tpm_esys_initialize(&esys_ctx);
  if(ret != 0)
  {
    goto_error(ret, MBEDTLS_ERR_ECP_ALLOC_FAILED,
               "Failed to connect to tpm", cleanup);
  };

  // Set OnwerAuth (empty)
  if(Esys_TR_SetAuth(esys_ctx, ESYS_TR_RH_OWNER, &ownerauth) != 0)
  {
    goto_error(ret, MBEDTLS_ERR_ECP_INVALID_KEY,
               "Failed to set ownerauth", cleanup);
  }

  // Re-Create Owner Key (function is deterministic)
  if(Esys_CreatePrimary(esys_ctx, ESYS_TR_RH_OWNER,
                        ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                        &sensitive, &primaryEccTemplate, &allOutsideInfo,
                        &allCreationPCR,
                        &parent, NULL, NULL, NULL, NULL) != 0)
  {
    goto_error(ret, MBEDTLS_ERR_ECP_INVALID_KEY,
               "Failed to create primary key", cleanup);
  }

  // Load Key
  if(Esys_Load(esys_ctx, parent,
               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
               &tpm_keypair_ecdsa.priv_key,
               &tpm_keypair_ecdsa.pub_key, &keyHandle) != 0)
  {
    goto_error(ret, MBEDTLS_ERR_ECP_INVALID_KEY,
               "Failed to load key", cleanup);
  }

  // Sign hash
  if(Esys_Sign(esys_ctx, keyHandle,
                ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                &digest, &inScheme, &validation, &outSig) != 0)
  {
    goto_error(ret, MBEDTLS_ERR_ECP_HW_ACCEL_FAILED,
               "Failed to execute ecdsa sign", cleanup);
  }

  // Convert Signature to mbedtls
  if(mbedtls_mpi_read_binary(s,
                             &outSig->signature.ecdsa.signatureS.buffer[0],
                             outSig->signature.ecdsa.signatureS.size) != 0)
  {
    goto_error(ret, MBEDTLS_ERR_MPI_ALLOC_FAILED,
               "Failed to convert s", cleanup);
  }

  if(mbedtls_mpi_read_binary(r,
                             &outSig->signature.ecdsa.signatureR.buffer[0],
                             outSig->signature.ecdsa.signatureR.size) != 0)
  {
    goto_error(ret, MBEDTLS_ERR_MPI_ALLOC_FAILED,
               "Failed to convert r", cleanup);
  }

cleanup:
  if(keyHandle != ESYS_TR_NONE) {
    Esys_FlushContext(esys_ctx, keyHandle);
  }

  if(parent != ESYS_TR_NONE) {
    Esys_FlushContext(esys_ctx, parent);
  }

  if(esys_ctx == NULL) {
    tpm_esys_finalize(&esys_ctx);
  }

  return ret;
}
