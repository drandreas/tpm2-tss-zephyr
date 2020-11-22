#pragma once

#include <inttypes.h>
#include <mbedtls/pk.h>
#include <tss2/tss2_esys.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tpm_keypair {
  int32_t       empty_auth;
  uint32_t      parent;
  TPM2B_PUBLIC  pub_key;
  TPM2B_PRIVATE priv_key;
} tpm_keypair_t;

/**
 * \brief          This function defines the device this utils should use.
 * \note           The char array must remain valid indefinitely. If this
 *                 function is never called or called with NULL than the
 *                 default device "tpm" will be used.
 * \param dev      This name will be passed to device_get_binding. Whenever
 *                 an utility function needs to communicate  with the tpm.
 */
void tpm_set_device_name(const char *dev);

/**
 * \brief           This function stores an ecdsa keypair in a global variable.
 *                  This kaypair will be used by the \c mbedtls_ecdsa_sign_alt
 *                  function during a CSR sign or TLS handshake.
 * \note            Due to current limitations in the secure socket API there
 *                  is no support for multiple keypairs of the same type.
 * \param keypair   The ECDSA keypair to use from now on. This function makes
 *                  a deep copy of the data. The pointer can be invalidated
 *                  after this function has completed.
 */
void tpm_set_ec_keypair(const tpm_keypair_t *keypair);

/**
 * \brief           This function returns a pointer to the global variable used
 *                  by \c mbedtls_ecdsa_sign_alt. This allows in contrast to
 *                  \c tpm_set_ec_keypair in place modifications of the keypair.
 *                  On one hand this saves memory for constraint devices on the
 *                   other it adds a risk for race conditions. Choose wisely.
 * \return          \c pointer to the variable used by \c mbedtls_ecdsa_sign_alt
 */
tpm_keypair_t *tpm_get_ec_keypair_ptr();

/**
 * \brief           This function creates an ecdsa keypair and copies it to
 *                  the output variable keypair.
 * \note            Since this API is in a very early stage only P-256 curves
 *                  are supported. Additionally the entire code assumes an empty
 *                  owner auth and no intermediate keys.
 * \param keypair   The data structure where the keypair should be written to.
 *                  The memory must be allocated by the caller.
 * \return          \c 0 on success.
 * \return          An \c errorno otherwise
 */
int tpm_generate_ec_keypair(tpm_keypair_t *keypair);

/**
 * \brief           This function loads a keypair from a tpm2-tss-engine
 *                  compatible DER encoded buffer.
 * \note            If a PEM formated file is used it must first be converted
 *                  to DER using mbedtls_pem_read_buffer.
 * \param keypair   The data structure where the keypair should be written to.
 *                  The memory must be allocated by the caller.
 * \param buf       The buffer holding the DER encoded keypair
 * \param len       The length of the DER encoded buffer.
 * \return          \c 0 on success.
 * \return          An \c errorno otherwise
 */
int tpm_load_keypair_der(tpm_keypair_t *keypair, uint8_t* buf, size_t len);

/**
 * \brief           This function stores a keypair to a DER encoded buffer.
 *                  The encoding is compatible to tpm2-tss-engine.
 * \note            The DER encoded buffer can be converted to PEM using
 *                  mbedtls_pem_write_buffer.
 * \param keypair   The keypair that shoudlk be converted to DER.
 * \param buf       The buffer the DER encoded keypair should be written to.
 * \param len       Buffer size on input. Output length after conversion.
 * \return          \c 0 on success.
 * \return          An \c errorno otherwise
 */
int tpm_store_keypair_der(const tpm_keypair_t *keypair, uint8_t* buf, size_t *len);

/**
 * \brief           This function converts the public key from the TPM specific
 *                  format to the mbedTLS specific one. It then can be used e.g.
 *                  to create a CSR.
 * \note            A CSR is only valid if it is signed with the private key.
 *                  Hence tpm_set_ec_keypair should be called before using
 *                  mbedtls_pk_context with mbedtls_x509write_csr.
 * \param pubkey    The public key in the TPM specific format
 * \param ctx       An already initialized (using mbedtls_pk_init) context.
 *                  This function will setup
 */
int tpm_export_pubkey(TPM2B_PUBLIC *pub_key, mbedtls_pk_context* ctx);

#ifdef __cplusplus
}
#endif
