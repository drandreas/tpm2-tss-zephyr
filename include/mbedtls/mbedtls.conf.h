#pragma once

#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_PEM_WRITE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CSR_WRITE_C

#undef MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
#define MBEDTLS_ENTROPY_HARDWARE_ALT

#if CONFIG_MBEDTLS_ECDSA_ALT_TPM
#define MBEDTLS_ECDSA_SIGN_ALT
#endif
