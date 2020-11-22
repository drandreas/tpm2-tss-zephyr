# TPM2 TSS-Zephyr Module

## Overview
This repo contains module definitions and glue code to ease the integration of
[TPM2-TSS](https://github.com/tpm2-software/tpm2-tss) into a Zephyr application.
Additionally, there are optional [utilities](include/mbedtls/tpm-utils.h) (enabled
with `CONFIG_MBEDTLS_ECDSA_ALT_TPM`) that redirect all mbedTLS ECDSA sign calls to
the TPM. This in turn enables the use of Zephyr's [Secure Sockets](https://docs.zephyrproject.org/latest/reference/networking/sockets.html#secure-socket-creation)
with a TPM as asymmetric crypto accelerator and certificate store.

My [proof of concept](https://github.com/drandreas/zephyr-tpm2-poc) ilustrates
the use of this module. 

## Using TPM2-TSS Module
This module is compatible with mainline Zephyr, mbedTLS and TPM2-TSS.
The only additonal requirement is [tpm-tis-spi](https://github.com/drandreas/tpm-tis-spi).

This module assumes that TPM2-TSS in a subfolder called import as illustrated below:
```
manifest:
  remotes:
    - name: tpm2-software
      url-base: https://github.com/tpm2-software

    - name: anticat
      url-base: https://github.com/drandreas

  projects:
    - name: tpm-tis-spi
      remote: anticat
      revision: master
      path: modules/drv/tpm-tis-spi

    - name: tpm2-tss
      remote: tpm2-software
      revision:  master
      path: modules/lib/tpm2-tss/import

    - name: tpm2-tss-zephyr
      remote: anticat
      revision: master
      path: modules/lib/tpm2-tss
```

