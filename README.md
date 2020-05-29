# TPM2 TSS-Zephyr Module

## Overview
This repo contains module definitions and glue code to ease the integration of TPM2-TSS into a Zephyr application.

## Using TPM2-TSS Module
A minimal `west.conf` of the application should look as follows:
```
manifest:
  remotes:
    - name: zephyrproject-rtos
      url-base: https://github.com/zephyrproject-rtos

    - name: anticat
      url-base: https://github.com/drandreas

  projects:
    - name: mbedtls
      remote: zephyrproject-rtos
      revision: ... TODO ...
      path: modules/crypto/mbedtls

    - name: zephyr
      remote: zephyrproject-rtos
      revision: ... TODO ...
      path: zephyr
      west-commands: scripts/west-commands.yml

    - name: tpm-tis-spi
      remote: anticat
      revision: master
      path: modules/drv/tpm-tis-spi

    - name: tpm2-tss
      remote: anticat
      revision:  master
      path: modules/lib/tpm2-tss/import

    - name: tpm2-tss-zephyr
      remote: anticat
      revision: master
      path: modules/lib/tpm2-tss
```

