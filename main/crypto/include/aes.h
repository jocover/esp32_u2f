/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_AES_H
#define CANOKEY_CRYPTO_AES_H

#include <stdint.h>

/**
 * The AES functions all encrypt only one block.
 * To invoke them, you should use the functions provided in block-cipher.h
 */

int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key);
int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key);

#endif
