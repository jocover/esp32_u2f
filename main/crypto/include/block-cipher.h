/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_BLOCK_CIPHER_H
#define CANOKEY_CRYPTO_BLOCK_CIPHER_H

#include <stddef.h>
#include <stdint.h>

enum BLOCK_CIPHER_MODE { ECB, CBC, CFB, OFB, CTR };

typedef struct {
  enum BLOCK_CIPHER_MODE mode;
  const uint8_t *in;
  size_t in_size;
  uint8_t *out;
  const uint8_t *iv;
  const uint8_t *key;
  uint8_t block_size;
  int (*encrypt)(const uint8_t *in, uint8_t *out, const uint8_t *key);
  int (*decrypt)(const uint8_t *in, uint8_t *out, const uint8_t *key);
} block_cipher_config;

int block_cipher_enc(block_cipher_config *cfg);
int block_cipher_dec(block_cipher_config *cfg);

#endif
