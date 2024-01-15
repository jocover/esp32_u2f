/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_RSA_H_
#define CANOKEY_CRYPTO_RSA_H_

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#define RSA_N_BIT_MAX 4096
#define E_LENGTH 4
#define PQ_LENGTH_MAX (RSA_N_BIT_MAX / 16)

typedef struct {
  uint16_t nbits;
  alignas(4) uint8_t e[E_LENGTH];
  alignas(4) uint8_t p[PQ_LENGTH_MAX];
  alignas(4) uint8_t q[PQ_LENGTH_MAX];
  alignas(4) uint8_t dp[PQ_LENGTH_MAX];
  alignas(4) uint8_t dq[PQ_LENGTH_MAX];
  alignas(4) uint8_t qinv[PQ_LENGTH_MAX];
} rsa_key_t;

/**
 * Generate a new RSA key. We always set e = 65537.
 *
 * @param key   The generated key.
 * @param nbits The size of the public key in bits.
 *
 * @return 0 on success.
 */
int rsa_generate_key(rsa_key_t *key, uint16_t nbits);

/**
 * Compute the public key given a RSA private key.
 *
 * @param key The given private key.
 * @param n   The corresponding public key.
 *
 * @return 0 on success.
 */
int rsa_get_public_key(rsa_key_t *key, uint8_t *n);

/**
 * Compute private key operation, used in sign or decrypt.
 * 
 * @param key The given private key.
 * @param input Input data.
 * @param output Output data.
 *
 * @return 0 on success.
 */
int rsa_private(const rsa_key_t *key, const uint8_t *input, uint8_t *output);

int rsa_sign_pkcs_v15(const rsa_key_t *key, const uint8_t *data, size_t len, uint8_t *sig);

int rsa_decrypt_pkcs_v15(const rsa_key_t *key, const uint8_t *in, size_t *olen, uint8_t *out, uint8_t *invalid_padding);

#endif
