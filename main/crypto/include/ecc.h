/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_ECC_H
#define CANOKEY_CRYPTO_ECC_H

#include <algo.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_EC_PRIVATE_KEY 68
#define MAX_EC_PUBLIC_KEY 132

typedef struct {
  uint8_t pri[MAX_EC_PRIVATE_KEY];
  uint8_t pub[MAX_EC_PUBLIC_KEY];
} ecc_key_t;

extern const uint8_t SM2_ID_DEFAULT[];

void swap_big_number_endian(uint8_t buf[32]);

/**
 * Generate an ECDSA key pair
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the generated key
 *
 * @return 0: Success, -1: Error
 */
int ecc_generate(key_type_t type, ecc_key_t *key);

/**
 * Verify the given private key.
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 1: verified, 0: not verified
 */
int ecc_verify_private_key(key_type_t type, ecc_key_t *key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 0: Success, -1: Error
 */
int ecc_complete_key(key_type_t type, ecc_key_t *key);

/**
 * Sign the given data or digest
 *
 * @param type           ECC algorithm
 * @param key            Pointer to the key
 * @param data_or_digest The data (for ED25519) or the digest (for other algorithms)
 * @param sig            The output buffer
 *
 * @return 0: Success, -1: Error
 */
int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig);

/**
 * Convert r,s signature to ANSI X9.62 format
 *
 * @param key_len Length of the key
 * @param input   The original signature
 * @param output  ANSI X9.62 format. The buffer should be at least 2 * key_size + 6 bytes. The buffer can be identical
 * to the input.
 *
 * @return Length of signature
 */
size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output);

/**
 * Compute Z specified by SM2
 *
 * @param id    User's ID. The first byte contains the length and followed by the ID.
 * @param key   Pointer to the key
 * @param z     The output buffer
 *
 * @return 0: Success, -1: Error
 */
int sm2_z(const uint8_t *id, const ecc_key_t *key, uint8_t *z);

/**
 * Compute ECDH result
 *
 * @param type              ECC algorithm
 * @param priv_key          The private key s
 * @param receiver_pub_key  The receiver's public key P
 * @param out               s*P
 *
 * @return 0: Success, -1: Error
 */
int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

// Below types and functions should not be used in canokey-core

/**
 * Generate an ECDSA key pair
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the generated key
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_generate(key_type_t type, ecc_key_t *key);

/**
 * Verify the given private key.
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 1: verified, 0: not verified
 */
int K__short_weierstrass_verify_private_key(const key_type_t type, const ecc_key_t *key);

/**
 * Compute the corresponding public key using the private key
 *
 * @param type      ECC algorithm
 * @param key       Pointer to the key
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_complete_key(key_type_t type, ecc_key_t *key);

/**
 * Sign the given data or digest
 *
 * @param type           ECC algorithm
 * @param key            Pointer to the key
 * @param data_or_digest The data (for ED25519) or the digest (for other algorithms)
 * @param sig            The output buffer
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig);

/**
 * Compute ECDH result
 *
 * @param type              ECC algorithm
 * @param priv_key          The private key s
 * @param receiver_pub_key  The receiver's public key P
 * @param out               s*P
 *
 * @return 0: Success, -1: Error
 */
int K__short_weierstrass_ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out);

typedef unsigned char K__ed25519_signature[64];
typedef unsigned char K__ed25519_public_key[32];
typedef unsigned char K__ed25519_secret_key[32];
typedef unsigned char K__x25519_key[32];

/**
 * Calculate public key from private key
 *
 * @param sk Input private key
 * @param pk Output public key
*/
void K__ed25519_publickey(const K__ed25519_secret_key sk, K__ed25519_public_key pk);

/**
 * Calculate Ed25519 signature of data
 *
 * @param m Input data
 * @param mlen Length of data
 * @param sk Private key
 * @param pk Public key
 * @param rs Output signature
*/
void K__ed25519_sign(const unsigned char *m, size_t mlen, const K__ed25519_secret_key sk,
                     const K__ed25519_public_key pk, K__ed25519_signature rs);

/**
 * Calculate shared_secret = private_key * public_key, the second step of X25519
 *
 * Note: X25519 spec uses little endian, but we use big endian here
 *
 * @param shared_secret Shared secret in big endian
 * @param private_key Valid private key in big endian
 * @param public_key Public key in big endian
*/
void K__x25519(K__x25519_key shared_secret, const K__x25519_key private_key, const K__x25519_key public_key);

#endif
