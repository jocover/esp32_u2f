/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_SHA_H_
#define CANOKEY_CRYPTO_SHA_H_

#include <stddef.h>
#include <stdint.h>

#define SHA1_BLOCK_LENGTH 64
#define SHA1_DIGEST_LENGTH 20
#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64

void sha1_init(void);
void sha1_update(const uint8_t *data, uint16_t len);
void sha1_final(uint8_t digest[SHA1_DIGEST_LENGTH]);
void sha1_raw(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]);
void sha256_init(void);
void sha256_update(const uint8_t *data, uint16_t len);
void sha256_final(uint8_t digest[SHA256_DIGEST_LENGTH]);
void sha256_raw(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LENGTH]);
void sha512_init(void);
void sha512_update(const uint8_t *data, uint16_t len);
void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH]);
void sha512_raw(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]);

#include "sha3.h"

#endif
