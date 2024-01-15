/* SPDX-License-Identifier: Apache-2.0 */
#ifndef CANOKEY_CRYPTO_SM3_H_
#define CANOKEY_CRYPTO_SM3_H_

#include <stddef.h>
#include <stdint.h>

#define SM3_BLOCK_LENGTH 64
#define SM3_DIGEST_LENGTH 32

void sm3_init(void);
void sm3_update(const uint8_t *data, uint16_t len);
void sm3_final(uint8_t digest[SM3_DIGEST_LENGTH]);
void sm3_raw(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_LENGTH]);

#endif
