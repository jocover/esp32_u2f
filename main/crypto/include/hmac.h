/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT HMAC_SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __HMAC_H__
#define __HMAC_H__

#include <sha.h>
#include <stddef.h>
#include <stdint.h>

#define SHA1_BLOCK_LENGTH 64
#define SHA1_DIGEST_LENGTH 20
#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64

typedef struct _HMAC_SHA1_CTX {
  uint8_t o_key_pad[SHA1_BLOCK_LENGTH];
} HMAC_SHA1_CTX;

typedef struct _HMAC_SHA256_CTX {
  uint8_t o_key_pad[SHA256_BLOCK_LENGTH];
} HMAC_SHA256_CTX;

typedef struct _HMAC_SHA512_CTX {
  uint8_t o_key_pad[SHA512_BLOCK_LENGTH];
} HMAC_SHA512_CTX;

void hmac_sha1_Init(HMAC_SHA1_CTX *hctx, const uint8_t *key, size_t keylen);
void hmac_sha1_Update(const HMAC_SHA1_CTX *hctx, const uint8_t *msg, size_t msglen);
void hmac_sha1_Final(HMAC_SHA1_CTX *hctx, uint8_t *hmac);
void hmac_sha1(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen, uint8_t *hmac);

void hmac_sha256_Init(HMAC_SHA256_CTX *hctx, const uint8_t *key, size_t keylen);
void hmac_sha256_Update(const HMAC_SHA256_CTX *hctx, const uint8_t *msg, size_t msglen);
void hmac_sha256_Final(HMAC_SHA256_CTX *hctx, uint8_t *hmac);
void hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen, uint8_t *hmac);

void hmac_sha512_Init(HMAC_SHA512_CTX *hctx, const uint8_t *key, size_t keylen);
void hmac_sha512_Update(const HMAC_SHA512_CTX *hctx, const uint8_t *msg, size_t msglen);
void hmac_sha512_Final(HMAC_SHA512_CTX *hctx, uint8_t *hmac);
void hmac_sha512(const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen, uint8_t *hmac);

#endif
