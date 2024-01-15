// Modified from https://github.com/AyrA/sm3/blob/master/sm3.c (Dec 24, 2023)
//
// MIT License
//
// Copyright (c) 2019 Kevin Gut
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "sm3.h"
#include <string.h>

#ifdef USE_MBEDCRYPTO
typedef struct {
  uint32_t digest[8];
  int nblocks;
  unsigned char block[64];
  int num;
} sm3_ctx_t;

static sm3_ctx_t ctx;
static void sm3_compress(uint32_t digest[8], const unsigned char block[64]);
#endif

__attribute__((weak)) void sm3_init(void) {
#ifdef USE_MBEDCRYPTO
  ctx.digest[0] = 0x7380166F;
  ctx.digest[1] = 0x4914B2B9;
  ctx.digest[2] = 0x172442D7;
  ctx.digest[3] = 0xDA8A0600;
  ctx.digest[4] = 0xA96F30BC;
  ctx.digest[5] = 0x163138AA;
  ctx.digest[6] = 0xE38DEE4D;
  ctx.digest[7] = 0xB0FB0E4E;

  ctx.nblocks = 0;
  ctx.num = 0;
#endif
}

__attribute__((weak)) void sm3_update(const uint8_t *data, uint16_t len) {
#ifdef USE_MBEDCRYPTO
  if (ctx.num) {
    const unsigned int left = SM3_BLOCK_LENGTH - ctx.num;
    if (len < left) {
      memcpy(ctx.block + ctx.num, data, len);
      ctx.num += len;
      return;
    } else {
      memcpy(ctx.block + ctx.num, data, left);
      sm3_compress(ctx.digest, ctx.block);
      ctx.nblocks++;
      data += left;
      len -= left;
    }
  }
  while (len >= SM3_BLOCK_LENGTH) {
    sm3_compress(ctx.digest, data);
    ctx.nblocks++;
    data += SM3_BLOCK_LENGTH;
    len -= SM3_BLOCK_LENGTH;
  }
  ctx.num = len;
  if (len) {
    memcpy(ctx.block, data, len);
  }
#else
  (void)data;
  (void)len;
#endif
}

__attribute__((weak)) void sm3_final(uint8_t digest[SM3_DIGEST_LENGTH]) {
#ifdef USE_MBEDCRYPTO
  unsigned int i;
  uint32_t *pdigest = (uint32_t *)digest;
  uint32_t *count = (uint32_t *)(ctx.block + SM3_BLOCK_LENGTH - 8);

  ctx.block[ctx.num] = 0x80;

  if (ctx.num + 9 <= SM3_BLOCK_LENGTH) {
    memset(ctx.block + ctx.num + 1, 0, SM3_BLOCK_LENGTH - ctx.num - 9);
  } else {
    memset(ctx.block + ctx.num + 1, 0, SM3_BLOCK_LENGTH - ctx.num - 1);
    sm3_compress(ctx.digest, ctx.block);
    memset(ctx.block, 0, SM3_BLOCK_LENGTH - 8);
  }

  count[0] = __builtin_bswap32(ctx.nblocks >> 23);
  count[1] = __builtin_bswap32((ctx.nblocks << 9) + (ctx.num << 3));

  sm3_compress(ctx.digest, ctx.block);
  for (i = 0; i < sizeof(ctx.digest) / sizeof(ctx.digest[0]); i++) {
    pdigest[i] = __builtin_bswap32(ctx.digest[i]);
  }
#else
  (void)digest;
#endif
}

#ifdef USE_MBEDCRYPTO
#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

void sm3_compress(uint32_t digest[8], const unsigned char block[64]) {
  int j;
  uint32_t W[68], W1[64];
  const uint32_t *pblock = (const uint32_t *)block;

  uint32_t A = digest[0];
  uint32_t B = digest[1];
  uint32_t C = digest[2];
  uint32_t D = digest[3];
  uint32_t E = digest[4];
  uint32_t F = digest[5];
  uint32_t G = digest[6];
  uint32_t H = digest[7];
  uint32_t SS1, SS2, TT1, TT2, T[64];

  for (j = 0; j < 16; j++) {
    W[j] = __builtin_bswap32(pblock[j]);
  }
  for (j = 16; j < 68; j++) {
    W[j] = P1(W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13], 7) ^ W[j - 6];;
  }
  for (j = 0; j < 64; j++) {
    W1[j] = W[j] ^ W[j + 4];
  }

  for (j = 0; j < 16; j++) {

    T[j] = 0x79CC4519;
    SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
    SS2 = SS1 ^ ROTATELEFT(A, 12);
    TT1 = FF0(A, B, C) + D + SS2 + W1[j];
    TT2 = GG0(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTATELEFT(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTATELEFT(F, 19);
    F = E;
    E = P0(TT2);
  }

  for (j = 16; j < 64; j++) {

    T[j] = 0x7A879D8A;
    SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
    SS2 = SS1 ^ ROTATELEFT(A, 12);
    TT1 = FF1(A, B, C) + D + SS2 + W1[j];
    TT2 = GG1(E, F, G) + H + SS1 + W[j];
    D = C;
    C = ROTATELEFT(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = ROTATELEFT(F, 19);
    F = E;
    E = P0(TT2);
  }

  digest[0] ^= A;
  digest[1] ^= B;
  digest[2] ^= C;
  digest[3] ^= D;
  digest[4] ^= E;
  digest[5] ^= F;
  digest[6] ^= G;
  digest[7] ^= H;
}
#endif

void sm3_raw(const uint8_t *data, size_t len, uint8_t digest[SM3_DIGEST_LENGTH]) {
  sm3_init();
  sm3_update(data, len);
  sm3_final(digest);
}
