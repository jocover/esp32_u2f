// SPDX-License-Identifier: Apache-2.0
#include <des.h>
#ifdef USE_MBEDCRYPTO
#include <mbedtls/des.h>
#endif

__attribute__((weak)) int des_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_enc(&ctx, key);
  if (mbedtls_des_crypt_ecb(&ctx, in, out) < 0) return -1;
  mbedtls_des_free(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int des_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_des_context ctx;
  mbedtls_des_init(&ctx);
  mbedtls_des_setkey_dec(&ctx, key);
  if (mbedtls_des_crypt_ecb(&ctx, in, out) < 0) return -1;
  mbedtls_des_free(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int tdes_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_des3_context ctx;
  mbedtls_des3_init(&ctx);
  mbedtls_des3_set3key_enc(&ctx, key);
  if (mbedtls_des3_crypt_ecb(&ctx, in, out) < 0) return -1;
  mbedtls_des3_free(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int tdes_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_des3_context ctx;
  mbedtls_des3_init(&ctx);
  mbedtls_des3_set3key_dec(&ctx, key);
  if (mbedtls_des3_crypt_ecb(&ctx, in, out) < 0) return -1;
  mbedtls_des3_free(&ctx);
  return 0;
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}
