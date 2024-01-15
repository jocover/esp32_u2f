// SPDX-License-Identifier: Apache-2.0
#include <aes.h>
#ifdef USE_MBEDCRYPTO
#include <mbedtls/aes.h>

static int aes(const void *in, void *out, const void *key, int keybits, int mode) {
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int ret;
  if (mode == MBEDTLS_AES_ENCRYPT)
    ret = mbedtls_aes_setkey_enc(&aes, key, keybits);
  else
    ret = mbedtls_aes_setkey_dec(&aes, key, keybits);
  if (ret < 0) return -1;
  mbedtls_aes_crypt_ecb(&aes, mode, in, out);
  return 0;
}
#endif

__attribute__((weak)) int aes128_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes(in, out, key, 128, MBEDTLS_AES_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes128_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes(in, out, key, 128, MBEDTLS_AES_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_enc(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes(in, out, key, 256, MBEDTLS_AES_ENCRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int aes256_dec(const uint8_t *in, uint8_t *out, const uint8_t *key) {
#ifdef USE_MBEDCRYPTO
  return aes(in, out, key, 256, MBEDTLS_AES_DECRYPT);
#else
  (void)in;
  (void)out;
  (void)key;
  return 0;
#endif
}
