#ifndef CANOKEY_CRYPTO_ALGO_H
#define CANOKEY_CRYPTO_ALGO_H

#include <stddef.h>

typedef enum {
  SECP256R1,
  SECP256K1,
  SECP384R1,
  SM2,
  ED25519,
  X25519,
  RSA2048,
  RSA3072,
  RSA4096,
  KEY_TYPE_PKC_END,
  TDEA,
  AES128,
  AES256,
} key_type_t;

extern const size_t PRIVATE_KEY_LENGTH[KEY_TYPE_PKC_END];
extern const size_t PUBLIC_KEY_LENGTH[KEY_TYPE_PKC_END];
extern const size_t SIGNATURE_LENGTH[KEY_TYPE_PKC_END];

#define IS_ECC(type) ((type) == SECP256R1 || (type) == SECP256K1 || (type) == SECP384R1 || (type) == SM2 || (type) == ED25519 || (type) == X25519)
#define IS_SHORT_WEIERSTRASS(type) ((type) == SECP256R1 || (type) == SECP256K1 || (type) == SECP384R1 || (type) == SM2)
#define IS_RSA(type) ((type) == RSA2048 || (type) == RSA3072 || (type) == RSA4096)

#endif // CANOKEY_CRYPTO_ALGO_H
