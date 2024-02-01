#ifndef ESP32_ED25519_H_
#define ESP32_ED25519_H_

#include <stdint.h>


//Length of EdDSA private keys
#define ED25519_PRIVATE_KEY_LEN 32
//Length of EdDSA public keys
#define ED25519_PUBLIC_KEY_LEN 32
//Length of EdDSA signatures
#define ED25519_SIGNATURE_LEN 64

//Ed25519ph flag
#define ED25519_PH_FLAG 1
//Prehash function output size
#define ED25519_PH_SIZE 64

typedef struct
{
   uint32_t x[8];
   uint32_t y[8];
   uint32_t z[8];
   uint32_t t[8];
} Ed25519Point;

typedef struct
{
   uint8_t k[64];
   uint8_t p[32];
   uint8_t r[32];
   uint8_t s[32];
   Ed25519Point ka;
   Ed25519Point rb;
   Ed25519Point sb;
   Ed25519Point u;
   Ed25519Point v;
   uint32_t a[8];
   uint32_t b[8];
   uint32_t c[8];
   uint32_t d[8];
   uint32_t e[8];
   uint32_t f[8];
   uint32_t g[8];
   uint32_t h[8];
} Ed25519State;

int ed25519GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey);

int ed25519GenerateSignature(const uint8_t *privateKey,
   const uint8_t *publicKey, const void *message, size_t messageLen,
   const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature);

#endif