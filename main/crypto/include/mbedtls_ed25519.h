#ifndef MBEDTLS_ED25519_H_
#define MBEDTLS_ED25519_H_

#include <stdint.h>

#define EDSIGN_SECRET_KEY_SIZE 32

/* Given a secret key, produce the public key (a packed Edwards-curve
 * point).
 */
#define EDSIGN_PUBLIC_KEY_SIZE 32



void mbedtls_edsign_sec_to_pub(uint8_t *pub, const uint8_t *secret);

/* Produce a signature for a message. */
#define EDSIGN_SIGNATURE_SIZE 64

void mbedtls_edsign_sign(uint8_t *signature, const uint8_t *pub,
                 const uint8_t *secret,
                 const uint8_t *message, size_t len);


#endif