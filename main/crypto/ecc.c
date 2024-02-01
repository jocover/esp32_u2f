// SPDX-License-Identifier: Apache-2.0
#include <ecc.h>
#include <memzero.h>
#include <rand.h>
#include <sm3.h>
#include <string.h>
#include "esp32_ed25519.h"

const uint8_t SM2_ID_DEFAULT[] = {0x10, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35,
                                  0x36, 0x37, 0x38};

#ifdef USE_MBEDCRYPTO
#include <sha.h>
#include <bn_mul.h>
#include <mbedtls/ecdsa.h>


typedef unsigned char K__ed25519_signature[64];
typedef unsigned char K__ed25519_public_key[32];
typedef unsigned char K__ed25519_secret_key[32];
typedef unsigned char K__x25519_key[32];


static const uint8_t grp_id[] = {
    [SECP256R1] = MBEDTLS_ECP_DP_SECP256R1,
    [SECP256K1] = MBEDTLS_ECP_DP_SECP256K1,
    [SECP384R1] = MBEDTLS_ECP_DP_SECP384R1,
};

/* SM2 uses 256 bit unsigned integers in big endian format */
#define SM2_INT_SIZE_BYTES 32

static const mbedtls_mpi_uint sm2_p[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF),
};
static const mbedtls_mpi_uint sm2_a[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF),
};
static const mbedtls_mpi_uint sm2_b[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0x93, 0x0E, 0x94, 0x4D, 0x41, 0xBD, 0xBC, 0xDD),
    MBEDTLS_BYTES_TO_T_UINT_8(0x92, 0x8F, 0xAB, 0x15, 0xF5, 0x89, 0x97, 0xF3),
    MBEDTLS_BYTES_TO_T_UINT_8(0xA7, 0x09, 0x65, 0xCF, 0x4B, 0x9E, 0x5A, 0x4D),
    MBEDTLS_BYTES_TO_T_UINT_8(0x34, 0x5E, 0x9F, 0x9D, 0x9E, 0xFA, 0xE9, 0x28),
};
static const mbedtls_mpi_uint sm2_gx[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0xC7, 0x74, 0x4C, 0x33, 0x89, 0x45, 0x5A, 0x71),
    MBEDTLS_BYTES_TO_T_UINT_8(0xE1, 0x0B, 0x66, 0xF2, 0xBF, 0x0B, 0xE3, 0x8F),
    MBEDTLS_BYTES_TO_T_UINT_8(0x94, 0xC9, 0x39, 0x6A, 0x46, 0x04, 0x99, 0x5F),
    MBEDTLS_BYTES_TO_T_UINT_8(0x19, 0x81, 0x19, 0x1F, 0x2C, 0xAE, 0xC4, 0x32),
};
static const mbedtls_mpi_uint sm2_gy[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0xA0, 0xF0, 0x39, 0x21, 0xE5, 0x32, 0xDF, 0x02),
    MBEDTLS_BYTES_TO_T_UINT_8(0x40, 0x47, 0x2A, 0xC6, 0x7C, 0x87, 0xA9, 0xD0),
    MBEDTLS_BYTES_TO_T_UINT_8(0x53, 0x21, 0x69, 0x6B, 0xE3, 0xCE, 0xBD, 0x59),
    MBEDTLS_BYTES_TO_T_UINT_8(0x9C, 0x77, 0xF6, 0xF4, 0xA2, 0x36, 0x37, 0xBC),
};
static const mbedtls_mpi_uint sm2_n[] = {
    MBEDTLS_BYTES_TO_T_UINT_8(0x23, 0x41, 0xD5, 0x39, 0x09, 0xF4, 0xBB, 0x53),
    MBEDTLS_BYTES_TO_T_UINT_8(0x2B, 0x05, 0xC6, 0x21, 0x6B, 0xDF, 0x03, 0x72),
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
    MBEDTLS_BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF),
};

#define LOAD_GROUP_A(G)                                                                                                \
  ecp_group_load(&grp, G##_p, sizeof(G##_p), G##_a, sizeof(G##_a), G##_b, sizeof(G##_b), G##_gx, sizeof(G##_gx),       \
                 G##_gy, sizeof(G##_gy), G##_n, sizeof(G##_n))

/*
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof mbedtls_mpi_uint)
 */
static inline void ecp_mpi_load(mbedtls_mpi *X, const mbedtls_mpi_uint *p, size_t len) {
  X->MBEDTLS_PRIVATE(s) = 1;
  X->MBEDTLS_PRIVATE(n) = len / sizeof(mbedtls_mpi_uint);
  X->MBEDTLS_PRIVATE(p) = (mbedtls_mpi_uint *)p;
}

/*
 * Set an MPI to static value 1
 */
static inline void ecp_mpi_set1(mbedtls_mpi *X) {
  static mbedtls_mpi_uint one[] = {1};
  X->MBEDTLS_PRIVATE(s) = 1;
  X->MBEDTLS_PRIVATE(n) = 1;
  X->MBEDTLS_PRIVATE(p) = one;
}

/*
 * Make group available from embedded constants
 */
static int ecp_group_load(mbedtls_ecp_group *grp, const mbedtls_mpi_uint *p, size_t plen, const mbedtls_mpi_uint *a,
                          size_t alen, const mbedtls_mpi_uint *b, size_t blen, const mbedtls_mpi_uint *gx, size_t gxlen,
                          const mbedtls_mpi_uint *gy, size_t gylen, const mbedtls_mpi_uint *n, size_t nlen) {
  ecp_mpi_load(&grp->P, p, plen);
  if (a != NULL) ecp_mpi_load(&grp->A, a, alen);
  ecp_mpi_load(&grp->B, b, blen);
  ecp_mpi_load(&grp->N, n, nlen);

  ecp_mpi_load(&grp->G.MBEDTLS_PRIVATE(X), gx, gxlen);
  ecp_mpi_load(&grp->G.MBEDTLS_PRIVATE(Y), gy, gylen);
  ecp_mpi_set1(&grp->G.MBEDTLS_PRIVATE(Z));

  grp->pbits = mbedtls_mpi_bitlen(&grp->P);
  grp->nbits = mbedtls_mpi_bitlen(&grp->N);

  grp->MBEDTLS_PRIVATE(h) = 1;

  return (0);
}

/* Generate random number 1 <= n < max */
static int mbed_gen_random_upto(mbedtls_mpi *n, mbedtls_mpi *max) {
  size_t sz = mbedtls_mpi_size(max);
  int found = 0;
  int mres = 0;

  do {
    mres = mbedtls_mpi_fill_random(n, sz, mbedtls_rnd, NULL);
    if (mres) return 1;
    if (mbedtls_mpi_bitlen(n) != 0 && mbedtls_mpi_cmp_mpi(n, max) == -1) found = 1;
  } while (!found);

  return 0;
}

/*
 * GM/T 0003.1‒2012 Part1 2 Section 6.1
 */
int sm2_mbedtls_dsa_sign(uint32_t algo, mbedtls_mpi *key, const uint8_t *msg, size_t msg_len, uint8_t *sig,
                         size_t *sig_len) {
  int res = 0;
  mbedtls_ecp_group grp = {};
  mbedtls_ecp_point x1y1p = {};
  int mres = 0;
  mbedtls_mpi k = {};
  mbedtls_mpi e = {};
  mbedtls_mpi r = {};
  mbedtls_mpi s = {};
  mbedtls_mpi tmp = {};

  if (*sig_len < 2 * SM2_INT_SIZE_BYTES) {
    *sig_len = 64;
    return -1;
  }

  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&tmp);

  mbedtls_ecp_point_init(&x1y1p);

  mbedtls_ecp_group_init(&grp);
  mres = LOAD_GROUP_A(sm2);
  if (mres) {
    res = -1;
    goto out;
  }

  /*
   * Steps A1 and A2 are the generation of the hash value e from user
   * information (ZA) and the message to be signed (M). There are not done
   * here since @msg is expected to be the hash value e already.
   */

  /* Step A3: generate random number 1 <= k < n */
  do {
    res = mbed_gen_random_upto(&k, &grp.N);
    if (res) goto out;

    res = -1;

    /* Step A4: compute (x1, y1) = [k]G */
    mres = mbedtls_ecp_mul(&grp, &x1y1p, &k, &grp.G, mbedtls_rnd, NULL);
    if (mres) goto out;

    /* Step A5: compute r = (e + x1) mod n */
    mbedtls_mpi_read_binary(&e, (unsigned char *)msg, msg_len);
    mres = mbedtls_mpi_add_mpi(&r, &e, &x1y1p.MBEDTLS_PRIVATE(X));
    if (mres) goto out;
    mres = mbedtls_mpi_mod_mpi(&r, &r, &grp.N);
    if (mres) goto out;

    /* Step A5 (continued): return to A3 if r = 0 or r + k = n */
    mres = mbedtls_mpi_add_mpi(&tmp, &r, &k);
    if (mres) goto out;
  } while (!mbedtls_mpi_cmp_int(&r, 0) || !mbedtls_mpi_cmp_mpi(&tmp, &grp.N));

  /* Step A6: compute s = ((1 + dA)^-1 * (k - r*dA)) mod n */
  mres = mbedtls_mpi_add_int(&s, key, 1);
  if (mres) goto out;
  mres = mbedtls_mpi_inv_mod(&s, &s, &grp.N);
  if (mres) goto out;
  mres = mbedtls_mpi_mul_mpi(&tmp, &r, key);
  if (mres) goto out;
  mres = mbedtls_mpi_mod_mpi(&tmp, &tmp, &grp.N);
  if (mres) goto out;
  mres = mbedtls_mpi_sub_mpi(&tmp, &k, &tmp);
  if (mres) goto out;
  mres = mbedtls_mpi_mul_mpi(&s, &s, &tmp);
  if (mres) goto out;
  mres = mbedtls_mpi_mod_mpi(&s, &s, &grp.N);
  if (mres) goto out;

  /* Step A7: convert (r, s) to binary for output */
  *sig_len = 2 * SM2_INT_SIZE_BYTES;
  memset(sig, 0, *sig_len);
  mres = mbedtls_mpi_write_binary(&r, sig, SM2_INT_SIZE_BYTES);
  if (mres) goto out;
  mres = mbedtls_mpi_write_binary(&s, sig + SM2_INT_SIZE_BYTES, SM2_INT_SIZE_BYTES);
  if (mres) goto out;

  res = 0;
out:
  mbedtls_ecp_point_free(&x1y1p);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&tmp);
  mbedtls_ecp_group_free(&grp);
  return res;
}
#endif

static const K__ed25519_public_key gx = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9};

static void x25519_key_from_random(K__x25519_key private_key) {
  private_key[31] &= 0xf8;
  private_key[0] &= 0x7f;
  private_key[0] |= 0x40;
}

void swap_big_number_endian(uint8_t buf[32]) {
  for (int i = 0; i < 16; ++i) {
    uint8_t tmp = buf[31 - i];
    buf[31 - i] = buf[i];
    buf[i] = tmp;
  }
}

int ecc_generate(key_type_t type, ecc_key_t *key) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_generate(type, key);
  } else { // ed25519 & x25519
    random_buffer(key->pri, PRIVATE_KEY_LENGTH[type]);
    if (type == ED25519) {
      K__ed25519_publickey(key->pri, key->pub);
    } else {
      x25519_key_from_random(key->pri);
      K__x25519(key->pub, key->pri, gx);
    }
    return 0;
  }
}

int ecc_sign(key_type_t type, const ecc_key_t *key, const uint8_t *data_or_digest, size_t len, uint8_t *sig) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_sign(type, key, data_or_digest, len, sig);
  } else { // ed25519 & x25519
    if (type == X25519) return -1;
    K__ed25519_signature sig_buf;
    K__ed25519_sign(data_or_digest, len, key->pri, key->pub, sig_buf);
    memcpy(sig, sig_buf, SIGNATURE_LENGTH[ED25519]);
    return 0;
  }
}

int ecc_verify_private_key(key_type_t type, ecc_key_t *key) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_verify_private_key(type, key);
  } else { // ed25519 & x25519
    return 1;
  }
}

int ecc_complete_key(key_type_t type, ecc_key_t *key) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_complete_key(type, key);
  } else { // ed25519 & x25519
    if (type == ED25519) {
      K__ed25519_publickey(key->pri, key->pub);
    } else {
      K__x25519(key->pub, key->pri, gx);
    }
    return 0;
  }
}

int ecdh(key_type_t type, const uint8_t *priv_key, const uint8_t *receiver_pub_key, uint8_t *out) {
  if (!IS_ECC(type)) return -1;

  if (IS_SHORT_WEIERSTRASS(type)) {
    return K__short_weierstrass_ecdh(type, priv_key, receiver_pub_key, out);
  } else { // ed25519 & x25519
    if (type == ED25519) return -1;
    uint8_t pub[32];
    memcpy(pub, receiver_pub_key, 32);
    swap_big_number_endian(pub);
    K__x25519(out, priv_key, pub);
    swap_big_number_endian(out);
    return 0;
  }
}

size_t ecdsa_sig2ansi(uint8_t key_len, const uint8_t *input, uint8_t *output) {
  int leading_zero_len1 = 0;
  int leading_zero_len2 = 0;
  for (uint8_t i = 0; i < key_len; ++i)
    if (input[i] == 0)
      ++leading_zero_len1;
    else {
      if (input[i] >= 0x80) --leading_zero_len1;
      break;
    }
  for (uint8_t i = key_len; i < key_len * 2; ++i)
    if (input[i] == 0)
      ++leading_zero_len2;
    else {
      if (input[i] >= 0x80) --leading_zero_len2;
      break;
    }
  uint8_t part1_len = key_len - leading_zero_len1;
  uint8_t part2_len = key_len - leading_zero_len2;
  if (leading_zero_len1 < 0) leading_zero_len1 = 0;
  if (leading_zero_len2 < 0) leading_zero_len2 = 0;
  memmove(output + 6 + part1_len + (part2_len == key_len + 1 ? 1 : 0), input + key_len + leading_zero_len2,
          key_len - leading_zero_len2);
  memmove(output + 4 + (part1_len == key_len + 1 ? 1 : 0), input + leading_zero_len1, key_len - leading_zero_len1);
  output[0] = 0x30;
  output[1] = part1_len + part2_len + 4;
  output[2] = 0x02;
  output[3] = part1_len;
  if (part1_len == key_len + 1) output[4] = 0;
  output[4 + part1_len] = 0x02;
  output[5 + part1_len] = part2_len;
  if (part2_len == key_len + 1) output[6 + part1_len] = 0;
  return 6 + part1_len + part2_len;
}

__attribute__((weak)) int sm2_z(const uint8_t *id, const ecc_key_t *key, uint8_t *z) {
  const uint8_t a[] = {0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
  const uint8_t b[] = {0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
                       0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93};
  const uint8_t xg[] = {0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
                        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7};
  const uint8_t yg[] = {0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
                        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0};
  const uint8_t entl[2] = {id[0] * 8 >> 8, id[0] * 8 & 0xFF};

  sm3_init();
  sm3_update(entl, sizeof(entl));
  sm3_update(id + 1, id[0]);
  sm3_update(a, sizeof(a));
  sm3_update(b, sizeof(b));
  sm3_update(xg, sizeof(xg));
  sm3_update(yg, sizeof(yg));
  sm3_update(key->pub, PUBLIC_KEY_LENGTH[SM2]);
  sm3_final(z);

  return 0;
}

__attribute__((weak)) int K__short_weierstrass_generate(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  if (type == SM2) {
    int res = 0;
    mbedtls_ecp_group grp = {};
    mbedtls_ecp_point x1y1p = {};
    int mres = 0;
    mbedtls_mpi k = {};
    mbedtls_mpi_init(&k);
    mbedtls_ecp_point_init(&x1y1p);
    mbedtls_ecp_group_init(&grp);
    mres = LOAD_GROUP_A(sm2);
    do {
      res = mbed_gen_random_upto(&k, &grp.N);
      if (res) goto out;
      res = -1;
      mres = mbedtls_ecp_mul(&grp, &x1y1p, &k, &grp.G, mbedtls_rnd, NULL);
      if (mres) goto out;
    } while (!mbedtls_mpi_cmp_mpi(&k, &grp.N));
    res = 0;
    mbedtls_mpi_write_binary(&k, key->pri, SM2_INT_SIZE_BYTES);
    mbedtls_mpi_write_binary(&x1y1p.MBEDTLS_PRIVATE(X), key->pub, SM2_INT_SIZE_BYTES);
    mbedtls_mpi_write_binary(&x1y1p.MBEDTLS_PRIVATE(Y), key->pub + SM2_INT_SIZE_BYTES, SM2_INT_SIZE_BYTES);
  out:
    mbedtls_ecp_point_free(&x1y1p);
    mbedtls_mpi_free(&k);
    mbedtls_ecp_group_free(&grp);
    return res;
  }

  mbedtls_ecp_keypair keypair;
  mbedtls_ecp_keypair_init(&keypair);

  mbedtls_ecp_gen_key(grp_id[type], &keypair, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&keypair.MBEDTLS_PRIVATE(d), key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&keypair.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), key->pub, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&keypair.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y), key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_ecp_keypair_free(&keypair);
#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int K__short_weierstrass_verify_private_key(key_type_t type, const ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_mpi d;
  mbedtls_ecp_group grp;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);

  if (type == SM2) {
    LOAD_GROUP_A(sm2);
  } else {
    mbedtls_ecp_group_load(&grp, grp_id[type]);
  }
  mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
  int res = mbedtls_ecp_check_privkey(&grp, &d) == 0 ? 1 : 0;

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return res;
#else
  (void)type;
  (void)key;
  return 0;
#endif
}

__attribute__((weak)) int K__short_weierstrass_complete_key(key_type_t type, ecc_key_t *key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_mpi d;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pnt;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&pnt);

  if (type == SM2) {
    LOAD_GROUP_A(sm2);
  } else {
    mbedtls_ecp_group_load(&grp, grp_id[type]);
  }
  mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_ecp_mul(&grp, &pnt, &d, &grp.G, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&pnt.MBEDTLS_PRIVATE(X), key->pub, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&pnt.MBEDTLS_PRIVATE(Y), key->pub + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&pnt);
#else
  (void)type;
  (void)key;
#endif
  return 0;
}

__attribute__((weak)) int K__short_weierstrass_sign(key_type_t type, const ecc_key_t *key,
                                                    const uint8_t *data_or_digest, size_t len, uint8_t *sig) {
#ifdef USE_MBEDCRYPTO
  if (type == SM2) {
    mbedtls_mpi bn;
    mbedtls_mpi_init(&bn);
    mbedtls_mpi_read_binary(&bn, key->pri, PRIVATE_KEY_LENGTH[type]);
    size_t sig_len = 64;
    int ret = sm2_mbedtls_dsa_sign(0, &bn, data_or_digest, len, sig, &sig_len);
    mbedtls_mpi_free(&bn);
    return ret;
  }

  mbedtls_mpi r, s, d;
  mbedtls_ecp_group grp;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);

  mbedtls_ecp_group_load(&grp, grp_id[type]);
  mbedtls_mpi_read_binary(&d, key->pri, PRIVATE_KEY_LENGTH[type]);
  mbedtls_ecdsa_sign(&grp, &r, &s, &d, data_or_digest, PRIVATE_KEY_LENGTH[type], mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&r, sig, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&s, sig + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
#else
  (void)type;
  (void)key;
  (void)data_or_digest;
  (void)len;
  (void)sig;
#endif
  return 0;
}

__attribute__((weak)) int K__short_weierstrass_ecdh(key_type_t type, const uint8_t *priv_key,
                                                    const uint8_t *receiver_pub_key, uint8_t *out) {
#ifdef USE_MBEDCRYPTO
  mbedtls_mpi d;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pnt;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&pnt);

  if (type == SM2) {
    LOAD_GROUP_A(sm2);
  } else {
    mbedtls_ecp_group_load(&grp, grp_id[type]);
  }
  mbedtls_mpi_read_binary(&d, priv_key, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_read_binary(&pnt.MBEDTLS_PRIVATE(X), receiver_pub_key, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_read_binary(&pnt.MBEDTLS_PRIVATE(Y), receiver_pub_key + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_lset(&pnt.MBEDTLS_PRIVATE(Z), 1);
  mbedtls_ecp_mul(&grp, &pnt, &d, &pnt, mbedtls_rnd, NULL);
  mbedtls_mpi_write_binary(&pnt.MBEDTLS_PRIVATE(X), out, PRIVATE_KEY_LENGTH[type]);
  mbedtls_mpi_write_binary(&pnt.MBEDTLS_PRIVATE(Y), out + PRIVATE_KEY_LENGTH[type], PRIVATE_KEY_LENGTH[type]);

  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  mbedtls_ecp_point_free(&pnt);
#else
  (void)type;
  (void)priv_key;
  (void)receiver_pub_key;
  (void)out;
#endif
  return 0;
}

__attribute__((weak)) void K__ed25519_publickey(const K__ed25519_secret_key sk, K__ed25519_public_key pk) {
  ed25519GeneratePublicKey(sk,pk);
}


__attribute__((weak)) void K__ed25519_sign(const unsigned char *m, size_t mlen, const K__ed25519_secret_key sk,
                                           const K__ed25519_public_key pk, K__ed25519_signature rs) {
  ed25519GenerateSignature(sk,pk,m,mlen,NULL,0,0,rs);

}

__attribute__((weak)) void K__x25519(K__x25519_key shared_secret, const K__x25519_key private_key,
                                     const K__x25519_key public_key) {
#ifdef USE_MBEDCRYPTO
  mbedtls_ecp_point base;
  mbedtls_ecp_point public;
  mbedtls_ecp_group cv25519;
  mbedtls_mpi sk;

  // init
  mbedtls_ecp_point_init(&base);
  mbedtls_ecp_point_init(&public);
  mbedtls_ecp_group_init(&cv25519);
  mbedtls_mpi_init(&sk);

  // load group
  mbedtls_ecp_group_load(&cv25519, MBEDTLS_ECP_DP_CURVE25519);

  // read base point
  mbedtls_mpi_read_binary(&base.MBEDTLS_PRIVATE(X), public_key, 32);
  mbedtls_mpi_free(&base.MBEDTLS_PRIVATE(Y));
  mbedtls_mpi_lset(&base.MBEDTLS_PRIVATE(Z), 1);

  // read secret
  mbedtls_mpi_read_binary(&sk, private_key, 32);

  // multiply scalar
  mbedtls_ecp_mul(&cv25519, &public, &sk, &base, mbedtls_rnd, NULL);

  // write result
  mbedtls_mpi_write_binary(&public.MBEDTLS_PRIVATE(X), shared_secret, 32);

  mbedtls_ecp_point_free(&base);
  mbedtls_ecp_point_free(&public);
  mbedtls_ecp_group_free(&cv25519);
  mbedtls_mpi_free(&sk);
#else
  (void)shared_secret;
  (void)private_key;
  (void)public_key;
#endif
}
