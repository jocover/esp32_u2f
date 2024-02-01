
#include "soc/hwcrypto_reg.h"
#include "soc/dport_reg.h"
#include "soc/dport_access.h"
#include "esp_private/periph_ctrl.h"
#include "esp_crypto_lock.h"
#include "esp32_ed25519.h"
#include <string.h>
#include "mbedtls/sha512.h"

// Length of the elliptic curve
#define CURVE25519_BIT_LEN 255
#define CURVE25519_BYTE_LEN 32
#define CURVE25519_WORD_LEN 8

typedef struct
{
   const void *buffer;
   size_t length;
} EddsaMessageChunk;

uint32_t curve25519Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b);
void curve25519Sqr(uint32_t *r, const uint32_t *a);

void ed25519Double(Ed25519State *state, Ed25519Point *r, const Ed25519Point *p);
void ed25519Mul(Ed25519State *state, Ed25519Point *r, const uint8_t *k, const Ed25519Point *p);

// Square root of -1 modulo p (constant)
static const uint32_t CURVE25519_SQRT_MINUS_1[8] =
    {
        0x4A0EA0B0, 0xC4EE1B27, 0xAD2FE478, 0x2F431806,
        0x3DFBD7A7, 0x2B4D0099, 0x4FC1DF0B, 0x2B832480};

// Base point B
static const Ed25519Point ED25519_B =
    {
        {0x8F25D51A, 0xC9562D60, 0x9525A7B2, 0x692CC760,
         0xFDD6DC5C, 0xC0A4E231, 0xCD6E53FE, 0x216936D3},
        {0x66666658, 0x66666666, 0x66666666, 0x66666666,
         0x66666666, 0x66666666, 0x66666666, 0x66666666},
        {0x00000001, 0x00000000, 0x00000000, 0x00000000,
         0x00000000, 0x00000000, 0x00000000, 0x00000000},
        {0xA5B7DDA3, 0x6DDE8AB3, 0x775152F5, 0x20F09F80,
         0x64ABE37D, 0x66EA4E8E, 0xD78B7665, 0x67875F0F}};

static const uint32_t ED25519_2D[8] =
    {
        0x26B2F159, 0xEBD69B94, 0x8283B156, 0x00E0149A,
        0xEEF3D130, 0x198E80F2, 0x56DFFCE7, 0x2406D9DC};

// Order of the base point L
static const uint8_t ED25519_L[33] =
    {
        0xED,
        0xD3,
        0xF5,
        0x5C,
        0x1A,
        0x63,
        0x12,
        0x58,
        0xD6,
        0x9C,
        0xF7,
        0xA2,
        0xDE,
        0xF9,
        0xDE,
        0x14,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x10,
        0x00,
};

// Pre-computed value of mu = b^(2 * k) / L with b = 2^8 and k = 32
static const uint8_t ED25519_MU[33] =
    {
        0x1B, 0x13, 0x2C, 0x0A, 0xA3, 0xE5, 0x9C, 0xED,
        0xA7, 0x29, 0x63, 0x08, 0x5D, 0x21, 0x06, 0x21,
        0xEB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x0F};

inline uint32_t htole32(uint32_t host_32bits)
{
   return host_32bits;
}


void mpi_enable_hardware_hw_op( void )
{
    esp_crypto_mpi_lock_acquire();

    /* Enable RSA hardware */
    periph_module_enable(PERIPH_RSA_MODULE);

#ifdef CONFIG_IDF_TARGET_ESP32S3
    REG_CLR_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);
#elif CONFIG_IDF_TARGET_ESP32S2
    DPORT_REG_CLR_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_MEM_PD);
#endif

    while (DPORT_REG_READ(RSA_QUERY_CLEAN_REG) != 1) {
    }
    // Note: from enabling RSA clock to here takes about 1.3us

    REG_WRITE(RSA_INTERRUPT_REG, 0);

}


void mpi_disable_hardware_hw_op( void )
{
#ifdef CONFIG_IDF_TARGET_ESP32S3
    REG_SET_BIT(SYSTEM_RSA_PD_CTRL_REG, SYSTEM_RSA_MEM_PD);
#elif CONFIG_IDF_TARGET_ESP32S2
    DPORT_REG_SET_BIT(DPORT_RSA_PD_CTRL_REG, DPORT_RSA_PD);
#endif
    /* Disable RSA hardware */
    periph_module_disable(PERIPH_RSA_MODULE);

    esp_crypto_mpi_lock_release();
}

static inline void start_op(uint32_t op_reg)
{
    /* Clear interrupt status */
    DPORT_REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);

    /* Note: above REG_WRITE includes a memw, so we know any writes
       to the memory blocks are also complete. */

    DPORT_REG_WRITE(op_reg, 1);
}

static inline void wait_op_complete(void)
{
    while (DPORT_REG_READ(RSA_QUERY_INTERRUPT_REG) != 1)
    { }

    /* clear the interrupt */
    DPORT_REG_WRITE(RSA_CLEAR_INTERRUPT_REG, 1);
}



void curve25519Mul(uint32_t *r, const uint32_t *a, const uint32_t *b)
{

   uint32_t i;

   // Set mode register
   DPORT_REG_WRITE(RSA_LENGTH_REG, 7);

   // Copy the first operand to RSA_X_MEM
   for (i = 0; i < 8; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_X_BLOCK_BASE + i * 4, a[i]);
   }

   // Copy the second operand to RSA_Y_MEM
   for (i = 0; i < 8; i++)
   {
      DPORT_REG_WRITE(RSA_MEM_Y_BLOCK_BASE + i * 4, b[i]);
   }

   // Copy the modulus to RSA_M_MEM
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE, 0xFFFFFFED);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 4, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 8, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 12, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 16, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 20, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 24, 0xFFFFFFFF);
   DPORT_REG_WRITE(RSA_MEM_M_BLOCK_BASE + 28, 0x7FFFFFFF);

   // Copy the pre-calculated value of R^2 mod M to RSA_Z_MEM
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE, 0x000005A4);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 4, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 8, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 12, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 16, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 20, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 24, 0x00000000);
   DPORT_REG_WRITE(RSA_MEM_RB_BLOCK_BASE + 28, 0x00000000);

   // Write the value of M' to RSA_M_PRIME_REG
   DPORT_REG_WRITE(RSA_M_DASH_REG, 0x286BCA1B);
   // Start large-number modular multiplication
   start_op(RSA_MOD_MULT_START_REG);

   // Wait for the operation to complete
   wait_op_complete();

   // Read the result from RSA_Z_MEM
   for (i = 0; i < 8; i++)
   {
      r[i] = DPORT_SEQUENCE_REG_READ(RSA_MEM_Z_BLOCK_BASE + i * 4);
   }

}

void curve25519SetInt(uint32_t *a, uint32_t b)
{
   uint32_t i;

   // Set the value of the least significant word
   a[0] = b;

   // Initialize the rest of the integer
   for (i = 1; i < 8; i++)
   {
      a[i] = 0;
   }
}

void curve25519Select(uint32_t *r, const uint32_t *a, const uint32_t *b,
                      uint32_t c)
{
   uint32_t i;
   uint32_t mask;

   // The mask is the all-1 or all-0 word
   mask = c - 1;

   // Select between A and B
   for (i = 0; i < 8; i++)
   {
      // Constant time implementation
      r[i] = (a[i] & mask) | (b[i] & ~mask);
   }
}

void curve25519Sqr(uint32_t *r, const uint32_t *a)
{
   // Compute R = (A ^ 2) mod p
   curve25519Mul(r, a, a);
}

void curve25519Pwr2(uint32_t *r, const uint32_t *a, uint32_t n)
{
   uint32_t i;

   // Pre-compute (A ^ 2) mod p
   curve25519Sqr(r, a);

   // Compute R = (A ^ (2^n)) mod p
   for (i = 1; i < n; i++)
   {
      curve25519Sqr(r, r);
   }
}

uint32_t curve25519Comp(const uint32_t *a, const uint32_t *b)
{
   uint32_t i;
   uint32_t mask;

   // Initialize mask
   mask = 0;

   // Compare A and B
   for (i = 0; i < 8; i++)
   {
      // Constant time implementation
      mask |= a[i] ^ b[i];
   }

   // Return 0 if A = B, else 1
   return ((uint32_t)(mask | (~mask + 1))) >> 31;
}

void curve25519Red(uint32_t *r, const uint32_t *a)
{
   uint32_t i;
   uint64_t temp;
   uint32_t b[8];

   // Compute B = A + 19
   for (temp = 19, i = 0; i < 8; i++)
   {
      temp += a[i];
      b[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   // Compute B = A - (2^255 - 19)
   b[7] -= 0x80000000;

   // If B < (2^255 - 19) then R = B, else R = A
   curve25519Select(r, b, a, (b[7] & 0x80000000) >> 31);
}

void curve25519Add(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint32_t i;
   uint64_t temp;

   // Compute R = A + B
   for (temp = 0, i = 0; i < 8; i++)
   {
      temp += a[i];
      temp += b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   // Perform modular reduction
   curve25519Red(r, r);
}

void curve25519Sub(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint32_t i;
   int64_t temp;

   // Compute R = A - 19 - B
   for (temp = -19, i = 0; i < 8; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = temp & 0xFFFFFFFF;
      temp >>= 32;
   }

   // Compute R = A + (2^255 - 19) - B
   r[7] += 0x80000000;

   // Perform modular reduction
   curve25519Red(r, r);
}

uint32_t curve25519Sqrt(uint32_t *r, const uint32_t *a, const uint32_t *b)
{
   uint32_t res1;
   uint32_t res2;
   uint32_t c[8];
   uint32_t u[8];
   uint32_t v[8];

   // Compute the candidate root (A / B)^((p + 3) / 8). This can be done
   // with the following trick, using a single modular powering for both the
   // inversion of B and the square root: A * B^3 * (A * B^7)^((p - 5) / 8)
   curve25519Sqr(v, b);
   curve25519Mul(v, v, b);
   curve25519Sqr(v, v);
   curve25519Mul(v, v, b);

   // Compute C = A * B^7
   curve25519Mul(c, a, v);

   // Compute U = C^((p - 5) / 8)
   curve25519Sqr(u, c);
   curve25519Mul(u, u, c); // C^(2^2 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); // C^(2^3 - 1)
   curve25519Pwr2(u, v, 3);
   curve25519Mul(u, u, v); // C^(2^6 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); // C^(2^7 - 1)
   curve25519Pwr2(u, v, 7);
   curve25519Mul(u, u, v); // C^(2^14 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); // C^(2^15 - 1)
   curve25519Pwr2(u, v, 15);
   curve25519Mul(u, u, v); // C^(2^30 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); // C^(2^31 - 1)
   curve25519Pwr2(u, v, 31);
   curve25519Mul(v, u, v); // C^(2^62 - 1)
   curve25519Pwr2(u, v, 62);
   curve25519Mul(u, u, v); // C^(2^124 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, c); // C^(2^125 - 1)
   curve25519Pwr2(u, v, 125);
   curve25519Mul(u, u, v); // C^(2^250 - 1)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, c); // C^(2^252 - 3)

   // The first candidate root is U = A * B^3 * (A * B^7)^((p - 5) / 8)
   curve25519Mul(u, u, a);
   curve25519Sqr(v, b);
   curve25519Mul(v, v, b);
   curve25519Mul(u, u, v);

   // The second candidate root is V = U * sqrt(-1)
   curve25519Mul(v, u, CURVE25519_SQRT_MINUS_1);

   // Calculate C = B * U^2
   curve25519Sqr(c, u);
   curve25519Mul(c, c, b);

   // Check whether B * U^2 = A
   res1 = curve25519Comp(c, a);

   // Calculate C = B * V^2
   curve25519Sqr(c, v);
   curve25519Mul(c, c, b);

   // Check whether B * V^2 = A
   res2 = curve25519Comp(c, a);

   // Select the first or the second candidate root
   curve25519Select(r, u, v, res1);

   // Return 0 if the square root exists
   return res1 & res2;
}

void curve25519Copy(uint32_t *a, const uint32_t *b)
{
   uint32_t i;

   // Copy the value of the integer
   for (i = 0; i < 8; i++)
   {
      a[i] = b[i];
   }
}

void curve25519Inv(uint32_t *r, const uint32_t *a)
{
   uint32_t u[8];
   uint32_t v[8];

   // Since GF(p) is a prime field, the Fermat's little theorem can be
   // used to find the multiplicative inverse of A modulo p
   curve25519Sqr(u, a);
   curve25519Mul(u, u, a); // A^(2^2 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); // A^(2^3 - 1)
   curve25519Pwr2(u, v, 3);
   curve25519Mul(u, u, v); // A^(2^6 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); // A^(2^7 - 1)
   curve25519Pwr2(u, v, 7);
   curve25519Mul(u, u, v); // A^(2^14 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); // A^(2^15 - 1)
   curve25519Pwr2(u, v, 15);
   curve25519Mul(u, u, v); // A^(2^30 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); // A^(2^31 - 1)
   curve25519Pwr2(u, v, 31);
   curve25519Mul(v, u, v); // A^(2^62 - 1)
   curve25519Pwr2(u, v, 62);
   curve25519Mul(u, u, v); // A^(2^124 - 1)
   curve25519Sqr(u, u);
   curve25519Mul(v, u, a); // A^(2^125 - 1)
   curve25519Pwr2(u, v, 125);
   curve25519Mul(u, u, v); // A^(2^250 - 1)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, a); // A^(2^252 - 3)
   curve25519Sqr(u, u);
   curve25519Sqr(u, u);
   curve25519Mul(u, u, a); // A^(2^254 - 11)
   curve25519Sqr(u, u);
   curve25519Mul(r, u, a); // A^(2^255 - 21)
}

void curve25519Export(uint32_t *a, uint8_t *data)
{
   uint32_t i;

   // Convert from host byte order to little-endian byte order
   for (i = 0; i < 8; i++)
   {
      a[i] = htole32(a[i]);
   }

   // Export the octet string
   memcpy(data, a, 32);
}

void ed25519Add(Ed25519State *state, Ed25519Point *r, const Ed25519Point *p,
                const Ed25519Point *q)
{
   // Compute A = (Y1 + X1) * (Y2 + X2)
   curve25519Add(state->c, p->y, p->x);
   curve25519Add(state->d, q->y, q->x);
   curve25519Mul(state->a, state->c, state->d);
   // Compute B = (Y1 - X1) * (Y2 - X2)
   curve25519Sub(state->c, p->y, p->x);
   curve25519Sub(state->d, q->y, q->x);
   curve25519Mul(state->b, state->c, state->d);
   // Compute C = 2 * Z1 * Z2
   curve25519Mul(state->c, p->z, q->z);
   curve25519Add(state->c, state->c, state->c);
   // Compute D = (2 * d) * T1 * T2
   curve25519Mul(state->d, p->t, q->t);
   curve25519Mul(state->d, state->d, ED25519_2D);
   // Compute E = A + B
   curve25519Add(state->e, state->a, state->b);
   // Compute F = A - B
   curve25519Sub(state->f, state->a, state->b);
   // Compute G = C + D
   curve25519Add(state->g, state->c, state->d);
   // Compute H = C - D
   curve25519Sub(state->h, state->c, state->d);
   // Compute X3 = F * H
   curve25519Mul(r->x, state->f, state->h);
   // Compute Y3 = E * G
   curve25519Mul(r->y, state->e, state->g);
   // Compute Z3 = G * H
   curve25519Mul(r->z, state->g, state->h);
   // Compute T3 = E * F
   curve25519Mul(r->t, state->e, state->f);
}

void ed25519Double(Ed25519State *state, Ed25519Point *r, const Ed25519Point *p)
{
   // Compute A = X1^2
   curve25519Sqr(state->a, p->x);
   // Compute B = Y1^2
   curve25519Sqr(state->b, p->y);
   // Compute C = 2 * Z1^2
   curve25519Sqr(state->c, p->z);
   curve25519Add(state->c, state->c, state->c);
   // Compute E = A + B
   curve25519Add(state->e, state->a, state->b);
   // Compute F = E - (X1 + Y1)^2
   curve25519Add(state->f, p->x, p->y);
   curve25519Sqr(state->f, state->f);
   curve25519Sub(state->f, state->e, state->f);
   // Compute G = A - B
   curve25519Sub(state->g, state->a, state->b);
   // Compute H = C + G
   curve25519Add(state->h, state->c, state->g);
   // Compute X3 = F * H
   curve25519Mul(r->x, state->f, state->h);
   // Compute Y3 = E * G
   curve25519Mul(r->y, state->e, state->g);
   // Compute Z3 = G * H
   curve25519Mul(r->z, state->g, state->h);
   // Compute T3 = E * F
   curve25519Mul(r->t, state->e, state->f);
}

void ed25519Mul(Ed25519State *state, Ed25519Point *r,
                const uint8_t *k, const Ed25519Point *p)
{
   int32_t i;
   uint8_t b;

   // The neutral element is represented by (0, 1, 1, 0)
   curve25519SetInt(state->u.x, 0);
   curve25519SetInt(state->u.y, 1);
   curve25519SetInt(state->u.z, 1);
   curve25519SetInt(state->u.t, 0);

   // Perform scalar multiplication
   for (i = CURVE25519_BIT_LEN - 1; i >= 0; i--)
   {
      // The scalar is processed in a left-to-right fashion
      b = (k[i / 8] >> (i % 8)) & 1;

      // Compute U = 2 * U
      ed25519Double(state, &state->u, &state->u);
      // Compute V = U + P
      ed25519Add(state, &state->v, &state->u, p);

      // If b is set, then U = V
      curve25519Select(state->u.x, state->u.x, state->v.x, b);
      curve25519Select(state->u.y, state->u.y, state->v.y, b);
      curve25519Select(state->u.z, state->u.z, state->v.z, b);
      curve25519Select(state->u.t, state->u.t, state->v.t, b);
   }

   // Copy result
   curve25519Copy(r->x, state->u.x);
   curve25519Copy(r->y, state->u.y);
   curve25519Copy(r->z, state->u.z);
   curve25519Copy(r->t, state->u.t);
}

void ed25519Encode(Ed25519Point *p, uint8_t *data)
{

   // Retrieve affine representation
   curve25519Inv(p->z, p->z);
   curve25519Mul(p->x, p->x, p->z);
   curve25519Mul(p->y, p->y, p->z);
   curve25519SetInt(p->z, 1);
   curve25519Mul(p->t, p->x, p->y);

   // Encode the y-coordinate as a little-endian string of 32 octets. The most
   // significant bit of the final octet is always zero
   curve25519Export(p->y, data);

   // Copy the least significant bit of the x-coordinate to the most significant
   // bit of the final octet
   data[31] |= (p->x[0] & 1) << 7;
}

/**
 * @brief Derive the public key from an EdDSA private key
 * @param[in] privateKey EdDSA private key (32 bytes)
 * @param[out] publicKey EdDSA public key (32 bytes)
 * @return Error code
 **/

int ed25519GeneratePublicKey(const uint8_t *privateKey, uint8_t *publicKey)
{

   uint8_t *s;

   uint8_t digest[64];

   Ed25519State *state;

   // Check parameters
   if (privateKey == NULL || publicKey == NULL)
      return -1;

   // Allocate working state
   state = malloc(sizeof(Ed25519State));
   // Failed to allocate memory?
   if (state == NULL)
      return -1;

   memset(state, 0, sizeof(Ed25519State));

   // Hash the 32-byte private key using SHA-512
   mbedtls_sha512_context sha512Context;
   mbedtls_sha512_init(&sha512Context);
   mbedtls_sha512_starts(&sha512Context, 0);
   mbedtls_sha512_update(&sha512Context, privateKey, ED25519_PRIVATE_KEY_LEN);
   mbedtls_sha512_finish(&sha512Context, digest);
   mbedtls_sha512_free(&sha512Context);

   // Only the lower 32 bytes are used for generating the public key. Interpret
   // the buffer as the little-endian integer, forming a secret scalar s
   s = digest;

   mpi_enable_hardware_hw_op();

   // The lowest three bits of the first octet are cleared, the highest bit
   // of the last octet is cleared, and the second highest bit of the last
   // octet is set
   s[0] &= 0xF8;
   s[31] &= 0x7F;
   s[31] |= 0x40;

   // Perform a fixed-base scalar multiplication s * B
   ed25519Mul(state, &state->sb, s, &ED25519_B);

   // The public key A is the encoding of the point s * B
   ed25519Encode(&state->sb, publicKey);

   mpi_disable_hardware_hw_op();

   // Erase working state
   memset(state, 0, sizeof(Ed25519State));

   // Release working state
   free(state);

   // Successful processing
   return 0;
}

void ed25519CopyInt(uint8_t *a, const uint8_t *b, uint32_t n)
{
   uint32_t i;

   // Copy the value of the integer
   for (i = 0; i < n; i++)
   {
      a[i] = b[i];
   }
}

void ed25519SelectInt(uint8_t *r, const uint8_t *a, const uint8_t *b,
                      uint8_t c, uint32_t n)
{
   uint32_t i;
   uint8_t mask;

   // The mask is the all-1 or all-0 word
   mask = c - 1;

   // Select between A and B
   for (i = 0; i < n; i++)
   {
      // Constant time implementation
      r[i] = (a[i] & mask) | (b[i] & ~mask);
   }
}

void ed25519AddInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint32_t n)
{
   uint32_t i;
   uint16_t temp;

   // Compute R = A + B
   for (temp = 0, i = 0; i < n; i++)
   {
      temp += a[i];
      temp += b[i];
      r[i] = temp & 0xFF;
      temp >>= 8;
   }
}

uint8_t ed25519SubInt(uint8_t *r, const uint8_t *a, const uint8_t *b, uint32_t n)
{
   uint32_t i;
   int16_t temp;

   // Compute R = A - B
   for (temp = 0, i = 0; i < n; i++)
   {
      temp += a[i];
      temp -= b[i];
      r[i] = temp & 0xFF;
      temp >>= 8;
   }

   // Return 1 if the result of the subtraction is negative
   return temp & 1;
}

void ed25519MulInt(uint8_t *rl, uint8_t *rh, const uint8_t *a,
                   const uint8_t *b, uint32_t n)
{
   uint32_t i;
   uint32_t j;
   uint32_t temp;

   // Compute the low part of the multiplication
   for (temp = 0, i = 0; i < n; i++)
   {
      // The Comba's algorithm computes the products, column by column
      for (j = 0; j <= i; j++)
      {
         temp += (uint16_t)a[j] * b[i - j];
      }

      // At the bottom of each column, the final result is written to memory
      if (rl != NULL)
      {
         rl[i] = temp & 0xFF;
      }

      // Propagate the carry upwards
      temp >>= 8;
   }

   // Check whether the high part of the multiplication should be calculated
   if (rh != NULL)
   {
      // Compute the high part of the multiplication
      for (i = n; i < (2 * n); i++)
      {
         // The Comba's algorithm computes the products, column by column
         for (j = i + 1 - n; j < n; j++)
         {
            temp += (uint16_t)a[j] * b[i - j];
         }

         // At the bottom of each column, the final result is written to memory
         rh[i - n] = temp & 0xFF;

         // Propagate the carry upwards
         temp >>= 8;
      }
   }
}

void ed25519RedInt(uint8_t *r, const uint8_t *a)
{
   uint8_t c;
   uint8_t u[33];
   uint8_t v[33];

   // Compute the estimate of the quotient u = ((a / b^(k - 1)) * mu) / b^(k + 1)
   ed25519MulInt(NULL, u, a + 31, ED25519_MU, 33);
   // Compute v = u * L mod b^(k + 1)
   ed25519MulInt(v, NULL, u, ED25519_L, 33);

   // Compute the estimate of the remainder u = a mod b^(k + 1) - v
   // If u < 0, then u = u + b^(k + 1)
   ed25519SubInt(u, a, v, 33);

   // This estimation implies that at most two subtractions of L are required to
   // obtain the correct remainder r
   c = ed25519SubInt(v, u, ED25519_L, 33);
   ed25519SelectInt(u, v, u, c, 33);
   c = ed25519SubInt(v, u, ED25519_L, 33);
   ed25519SelectInt(u, v, u, c, 33);

   // Copy the resulting remainder
   ed25519CopyInt(r, u, 32);
}

int ed25519GenerateSignatureEx(const uint8_t *privateKey,
                               const uint8_t *publicKey, const EddsaMessageChunk *messageChunks,
                               const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature)
{
   uint32_t i;
   uint8_t c;
   uint8_t digest[64];
   Ed25519State *state;
   mbedtls_sha512_context sha512Scontext;

   // Check parameters
   if (privateKey == NULL || signature == NULL)
      return -1;
   if (messageChunks == NULL)
      return -1;
   if (context == NULL && contextLen != 0)
      return -1;

   state = malloc(sizeof(Ed25519State));

   // Failed to allocate memory?
   if (state == NULL)
      return -1;
   memset(state, 0, sizeof(Ed25519State));

   // Hash the private key, 32 octets, using SHA-512. Let h denote the
   // resulting digest

   mbedtls_sha512_init(&sha512Scontext);
   mbedtls_sha512_starts(&sha512Scontext, 0);
   mbedtls_sha512_update(&sha512Scontext, privateKey, ED25519_PRIVATE_KEY_LEN);
   mbedtls_sha512_finish(&sha512Scontext, digest);
   mbedtls_sha512_free(&sha512Scontext);

   // Construct the secret scalar s from the first half of the digest
   memcpy(state->s, digest, 32);

   mpi_enable_hardware_hw_op();

   // The lowest three bits of the first octet are cleared, the highest bit
   // of the last octet is cleared, and the second highest bit of the last
   // octet is set
   state->s[0] &= 0xF8;
   state->s[31] &= 0x7F;
   state->s[31] |= 0x40;

   // The public key is optional
   if (publicKey == NULL)
   {
      // Perform a fixed-base scalar multiplication s * B
      ed25519Mul(state, &state->sb, state->s, &ED25519_B);
      // The public key A is the encoding of the point s * B
      ed25519Encode(&state->sb, state->k);
      // Point to the resulting public key
      publicKey = state->k;
   }

   // Let prefix denote the second half of the hash digest
   memcpy(state->p, digest + 32, 32);

   // Initialize SHA-512 context
   mbedtls_sha512_init(&sha512Scontext);
   mbedtls_sha512_starts(&sha512Scontext, 0);

   // For Ed25519ctx and Ed25519ph schemes, dom2(x, y) is the octet string
   //"SigEd25519 no Ed25519 collisions" || octet(x) || octet(OLEN(y)) || y,
   // where x is in range 0-255 and y is an octet string of at most 255 octets
   if (context != NULL || flag != 0)
   {
      mbedtls_sha512_update(&sha512Scontext, (const uint8_t *)"SigEd25519 no Ed25519 collisions", 32);
      mbedtls_sha512_update(&sha512Scontext, &flag, sizeof(uint8_t));
      mbedtls_sha512_update(&sha512Scontext, &contextLen, sizeof(uint8_t));
      mbedtls_sha512_update(&sha512Scontext, context, contextLen);
   }

   // Digest prefix
   mbedtls_sha512_update(&sha512Scontext, state->p, 32);

   // The message is split over multiple chunks
   for (i = 0; messageChunks[i].buffer != NULL; i++)
   {
      // Digest current chunk
      mbedtls_sha512_update(&sha512Scontext, messageChunks[i].buffer,
                            messageChunks[i].length);
   }

   // Compute SHA-512(dom2(F, C) || prefix || PH(M))
   mbedtls_sha512_finish(&sha512Scontext, digest);
   mbedtls_sha512_free(&sha512Scontext);

   // Reduce the 64-octet digest as a little-endian integer r
   ed25519RedInt(state->r, digest);
   // Compute the point r * B
   ed25519Mul(state, &state->rb, state->r, &ED25519_B);
   // Let the string R be the encoding of this point
   ed25519Encode(&state->rb, signature);

   // Initialize SHA-512 context
   mbedtls_sha512_init(&sha512Scontext);
   mbedtls_sha512_starts(&sha512Scontext, 0);

   // For Ed25519ctx and Ed25519ph schemes, dom2(x, y) is the octet string
   //"SigEd25519 no Ed25519 collisions" || octet(x) || octet(OLEN(y)) || y,
   // where x is in range 0-255 and y is an octet string of at most 255 octets
   if (context != NULL || flag != 0)
   {
      mbedtls_sha512_update(&sha512Scontext, (const uint8_t *)"SigEd25519 no Ed25519 collisions", 32);
      mbedtls_sha512_update(&sha512Scontext, &flag, sizeof(uint8_t));
      mbedtls_sha512_update(&sha512Scontext, &contextLen, sizeof(uint8_t));
      mbedtls_sha512_update(&sha512Scontext, context, contextLen);
   }

   // Digest R || A
   mbedtls_sha512_update(&sha512Scontext, signature, ED25519_SIGNATURE_LEN / 2);
   mbedtls_sha512_update(&sha512Scontext, publicKey, ED25519_PUBLIC_KEY_LEN);

   // The message is split over multiple chunks
   for (i = 0; messageChunks[i].buffer != NULL; i++)
   {
      // Digest current chunk
      mbedtls_sha512_update(&sha512Scontext, messageChunks[i].buffer,
                            messageChunks[i].length);
   }

   // Compute SHA512(dom2(F, C) || R || A || PH(M)) and interpret the 64-octet
   // digest as a little-endian integer k
   mbedtls_sha512_finish(&sha512Scontext, state->k);
   mbedtls_sha512_free(&sha512Scontext);

   // Compute S = (r + k * s) mod L. For efficiency, reduce k modulo L first
   ed25519RedInt(state->p, state->k);
   ed25519MulInt(state->k, state->k + 32, state->p, state->s, 32);
   ed25519RedInt(state->p, state->k);
   ed25519AddInt(state->s, state->p, state->r, 32);

   // Perform modular reduction
   c = ed25519SubInt(state->p, state->s, ED25519_L, 32);
   ed25519SelectInt(signature + 32, state->p, state->s, c, 32);

   mpi_disable_hardware_hw_op();

   // Erase working state
   memset(state, 0, sizeof(Ed25519State));

   // Release working state
   free(state);

   // Successful processing
   return 0;
}

int ed25519GenerateSignature(const uint8_t *privateKey,
                             const uint8_t *publicKey, const void *message, size_t messageLen,
                             const void *context, uint8_t contextLen, uint8_t flag, uint8_t *signature)
{
   int error;
   EddsaMessageChunk messageChunks[2];

   // The message fits in a single chunk
   messageChunks[0].buffer = message;
   messageChunks[0].length = messageLen;
   messageChunks[1].buffer = NULL;
   messageChunks[1].length = 0;

   // Ed25519 signature generation
   error = ed25519GenerateSignatureEx(privateKey, publicKey, messageChunks,
                                      context, contextLen, flag, signature);

   // Return status code
   return error;
}