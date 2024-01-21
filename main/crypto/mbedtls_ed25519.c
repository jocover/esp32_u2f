#include "mbedtls/error.h"
#include "mbedtls/private_access.h"
#include "mbedtls/ecp.h"
#include "bn_mul.h"
#include <string.h>
#include "mbedtls_ed25519.h"
#include "sha.h"
#include "rand.h"

#define EDSIGN_SECRET_KEY_SIZE  32
#define EDSIGN_PUBLIC_KEY_SIZE  32
#define EDSIGN_SIGNATURE_SIZE  64

static int ecp_use_ed25519(mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* P = 2^255 - 19 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->P, 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(&grp->P, 255));
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->P, &grp->P, 19));
    grp->pbits = mbedtls_mpi_bitlen(&grp->P);

    /* N = 2^252 + 27742317777372353535851937790883648493 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&grp->N, 16,
                                            "14DEF9DEA2F79CD65812631A5CF5D3ED"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(&grp->N, 252, 1));

    /* A = -1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(&grp->A, &grp->P, 1));

    /* B = -121665/121666 (actually d of edwards25519) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&grp->B, 16,
                                            "52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3"));

    /* (X(P),Y(P)) of edwards25519 in RFC7748. Also set Z so that
     * projective coordinates can be used. */
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&grp->G.MBEDTLS_PRIVATE(X), 16,
                                            "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_read_string(&grp->G.MBEDTLS_PRIVATE(Y), 16,
                                            "6666666666666666666666666666666666666666666666666666666666666658"));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&grp->G.MBEDTLS_PRIVATE(Z), 1));

cleanup:
    if (ret != 0)
        mbedtls_ecp_group_free(grp);

    return (ret);
}

/* Size of p255 in terms of mbedtls_mpi_uint */
#define P255_WIDTH (255 / 8 / sizeof(mbedtls_mpi_uint) + 1)

/*
 * Fast quasi-reduction modulo p255 = 2^255 - 19
 * Write N as A0 + 2^255 A1, return A0 + 19 * A1
 */
static int ecp_mod_p255(mbedtls_mpi *N)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    mbedtls_mpi M;
    mbedtls_mpi_uint Mp[P255_WIDTH + 2];

    if (N->MBEDTLS_PRIVATE(n) < P255_WIDTH)
        return (0);

    /* M = A1 */
    M.MBEDTLS_PRIVATE(s) = 1;
    M.MBEDTLS_PRIVATE(n) = N->MBEDTLS_PRIVATE(n) - (P255_WIDTH - 1);
    if (M.MBEDTLS_PRIVATE(n) > P255_WIDTH + 1)
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    M.MBEDTLS_PRIVATE(p) = Mp;
    memset(Mp, 0, sizeof Mp);
    memcpy(Mp, N->MBEDTLS_PRIVATE(p) + P255_WIDTH - 1, M.MBEDTLS_PRIVATE(n) * sizeof(mbedtls_mpi_uint));
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&M, 255 % (8 * sizeof(mbedtls_mpi_uint))));
    M.MBEDTLS_PRIVATE(n)++; /* Make room for multiplication by 19 */

    /* N = A0 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_set_bit(N, 255, 0));
    for (i = P255_WIDTH; i < N->MBEDTLS_PRIVATE(n); i++)
        N->MBEDTLS_PRIVATE(p)[i] = 0;

    /* N = A0 + 19 * A1 */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_int(&M, &M, 19));
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_abs(N, N, &M));

cleanup:
    return (ret);
}

/*
 * For Edwards curves, we do all the internal arithmetic in projective
 * coordinates. Import/export of points uses only the x and y coordinates,
 * which are internally represented as X/Z and Y/Z.
 *
 * For scalar multiplication, we'll use a Montgomery ladder.
 */

/*

 * Normalize Edwards x/y/z coordinates: X = X/Z, Y = Y/Z, Z = 1

 * Cost: 2M + 1I

 */

/*
 * Wrapper around fast quasi-modp functions, with fall-back to mbedtls_mpi_mod_mpi.
 * See the documentation of struct mbedtls_ecp_group.
 *
 * This function is in the critial loop for mbedtls_ecp_mul, so pay attention to perf.
 */
static int ecp_modp(mbedtls_mpi *N, const mbedtls_ecp_group *grp)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (grp->MBEDTLS_PRIVATE(modp) == NULL)
        return (mbedtls_mpi_mod_mpi(N, N, &grp->P));

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if ((N->MBEDTLS_PRIVATE(s) < 0 && mbedtls_mpi_cmp_int(N, 0) != 0) ||
        mbedtls_mpi_bitlen(N) > 2 * grp->pbits)
    {
        return (MBEDTLS_ERR_ECP_BAD_INPUT_DATA);
    }

    MBEDTLS_MPI_CHK(grp->MBEDTLS_PRIVATE(modp(N)));

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while (N->MBEDTLS_PRIVATE(s) < 0 && mbedtls_mpi_cmp_int(N, 0) != 0)
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(N, N, &grp->P));

    while (mbedtls_mpi_cmp_mpi(N, &grp->P) >= 0)
        /* we known P, N and the result are positive */
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(N, N, &grp->P));

cleanup:
    return (ret);
}

#define MOD_MUL(N)                            \
    do                                        \
    {                                         \
        MBEDTLS_MPI_CHK(ecp_modp(&(N), grp)); \
    } while (0)

static inline int ed25519_mpi_mul_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(X, A, B));
    MOD_MUL(*X);
cleanup:
    return ret;
}

#define MOD_ADD(N)                                  \
    while (mbedtls_mpi_cmp_mpi(&(N), &grp->P) >= 0) \
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(&(N), &(N), &grp->P))


static inline int ed25519_mpi_add_mod( const mbedtls_ecp_group *grp,
                                       mbedtls_mpi *X,
                                       const mbedtls_mpi *A,
                                       const mbedtls_mpi *B )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK( mbedtls_mpi_add_mpi( X, A, B ) );
    MOD_ADD( *X );
cleanup:
    return( ret );
}

static inline int ed25519_mpi_shift_l_mod(const mbedtls_ecp_group *grp,
                                          mbedtls_mpi *X,
                                          size_t count)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_shift_l(X, count));
    MOD_ADD(*X);
cleanup:
    return (ret);
}

#define MOD_SUB(N)                                         \
    while ((N).MBEDTLS_PRIVATE(s) < 0 && mbedtls_mpi_cmp_int(&(N), 0) != 0) \
    MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&(N), &(N), &grp->P))

static inline int ed25519_mpi_sub_mod(const mbedtls_ecp_group *grp,
                                      mbedtls_mpi *X,
                                      const mbedtls_mpi *A,
                                      const mbedtls_mpi *B)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(X, A, B));
    MOD_SUB(*X);
cleanup:
    return (ret);
}




static int ecp_normalize_edxyz(const mbedtls_ecp_group *grp, mbedtls_ecp_point *P)

{

    mbedtls_mpi Zi;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi_init(&Zi);
    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&Zi, &P->MBEDTLS_PRIVATE(Z), &grp->P));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &P->MBEDTLS_PRIVATE(X), &P->MBEDTLS_PRIVATE(X), &Zi));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &P->MBEDTLS_PRIVATE(Y), &P->MBEDTLS_PRIVATE(Y), &Zi));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&P->MBEDTLS_PRIVATE(Z), 1));
cleanup:
    mbedtls_mpi_free(&Zi);
    return (ret);
}

/*
 * Randomize projective x/y/z coordinates:
 * (X, Y, Z) -> (l X, l Y, l Z) for random l
 * This is sort of the reverse operation of ecp_normalize_edxyz().
 *
 * This countermeasure was first suggested in [2].
 * Cost: 3M
 */
static int ecp_randomize_edxyz(const mbedtls_ecp_group *grp, mbedtls_ecp_point *P,
                               int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi l;
    size_t p_size;
    int count = 0;

    p_size = (grp->pbits + 7) / 8;
    mbedtls_mpi_init(&l);

    /* Generate l such that 1 < l < p */
    do
    {
        MBEDTLS_MPI_CHK(mbedtls_mpi_fill_random(&l, p_size, f_rng, p_rng));

        while (mbedtls_mpi_cmp_mpi(&l, &grp->P) >= 0)
            MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(&l, 1));

        if (count++ > 10)
            return (MBEDTLS_ERR_ECP_RANDOM_FAILED);
    } while (mbedtls_mpi_cmp_int(&l, 1) <= 0);

    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &P->MBEDTLS_PRIVATE(X), &P->MBEDTLS_PRIVATE(X), &l));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &P->MBEDTLS_PRIVATE(Y), &P->MBEDTLS_PRIVATE(Y), &l));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &P->MBEDTLS_PRIVATE(Z), &P->MBEDTLS_PRIVATE(Z), &l));

cleanup:
    mbedtls_mpi_free(&l);

    return (ret);
}

/*
 * Add for: R = P + Q for both Edwards and Twisted Edwards curves in projective
 * coordinates.
 *
 * https://hyperelliptic.org/EFD/g1p/auto-code/twisted/projective/addition/add-2008-bbjlp.op3
 * with
 * P = (X1, Z1)
 * Q = (X2, Z2)
 * R = (X3, Z3)
 * and eliminating temporary variables t0, t3, ..., t9.
 *
 * Cost: 10M + 1S
 */
static int ecp_add_edxyz(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi A, B, C, D, E, F, G, t1, t2;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&C);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&F);
    mbedtls_mpi_init(&G);
    mbedtls_mpi_init(&t1);
    mbedtls_mpi_init(&t2);

    /* A = Z1*Z2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &A, &P->MBEDTLS_PRIVATE(Z), &Q->MBEDTLS_PRIVATE(Z)));
    /* B = A^2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &B, &A, &A));
    /* C = X1*X2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &C, &P->MBEDTLS_PRIVATE(X), &Q->MBEDTLS_PRIVATE(X)));
    /* D = Y1*Y2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &D, &P->MBEDTLS_PRIVATE(Y), &Q->MBEDTLS_PRIVATE(Y)));
    /* E = d*C*D */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &E, &C, &D));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &E, &E, &grp->B));
    /* F = B-E */
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &F, &B, &E));
    /* G = B+E */
    MBEDTLS_MPI_CHK(ed25519_mpi_add_mod(grp, &G, &B, &E));
    /* X3 = A*F*((X1+Y1)*(X2+Y2)-C-D) */
    MBEDTLS_MPI_CHK(ed25519_mpi_add_mod(grp, &t1, &P->MBEDTLS_PRIVATE(X), &P->MBEDTLS_PRIVATE(Y)));
    MBEDTLS_MPI_CHK(ed25519_mpi_add_mod(grp, &t2, &Q->MBEDTLS_PRIVATE(X), &Q->MBEDTLS_PRIVATE(Y)));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(X), &t1, &t2));
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &R->MBEDTLS_PRIVATE(X), &R->MBEDTLS_PRIVATE(X), &C));
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &R->MBEDTLS_PRIVATE(X), &R->MBEDTLS_PRIVATE(X), &D));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(X), &R->MBEDTLS_PRIVATE(X), &F));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(X), &R->MBEDTLS_PRIVATE(X), &A));
    /* Y3 = A*G*(D-a*C) */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(Y), &grp->A, &C));
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &R->MBEDTLS_PRIVATE(Y), &D, &R->MBEDTLS_PRIVATE(Y)));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(Y), &R->MBEDTLS_PRIVATE(Y), &G));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(Y), &R->MBEDTLS_PRIVATE(Y), &A));
    /* Z3 = F*G */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(Z), &F, &G));

cleanup:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&F);
    mbedtls_mpi_free(&G);
    mbedtls_mpi_free(&t1);
    mbedtls_mpi_free(&t2);

    return (ret);
}

/*
 * Double for: R = 2 * P for both Edwards and Twisted Edwards curves in projective
 * coordinates.
 *
 * https://hyperelliptic.org/EFD/g1p/auto-code/twisted/projective/doubling/dbl-2008-bbjlp.op3
 * with
 * P = (X1, Z1)
 * R = (X3, Z3)
 * and eliminating H and temporary variables t0, ..., t4.
 *
 * Cost: 3M + 4S
 */
static int ecp_double_edxyz(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                            const mbedtls_ecp_point *P)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi A, B, C, D, E, F, J;

    mbedtls_mpi_init(&A);
    mbedtls_mpi_init(&B);
    mbedtls_mpi_init(&C);
    mbedtls_mpi_init(&D);
    mbedtls_mpi_init(&E);
    mbedtls_mpi_init(&F);
    mbedtls_mpi_init(&J);

    /* B = (X1+Y1)^2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_add_mod(grp, &B, &P->MBEDTLS_PRIVATE(X), &P->MBEDTLS_PRIVATE(Y)));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &B, &B, &B));
    /* C = X1^2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &C, &P->MBEDTLS_PRIVATE(X), &P->MBEDTLS_PRIVATE(X)));
    /* D = Y1^2 */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &D, &P->MBEDTLS_PRIVATE(Y), &P->MBEDTLS_PRIVATE(Y)));
    /* E = a*C */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &E, &grp->A, &C));
    /* F = E+D */
    MBEDTLS_MPI_CHK(ed25519_mpi_add_mod(grp, &F, &E, &D));
    /* J = F-2*(Z1^2) */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &J, &P->MBEDTLS_PRIVATE(Z), &P->MBEDTLS_PRIVATE(Z)));
    MBEDTLS_MPI_CHK(ed25519_mpi_shift_l_mod(grp, &J, 1));
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &J, &F, &J));
    /* X3 = (B-C-D)*J */
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &R->MBEDTLS_PRIVATE(X), &B, &C));
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &R->MBEDTLS_PRIVATE(X), &R->MBEDTLS_PRIVATE(X), &D));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(X), &R->MBEDTLS_PRIVATE(X), &J));
    /* Y3 = F*(E-D) */
    MBEDTLS_MPI_CHK(ed25519_mpi_sub_mod(grp, &R->MBEDTLS_PRIVATE(Y), &E, &D));
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(Y), &R->MBEDTLS_PRIVATE(Y), &F));
    /* Z3 = F*J */
    MBEDTLS_MPI_CHK(ed25519_mpi_mul_mod(grp, &R->MBEDTLS_PRIVATE(Z), &F, &J));

cleanup:
    mbedtls_mpi_free(&A);
    mbedtls_mpi_free(&B);
    mbedtls_mpi_free(&C);
    mbedtls_mpi_free(&D);
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&F);
    mbedtls_mpi_free(&J);

    return (ret);
}

/*
 * Multiplication with Montgomery ladder in x/y/z coordinates,
 * for curves in Edwards form.
 */
static int ecp_mul_edxyz(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                         int (*f_rng)(void *, unsigned char *, size_t),
                         void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t i;
    unsigned char b;
    mbedtls_ecp_point RP;

    mbedtls_ecp_point_init(&RP);

    /* Read from P before writing to R, in case P == R */
    MBEDTLS_MPI_CHK(mbedtls_ecp_copy(&RP, P));

    /* Set R to zero in projective coordinates */
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->MBEDTLS_PRIVATE(X), 0));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->MBEDTLS_PRIVATE(Y), 1));
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&R->MBEDTLS_PRIVATE(Z), 1));

    /* RP.X and RP.Y might be slightly larger than P, so reduce them */
    MOD_ADD(RP.MBEDTLS_PRIVATE(X));
    MOD_ADD(RP.MBEDTLS_PRIVATE(Y));

    /* Randomize coordinates of the starting point */
    if (f_rng != NULL)
        MBEDTLS_MPI_CHK(ecp_randomize_edxyz(grp, &RP, f_rng, p_rng));

    /* Loop invariant: R = result so far, RP = R + P */
    i = mbedtls_mpi_bitlen(m); /* one past the (zero-based) most significant bit */
    while (i-- > 0)
    {
        b = mbedtls_mpi_get_bit(m, i);
        /*
         *  if (b) R = 2R + P else R = 2R,
         * which is:
         *  if (b) add( R, R, RP )
         *         add( RP, RP, RP )
         *  else   add( RP, RP, R )
         *         add( R, R, R )
         * but using safe conditional swaps to avoid leaks
         */
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap(&R->MBEDTLS_PRIVATE(X), &RP.MBEDTLS_PRIVATE(X), b));
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap(&R->MBEDTLS_PRIVATE(Y), &RP.MBEDTLS_PRIVATE(Y), b));
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap(&R->MBEDTLS_PRIVATE(Z), &RP.MBEDTLS_PRIVATE(Z), b));
        MBEDTLS_MPI_CHK(ecp_add_edxyz(grp, &RP, &RP, R));
        MBEDTLS_MPI_CHK(ecp_double_edxyz(grp, R, R));
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap(&R->MBEDTLS_PRIVATE(X), &RP.MBEDTLS_PRIVATE(X), b));
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap(&R->MBEDTLS_PRIVATE(Y), &RP.MBEDTLS_PRIVATE(Y), b));
        MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_swap(&R->MBEDTLS_PRIVATE(Z), &RP.MBEDTLS_PRIVATE(Z), b));
    }

    /*
     * Knowledge of the projective coordinates may leak the last few bits of the
     * scalar [1], and since our MPI implementation isn't constant-flow,
     * inversion (used for coordinate normalization) may leak the full value
     * of its input via side-channels [2].
     *
     * [1] https://eprint.iacr.org/2003/191
     * [2] https://eprint.iacr.org/2020/055
     *
     * Avoid the leak by randomizing coordinates before we normalize them.
     */
    if (f_rng != NULL)
        MBEDTLS_MPI_CHK(ecp_randomize_edxyz(grp, R, f_rng, p_rng));

    MBEDTLS_MPI_CHK(ecp_normalize_edxyz(grp, R));

cleanup:
    mbedtls_ecp_point_free(&RP);

    return (ret);
}

/*

 * Point addition R = P + Q

 */

int mbedtls_ecp_add(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,

                    const mbedtls_ecp_point *P, const mbedtls_ecp_point *Q)

{

    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    MBEDTLS_MPI_CHK(ecp_add_edxyz(grp, R, P, Q));
    MBEDTLS_MPI_CHK(ecp_normalize_edxyz(grp, R));

cleanup:

    return (ret);
}

int ed25519_ecp_group_load(mbedtls_ecp_group *grp)
{

    mbedtls_ecp_group_free(grp);

    grp->MBEDTLS_PRIVATE(modp) = ecp_mod_p255;
    return ecp_use_ed25519(grp);
}

int ed25519_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{

    int ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    MBEDTLS_MPI_CHK(ecp_mul_edxyz(grp, R, m, P, f_rng, p_rng));

cleanup:
    return (ret);
}

int ed25519_ecp_point_write_binary(const mbedtls_ecp_group *grp,
                                   const mbedtls_ecp_point *P,
                                   int format, size_t *olen,
                                   unsigned char *buf, size_t buflen)
{
    int ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    size_t plen;

    plen = mbedtls_mpi_size(&grp->P);

    /* We need to add an extra bit to store the least significant bit of X. */
    plen = (mbedtls_mpi_bitlen(&grp->P) + 1 + 7) >> 3;

    *olen = plen;
    if (buflen < *olen)
        return (MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL);

    if (mbedtls_mpi_cmp_int(&P->MBEDTLS_PRIVATE(Z), 1) != 0)
        return MBEDTLS_ERR_MPI_BAD_INPUT_DATA;

    MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary_le(&P->MBEDTLS_PRIVATE(Y), buf, plen));

    /* Store the least significant bit of X into the most significant
     * bit of the final octet. */
    if (mbedtls_mpi_get_bit(&P->MBEDTLS_PRIVATE(X), 0))
        buf[plen - 1] |= 0x80;

cleanup:
    return (ret);
}

void mbedtls_edsign_sec_to_pub(uint8_t *pk, const uint8_t *sk)
{

    // calc sha512 of sk
    uint8_t digest[SHA512_DIGEST_LENGTH];
    sha512_raw(sk, EDSIGN_SECRET_KEY_SIZE, digest);

    // normalize
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;

    // init ed25519 group
    mbedtls_ecp_group ed25519;
    mbedtls_ecp_group_init(&ed25519);
    ed25519_ecp_group_load(&ed25519);

    // load digest
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary_le(&s, digest, 32);

    // P = s*B
    mbedtls_ecp_point p;
    mbedtls_ecp_point_init(&p);
    ed25519_ecp_mul(&ed25519, &p, &s, &ed25519.G, mbedtls_rnd, NULL);

    // write result
    size_t output_len;
    ed25519_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED, &output_len, pk,
                                   EDSIGN_PUBLIC_KEY_SIZE);

    // cleanup
    mbedtls_ecp_group_free(&ed25519);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&p);
}

void mbedtls_edsign_sign(uint8_t *rs, const uint8_t *pk,
                         const uint8_t *sk,
                         const uint8_t *m, size_t mlen)
{

    // calc sha512 of sk
    uint8_t digest[SHA512_DIGEST_LENGTH];
    sha512_raw(sk, EDSIGN_SECRET_KEY_SIZE, digest);
    // normalize
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;

    // digest[0..32] is s, digest[32..64] is prefix

    // sha512(prefix || m)
    uint8_t digest_m[SHA512_DIGEST_LENGTH];
    sha512_init();
    sha512_update(digest + 32, 32);
    sha512_update(m, mlen);
    sha512_final(digest_m);

    // init ed25519 group
    mbedtls_ecp_group ed25519;
    mbedtls_ecp_group_init(&ed25519);
    ed25519_ecp_group_load(&ed25519);

    // load digest_m into r
    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_read_binary_le(&r, digest_m, SHA512_DIGEST_LENGTH);

    // P = r*B
    mbedtls_ecp_point p;
    mbedtls_ecp_point_init(&p);
    ed25519_ecp_mul(&ed25519, &p, &r, &ed25519.G, mbedtls_rnd, NULL);

    // write result to RS[0..32]
    size_t output_len;
    ed25519_ecp_point_write_binary(&ed25519, &p, MBEDTLS_ECP_PF_COMPRESSED, &output_len, rs,
                                   EDSIGN_PUBLIC_KEY_SIZE);

    // k = sha512(R, pk, m)
    uint8_t digest_k[SHA512_DIGEST_LENGTH];
    sha512_init();
    sha512_update(rs, 32);
    sha512_update(pk, EDSIGN_PUBLIC_KEY_SIZE);
    sha512_update(m, mlen);
    sha512_final(digest_k);

    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    mbedtls_mpi_read_binary_le(&k, digest_k, SHA512_DIGEST_LENGTH);
    mbedtls_mpi_mod_mpi(&k, &k, &ed25519.N);

    // s
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary_le(&s, digest, 32);
    mbedtls_mpi_mod_mpi(&s, &s, &ed25519.N);

    // k * s
    mbedtls_mpi_mul_mpi(&k, &k, &s);
    mbedtls_mpi_mod_mpi(&k, &k, &ed25519.N);

    // r + k * s
    mbedtls_mpi_add_mpi(&k, &k, &r);
    mbedtls_mpi_mod_mpi(&k, &k, &ed25519.N);

    // write result to RS[32..64]
    mbedtls_mpi_write_binary_le(&k, rs + 32, 32);

    // cleanup
    mbedtls_ecp_group_free(&ed25519);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&p);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&s);
}