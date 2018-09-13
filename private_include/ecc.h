#ifndef _ECC_H_
#define _ECC_H_

#include "typedef.h"

#define ECC_WORDSIZE 8
#define ECC_NUMBITS 256
#define ECC_NUMWORD (ECC_NUMBITS/ECC_WORDSIZE) //32

#define ECC_MAX_DIGITS  4

#define SWAP(a,b) { u32 t = a; a = b; b = t;}

#define digit2str16(x, y)   {                               \
	        (y)[0] = (u64)((x >> 8 ) & 0x000000FF);      \
	        (y)[1] = (u64)((x >> 0 ) & 0x000000FF);      \
}

#define str2digit16(y, x)    {                                  \
	        x = ((((u16)(y)[0]) & 0x000000FF) << 8)  |  \
	            ((((u16)(y)[1]) & 0x000000FF) << 0 );   \
}

#define digit2str32(x, y)   {                               \
	        (y)[0] = (u64)((x >> 24) & 0x000000FF);      \
	        (y)[1] = (u64)((x >> 16) & 0x000000FF);      \
	        (y)[2] = (u64)((x >> 8 ) & 0x000000FF);      \
	        (y)[3] = (u64)((x >> 0 ) & 0x000000FF);      \
}

#define str2digit32(y, x)    {                                   \
	        x = ((((u32)(y)[0]) & 0x000000FF) << 24)  |  \
	            ((((u32)(y)[1]) & 0x000000FF) << 16)  |  \
	            ((((u32)(y)[2]) & 0x000000FF) << 8 )  |  \
	            ((((u32)(y)[3]) & 0x000000FF) << 0 );    \
}

typedef struct ecc_point
{
    u64 x[ECC_MAX_DIGITS];
    u64 y[ECC_MAX_DIGITS];
} ecc_point;

struct ecc_curve {
	struct ecc_point g;
	u64 p[ECC_MAX_DIGITS];
	u64 n[ECC_MAX_DIGITS];
	u64 h[ECC_MAX_DIGITS];
	u64 a[ECC_MAX_DIGITS];
	u64 b[ECC_MAX_DIGITS];
};

void ecc_point_add(ecc_point *result, ecc_point *x, ecc_point *y);
void ecc_point_mult(ecc_point *result, ecc_point *point, u64 *scalar, u64 *initialZ);
void ecc_point_mult2(ecc_point *result, ecc_point *g, ecc_point *p, u64 *s, u64 *t);
int ecc_point_is_zero(ecc_point *point);

typedef struct {
	u64 m_low;
	u64 m_high;
} u128;

void vli_clear(u64 *vli);

/* Returns true if vli == 0, false otherwise. */
int vli_is_zero(u64 *vli);

/* Returns nonzero if bit bit of vli is set. */
u64 vli_test_bit(u64 *vli, uint bit);

/* Counts the number of 8-bit "digits" in vli. */
u32 vli_num_digits(u64 *vli);

/* Counts the number of bits required for vli. */
u32 vli_num_bits(u64 *vli);
/* Sets dest = src. */

void vli_set(u64 *dest, u64 *src);

/* Returns sign of left - right. */
int vli_cmp(u64 *left, u64 *right);

/* Computes result = in << c, returning carry. Can modify in place
 * (if result == in). 0 < shift < 8.
 */
u64 vli_lshift(u64 *result, u64 *in, u32 shift);

/* Computes vli = vli >> 1. */
void vli_rshift1(u64 *vli);

/* Computes result = left + right, returning carry. Can modify in place. */
u64 vli_add(u64 *result, u64 *left, u64 *right);

/* Computes result = left - right, returning borrow. Can modify in place. */
u64 vli_sub(u64 *result, u64 *left, u64 *right);

/* Computes result = left * right. */
void vli_mult(u64 *result, u64 *left, u64 *right);

/* Computes result = left^2. */
void vli_square(u64 *result, u64 *left);

/* Computes result = (left + right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_add(u64 *result, u64 *left, u64 *right, u64 *mod);

/* Computes result = (left - right) % mod.
   Assumes that left < mod and right < mod, result != mod. */
void vli_mod_sub(u64 *result, u64 *left, u64 *right, u64 *mod);

/* Computes result = (left * right) % ecc_curve.p. */
void vli_mod_mult_fast(u64 *result, u64 *left, u64 *right, u64 *mod);

/* Computes result = left^2 % ecc_curve.p. */
void vli_mod_square_fast(u64 *result, u64 *left, u64 *mod);

/* Computes result = (left * right) % mod. */
void vli_mod_mult(u64 *result, u64 *left, u64 *right, u64 *mod);

/* Computes result = (1 / input) % mod. All VLIs are the same size.
 * See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
 * https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf
 */
void vli_mod_inv(u64 *result, u64 *input, u64 *mod);


#endif
