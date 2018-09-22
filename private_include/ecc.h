#ifndef _ECC_H_
#define _ECC_H_

#include "typedef.h"

#define ECC_WORDSIZE 8
#define ECC_NUMBITS 256
#define ECC_NUMWORD (ECC_NUMBITS/ECC_WORDSIZE) //32

#define ECC_MAX_DIGITS  4

#define SWAP(a,b) { u32 t = a; a = b; b = t;}

/*
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
*/

typedef struct ecc_point
{
    u64 x[ECC_MAX_DIGITS];
    u64 y[ECC_MAX_DIGITS];
} ecc_point;

struct ecc_curve {
	u8 ndigits;
	struct ecc_point g;
	u64 p[ECC_MAX_DIGITS];
	u64 n[ECC_MAX_DIGITS];
	u64 h[ECC_MAX_DIGITS];
	u64 a[ECC_MAX_DIGITS];
	u64 b[ECC_MAX_DIGITS];
};

void ecc_bytes2native(u64 *native, void *bytes, u8 ndigits);
void ecc_native2bytes(void *bytes, u64 *native, u8 ndigits);

void ecc_point_add(struct ecc_curve *curve, ecc_point *result, ecc_point *x, ecc_point *y);
void ecc_point_mult(struct ecc_curve *curve, ecc_point *result, ecc_point *point, u64 *scalar, u64 *initialZ);
void ecc_point_mult2(struct ecc_curve *curve, ecc_point *result, ecc_point *g, ecc_point *p, u64 *s, u64 *t);
int ecc_point_is_zero(struct ecc_curve *curve, ecc_point *point);

#endif
