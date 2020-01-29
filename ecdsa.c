#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/swab.h>

#include "debug.h"
#include "random.h"
#include "big.h"
#include "ecc.h"
#include "sm2.h"
#include "sm3.h"

struct ecc_curve ecdsa_curve = {
	.ndigits = ECC_MAX_DIGITS,
	.g = {
		.x = {
			0xF4A13945D898C296ull, 0x77037D812DEB33A0ull,
			0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull
		},
		.y = {
			0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull,
			0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull
		},
	},
	.p = {
		0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull,
		0x0000000000000000ull, 0xFFFFFFFF00000001ull
	},
	.n = {
		0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull
	},
	.h = {
	},
	.a = {
	},
	.b = {
		0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull,
		0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull
	},
};

int ecdsa_valid_public_key(ecc_point *publicKey)
{
	u64 na[ECC_MAX_DIGITS] = {3}; /* a mod p = (-3) mod p */
	u64 tmp1[ECC_MAX_DIGITS];
	u64 tmp2[ECC_MAX_DIGITS];

	if (ecc_point_is_zero(&ecdsa_curve, publicKey))
		return 1;

	if (vli_cmp(ecdsa_curve.p, publicKey->x, ecdsa_curve.ndigits) != 1 
			|| vli_cmp(ecdsa_curve.p, publicKey->y, ecdsa_curve.ndigits) != 1)
		return 1;

	/* tmp1 = y^2 */
	vli_mod_square_fast(tmp1, publicKey->y, ecdsa_curve.p, ecdsa_curve.ndigits);
	/* tmp2 = x^2 */
	vli_mod_square_fast(tmp2, publicKey->x, ecdsa_curve.p, ecdsa_curve.ndigits);
	/* tmp2 = x^2 + a = x^2 - 3 */
	vli_mod_sub(tmp2, tmp2, na, ecdsa_curve.p, ecdsa_curve.ndigits);
	/* tmp2 = x^3 + ax */
	vli_mod_mult_fast(tmp2, tmp2, publicKey->x, ecdsa_curve.p, ecdsa_curve.ndigits);
	/* tmp2 = x^3 + ax + b */
	vli_mod_add(tmp2, tmp2, ecdsa_curve.b, ecdsa_curve.p, ecdsa_curve.ndigits);

	/* Make sure that y^2 == x^3 + ax + b */
	if (vli_cmp(tmp1, tmp2, ecdsa_curve.ndigits) != 0)
		return 1;

	return 0;
}

int ecdsa_make_prikey(u8 *prikey)
{
	ecc_point pub[1];
	u64 pri[ECC_MAX_DIGITS];
	int i = 10;

	do {
		vli_get_random((u8*)pri, ecdsa_curve.ndigits);
		if(vli_cmp(ecdsa_curve.n, pri, ecdsa_curve.ndigits) != 1) {
			vli_sub(pri, pri, ecdsa_curve.n, ecdsa_curve.ndigits);
		}

		/* The private key cannot be 0 (mod p). */
		if(!vli_is_zero(pri, ecdsa_curve.ndigits)) {
			ecc_native2bytes(prikey, pri, ecdsa_curve.ndigits);
			return 0;
		}
	} while(i--);

	return -1;
}

int ecdsa_make_pubkey(u8 *prikey, ecc_point *pubkey)
{
	ecc_point pub[1];
	u64 pri[ECC_MAX_DIGITS];

	ecc_bytes2native(pri, prikey, ecdsa_curve.ndigits);
	ecc_point_mult(&ecdsa_curve, pub, &ecdsa_curve.g, pri, NULL);
	ecc_native2bytes(pubkey->x, pub->x, ecdsa_curve.ndigits);
	ecc_native2bytes(pubkey->y, pub->y, ecdsa_curve.ndigits);

	return 0;
}

int ecdsa_make_keypair(u8 *prikey, ecc_point *pubkey)
{
	sm2_make_prikey(prikey);
	sm2_make_pubkey(prikey, pubkey);
	return 0;
}

int ecdsa_point_mult(ecc_point *G, u8 *k, ecc_point *P)
{
	int rc = 0;

	ecc_point G_[1];
	ecc_point P_[1];
	u64 k_[ECC_MAX_DIGITS];

	ecc_bytes2native(k_, k, ecdsa_curve.ndigits);
	ecc_bytes2native(G_->x, G->x, ecdsa_curve.ndigits);
	ecc_bytes2native(G_->y, G->y, ecdsa_curve.ndigits);

	ecc_point_mult(&ecdsa_curve, P_, G_, k_, NULL);

	ecc_native2bytes(P->x, P_->x, ecdsa_curve.ndigits);
	ecc_native2bytes(P->y, P_->y, ecdsa_curve.ndigits);

	return rc;
}

int ecdsa_sign(u8 *r_, u8 *s_, u8 *prikey, u8 *hash_)
{
	u64 k[ECC_MAX_DIGITS];
	u64 one[ECC_MAX_DIGITS] = {1};
	u64 random[ECC_MAX_DIGITS];
	u64 pri[ECC_MAX_DIGITS];
	u64 hash[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];

	ecc_point p;

	ecc_bytes2native(pri, prikey, ecdsa_curve.ndigits);
	ecc_bytes2native(hash, hash_, ecdsa_curve.ndigits);

	vli_get_random((u8*)random, ecdsa_curve.ndigits);
	if (vli_is_zero(random, ecdsa_curve.ndigits)) {
		/* The random number must not be 0. */
		return 0;
	}

	vli_set(k, random, ecdsa_curve.ndigits);
	if (vli_cmp(ecdsa_curve.n, k, ecdsa_curve.ndigits) != 1) {
		vli_sub(k, k, ecdsa_curve.n, ecdsa_curve.ndigits);
	}

	/* tmp = k * G */
	ecc_point_mult(&ecdsa_curve, &p, &ecdsa_curve.g, k, NULL);

	/* r = x1 + e (mod n) */
	vli_mod_add(r, p.x, hash, ecdsa_curve.n, ecdsa_curve.ndigits);
	if (vli_cmp(ecdsa_curve.n, r, ecdsa_curve.ndigits) != 1) {
		vli_sub(r, r, ecdsa_curve.n, ecdsa_curve.ndigits);
	}

	if (vli_is_zero(r, ecdsa_curve.ndigits)) {
		/* If r == 0, fail (need a different random number). */
		return 0;
	}

	/* s = r*d */
	vli_mod_mult(s, r, pri, ecdsa_curve.n, ecdsa_curve.ndigits);
	/* k-r*d */
	vli_mod_sub(s, k, s, ecdsa_curve.n, ecdsa_curve.ndigits);
	/* 1+d */
	vli_mod_add(pri, pri, one, ecdsa_curve.n, ecdsa_curve.ndigits);
	/* (1+d)' */
	vli_mod_inv(pri, pri, ecdsa_curve.n, ecdsa_curve.ndigits);
	/* (1+d)'*(k-r*d) */
	vli_mod_mult(s, pri, s, ecdsa_curve.n, ecdsa_curve.ndigits);

	ecc_native2bytes(r_, r, ecdsa_curve.ndigits);
	ecc_native2bytes(s_, s, ecdsa_curve.ndigits);

	return 1;
}

int ecdsa_verify(ecc_point *pubkey, u8 *hash_, u8 *r_, u8 *s_)
{
	ecc_point result;
	ecc_point pub[1];
	u64 t[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];
	u64 hash[ECC_MAX_DIGITS];

	ecc_bytes2native(pub->x, pubkey->x, ecdsa_curve.ndigits);
	ecc_bytes2native(pub->y, pubkey->y, ecdsa_curve.ndigits);
	ecc_bytes2native(r, r_, ecdsa_curve.ndigits);
	ecc_bytes2native(s, s_, ecdsa_curve.ndigits);
	ecc_bytes2native(hash, hash_, ecdsa_curve.ndigits);

	if (vli_is_zero(r, ECC_NUMWORD) || vli_is_zero(s, ECC_NUMWORD)) {
		/* r, s must not be 0. */
		return -1;
	}

	if (vli_cmp(ecdsa_curve.n, r, ECC_NUMWORD) != 1 || vli_cmp(ecdsa_curve.n, s, ECC_NUMWORD) != 1) {
		/* r, s must be < n. */
		return -1;
	}

	vli_mod_add(t, r, s, ecdsa_curve.n, ECC_NUMWORD); /* r + s */
	if (t == 0)
		return -1;

	ecc_point_mult2(&ecdsa_curve, &result, &ecdsa_curve.g, pub, s, t);

	/* v = x1 + e (mod n) */
	vli_mod_add(result.x, result.x, hash, ecdsa_curve.n, ECC_NUMWORD);

	if(vli_cmp(ecdsa_curve.n, result.x, ECC_NUMWORD) != 1) {
		vli_sub(result.x, result.x, ecdsa_curve.n, ECC_NUMWORD);
	}

	/* Accept only if v == r. */
	return vli_cmp(result.x, r, ECC_NUMWORD);
}
