#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/swab.h>

#include "debug.h"
#include "random.h"
#include "ecc.h"
#include "sm2.h"
#include "sm3.h"

struct ecc_curve ecc_curve = {
	.g = {
		.x = {
			0x715A4589334C74C7ull, 0x8FE30BBFF2660BE1ull,
			0x5F9904466A39C994ull, 0x32C4AE2C1F198119ull
		},
		.y = {
			0x02DF32E52139F0A0ull, 0xD0A9877CC62A4740ull,
			0x59BDCEE36B692153ull, 0xBC3736A2F4F6779Cull
		},
	},
	.p = {
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
	},
	.n = {
		0x53BBF40939D54123ull, 0x7203DF6B21C6052Bull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
	},
	.h = {
		0x0000000000000001ull, 0x0000000000000000ull,
		0x0000000000000000ull, 0x0000000000000000ull,
	},
	.a = {
		0xFFFFFFFFFFFFFFFCull, 0xFFFFFFFF00000000ull,
		0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFEFFFFFFFFull
	},
	.b = {
		0xDDBCBD414D940E93ull, 0xF39789F515AB8F92ull,
		0x4D5A9E4BCF6509A7ull, 0x28E9FA9E9D9F5E34ull
	},
};

void ecc_bytes2native(u64 *native, u64 *bytes)
{
	unsigned int i;

	for (i = 0; i < ECC_MAX_DIGITS/2; ++i) {
		if (native == bytes) {
			u64 temp;

			temp = __swab64(native[i]);
			native[i] =  __swab64(bytes[ECC_MAX_DIGITS - i - 1]);
			bytes[ECC_MAX_DIGITS - i - 1] = temp;
		}else {
			native[i] =  __swab64(bytes[ECC_MAX_DIGITS - i - 1]);
			native[ECC_MAX_DIGITS - i - 1] =  __swab64(bytes[i]);
		}
	}
}

void ecc_native2bytes(u64 *bytes, u64 *native)
{
	unsigned int i;

	for (i = 0; i < ECC_MAX_DIGITS/2; ++i) {
		if (bytes == native) {
			u64 temp;
			temp =  __swab64(bytes[ECC_MAX_DIGITS - i - 1]);
			bytes[ECC_MAX_DIGITS - i - 1] =  __swab64(native[i]);
			native[i] = temp;
		} else {
			bytes[i] =  __swab64(native[ECC_MAX_DIGITS - i - 1]);
			bytes[ECC_MAX_DIGITS - i - 1] =  __swab64(native[i]);
		}
	}
}

/*x¯2 = 2w + (x2&(2w − 1))*/
void sm2_w(u64 *result, u64 *x)
{
	result[0] = x[0];
	result[1] = x[1];
	result[1] |= 0x80;
	result[2] = 0;
	result[3] = 0;
}

void sm3_kdf(u8 *Z ,u32 zlen, u8 *K, u32 klen)
{
	u32 ct = 0x00000001;
	u8 ct_char[32];
	u8 *hash = K ;
	u32 i, t;
	sm3_ctx md[1];

	t = klen/ECC_NUMWORD;
	//s4: K=Ha1||Ha2||...
	for (i = 0; i < t; i++) {
		//s2: Hai=Hv(Z||ct)
		sm3_init(md);
		sm3_update(md, Z, zlen);
		digit2str32(ct, ct_char);
		sm3_update(md, ct_char, 4);
		sm3_finish(md, hash);
		hash += 32;
		ct++;
	}

	t = klen%ECC_NUMBITS;
	if (t) {
		sm3_init(md);
		sm3_update(md, Z, zlen);
		digit2str32(ct, ct_char);
		sm3_update(md, ct_char, 4);
		sm3_finish(md, ct_char);
		memcpy(hash, ct_char, t);
	}
}

void sm3_z(u8 *id, u32 idlen, ecc_point *pub, u8 *hash)
{
	u8 a[ECC_NUMWORD];
	u8 b[ECC_NUMWORD];
	u8 x[ECC_NUMWORD];
	u8 y[ECC_NUMWORD];
	u8 idlen_char[2];
	sm3_ctx md[1];

	digit2str16(idlen<<3, idlen_char);

	ecc_bytes2native((u64*)a, ecc_curve.a);
	ecc_bytes2native((u64*)b, ecc_curve.b);
	ecc_bytes2native((u64*)x, ecc_curve.g.x);
	ecc_bytes2native((u64*)y, ecc_curve.g.y);

	sm3_init(md);
	sm3_update(md, idlen_char, 2);
	sm3_update(md, id, idlen);
	sm3_update(md, a, ECC_NUMWORD);
	sm3_update(md, b, ECC_NUMWORD);
	sm3_update(md, x, ECC_NUMWORD);
	sm3_update(md, y, ECC_NUMWORD);
	sm3_update(md, (u8*)pub->x, ECC_NUMWORD);
	sm3_update(md, (u8*)pub->y, ECC_NUMWORD);
	sm3_finish(md, hash);

	return;
}

int ecc_valid_public_key(ecc_point *publicKey)
{
	u64 na[ECC_MAX_DIGITS] = {3}; /* a mod p = (-3) mod p */
	u64 tmp1[ECC_MAX_DIGITS];
	u64 tmp2[ECC_MAX_DIGITS];

	if (ecc_point_is_zero(publicKey))
		return 1;

	if (vli_cmp(ecc_curve.p, publicKey->x) != 1 || vli_cmp(ecc_curve.p, publicKey->y) != 1)
		return 1;

	vli_mod_square_fast(tmp1, publicKey->y, ecc_curve.p); /* tmp1 = y^2 */
	vli_mod_square_fast(tmp2, publicKey->x, ecc_curve.p); /* tmp2 = x^2 */
	vli_mod_sub(tmp2, tmp2, na, ecc_curve.p);  /* tmp2 = x^2 + a = x^2 - 3 */
	vli_mod_mult_fast(tmp2, tmp2, publicKey->x, ecc_curve.p); /* tmp2 = x^3 + ax */
	vli_mod_add(tmp2, tmp2, ecc_curve.b, ecc_curve.p); /* tmp2 = x^3 + ax + b */

	/* Make sure that y^2 == x^3 + ax + b */
	if (vli_cmp(tmp1, tmp2) != 0)
		return 1;

	return 0;
}

int sm2_make_prikey(u8 *prikey)
{
	ecc_point pub[1];
	u64 pri[ECC_MAX_DIGITS];
	int i = 10;

	do {
		vli_get_random((u8*)pri, ECC_NUMWORD);
		if(vli_cmp(ecc_curve.n, pri) != 1) {
			vli_sub(pri, pri, ecc_curve.n);
		}

		/* The private key cannot be 0 (mod p). */
		if(!vli_is_zero(pri)) {
			ecc_bytes2native((u64*)prikey, pri);
			return 0;
		}
	} while(i--);

	return -1;
}

int sm2_make_pubkey(u8 *prikey, ecc_point *pubkey)
{
	ecc_point pub[1];
	u64 pri[ECC_MAX_DIGITS];

	ecc_bytes2native(pri, (u64*)prikey);
	ecc_point_mult(pub, &ecc_curve.g, pri, NULL);
	ecc_bytes2native(pubkey->x, pub->x);
	ecc_bytes2native(pubkey->y, pub->y);

	return 0;
}

int sm2_make_keypair(u8 *prikey, ecc_point *pubkey)
{
	sm2_make_prikey(prikey);
	sm2_make_pubkey(prikey, pubkey);
	return 0;
}

int sm2_point_mult(ecc_point *G, u8 *k, ecc_point *P)
{
	int rc = 0;

	ecc_point G_[1];
	ecc_point P_[1];
	u64 k_[ECC_MAX_DIGITS];

	ecc_bytes2native(k_, (u64*)k);
	ecc_bytes2native(G_->x, G->x);
	ecc_bytes2native(G_->y, G->y);

	ecc_point_mult(P_, G_, k_, NULL);

	ecc_bytes2native(P->x, P_->x);
	ecc_bytes2native(P->y, P_->y);

	return rc;
}

int sm2_sign(u8 *r_, u8 *s_, u8 *prikey, u8 *hash_)
{
	u64 k[ECC_MAX_DIGITS];
	u64 one[ECC_MAX_DIGITS] = {1};
	u64 random[ECC_MAX_DIGITS];
	u64 pri[ECC_MAX_DIGITS];
	u64 hash[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];

	ecc_point p;

	ecc_bytes2native(pri, (u64*)prikey);
	ecc_bytes2native(hash, (u64*)hash_);

	vli_get_random((u8*)random, ECC_NUMWORD);
	if (vli_is_zero(random)) {
		/* The random number must not be 0. */
		return 0;
	}

	vli_set(k, random);
	if (vli_cmp(ecc_curve.n, k) != 1) {
		vli_sub(k, k, ecc_curve.n);
	}

	/* tmp = k * G */
	ecc_point_mult(&p, &ecc_curve.g, k, NULL);

	/* r = x1 + e (mod n) */
	vli_mod_add(r, p.x, hash, ecc_curve.n);
	if (vli_cmp(ecc_curve.n, r) != 1) {
		vli_sub(r, r, ecc_curve.n);
	}

	if (vli_is_zero(r)) {
		/* If r == 0, fail (need a different random number). */
		return 0;
	}

	vli_mod_mult(s, r, pri, ecc_curve.n); /* s = r*d */
	vli_mod_sub(s, k, s, ecc_curve.n); /* k-r*d */
	vli_mod_add(pri, pri, one, ecc_curve.n); /* 1+d */
	vli_mod_inv(pri, pri, ecc_curve.n); /* (1+d)' */
	vli_mod_mult(s, pri, s, ecc_curve.n); /* (1+d)'*(k-r*d) */

	ecc_bytes2native((u64*)r_, r);
	ecc_bytes2native((u64*)s_, s);

	return 1;
}

int sm2_verify(ecc_point *pubkey, u8 *hash_, u8 *r_, u8 *s_)
{
	ecc_point result;
	ecc_point pub[1];
	u64 t[ECC_MAX_DIGITS];
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];
	u64 hash[ECC_MAX_DIGITS];

	ecc_bytes2native(pub->x, pubkey->x);
	ecc_bytes2native(pub->y, pubkey->y);
	ecc_bytes2native(r, (u64*)r_);
	ecc_bytes2native(s, (u64*)s_);
	ecc_bytes2native(hash, (u64*)hash_);

	if (vli_is_zero(r) || vli_is_zero(s)) {
		/* r, s must not be 0. */
		return -1;
	}

	if (vli_cmp(ecc_curve.n, r) != 1 || vli_cmp(ecc_curve.n, s) != 1) {
		/* r, s must be < n. */
		return -1;
	}

	vli_mod_add(t, r, s, ecc_curve.n); // r + s
	if (t == 0)
		return -1;

	ecc_point_mult2(&result, &ecc_curve.g, pub, s, t);

	/* v = x1 + e (mod n) */
	vli_mod_add(result.x, result.x, hash, ecc_curve.n);

	if(vli_cmp(ecc_curve.n, result.x) != 1) {
		vli_sub(result.x, result.x, ecc_curve.n);
	}

	/* Accept only if v == r. */
	return vli_cmp(result.x, r);
}

int sm2_encrypt(ecc_point *pubKey, u8 *M, u32 Mlen, u8 *C, u32 *Clen)
{
	u64 k[ECC_MAX_DIGITS];
	u8 t[SM3_DATA_LEN];
	ecc_point pub[1];
	ecc_point *C1 = (ecc_point *)C;
	u8 *C2 = C + ECC_NUMWORD*2;
	u8 *C3 = C + ECC_NUMWORD*2 + Mlen;

	ecc_point kP;
	u8 *x2 = (u8*)kP.x;
	u8 *y2 = (u8*)kP.y;
	u8 *x2y2 = (u8*)kP.x;
	sm3_ctx md[1];
	int i=0;

	ecc_bytes2native(pub->x, pubKey->x);
	ecc_bytes2native(pub->y, pubKey->y);

	vli_get_random((u8*)k, ECC_NUMWORD);

	/* C1 = k * G */
	ecc_point_mult(C1, &ecc_curve.g, k, NULL);
	ecc_bytes2native(C1->x, C1->x);
	ecc_bytes2native(C1->y, C1->y);

	/* S = h * Pb */
	ecc_point S;
	ecc_point_mult(&S, pub, ecc_curve.h, NULL);
	if (ecc_valid_public_key(&S) != 0)
		return -1;

	/* kP = k * Pb */
	ecc_point_mult(&kP, pub, k, NULL);
	if (vli_is_zero(kP.x) | vli_is_zero(kP.y)) {
		return 0;
	}
	ecc_bytes2native(kP.x, kP.x);
	ecc_bytes2native(kP.y, kP.y);

	/* t=KDF(x2 ∥ y2, klen) */
	sm3_kdf(x2y2, ECC_NUMWORD*2, t, Mlen);

	/* C2 = M ⊕ t；*/
	for (i = 0; i < Mlen; i++) {
		C2[i] = M[i]^t[+i];
	}

	/*C3 = Hash(x2 ∥ M ∥ y2)*/
	sm3_init(md);
	sm3_update(md, x2, ECC_NUMWORD);
	sm3_update(md, M, Mlen);
	sm3_update(md, y2, ECC_NUMWORD);
	sm3_finish(md, C3);

	if (Clen)
		*Clen = Mlen + ECC_NUMWORD*2 + SM3_DATA_LEN;

	return 0;
}

int sm2_decrypt(u8 *prikey, u8 *C, u32 Clen, u8 *M, u32 *Mlen)
{
	u8 hash[SM3_DATA_LEN];
	u64 pri[ECC_MAX_DIGITS];
	ecc_point *C1 = (ecc_point *)C;
	u8 *C2 = C + ECC_NUMWORD*2;
	u8 *C3 = C + Clen - SM3_DATA_LEN;
	ecc_point dB;
	u64 *x2 = dB.x;
	u64 *y2 = dB.y;
	u64 *x2y2 = x2;
	sm3_ctx md[1];
	int outlen = Clen - ECC_NUMWORD*2 - SM3_DATA_LEN;
	int i=0;

	ecc_bytes2native(pri, (u64*)prikey);
	ecc_bytes2native(C1->x, C1->x);
	ecc_bytes2native(C1->y, C1->y);

	if (ecc_valid_public_key(C1) != 0)
		return -1;

	ecc_point S;
	ecc_point_mult(&S, C1, ecc_curve.h, NULL);
	if (ecc_valid_public_key(&S) != 0)
		return -1;

	ecc_point_mult(&dB, C1, pri, NULL);
	ecc_bytes2native(x2, x2);
	ecc_bytes2native(y2, y2);

	sm3_kdf((u8*)x2y2, ECC_NUMWORD*2, M, outlen);
	if (vli_is_zero(x2) | vli_is_zero(y2)) {
		return 0;
	}

	for (i = 0; i < outlen; i++)
		M[i]=M[i]^C2[i];

	sm3_init(md);
	sm3_update(md, (u8*)x2, ECC_NUMWORD);
	sm3_update(md, M, outlen);
	sm3_update(md, (u8*)y2, ECC_NUMWORD);
	sm3_finish(md, hash);

	*Mlen = outlen;
	if (memcmp(hash , C3, SM3_DATA_LEN) != 0)
		return -1;
	else
		return 0;
}

int sm2_shared_point(u8* selfPriKey,  u8* selfTempPriKey, ecc_point* selfTempPubKey,
		 ecc_point *otherPubKey, ecc_point* otherTempPubKey, ecc_point *key)
{
	ecc_point selfTempPub;
	ecc_point otherTempPub;
	ecc_point otherPub;
	ecc_point U[1];

	u64 selfTempPri[ECC_MAX_DIGITS];
	u64 selfPri[ECC_MAX_DIGITS];
	u64 temp1[ECC_MAX_DIGITS];
	u64 temp2[ECC_MAX_DIGITS];
	u64 tA[ECC_MAX_DIGITS];

	ecc_bytes2native(selfTempPri, (u64*)selfTempPriKey);
	ecc_bytes2native(selfPri, (u64*)selfPriKey);
	ecc_bytes2native(selfTempPub.x, selfTempPubKey->x);
	ecc_bytes2native(selfTempPub.y, selfTempPubKey->y);
	ecc_bytes2native(otherTempPub.x, otherTempPubKey->x);
	ecc_bytes2native(otherTempPub.y, otherTempPubKey->y);
	ecc_bytes2native(otherPub.x, otherPubKey->x);
	ecc_bytes2native(otherPub.y, otherPubKey->y);

	/***********x1_=2^w+x2 & (2^w-1)*************/
	sm2_w(temp1, selfTempPub.x);
	/***********tA=(dA+x1_*rA)mod n *************/
	vli_mod_mult(temp1, selfTempPri, temp1, ecc_curve.n);
	vli_mod_add(tA, selfPri, temp1, ecc_curve.n);
	/***********x2_=2^w+x2 & (2^w-1)*************/
	if(ecc_valid_public_key(&otherTempPub) != 0)
		return -1;
	sm2_w(temp2, otherTempPub.x);
	/**************U=[h*tA](PB+[x2_]RB)**********/
	ecc_point_mult(U, &otherTempPub, temp2, NULL);/* U=[x2_]RB */
	ecc_point_add(U, &otherPub, U); /*U=PB+U*/
	vli_mod_mult(tA, tA, ecc_curve.h, ecc_curve.n); /*tA=tA*h */
	ecc_point_mult(U, U,tA, NULL);

	ecc_bytes2native(key->x, U->x);
	ecc_bytes2native(key->y, U->y);
}

int sm2_shared_key(ecc_point *point, u8 *ZA, u8 *ZB, u32 keyLen, u8 *key)
{
	u8 Z[ECC_NUMWORD*4];
	memcpy(Z, point->x, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD, point->y, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD*2, ZA, ECC_NUMWORD);
	memcpy(Z + ECC_NUMWORD*3, ZB, ECC_NUMWORD);
	sm3_kdf(Z, ECC_NUMWORD*4, key, keyLen);
}

/****hash = Hash(Ux||ZA||ZB||x1||y1||x2||y2)****/
int ECC_Key_ex_hash1(u8* x, ecc_point *RA, ecc_point* RB, u8 ZA[],u8 ZB[],u8 *hash)
{
	sm3_ctx md[1];

	sm3_init(md);
	sm3_update(md, x, ECC_NUMWORD);
	sm3_update(md, ZA, ECC_NUMWORD);
	sm3_update(md, ZB, ECC_NUMWORD);
	sm3_update(md, (u8*)RA->x, ECC_NUMWORD);
	sm3_update(md, (u8*)RA->y, ECC_NUMWORD);
	sm3_update(md, (u8*)RB->x, ECC_NUMWORD);
	sm3_update(md, (u8*)RB->y, ECC_NUMWORD);
	sm3_finish(md, (u8*)hash);

	return 0;
}

/****SA = Hash(temp||Uy||Hash)****/
int ECC_Key_ex_hash2(u8 temp, u8* y,u8 *hash, u8* SA)
{
	sm3_ctx md[1];

	sm3_init(md);
	sm3_update(md, &temp,1);
	sm3_update(md, y,ECC_NUMWORD);
	sm3_update(md, hash,ECC_NUMWORD);
	sm3_finish(md, SA);

	return 0;
}

int ECC_KeyEx_Init_I(u8 *pri, ecc_point *pub)
{
	return sm2_make_pubkey(pri, pub);
}

int ECC_KeyEx_Re_I(u8 *rb, u8 *dB, ecc_point *RA, ecc_point *PA, u8* ZA, u8 *ZB, u8 *K, u32 klen, ecc_point *RB, ecc_point *V, u8* SB)
{
	sm3_ctx md[1];
	u8 Z[ECC_NUMWORD*2 + ECC_NUMBITS/4]={0};
	u8 hash[ECC_NUMWORD],S1[ECC_NUMWORD];
	u8 temp=0x02;

	//--------B2: RB=[rb]G=(x2,y2)--------
	sm2_make_pubkey(rb, RB);
	/********************************************/
	sm2_shared_point(dB,  rb, RB, PA, RA, V);
	//------------B7:KB=KDF(VX,VY,ZA,ZB,KLEN)----------
	memcpy(Z, V->x, ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD, (u8*)V->y, ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*2, ZA,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*3, ZB,ECC_NUMWORD);
	sm3_kdf(Z,ECC_NUMWORD*4, K, klen);
	//---------------B8:(optional) SB=hash(0x02||Vy||HASH(Vx||ZA||ZB||x1||y1||x2||y2)-------------
	ECC_Key_ex_hash1((u8*)V->x,  RA, RB, ZA, ZB, hash);
	ECC_Key_ex_hash2(temp, (u8*)V->y, hash, SB);

	return 0;
}

int ECC_KeyEx_Init_II(u8* ra, u8* dA, ecc_point* RA, ecc_point* RB, ecc_point* PB, u8
		ZA[],u8 ZB[],u8 SB[],u8 K[], u32 klen,u8 SA[])
{
	sm3_ctx md[1];
	u8 Z[ECC_NUMWORD*2 + ECC_NUMWORD*2]={0};
	u8 hash[ECC_NUMWORD],S1[ECC_NUMWORD];
	u8 temp[2]={0x02,0x03};
	ecc_point U[1];

	/********************************************/
	sm2_shared_point(dA, ra, RA, PB, RB, U);
	/************KA=KDF(UX,UY,ZA,ZB,KLEN)**********/
	memcpy(Z, U->x,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD, U->y,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*2,ZA,ECC_NUMWORD);
	memcpy(Z+ECC_NUMWORD*2 +ECC_NUMWORD ,ZB,ECC_NUMWORD);
	sm3_kdf(Z,ECC_NUMWORD*2+ECC_NUMWORD*2, K, klen);
	/****S1 = Hash(0x02||Uy||Hash(Ux||ZA||ZB||x1||y1||x2||y2))****/
	ECC_Key_ex_hash1((u8*)U->x,  RA, RB, ZA, ZB, hash);
	ECC_Key_ex_hash2(temp[0], (u8*)U->y, hash, S1);
	/*test S1=SB?*/
	if( memcmp(S1,SB,ECC_NUMWORD)!=0)
		return -1;
	/*SA = Hash(0x03||yU||Hash(xU||ZA||ZB||x1||y1||x2||y2)) */
	ECC_Key_ex_hash2(temp[1], (u8*)U->y, hash, SA);

	return 0;
}

int ECC_KeyEx_Re_II(ecc_point *V, ecc_point *RA, ecc_point *RB, u8 ZA[], u8 ZB[], u8 SA[])
{
	u8 hash[ECC_NUMWORD];
	u8 S2[ECC_NUMWORD];
	u8 temp=0x03;
	sm3_ctx md[1];

	/*S2 = Hash(0x03||Vy||Hash(Vx||ZA||ZB||x1||y1||x2||y2))*/
	ECC_Key_ex_hash1((u8*)V->x,  RA, RB, ZA, ZB, hash);
	ECC_Key_ex_hash2(temp, (u8*)V->y, hash, S2);

	if( memcmp(S2,SA,ECC_NUMWORD)!=0)
		return -1;

	return 0;
}
