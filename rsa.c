#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include "rsa.h"
#include "debug.h"
#include "big.h"
#include "random.h"

static void rsa_decode(u64 *bn, u32 digits, u8 *hexarr, u32 size)
{
	u64 t;
	int i, j, u;

	for (i=0,j=size-1; i<digits && j>=0; i++) {
		t = 0;
		for (u=0; j>=0 && u<VLI_DIGIT_BITS; j--, u+=8) {
			t |= ((u64)hexarr[j]) << u;
		}
		bn[i] = t;
	}

	for (; i<digits; i++) {
		bn[i] = 0;
	}
}

static void rsa_encode(u8 *hexarr, u32 size, u64 *bn, u32 digits)
{
	u64 t;
	int i, j, u;

	for (i=0,j=size-1; i<digits && j>=0; i++) {
		t = bn[i];
		for (u=0; j>=0 && u<VLI_DIGIT_BITS; j--, u+=8) {
			hexarr[j] = (u8)(t >> u);
		}
	}

	for (; j >= 0; j--) {
		hexarr[j] = 0;
	}
}

#define RSA_MAX_DIGITS  (RSA_MAX_MODULUS_BITS/VLI_DIGIT_BITS)
static int public_block_operation(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_pk_t *pk)
{
	u64 c[RSA_MAX_DIGITS];
	u64 e[RSA_MAX_DIGITS];
	u64 m[RSA_MAX_DIGITS];
	u64 n[RSA_MAX_DIGITS];

	u32 bytes = (be32_to_cpu(pk->bits) + 7) / 8;
	u32 digits = bytes/VLI_DIGIT_BYTES;

	rsa_decode(m, RSA_MAX_DIGITS, in, in_len);
	rsa_decode(n, RSA_MAX_DIGITS, pk->modulus, RSA_MAX_MODULUS_LEN);
	rsa_decode(e, RSA_MAX_DIGITS, pk->exponent, RSA_MAX_MODULUS_LEN);

	if (vli_cmp(m, n, digits) >= 0) {
		return ERR_WRONG_DATA;
	}

	vli_mod_exp(c, m, e, n, digits);

	*out_len = bytes;
	rsa_encode(out, bytes, c, RSA_MAX_DIGITS);

	return 0;
}


static int private_block_operation(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_sk_t *sk)
{
	u64 c[RSA_MAX_DIGITS], c_[RSA_MAX_DIGITS], cp[RSA_MAX_DIGITS], cq[RSA_MAX_DIGITS];
	u64 dp[RSA_MAX_DIGITS], dq[RSA_MAX_DIGITS], mp[RSA_MAX_DIGITS], mq[RSA_MAX_DIGITS];
	u64 n[RSA_MAX_DIGITS], p[RSA_MAX_DIGITS], q[RSA_MAX_DIGITS], q_inv[RSA_MAX_DIGITS];
	u64 t[RSA_MAX_DIGITS], t_[RSA_MAX_DIGITS];
	u32 bytes = (be32_to_cpu(sk->bits) + 7) / 8;
	u32 digits = bytes/VLI_DIGIT_BYTES;
	u32 pdigits;

	rsa_decode(c, RSA_MAX_DIGITS, in, in_len);
	rsa_decode(c_, RSA_MAX_DIGITS, in, in_len);
	rsa_decode(n, RSA_MAX_DIGITS, sk->modulus, RSA_MAX_MODULUS_LEN);
	rsa_decode(p, RSA_MAX_DIGITS, sk->prime1, RSA_MAX_PRIME_LEN);
	rsa_decode(q, RSA_MAX_DIGITS, sk->prime2, RSA_MAX_PRIME_LEN);
	rsa_decode(dp, RSA_MAX_DIGITS, sk->prime_exponent1, RSA_MAX_PRIME_LEN);
	rsa_decode(dq, RSA_MAX_DIGITS, sk->prime_exponent2, RSA_MAX_PRIME_LEN);
	rsa_decode(q_inv, RSA_MAX_DIGITS, sk->coefficient, RSA_MAX_PRIME_LEN);

	pdigits = vli_num_digits(p, RSA_MAX_DIGITS);

	if (vli_cmp(c, n, digits) >= 0)
		return ERR_WRONG_DATA;

	vli_mod(cq, c, q, pdigits);
	vli_mod(cp, c_, p, pdigits);
	vli_mod_exp(mp, cp, dp, p, pdigits);
	vli_clear(mq, digits);
	vli_mod_exp(mq, cq, dq, q, pdigits);

	if (vli_cmp(mp, mq, pdigits) >= 0) {
		vli_sub(t, mp, mq, pdigits);
	} else {
		vli_sub(t, mq, mp, pdigits);
		vli_sub(t, p, t, pdigits);
	}
	vli_mod_mult(t, t, q_inv, p, pdigits);
	vli_mult(t_, t, q, pdigits);
	vli_add(t, t_, mq, digits);

	*out_len = bytes;
	rsa_encode(out, bytes, t, digits);

	/* Clear potentially sensitive information*/
	memset((u8 *)c, 0, sizeof(c));
	memset((u8 *)cp, 0, sizeof(cp));
	memset((u8 *)cq, 0, sizeof(cq));
	memset((u8 *)dp, 0, sizeof(dp));
	memset((u8 *)dq, 0, sizeof(dq));
	memset((u8 *)mp, 0, sizeof(mp));
	memset((u8 *)mq, 0, sizeof(mq));
	memset((u8 *)p, 0, sizeof(p));
	memset((u8 *)q, 0, sizeof(q));
	memset((u8 *)q_inv, 0, sizeof(q_inv));
	memset((u8 *)t, 0, sizeof(t));

	return 0;
}

int rsa_make_keypair(struct rsa_sk_t *prikey, struct rsa_pk_t *pubkey)
{
	int rc = 0;

	return rc;
}

int rsa_encrypt(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_pk_t *pk)
{
	u8 byte, block[RSA_MAX_MODULUS_LEN];
	u32 i, modulus_len;
	int rc;

	modulus_len = (be32_to_cpu(pk->bits) + 7) / 8;
	if (in_len + 11 > modulus_len) {
		return ERR_WRONG_LEN;
	}

	block[0] = 0;
	block[1] = 2;

	for ( i = 2; i < modulus_len - in_len - 1; i++) {
		do {
			vli_get_random(&byte, 1);
		} while (byte == 0);
		block[i] = byte;
	}

	block[i++] = 0;

	memcpy(&block[i], in, in_len);
	rc = public_block_operation(out, out_len, block, modulus_len, pk);

	/* Clear potentially sensitive information */
	byte = 0;
	memset((u8 *)block, 0, sizeof(block));

	return rc;
}

int rsa_decrypt(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_sk_t *sk)
{
	int rc;
	u8 block[RSA_MAX_MODULUS_LEN];
	u32 i, modulus_len, block_len;

	modulus_len = (be32_to_cpu(sk->bits) + 7) / 8; 
	if (in_len > modulus_len)
		return ERR_WRONG_LEN;

	rc = private_block_operation(block, &block_len, in, in_len, sk);
	if (rc != 0)
		return rc;

	if (block_len != modulus_len)
		return ERR_WRONG_LEN;

	if ((block[0] != 0) || (block[1] != 2))
		return ERR_WRONG_DATA;

	for (i=2; i<modulus_len-1; i++) {
		if(block[i] == 0)  break;
	}

	i++;
	if (i >= modulus_len)
		return ERR_WRONG_DATA;
	*out_len = modulus_len - i;
	if (*out_len + 11 > modulus_len)
		return ERR_WRONG_DATA;
	memcpy((u8 *)out, (u8 *)&block[i], *out_len);

	/* Clear potentially sensitive information */
	memset((u8 *)block, 0, sizeof(block));

	return rc;
}

int rsa_sign(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_sk_t *sk)
{
	u8 block[RSA_MAX_MODULUS_LEN];
	u32 i, modulus_len;
	int rc;

	modulus_len = (be32_to_cpu(sk->bits) + 7) / 8; 
	if (in_len + 11 > modulus_len)
		return ERR_WRONG_LEN;

	block[0] = 0;
	block[1] = 1;
	for (i=2; i<modulus_len-in_len-1; i++) {
		block[i] = 0xFF;
	}

	block[i++] = 0;

	memcpy((u8 *)&block[i], (u8 *)in, in_len);

	rc = private_block_operation(out, out_len, block, modulus_len, sk);

	/* Clear potentially sensitive information */
	memset((u8 *)block, 0, sizeof(block));

	return rc;
}

int rsa_verify(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_pk_t *pk)
{
	u8 block[RSA_MAX_MODULUS_LEN];
	u32 i, modulus_len, block_len;
	int rc;

	modulus_len = (be32_to_cpu(pk->bits) + 7) / 8;
	if (in_len > modulus_len)
		return ERR_WRONG_LEN;

	rc = public_block_operation(block, &block_len, in, in_len, pk);
	if (rc != 0)
		return rc;

	if (block_len != modulus_len)
		return ERR_WRONG_LEN;

	if ((block[0] != 0) || (block[1] != 1))
		return ERR_WRONG_DATA;

	for (i=2; i<modulus_len-1; i++) {
		if(block[i] != 0xFF)   break;
	}

	if (block[i++] != 0)
		return ERR_WRONG_DATA;

	*out_len = modulus_len - i;
	if (*out_len + 11 > modulus_len)
		return ERR_WRONG_DATA;

	memcpy((u8 *)out, (u8 *)&block[i], *out_len);

	/* Clear potentially sensitive information */
	memset((u8 *)block, 0, sizeof(block));

	return rc;
}

