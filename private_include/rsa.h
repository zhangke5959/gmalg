#ifndef __RSA_H__
#define __RSA_H__

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RSA_MAX_MODULUS_BITS          2048
#define RSA_MAX_MODULUS_LEN           ((RSA_MAX_MODULUS_BITS + 7) / 8)
#define RSA_MAX_PRIME_BITS            ((RSA_MAX_MODULUS_BITS + 1) / 2)
#define RSA_MAX_PRIME_LEN             ((RSA_MAX_PRIME_BITS + 7) / 8)

#define ERR_WRONG_DATA                (-1)
#define ERR_WRONG_LEN                 (-2)

typedef struct rsa_pk_t{
    u32 bits;
    u8  modulus[RSA_MAX_MODULUS_LEN];
    u8  exponent[RSA_MAX_MODULUS_LEN];
} rsa_pk;

typedef struct rsa_sk_t{
    u32 bits;
    u8  modulus[RSA_MAX_MODULUS_LEN];
    u8  public_exponet[RSA_MAX_MODULUS_LEN];
    u8  exponent[RSA_MAX_MODULUS_LEN];
    u8  prime1[RSA_MAX_PRIME_LEN];
    u8  prime2[RSA_MAX_PRIME_LEN];
    u8  prime_exponent1[RSA_MAX_PRIME_LEN];
    u8  prime_exponent2[RSA_MAX_PRIME_LEN];
    u8  coefficient[RSA_MAX_PRIME_LEN];
} rsa_sk;

int rsa_make_keypair(struct rsa_sk_t *prikey, struct rsa_pk_t *pubkey);
int rsa_encrypt(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_pk_t *pk);
int rsa_decrypt(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_sk_t *sk);
int rsa_sign(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_sk_t *sk);
int rsa_verify(u8 *out, u32 *out_len, u8 *in, u32 in_len, struct rsa_pk_t *pk);

#ifdef __cplusplus
}
#endif

#endif  /*__RSA_H__*/

