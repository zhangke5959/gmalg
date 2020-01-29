#ifndef _SM4_H_
#define _SM4_H_

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

struct sm4_ctx{
	u32 sk_enc[32];
	u32 sk_dec[32];
	u32 iv[16];
};

void sm4_ecb_encrypt(struct sm4_ctx *ctx, u8 *key, u8 *in, u32 len, u8 *out);
void sm4_ecb_decrypt(struct sm4_ctx *ctx, u8 *key, u8 *in, u32 len, u8 *out);
void sm4_cbc_encrypt(struct sm4_ctx *ctx, u8 *key, u8 *iv, u8 *in, u32 len, u8 *out);
void sm4_cbc_decrypt(struct sm4_ctx *ctx, u8 *key, u8 *iv, u8 *in, u32 len, u8 *out);

#ifdef __cplusplus
}
#endif

#endif /* _SM4_H_ */
