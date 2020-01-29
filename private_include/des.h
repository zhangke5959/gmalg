#ifndef __DES_H
#define __DES_H

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DES_KEY_SIZE		8
#define DES_EXPKEY_WORDS	32
#define DES_BLOCK_SIZE		8

#define DES3_EDE_KEY_SIZE	(3 * DES_KEY_SIZE)
#define DES3_EDE_EXPKEY_WORDS	(3 * DES_EXPKEY_WORDS)
#define DES3_EDE_BLOCK_SIZE	DES_BLOCK_SIZE

struct des_ctx {
	u32 expkey[DES_EXPKEY_WORDS];
};

struct des3_ede_ctx {
	u32 expkey[DES3_EDE_EXPKEY_WORDS];
};

void des_ecb_encrypt(struct des_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out);
void des_ecb_decrypt(struct des_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out);
void des3_ecb_encrypt(struct des3_ede_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out);
void des3_ecb_decrypt(struct des3_ede_ctx *ctx, u8 *key, u8 *in, u8 len, u8 *out);


#ifdef __cplusplus
}
#endif

#endif /* __DES_H */
