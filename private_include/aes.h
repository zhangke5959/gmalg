#ifndef _AES_H
#define _AES_H

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AES_MIN_KEY_SIZE	16
#define AES_MAX_KEY_SIZE	32
#define AES_KEYSIZE_128		16
#define AES_KEYSIZE_192		24
#define AES_KEYSIZE_256		32
#define AES_BLOCK_SIZE		16
#define AES_MAX_KEYLENGTH	(15 * 16)
#define AES_MAX_KEYLENGTH_U32	(AES_MAX_KEYLENGTH / sizeof(u32))

struct aes_ctx {
	u32 key_enc[AES_MAX_KEYLENGTH_U32];
	u32 key_dec[AES_MAX_KEYLENGTH_U32];
	u32 key_length;
};

void aes_ecb_encrypt(struct aes_ctx *ctx, u8 *key, u8 key_len, u8 *in, u8 len, u8 *out);
void aes_ecb_decrypt(struct aes_ctx *ctx, u8 *key, u8 key_len, u8 *in, u8 len, u8 *out);
void aes_cbc_encrypt(struct aes_ctx *ctx, u8 *key, u8 key_len, u8 *iv, u8 *in, u8 len, u8 *out);
void aes_cbc_decrypt(struct aes_ctx *ctx, u8 *key, u8 key_len, u8 *iv, u8 *in, u8 len, u8 *out);

#ifdef __cplusplus
}
#endif

#endif
