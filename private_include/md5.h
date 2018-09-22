#ifndef __MD5_H__
#define __MD5_H__

#include <stdint.h>
#include "typedef.h"

#define MD5_DIGEST_SIZE   16
#define MD5_BLOCK_WORDS   16

#define MD5_H0  0x67452301UL
#define MD5_H1  0xefcdab89UL
#define MD5_H2  0x98badcfeUL
#define MD5_H3  0x10325476UL

struct md5_ctx {
	u32 hash[MD5_DIGEST_SIZE / 4];
	u32 block[MD5_BLOCK_WORDS];
	u64 byte_count;
};

int md5_init(struct md5_ctx *ctx);
int md5_update(struct md5_ctx *ctx, const u8 *data, u32 len);
int md5_final(struct md5_ctx *ctx, u8 *digest);

#endif
