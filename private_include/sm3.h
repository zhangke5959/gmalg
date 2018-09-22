#ifndef _SM3_H_
#define _SM3_H_

#include <stdint.h>
#include "typedef.h"

#define SM3_DATA_LEN	32

struct sm3_ctx {
	u32 total[2];    /*!< number of bytes processed  */
	u32 state[8];    /*!< intermediate digest state  */
	u8 buffer[64];   /*!< data block being processed */
	u8 ipad[64];     /*!< HMAC: inner padding        */
	u8 opad[64];     /*!< HMAC: outer padding        */
};

int sm3_init(struct sm3_ctx *ctx);
int sm3_update(struct sm3_ctx *ctx, const u8 *input, u32 ilen);
int sm3_final(struct sm3_ctx *ctx, u8 *output);

#endif /* _SM3_H_ */
