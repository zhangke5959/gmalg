#ifndef _SM3_H_
#define _SM3_H_



#include <stdint.h>
#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

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

int sm3_finup(struct sm3_ctx *ctx, const u8 *data,
		u32 len, u8 *out);


void sm3_hmac_starts(struct sm3_ctx *ctx, unsigned char *key, int keylen );

/*
 * SM3 HMAC process buffer
 */
void sm3_hmac_update(struct sm3_ctx *ctx, unsigned char *input, int ilen );

/*
 * SM3 HMAC final digest
 */
void sm3_hmac_finish(struct sm3_ctx *ctx, unsigned char output[32] );


/*
 * output = HMAC-SM#( hmac key, input buffer )
 */
void sm3_hmac( unsigned char *key, int keylen,
               unsigned char *input, int ilen,
               unsigned char output[32] );


#ifdef __cplusplus
}
#endif

#endif /* _SM3_H_ */
