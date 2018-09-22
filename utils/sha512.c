#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "debug.h"
#include "sha.h"

u8 in[64];
u8 hash[32];
u8 len = 64;

int main(int argc, char **agv)
{
	struct sha512_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
		
	sha512_init(ctx);
	sha512_update(ctx, in, len);
	sha512_final(ctx, hash);

	printHex("hash", hash, SHA512_DIGEST_SIZE);

	return 0;
}
