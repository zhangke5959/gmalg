#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "debug.h"
#include "md5.h"

u8 in[64];
u8 hash[32];
u8 len = 64;

int main(int argc, char **agv)
{
	struct md5_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
		
	md5_init(ctx);
	md5_update(ctx, in, len);
	md5_final(ctx, hash);

	printHex("hash", hash, MD5_DIGEST_SIZE);

	return 0;
}
