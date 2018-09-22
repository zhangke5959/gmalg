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
	struct sha256_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
		
	sha256_init(ctx);
	sha256_update(ctx, in, len);
	sha256_final(ctx, hash);

	printHex("hash", hash, SHA256_DIGEST_SIZE);

	return 0;
}
