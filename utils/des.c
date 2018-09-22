#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "debug.h"
#include "des.h"

u8 iv[16];
u8 key[16];
u8 in[128];
u8 out[128];
u8 len = 64;
u8 key_len = 16;

int main(int argc, char **agv)
{
	struct des3_ede_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
	memset(key, 0x88, 16);
	memset(iv, 0x99, 16);

	des3_ecb_encrypt(ctx, key, in, len, out);

	printHex("encrypt key ", key, 16);
	printHex("encrypt in ", in, len);
	printHex("encrypt out", out, len);

	des3_ecb_decrypt(ctx, key, out, len, in);

	printHex("encrypt key ", key, 16);
	printHex("decrypt out", out, len);
	printHex("decrypt in ", in, len);

	return 0;
}
