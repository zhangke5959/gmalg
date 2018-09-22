#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "debug.h"
#include "aes.h"

u8 iv[16];
u8 key[16];
u8 in[128];
u8 out[128];
u8 len = 64;
u8 key_len = 16;

int main(int argc, char **agv)
{
	struct aes_ctx ctx[1];
	int i;

	for (i = 0; i < len; i++) {
		in[i] = i;
	}
	memset(key, 0x88, 16);

	aes_ecb_encrypt(ctx, key, key_len, in, len, out);

	printHex("ecb encrypt key ", key, 16);
	printHex("ecb encrypt in ", in, len);
	printHex("ecb encrypt out", out, len);

	aes_ecb_decrypt(ctx, key, key_len, out, len, in);

	printHex("ecb encrypt key ", key, 16);
	printHex("ecb decrypt in", out, len);
	printHex("ecb decrypt out ", in, len);


	aes_cbc_encrypt(ctx, key, key_len, iv, in, len, out);

	printHex("cbc encrypt key ", key, 16);
	printHex("cbc encrypt iv ", iv, 16);
	printHex("cbc encrypt in ", in, len);
	printHex("cbc encrypt out", out, len);

	aes_cbc_decrypt(ctx, key, key_len, iv, out, len, in);

	printHex("cbc encrypt key ", key, 16);
	printHex("cbc encrypt iv ", iv, 16);
	printHex("cbc decrypt in", out, len);
	printHex("cbc decrypt out ", in, len);
	return 0;
}
