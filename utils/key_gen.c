#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "sm2.h"
#include "debug.h"

int main(int argc, char **argv)
{
	u8 pri[ECC_NUMWORD];
	ecc_point pub[1];
	int i = 1;

	if (argc > 1)
		i = atoi(argv[1]);

	while(i--){
		speed_test("aa", 2);
		sm2_make_keypair(pri, pub);
	}

	printHex("private", pri, 32);
	printHex("public_x", (u8*)pub->x, 32);
	printHex("public_y", (u8*)pub->y, 32);

	return 0;
}
