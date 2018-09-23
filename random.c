
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "debug.h"
#include "random.h"

int vli_get_random(u8 *data, u32 len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	int ret = -1;

	if (fd > 0) {
		ret = read(fd, data, len);
		close(fd);

	}
//	memset(data, 0x33, len);
	return ret;
}
