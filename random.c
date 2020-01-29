
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef RANDOM_SOFTWARE
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#endif

#include "debug.h"
#include "random.h"


static int gRadomFixedFlag;

/*SM2 Standard Random*/
static u8 gRandomFixed[32]= {0x21,0xBC,0xC1,0xEA,0x0D,0xB8,0x54,0x6D,0xCE,0xE4,0xDB,0x3C,0xFA,0xC1,0x3C,0xEF,
                             0xCC,0x2D,0xC0,0xD9,0x3A,0x0F,0x68,0x16,0x1A,0x86,0x06,0xD5,0x27,0x6E,0x27,0x59
                            };


int vli_set_random_mode(u32 mode)
{
    gRadomFixedFlag = mode;
}

int vli_get_random_mode(void)
{
    return gRadomFixedFlag;
}

int vli_set_random_fixed(u8 *data, u32 len)
{
    vli_set_random_mode(1);

    if(len == sizeof(gRandomFixed))
    {
        memcpy(gRandomFixed, data, len);
    }
}


int vli_get_random(u8 *data, u32 len)
{

#ifdef RANDOM_SOFTWARE
    int i;
    int j;
    static int counter;

    if((!gRadomFixedFlag)
       ||(len != sizeof(gRandomFixed)))
    {
        srand(counter++);
	 counter +=j ;
	 
        for(i = 0; i < len; i++)
        {
            data[i]= rand();
        }

        return len;
    }
    else
    {
        memcpy(data, gRandomFixed, len);
    }

#else
	
  int fd = open("/dev/urandom", O_RDONLY);
  int ret = -1;

  if (fd > 0) {
      ret = read(fd, data, len);
      close(fd);

  }

  /*
  memset(data, 0x33, len);
  */
  
  return ret;
  
#endif

}
