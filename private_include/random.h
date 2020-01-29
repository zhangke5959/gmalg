
#ifndef _RANDOM_H_
#define _RANDOM_H_

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

int vli_set_random_mode(u32 mode);

int vli_get_random_mode(void);

int vli_set_random_fixed(u8 *data, u32 len);

int vli_get_random(u8 *p_data, u32 len);


#ifdef __cplusplus
}
#endif

#endif
