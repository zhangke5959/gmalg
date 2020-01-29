#ifndef __DEBUG_H_
#define __DEBUG_H_


#ifdef __cplusplus
extern "C" {
#endif

#define DEBUG 0
#define ALG_DEBUG 0

void printHex(unsigned char *name, unsigned char *c, int n);
void speed_test( char *name, int len);

#ifdef __cplusplus
}
#endif

#endif
