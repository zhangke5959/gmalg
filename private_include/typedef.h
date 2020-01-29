#ifndef __TYPEDEF_H__
#define __TYPEDEF_H__


#ifdef __cplusplus
extern "C" {
#endif


/****************************Start***************************/


#define __BULID_LINUX__
/*#define __BUILD_NO_OS__*/


#define __LITTLE_ENDIAN__
/*#define __BIG_ENDIAN__*/


/*#define RANDOM_SOFTWARE*/


/*Big Numer MAX BIT*/
#define RSA_MAX_MODULUS_BITS  2048
#define RSA_MAX_DIGITS  (RSA_MAX_MODULUS_BITS/VLI_DIGIT_BITS)
#define BIGNUM_MAX_DIGITS  RSA_MAX_DIGITS


/*For C Language Standards */
#if defined(__STDC__)
#define PREDEF_STANDARD_C_1989  /*C89 , C90*/
	
#if defined(__STDC_VERSION__)
#if (__STDC_VERSION__ >= 199901L)
#define PREDEF_STANDARD_C_1999  /*C99*/
#undef PREDEF_STANDARD_C_1989
#endif
#endif

#endif
	

#ifdef PREDEF_STANDARD_C_1989 /*C89 , C90*/
#define inline __inline
#endif

/****************************End***************************/

#ifdef __BULID_LINUX__

#include <linux/types.h>
#include <asm/byteorder.h>

typedef unsigned int uint;

typedef	__u8   u8;
typedef	__u16  u16;
typedef	__u32  u32;
typedef	__u64  u64;
	
typedef	__s8   s8;
typedef	__s16  s16;
typedef	__s32  s32;
typedef	__s64  s64;


#define le16_to_cpu __le16_to_cpu
#define le32_to_cpu __le32_to_cpu
#define le64_to_cpu __le64_to_cpu
	
#define cpu_to_le16 __cpu_to_le16
#define cpu_to_le32 __cpu_to_le32
#define cpu_to_le64 __cpu_to_le64
	
#define be16_to_cpu __be16_to_cpu
#define be32_to_cpu __be32_to_cpu
#define be64_to_cpu __be64_to_cpu
	
#define cpu_to_be16 __cpu_to_be16
#define cpu_to_be32 __cpu_to_be32
#define cpu_to_be64 __cpu_to_be64


#else


#ifdef __BUILD_NO_OS__

#define RANDOM_SOFTWARE

typedef	unsigned char u8;
typedef	unsigned short u16;
typedef	unsigned int  u32;
typedef	unsigned long long u64;

typedef	char s8;
typedef	short s16;
typedef	int s32;
typedef	long s64;

typedef unsigned int uint;

#define __swap16(A) ((((u16)(A) & 0xff00) >> 8) | (((u16)(A) & 0x00ff) << 8))

#define __swap32(A) ((((u32)(A) & 0xff000000) >> 24) | \
				   (((u32)(A) & 0x00ff0000) >>  8) | \
				   (((u32)(A) & 0x0000ff00) <<  8) | \
				   (((u32)(A) & 0x000000ff) << 24))
				   
#define __swap64(A) ((u64)( \
				 (((u64)(A) & (u64)0x00000000000000ffULL) << 56) | \
				 (((u64)(A) & (u64)0x000000000000ff00ULL) << 40) | \
				 (((u64)(A) & (u64)0x0000000000ff0000ULL) << 24) | \
				 (((u64)(A) & (u64)0x00000000ff000000ULL) <<  8) | \
				 (((u64)(A) & (u64)0x000000ff00000000ULL) >>  8) | \
				 (((u64)(A) & (u64)0x0000ff0000000000ULL) >> 24)| \
				(((u64)(A) & (u64)0x00ff000000000000ULL) >> 40) |\
				(((u64)(A) & (u64)0xff00000000000000ULL) >> 56)))

/*To Test Little Endian or Big Endian*/
static union {   
    char c[4];   
    unsigned long mylong;   
} endian_test = {{ 'l', '?', '?', 'b' } };  


#define ENDIANNESS ((char)endian_test.mylong) 

#include "inet.h"

#endif /*__BUILD_NO_OS__*/

#endif/*__BULID_LINUX__*/







u16 __get_unaligned_le16(const u8 *p);
u32 __get_unaligned_le32(const u8 *p);
u64 __get_unaligned_le64(const u8 *p);
void __put_unaligned_le16(u16 val, u8 *p);
void __put_unaligned_le32(u32 val, u8 *p);
void __put_unaligned_le64(u64 val, u8 *p);
u16 get_unaligned_le16(const void *p);
u32 get_unaligned_le32(const void *p);
u64 get_unaligned_le64(const void *p);
void put_unaligned_le16(u16 val, void *p);
void put_unaligned_le32(u32 val, void *p);
void put_unaligned_le64(u64 val, void *p);
u16 __get_unaligned_be16(const u8 *p);
u32 __get_unaligned_be32(const u8 *p);
u64 __get_unaligned_be64(const u8 *p);
void __put_unaligned_be16(u16 val, u8 *p);
void __put_unaligned_be32(u32 val, u8 *p);
void __put_unaligned_be64(u64 val, u8 *p);
u16 get_unaligned_be16(const void *p);
u32 get_unaligned_be32(const void *p);
u64 get_unaligned_be64(const void *p);
void put_unaligned_be16(u16 val, void *p);
void put_unaligned_be32(u32 val, void *p);
void put_unaligned_be64(u64 val, void *p);




#ifdef __cplusplus
}
#endif

#endif
