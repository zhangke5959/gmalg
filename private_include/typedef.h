#ifndef __TYPEDEF_H__
#define __TYPEDEF_H__

#include <linux/types.h>
#include <asm/byteorder.h>

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


static inline u16 __get_unaligned_le16(const u8 *p)
{
	return p[0] | p[1] << 8;
}

static inline u32 __get_unaligned_le32(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline u64 __get_unaligned_le64(const u8 *p)
{
	return (u64)__get_unaligned_le32(p + 4) << 32 |
		__get_unaligned_le32(p);
}

static inline void __put_unaligned_le16(u16 val, u8 *p)
{
	*p++ = val;
	*p++ = val >> 8;
}

static inline void __put_unaligned_le32(u32 val, u8 *p)
{
	__put_unaligned_le16(val >> 16, p + 2);
	__put_unaligned_le16(val, p);
}

static inline void __put_unaligned_le64(u64 val, u8 *p)
{
	__put_unaligned_le32(val >> 32, p + 4);
	__put_unaligned_le32(val, p);
}

static inline u16 get_unaligned_le16(const void *p)
{
	return __get_unaligned_le16((const u8 *)p);
}

static inline u32 get_unaligned_le32(const void *p)
{
	return __get_unaligned_le32((const u8 *)p);
}

static inline u64 get_unaligned_le64(const void *p)
{
	return __get_unaligned_le64((const u8 *)p);
}

static inline void put_unaligned_le16(u16 val, void *p)
{
	__put_unaligned_le16(val, p);
}

static inline void put_unaligned_le32(u32 val, void *p)
{
	__put_unaligned_le32(val, p);
}

static inline void put_unaligned_le64(u64 val, void *p)
{
	__put_unaligned_le64(val, p);
}

static inline u16 __get_unaligned_be16(const u8 *p)
{
	return p[0] << 8 | p[1];
}

static inline u32 __get_unaligned_be32(const u8 *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline u64 __get_unaligned_be64(const u8 *p)
{
	return (u64)__get_unaligned_be32(p) << 32 |
		__get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(u16 val, u8 *p)
{
	*p++ = val >> 8;
	*p++ = val;
}

static inline void __put_unaligned_be32(u32 val, u8 *p)
{
	__put_unaligned_be16(val >> 16, p);
	__put_unaligned_be16(val, p + 2);
}

static inline void __put_unaligned_be64(u64 val, u8 *p)
{
	__put_unaligned_be32(val >> 32, p);
	__put_unaligned_be32(val, p + 4);
}

static inline u16 get_unaligned_be16(const void *p)
{
	return __get_unaligned_be16((const u8 *)p);
}

static inline u32 get_unaligned_be32(const void *p)
{
	return __get_unaligned_be32((const u8 *)p);
}

static inline u64 get_unaligned_be64(const void *p)
{
	return __get_unaligned_be64((const u8 *)p);
}

static inline void put_unaligned_be16(u16 val, void *p)
{
	__put_unaligned_be16(val, p);
}

static inline void put_unaligned_be32(u32 val, void *p)
{
	__put_unaligned_be32(val, p);
}

static inline void put_unaligned_be64(u64 val, void *p)
{
	__put_unaligned_be64(val, p);
}

#endif
