#include "typedef.h"

#ifdef __BUILD_NO_OS__

inline u16 _htons(u16 hs)
{
	return (ENDIANNESS=='l') ? __swap16(hs): hs;
}

inline u32 _htonl(u32 hl)
{
	return (ENDIANNESS=='l') ? __swap32(hl): hl;
}

inline u32 _htonl64(u64 hl)
{
	return (ENDIANNESS=='l') ? __swap64(hl): hl;
}

inline u16 _ntohs(u16 ns)
{
	return (ENDIANNESS=='l') ? __swap16(ns): ns;	
}

inline u64 _ntohl(u32 nl)
{
	return (ENDIANNESS=='l') ? __swap32(nl): nl;	
}

inline u64 _ntohl64(u64 nl)
{
	return (ENDIANNESS=='l') ? __swap64(nl): nl;	
}

inline u16 le16_to_cpu(u16 data) 
{
	return (ENDIANNESS=='b') ? __swap16(data):data;
}
inline u32 le32_to_cpu(u32 data)
{
	return (ENDIANNESS=='b') ? __swap32(data):data;
}
inline u64 le64_to_cpu(u64 data) 
{
	return (ENDIANNESS=='b') ? __swap64(data):data;
}
inline u16 cpu_to_le16(u16 data) 
{
	return (ENDIANNESS=='b') ? __swap16(data):data;
}
inline u32 cpu_to_le32(u32 data)
{
	return (ENDIANNESS=='b') ? __swap32(data):data;
}
inline u64 cpu_to_le64(u64 data) 
{
	return (ENDIANNESS=='b') ? __swap64(data):data;
}

inline u16 be16_to_cpu(u16 data) 
{
	return _ntohs(data);
}

inline u32 be32_to_cpu(u32 data)
{
	return _ntohl(data);
}

inline u16 cpu_to_be16(u16 data)
{
	return _ntohs(data);
}

inline u32 cpu_to_be32(u32 data)
{
	return _ntohl(data);
}

inline u64 be64_to_cpu(u64 data)
{
	return _ntohl64(data);
}

inline u64 cpu_to_be64(u64 data)
{
	return _ntohl64(data);
}

#endif


inline u16 __get_unaligned_le16(const u8 *p)
{
	return p[0] | p[1] << 8;
}

inline u32 __get_unaligned_le32(const u8 *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

inline u64 __get_unaligned_le64(const u8 *p)
{
	return (u64)__get_unaligned_le32(p + 4) << 32 |
		__get_unaligned_le32(p);
}

inline void __put_unaligned_le16(u16 val, u8 *p)
{
	*p++ = val;
	*p++ = val >> 8;
}

inline void __put_unaligned_le32(u32 val, u8 *p)
{
	__put_unaligned_le16(val >> 16, p + 2);
	__put_unaligned_le16(val, p);
}

inline void __put_unaligned_le64(u64 val, u8 *p)
{
	__put_unaligned_le32(val >> 32, p + 4);
	__put_unaligned_le32(val, p);
}

inline u16 get_unaligned_le16(const void *p)
{
	return __get_unaligned_le16((const u8 *)p);
}

inline u32 get_unaligned_le32(const void *p)
{
	return __get_unaligned_le32((const u8 *)p);
}

inline u64 get_unaligned_le64(const void *p)
{
	return __get_unaligned_le64((const u8 *)p);
}

inline void put_unaligned_le16(u16 val, void *p)
{
	__put_unaligned_le16(val, (u8*)p);
}

inline void put_unaligned_le32(u32 val, void *p)
{
	__put_unaligned_le32(val, (u8*)p);
}

inline void put_unaligned_le64(u64 val, void *p)
{
	__put_unaligned_le64(val, (u8*)p);
}

inline u16 __get_unaligned_be16(const u8 *p)
{
	return p[0] << 8 | p[1];
}

inline u32 __get_unaligned_be32(const u8 *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

inline u64 __get_unaligned_be64(const u8 *p)
{
	return (u64)__get_unaligned_be32(p) << 32 |
		__get_unaligned_be32(p + 4);
}

inline void __put_unaligned_be16(u16 val, u8 *p)
{
	*p++ = val >> 8;
	*p++ = val;
}

inline void __put_unaligned_be32(u32 val, u8 *p)
{
	__put_unaligned_be16(val >> 16, p);
	__put_unaligned_be16(val, p + 2);
}

inline void __put_unaligned_be64(u64 val, u8 *p)
{
	__put_unaligned_be32(val >> 32, p);
	__put_unaligned_be32(val, p + 4);
}

inline u16 get_unaligned_be16(const void *p)
{
	return __get_unaligned_be16((const u8 *)p);
}

inline u32 get_unaligned_be32(const void *p)
{
	return __get_unaligned_be32((const u8 *)p);
}

inline u64 get_unaligned_be64(const void *p)
{
	return __get_unaligned_be64((const u8 *)p);
}

inline void put_unaligned_be16(u16 val, void *p)
{
	__put_unaligned_be16(val, (u8*)p);
}

inline void put_unaligned_be32(u32 val, void *p)
{
	__put_unaligned_be32(val, (u8*)p);
}

inline void put_unaligned_be64(u64 val, void *p)
{
	__put_unaligned_be64(val, (u8*)p);
}

