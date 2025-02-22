/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __LINUX_HASH_LUSTRE_H__
#define __LINUX_HASH_LUSTRE_H__

#include <linux/types.h>
#include <linux/hash.h>

#ifdef HAVE_BROKEN_HASH_64

#define GOLDEN_RATIO_32 0x61C88647
#define GOLDEN_RATIO_64 0x61C8864680B583EBull

static inline u32 cfs_hash_32(u32 val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return (val * GOLDEN_RATIO_32) >> (32 - bits);
}

static __always_inline u32 cfs_hash_64(u64 val, unsigned int bits)
{
#if BITS_PER_LONG == 64
	/* 64x64-bit multiply is efficient on all 64-bit processors */
	return val * GOLDEN_RATIO_64 >> (64 - bits);
#else
	/* Hash 64 bits using only 32x32-bit multiply. */
	return cfs_hash_32(((u32)val ^ ((val >> 32) * GOLDEN_RATIO_32)), bits);
#endif
}

#if BITS_PER_LONG == 32
#define cfs_hash_long(val, bits) cfs_hash_32(val, bits)
#elif BITS_PER_LONG == 64
#define cfs_hash_long(val, bits) cfs_hash_64(val, bits)
#else
#error Wordsize not 32 or 64
#endif

#else

#define cfs_hash_32 hash_32
#define cfs_hash_64 hash_64
#define cfs_hash_long hash_long

#endif /* HAVE_BROKEN_HASH_64 */
#endif /* __LINUX_HASH_LUSTRE_H__ */
