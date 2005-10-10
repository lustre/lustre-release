#ifndef _LIBCFS_TYPES_H
#define _LIBCFS_TYPES_H

/*
 * Note: This is currently a duplicate of <lustre/types.h>
 * It was necssary to introduce this to fix build issues
 * on the XT3 (Catamount).  <lustre/types.h> should have 
 * been removed immediatly, however at the time of this writing
 * it's unclear what the external dependencies are tied
 * to that file (It's not just some source file #including it)
 * there is some build/packaging infrastructure that includes it.
 * Hopefully that will be resolved shortly, that file will
 * be removed, and this comment can be deleted.
 */

typedef unsigned short umode_t;

#if (!defined(_LINUX_TYPES_H) && !defined(_BLKID_TYPES_H) && \
	!defined(_EXT2_TYPES_H) && !defined(_I386_TYPES_H))

/*
 * __xx is ok: it doesn't pollute the POSIX namespace. Use these in the
 * header files exported to user space
 */

typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;

typedef __signed__ long long __s64;
typedef unsigned long long __u64;
#endif

#endif
