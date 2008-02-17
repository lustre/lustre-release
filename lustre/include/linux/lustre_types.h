#ifndef _LUSTRE_LINUX_TYPES_H
#define _LUSTRE_LINUX_TYPES_H

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/fs.h>    /* to check for FMODE_EXEC, dev_t, lest we redefine */
#else
#ifdef __CYGWIN__
# include <sys/types.h>
#elif defined(_AIX)
# include <inttypes.h>
#else
# include <stdint.h>
#endif
#endif

#if !defined(_LINUX_TYPES_H) && !defined(_BLKID_TYPES_H) && \
        !defined(_EXT2_TYPES_H) && !defined(_I386_TYPES_H) && \
        !defined(_ASM_IA64_TYPES_H) && !defined(_X86_64_TYPES_H) && \
        !defined(_PPC_TYPES_H) && !defined(_PPC64_TYPES_H) && \
        !defined(_ASM_POWERPC_TYPES_H) && !defined(__mips64__)
        /* yuck, would be nicer with _ASM_TYPES_H */

typedef unsigned short umode_t;
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
