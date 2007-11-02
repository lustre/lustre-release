/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * Lustre public user-space interface definitions.
 */

#ifndef _LINUX_LUSTRE_USER_H
#define _LINUX_LUSTRE_USER_H

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#else
#include <lustre/types.h>
#endif


#ifndef __KERNEL__
# define NEED_QUOTA_DEFS
# ifdef HAVE_QUOTA_SUPPORT
#  include <sys/quota.h>
# endif
#else
# include <linux/version.h>
# ifdef HAVE_QUOTA_SUPPORT
#  include <linux/quota.h>
# endif
#endif

/*
 * asm-x86_64/processor.h on some SLES 9 distros seems to use
 * kernel-only typedefs.  fortunately skipping it altogether is ok
 * (for now).
 */
#define __ASM_X86_64_PROCESSOR_H

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#include <sys/stat.h>
#endif

#if defined(__x86_64__) || defined(__ia64__) || defined(__ppc64__) || \
    defined(__craynv) || defined (__mips64__)
typedef struct stat     lstat_t;
#define lstat_f         lstat
#define HAVE_LOV_USER_MDS_DATA
#elif defined(__USE_LARGEFILE64) || defined(__KERNEL__)
typedef struct stat64   lstat_t;
#define lstat_f         lstat64
#define HAVE_LOV_USER_MDS_DATA
#endif

#ifndef LPU64
/* this is a bit chunky */
#if defined(__KERNEL__)
 #define _LWORDSIZE BITS_PER_LONG
#else
 #define _LWORDSIZE __WORDSIZE
#endif
/* x86_64 defines __u64 as "long" in userspace, but "long long" in the kernel */
#if (defined(__x86_64__) && (defined(__KERNEL__) || defined(CRAY_XT3)))
# define LPU64 "%Lu"
# define LPD64 "%Ld"
# define LPX64 "%#Lx"
# define LPSZ  "%lu"
# define LPSSZ "%ld"
#elif (_LWORDSIZE == 32)
# define LPU64 "%Lu"
# define LPD64 "%Ld"
# define LPX64 "%#Lx"
# define LPSZ  "%u"
# define LPSSZ "%d"
#elif (_LWORDSIZE == 64)
# define LPU64 "%lu"
# define LPD64 "%ld"
# define LPX64 "%#lx"
# define LPSZ  "%lu"
# define LPSSZ "%ld"
#endif

#undef _LWORDSIZE

#endif /* !LPU64 */

#endif /* _LUSTRE_USER_H */
