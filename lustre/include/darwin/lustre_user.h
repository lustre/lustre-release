/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * Lustre public user-space interface definitions.
 */

#ifndef _DARWIN_LUSTRE_USER_H
#define _DARWIN_LUSTRE_USER_H

#include <lustre/types.h>

#ifndef __KERNEL__
/* for llmount */
# define _GNU_SOURCE
# include <getopt.h>
# include <sys/utsname.h>
# include <sys/stat.h>
# include <errno.h>
# include <sys/mount.h>
# include <sys/fcntl.h>
# include <sys/ioccom.h>
# include <sys/wait.h>
# include <string.h>
#endif

typedef struct stat     lstat_t;
#define HAVE_LOV_USER_MDS_DATA

#ifndef LPU64
#if (BITS_PER_LONG == 32 || __WORDSIZE == 32)
# define LPU64 "%llu"
# define LPD64 "%lld"
# define LPX64 "%#llx"
# define LPSZ  "%u"
# define LPSSZ "%d"
#elif (BITS_PER_LONG == 64 || __WORDSIZE == 64)
# define LPU64 "%lu"
# define LPD64 "%ld"
# define LPX64 "%#lx"
# define LPSZ  "%lu"
# define LPSSZ "%ld"
#endif
#endif /* !LPU64 */

#endif /* _LUSTRE_USER_H */
