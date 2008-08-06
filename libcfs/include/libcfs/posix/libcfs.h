/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/posix/libcfs.h
 *
 * Defines for posix userspace.
 *
 * Author: Robert Read <rread@sun.com>
 */

#ifndef __LIBCFS_POSIX_LIBCFS_H__
#define __LIBCFS_POSIX_LIBCFS_H__

#include <sys/errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <assert.h>
#include <sys/signal.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>
#endif

#if defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_USER_H
# include <sys/user.h>
#endif

#ifdef HAVE_SYS_VFS_H
# include <sys/vfs.h>
#endif

#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif

#include <libcfs/list.h>
#include <libcfs/posix/posix-types.h>
#include <libcfs/user-time.h>
#include <libcfs/user-prim.h>
#include <libcfs/user-mem.h>
#include <libcfs/user-lock.h>
#include <libcfs/user-tcpip.h>
#include <libcfs/posix/posix-wordsize.h>
#include <libcfs/user-bitops.h>

# define do_gettimeofday(tv) gettimeofday(tv, NULL);
typedef unsigned long long cycles_t;

#define IS_ERR(a) ((unsigned long)(a) > (unsigned long)-1000L)
#define PTR_ERR(a) ((long)(a))
#define ERR_PTR(a) ((void*)((long)(a)))

/* this goes in posix-fs.h */
#include <sys/mount.h>

#ifdef __linux__
#include <mntent.h>
#endif

typedef struct file cfs_file_t;
typedef struct dentry cfs_dentry_t;
#ifdef __linux__
typedef struct dirent64 cfs_dirent_t;
#endif

#ifdef __linux__
/* Userpace byte flipping */
# include <endian.h>
# include <byteswap.h>
# define __swab16(x) bswap_16(x)
# define __swab32(x) bswap_32(x)
# define __swab64(x) bswap_64(x)
# define __swab16s(x) do {*(x) = bswap_16(*(x));} while (0)
# define __swab32s(x) do {*(x) = bswap_32(*(x));} while (0)
# define __swab64s(x) do {*(x) = bswap_64(*(x));} while (0)
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define le16_to_cpu(x) (x)
#  define cpu_to_le16(x) (x)
#  define le32_to_cpu(x) (x)
#  define cpu_to_le32(x) (x)
#  define le64_to_cpu(x) (x)
#  define cpu_to_le64(x) (x)

#  define be16_to_cpu(x) bswap_16(x)
#  define cpu_to_be16(x) bswap_16(x)
#  define be32_to_cpu(x) bswap_32(x)
#  define cpu_to_be32(x) bswap_32(x)
#  define be64_to_cpu(x) bswap_64(x)
#  define cpu_to_be64(x) bswap_64(x)
# else
#  if __BYTE_ORDER == __BIG_ENDIAN
#   define le16_to_cpu(x) bswap_16(x)
#   define cpu_to_le16(x) bswap_16(x)
#   define le32_to_cpu(x) bswap_32(x)
#   define cpu_to_le32(x) bswap_32(x)
#   define le64_to_cpu(x) bswap_64(x)
#   define cpu_to_le64(x) bswap_64(x)

#   define be16_to_cpu(x) (x)
#   define cpu_to_be16(x) (x)
#   define be32_to_cpu(x) (x)
#   define cpu_to_be32(x) (x)
#   define be64_to_cpu(x) (x)
#   define cpu_to_be64(x) (x)

#  else
#   error "Unknown byte order"
#  endif /* __BIG_ENDIAN */
# endif /* __LITTLE_ENDIAN */
#elif __APPLE__
#define __cpu_to_le64(x)                        OSSwapHostToLittleInt64(x)
#define __cpu_to_le32(x)                        OSSwapHostToLittleInt32(x)
#define __cpu_to_le16(x)                        OSSwapHostToLittleInt16(x)

#define __le16_to_cpu(x)                        OSSwapLittleToHostInt16(x)
#define __le32_to_cpu(x)                        OSSwapLittleToHostInt32(x)
#define __le64_to_cpu(x)                        OSSwapLittleToHostInt64(x)

#define cpu_to_le64(x)                          __cpu_to_le64(x)
#define cpu_to_le32(x)                          __cpu_to_le32(x)
#define cpu_to_le16(x)                          __cpu_to_le16(x)

#define le64_to_cpu(x)                          __le64_to_cpu(x)
#define le32_to_cpu(x)                          __le32_to_cpu(x)
#define le16_to_cpu(x)                          __le16_to_cpu(x)

#define __swab16(x)                             OSSwapInt16(x)
#define __swab32(x)                             OSSwapInt32(x)
#define __swab64(x)                             OSSwapInt64(x)
#define __swab16s(x)                            do { *(x) = __swab16(*(x)); } while (0)
#define __swab32s(x)                            do { *(x) = __swab32(*(x)); } while (0)
#define __swab64s(x)                            do { *(x) = __swab64(*(x)); } while (0)
#endif


# ifndef THREAD_SIZE /* x86_64 linux has THREAD_SIZE in userspace */
#  define THREAD_SIZE 8192
# endif

#define LUSTRE_TRACE_SIZE (THREAD_SIZE >> 5)

#define CHECK_STACK() do { } while(0)
#define CDEBUG_STACK() (0L)

/* initial pid  */
#define LUSTRE_LNET_PID          12345

#define ENTRY_NESTING_SUPPORT (1)
#define ENTRY_NESTING   do {;} while (0)
#define EXIT_NESTING   do {;} while (0)
#define __current_nesting_level() (0)

/**
 * Platform specific declarations for cfs_curproc API (libcfs/curproc.h)
 *
 * Implementation is in linux-curproc.c
 */
#define CFS_CURPROC_COMM_MAX (sizeof ((struct task_struct *)0)->comm)

typedef __u32 cfs_kernel_cap_t;

/**
 * Module support (probably shouldn't be used in generic code?)
 */
struct module {
        int count;
};

static inline void MODULE_AUTHOR(char *name)
{
        printf("%s\n", name);
}
#define MODULE_DESCRIPTION(name) MODULE_AUTHOR(name)
#define MODULE_LICENSE(name) MODULE_AUTHOR(name)

#define THIS_MODULE NULL
#define __init
#define __exit

static inline int request_module(char *name)
{
        return (-EINVAL);
}

static inline void __module_get(struct module *module)
{
}

static inline int try_module_get(struct module *module)
{
        return 1;
}

static inline void module_put(struct module *module)
{
}


#endif
