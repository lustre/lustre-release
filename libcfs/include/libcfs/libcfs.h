/*
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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_LIBCFS_H__
#define __LIBCFS_LIBCFS_H__

#include <libcfs/types.h>
#include <libcfs/list.h>

#ifdef __KERNEL__
# include <libcfs/linux/libcfs.h>
#else /* !__KERNEL__ */
# include <assert.h>
# include <ctype.h>
# include <errno.h>
# include <fcntl.h>
# include <limits.h>
# include <signal.h>
# include <stdarg.h>
# include <stdbool.h>
# include <stddef.h>
# include <stdint.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include <sys/ioctl.h>
# include <sys/socket.h>
# include <sys/stat.h>
# include <sys/time.h>
# include <sys/types.h>
# include <libcfs/user-time.h>
# include <libcfs/user-prim.h>
# include <libcfs/user-mem.h>
# include <libcfs/user-lock.h>
# include <libcfs/user-bitops.h>
#endif /* __KERNEL__ */

#include "curproc.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) ((sizeof (a)) / (sizeof ((a)[0])))
#endif

#if !defined(swap)
#define swap(x,y) do { typeof(x) z = x; x = y; y = z; } while (0)
#endif

#if !defined(container_of)
/* given a pointer @ptr to the field @member embedded into type (usually
 * struct) @type, return pointer to the embedding instance of @type. */
#define container_of(ptr, type, member) \
        ((type *)((char *)(ptr)-(char *)(&((type *)0)->member)))
#endif

static inline int __is_po2(unsigned long long val)
{
        return !(val & (val - 1));
}

#define IS_PO2(val) __is_po2((unsigned long long)(val))

#define LOWEST_BIT_SET(x)       ((x) & ~((x) - 1))

/* Sparse annotations */
#ifdef __KERNEL__
# if !defined(__must_hold)
#  ifdef __CHECKER__
#   define __must_hold(x) __attribute__((context(x, 1, 1)))
#  else	/* __CHECKER__ */
#   define __must_hold(x)
#  endif /* !__CHECKER__ */
# endif /* !__must_hold */
#else /* __KERNEL__ */
# define __acquires(x)
# define __releases(x)
# define __must_hold(x)
#endif /* !__KERNEL__ */

/*
 * Lustre Error Checksum: calculates checksum
 * of Hex number by XORing each bit.
 */
#define LERRCHKSUM(hexnum) (((hexnum) & 0xf) ^ ((hexnum) >> 4 & 0xf) ^ \
                           ((hexnum) >> 8 & 0xf))

/*
 * Some (nomina odiosa sunt) platforms define NULL as naked 0. This confuses
 * Lustre RETURN(NULL) macro.
 */
#if defined(NULL)
#undef NULL
#endif

#define NULL ((void *)0)

#ifdef __KERNEL__

#ifndef cfs_for_each_possible_cpu
#  error cfs_for_each_possible_cpu is not supported by kernel!
#endif

/* libcfs watchdogs */
struct lc_watchdog;

/* Add a watchdog which fires after "time" milliseconds of delay.  You have to
 * touch it once to enable it. */
struct lc_watchdog *lc_watchdog_add(int time,
                                    void (*cb)(pid_t pid, void *),
                                    void *data);

/* Enables a watchdog and resets its timer. */
void lc_watchdog_touch(struct lc_watchdog *lcw, int timeout);
#define CFS_GET_TIMEOUT(svc) (max_t(int, obd_timeout,                   \
                          AT_OFF ? 0 : at_get(&svc->srv_at_estimate)) * \
                          svc->srv_watchdog_factor)

/* Disable a watchdog; touch it to restart it. */
void lc_watchdog_disable(struct lc_watchdog *lcw);

/* Clean up the watchdog */
void lc_watchdog_delete(struct lc_watchdog *lcw);

/* Dump a debug log */
void lc_watchdog_dumplog(pid_t pid, void *data);

#else /* !__KERNEL__ */
#include <unistd.h>
#ifndef PAGE_SIZE
#define PAGE_SIZE sysconf(_SC_PAGESIZE)
#endif
#endif /* !__KERNEL__ */

/* need both kernel and user-land acceptor */
#define LNET_ACCEPTOR_MIN_RESERVED_PORT    512
#define LNET_ACCEPTOR_MAX_RESERVED_PORT    1023

/*
 * libcfs pseudo device operations
 *
 * struct struct miscdevice and
 * misc_register() and
 * misc_deregister() are declared in
 * libcfs/<os>/<os>-prim.h
 *
 * It's just draft now.
 */

struct cfs_psdev_file {
        unsigned long   off;
        void            *private_data;
        unsigned long   reserved1;
        unsigned long   reserved2;
};

struct cfs_psdev_ops {
	int (*p_open)(unsigned long, void *);
	int (*p_close)(unsigned long, void *);
	int (*p_read)(struct cfs_psdev_file *, char *, unsigned long);
	int (*p_write)(struct cfs_psdev_file *, char *, unsigned long);
	int (*p_ioctl)(struct cfs_psdev_file *, unsigned long, void __user *);
};

/*
 * Drop into debugger, if possible. Implementation is provided by platform.
 */

void cfs_enter_debugger(void);

/*
 * Defined by platform
 */
int unshare_fs_struct(void);
sigset_t cfs_block_allsigs(void);
sigset_t cfs_block_sigs(unsigned long sigs);
sigset_t cfs_block_sigsinv(unsigned long sigs);
void cfs_restore_sigs(sigset_t);
int cfs_signal_pending(void);
void cfs_clear_sigpending(void);

int convert_server_error(__u64 ecode);
int convert_client_oflag(int cflag, int *result);

/*
 * Stack-tracing filling.
 */

/*
 * Platform-dependent data-type to hold stack frames.
 */
struct cfs_stack_trace;

/*
 * Fill @trace with current back-trace.
 */
void cfs_stack_trace_fill(struct cfs_stack_trace *trace);

/*
 * Return instruction pointer for frame @frame_no. NULL if @frame_no is
 * invalid.
 */
void *cfs_stack_trace_frame(struct cfs_stack_trace *trace, int frame_no);

/*
 * Random number handling
 */

/* returns a random 32-bit integer */
unsigned int cfs_rand(void);
/* seed the generator */
void cfs_srand(unsigned int, unsigned int);
void cfs_get_random_bytes(void *buf, int size);

#include <libcfs/byteorder.h>
#include <libcfs/err.h>
#include <libcfs/libcfs_debug.h>
#include <libcfs/libcfs_private.h>
#include <libcfs/bitmap.h>
#include <libcfs/libcfs_cpu.h>
#include <libcfs/libcfs_ioctl.h>
#include <libcfs/libcfs_prim.h>
#include <libcfs/libcfs_time.h>
#include <libcfs/libcfs_string.h>
#include <libcfs/libcfs_kernelcomm.h>
#include <libcfs/libcfs_workitem.h>
#include <libcfs/libcfs_hash.h>
#include <libcfs/libcfs_heap.h>
#include <libcfs/libcfs_fail.h>

/* container_of depends on "likely" which is defined in libcfs_private.h */
static inline void *__container_of(const void *ptr, unsigned long shift)
{
	if (unlikely(IS_ERR(ptr) || ptr == NULL))
		return ERR_CAST(ptr);
	else
		return (char *)ptr - shift;
}

#define container_of0(ptr, type, member)				\
	((type *)__container_of((ptr), offsetof(type, member)))

#define _LIBCFS_H

int libcfs_arch_init(void);
void libcfs_arch_cleanup(void);

#endif /* _LIBCFS_H */
