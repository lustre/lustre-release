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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_DARWIN_KP30__
#define __LIBCFS_DARWIN_KP30__

#ifdef __KERNEL__

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <string.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <stdarg.h>

#include <libcfs/darwin/darwin-lock.h>
#include <libcfs/darwin/darwin-prim.h>
#include <lnet/lnet.h>

#error libcfs_register_panic_notifier() missing
#error libcfs_unregister_panic_notifier() missing

/* --------------------------------------------------------------------- */
#define num_online_cpus()                       cfs_online_cpus()

/******************************************************************************/
/* XXX Liang: There is no module parameter supporting in OSX */
#define CFS_MODULE_PARM(name, t, type, perm, desc)

#define CFS_SYSFS_MODULE_PARM    0 /* no sysfs access to module parameters */
/******************************************************************************/

#else  /* !__KERNEL__ */
# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <unistd.h>
# include <time.h>
# include <machine/limits.h>
# include <sys/types.h>
#endif

#define BITS_PER_LONG   LONG_BIT

#define IOCTL_LIBCFS_TYPE struct libcfs_ioctl_data

#define LPO64 "%#llo"
#define LPU64 "%llu"
#define LPD64 "%lld"
#define LPX64 "%#llx"
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long)0x5a5a5a5a)
# define LP_POISON ((void *)(long)0x5a5a5a5a)

/*
 * long_ptr_t & ulong_ptr_t, same to "long" for gcc
 */
# define LPLU "%lu"
# define LPLD "%ld"
# define LPLX "%#lx"

/*
 * pid_t
 */
# define LPPID "%d"

#endif
