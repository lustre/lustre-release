/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Basic library routines. 
 *
 */

#ifndef __LIBCFS_DARWIN_XNU_TYPES_H__
#define __LIBCFS_DARWIN_XNU_TYPES_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#include <mach/mach_types.h>
#include <sys/types.h>

#ifndef _BLKID_TYPES_H
#define _BLKID_TYPES_H
#endif

typedef u_int8_t        __u8;
typedef u_int16_t       __u16;
typedef u_int32_t       __u32;
typedef u_int64_t       __u64;
typedef int8_t          __s8;
typedef int16_t         __s16;
typedef int32_t         __s32;
typedef int64_t         __s64;

#ifdef __KERNEL__

#include <kern/kern_types.h>


typedef struct { int e; }		event_chan_t;
typedef dev_t				kdev_t;

/*
 * Atmoic define
 */
#include <libkern/OSAtomic.h>

typedef struct { volatile uint32_t counter; }	atomic_t;

#define ATOMIC_INIT(i)			{ (i) }
#define atomic_read(a)			((a)->counter)
#define atomic_set(a, v)		(((a)->counter) = (v))
#ifdef __DARWIN8__
/* OS*Atomic return the value before the operation */
#define atomic_add(v, a)		OSAddAtomic(v, (SInt32 *)&((a)->counter))
#define atomic_sub(v, a)		OSAddAtomic(-(v), (SInt32 *)&((a)->counter))
#define atomic_inc(a)			OSIncrementAtomic((SInt32 *)&((a)->counter))
#define atomic_dec(a)			OSDecrementAtomic((SInt32 *)&((a)->counter))
#else /* !__DARWIN8__ */
#define atomic_add(v, a)		hw_atomic_add((__u32 *)&((a)->counter), v)
#define atomic_sub(v, a)		hw_atomic_sub((__u32 *)&((a)->counter), v)
#define atomic_inc(a)			atomic_add(1, a)
#define atomic_dec(a)			atomic_sub(1, a)
#endif /* !__DARWIN8__ */
#define atomic_sub_and_test(v, a)       (atomic_sub(v, a) == (v))
#define atomic_dec_and_test(a)          (atomic_dec(a) == 1)
#define atomic_inc_return(a)            (atomic_inc(a) + 1)
#define atomic_dec_return(a)            (atomic_dec(a) - 1)

#include <libsa/mach/mach.h>
typedef off_t   			loff_t;

#else	/* !__KERNEL__ */

#include <stdint.h>

typedef off_t   			loff_t;

#endif	/* __KERNEL END */
typedef unsigned short                  umode_t;

#endif  /* __XNU_CFS_TYPES_H__ */
