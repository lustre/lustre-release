/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=4:tabstop=4:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Lustre; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __LIBCFS_WINNT_KP30_H__
#define __LIBCFS_WINNT_KP30_H__

#ifndef __LIBCFS_KP30_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#include <libcfs/winnt/portals_compat25.h>
#include <lnet/types.h>

#ifdef __KERNEL__

/* Module parameter support */
#define CFS_MODULE_PARM(name, t, type, perm, desc)

#define CFS_SYSFS_MODULE_PARM    0 /* no sysfs access to module parameters */


static inline void our_cond_resched()
{
    schedule_timeout(1i64);
}

#ifdef CONFIG_SMP
#define LASSERT_SPIN_LOCKED(lock) do {} while(0) /* XXX */
#else
#define LASSERT_SPIN_LOCKED(lock) do {} while(0)
#endif

#error Need a winnt version of panic()
#define LIBCFS_PANIC(msg) KeBugCheckEx(msg, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL, (ULONG_PTR)NULL)
#error libcfs_register_panic_notifier() missing
#error libcfs_unregister_panic_notifier() missing

#define cfs_work_struct_t WORK_QUEUE_ITEM
#define cfs_prepare_work(tq, routine, contex)
#define cfs_schedule_work(tq)
#define cfs_get_work_data(type,field,data)   (data)

/* ------------------------------------------------------------------- */

#define PORTAL_SYMBOL_REGISTER(x)               cfs_symbol_register(#x, &x)
#define PORTAL_SYMBOL_UNREGISTER(x)             cfs_symbol_unregister(#x)

#define PORTAL_SYMBOL_GET(x)                    (cfs_symbol_get(#x))
#define PORTAL_SYMBOL_PUT(x)                    cfs_symbol_put(#x)

#define PORTAL_MODULE_USE                       do{}while(0)
#define PORTAL_MODULE_UNUSE                     do{}while(0)

#define printk                                  DbgPrint
#define ptintf                                  DbgPrint

#else  /* !__KERNEL__ */

# include <stdio.h>
# include <stdlib.h>
#ifdef __CYGWIN__
# include <cygwin-ioctl.h>
#endif
# include <time.h>

#endif /* End of !__KERNEL__ */

/******************************************************************************/
/* Light-weight trace
 * Support for temporary event tracing with minimal Heisenberg effect. */
#define LWT_SUPPORT  0

/* kernel hasn't defined this? */
typedef struct {
        __s64      lwte_when;
        char       *lwte_where;
        void       *lwte_task;
        long_ptr        lwte_p1;
        long_ptr        lwte_p2;
        long_ptr        lwte_p3;
        long_ptr        lwte_p4;
# if BITS_PER_LONG > 32
        long_ptr        lwte_pad;
# endif
} lwt_event_t;


# define LWT_EVENT(p1,p2,p3,p4)


/* ------------------------------------------------------------------ */

#define IOCTL_LIBCFS_TYPE long_ptr

#ifdef __CYGWIN__
# ifndef BITS_PER_LONG
#  if (~0UL) == 0xffffffffUL
#   define BITS_PER_LONG 32
#  else
#   define BITS_PER_LONG 64
#  endif
# endif
#endif

#if BITS_PER_LONG > 32
# define LI_POISON ((int)0x5a5a5a5a5a5a5a5a)
# define LL_POISON ((long_ptr)0x5a5a5a5a5a5a5a5a)
# define LP_POISON ((char *)(long_ptr)0x5a5a5a5a5a5a5a5a)
#else
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long_ptr)0x5a5a5a5a)
# define LP_POISON ((char *)(long_ptr)0x5a5a5a5a)
#endif

#if defined(__x86_64__)
# define LPU64 "%I64u"
# define LPD64 "%I64d"
# define LPX64 "%I64x"
# define LPSZ  "%lu"
# define LPSSZ "%ld"
#elif (BITS_PER_LONG == 32 || __WORDSIZE == 32)
# define LPU64 "%I64u"
# define LPD64 "%I64d"
# define LPX64 "%I64x"
# define LPSZ  "%u"
# define LPSSZ "%d"
#elif (BITS_PER_LONG == 64 || __WORDSIZE == 64)
# define LPU64 "%I64u"
# define LPD64 "%I64d"
# define LPX64 "%I64x"
# define LPSZ  "%u"
# define LPSSZ "%d"
#endif
#ifndef LPU64
# error "No word size defined"
#endif

#endif
