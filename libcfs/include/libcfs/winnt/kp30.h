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

#ifndef __LIBCFS_WINNT_KP30_H__
#define __LIBCFS_WINNT_KP30_H__

#ifdef __KERNEL__

/* Module parameter support */
#define CFS_MODULE_PARM(name, t, type, perm, desc)

#define CFS_SYSFS_MODULE_PARM    0 /* no sysfs access to module parameters */


/* winnt panic */
void libcfs_panic(char *msg);
#define panic(msg) libcfs_panic(msg)
void libcfs_register_panic_notifier();
void libcfs_unregister_panic_notifier();


#define cfs_work_struct_t WORK_QUEUE_ITEM
#define cfs_schedule_work(tq)
#define cfs_get_work_data(type,field,data)   (data)

/* ------------------------------------------------------------------- */

#define PORTAL_SYMBOL_REGISTER(x)               cfs_symbol_register(#x, &x)
#define PORTAL_SYMBOL_UNREGISTER(x)             cfs_symbol_unregister(#x)

#define symbol_get(x)                    (cfs_symbol_get(#x))
#define symbol_put(x)                    cfs_symbol_put(#x)

#define try_module_get(THIS_MODULE)                       do{}while(0)
#define module_put(THIS_MODULE)                     do{}while(0)

#define printk                                  DbgPrint
#define ptintf                                  DbgPrint
#define printk_ratelimit()                      (FALSE)
#define vprintk(f, a)                           vDbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, f, a)
                                                /* vDbgPrintEx only available on xp and later OS */
#define cfs_assert                              ASSERT

#else  /* !__KERNEL__ */

# include <stdio.h>
# include <stdlib.h>
#ifdef __CYGWIN__
# include <cygwin-ioctl.h>
#endif
# include <time.h>
#include <crtdbg.h>

#define cfs_assert     _ASSERT

#ifndef get_cpu
#define get_cpu() smp_processor_id()
#define put_cpu() do { } while (0)
#else
#endif

#endif /* End of !__KERNEL__ */

#define IOCTL_LIBCFS_TYPE long_ptr_t

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
# define LL_POISON ((long_ptr_t)0x5a5a5a5a5a5a5a5a)
# define LP_POISON ((char *)(long_ptr_t)0x5a5a5a5a5a5a5a5a)
#else
# define LI_POISON ((int)0x5a5a5a5a)
# define LL_POISON ((long_ptr_t)0x5a5a5a5a)
# define LP_POISON ((char *)(long_ptr_t)0x5a5a5a5a)
#endif

#define LPF64 "%I64d"
#define LPU64 "%I64u"
#define LPD64 "%I64d"
#define LPX64 "%#I64x"
#define LPO64 "%#I64o"

/*
 * long_ptr_t & ulong_ptr_t, same to "long" for linux
 */
#if _x86_
# define LPLU "%u"
# define LPLD "%d"
# define LPLX "%#x"
# define LPPID "%d"
#else
# define LPLU "%Ii64u"
# define LPLD "%I64d"
# define LPLX "%#I64x"
# define LPPID "%d"
#endif

#endif
