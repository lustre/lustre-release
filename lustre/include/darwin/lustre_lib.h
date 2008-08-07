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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
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
 * lustre/include/darwin/lustre_lib.h
 *
 * Basic Lustre library routines.
 */

#ifndef _DARWIN_LUSTRE_LIB_H
#define _DARWIN_LUSTRE_LIB_H

#ifndef _LUSTRE_LIB_H
#error Do not #include this file directly. #include <lustre_lib.h> instead
#endif

#include <string.h>
#include <libcfs/libcfs.h>

#ifndef LP_POISON
#define LI_POISON ((int)0x5a5a5a5a)
#define LL_POISON ((long)0x5a5a5a5a)
#define LP_POISON ((void *)(long)0x5a5a5a5a)
#endif

#ifndef LPU64
#define LPU64 "%llu"
#define LPD64 "%lld"
#define LPX64 "%llx"
#endif

struct obd_ioctl_data;
#define OBD_IOC_DATA_TYPE               struct obd_ioctl_data

#define LUSTRE_FATAL_SIGS (sigmask(SIGKILL) | sigmask(SIGINT) |                \
                           sigmask(SIGTERM) | sigmask(SIGQUIT) |               \
                           sigmask(SIGALRM) | sigmask(SIGHUP))

#ifdef __KERNEL__
static inline sigset_t l_w_e_set_sigs(sigset_t sigs)
{
        sigset_t old = 0;

        /* XXX Liang: how to change sigmask in Darwin8.x? 
         * there is syscall like pthread_sigmask() but we cannot 
         * use in kernel  */
#if !defined(__DARWIN8__)
        struct proc     *p = current_proc();
        extern int block_procsigmask(struct proc *p,  int bit);
        old = cfs_current()->uu_sigmask;
        block_procsigmask(p, ~sigs);
#endif

        return old;
}
#endif

#endif
