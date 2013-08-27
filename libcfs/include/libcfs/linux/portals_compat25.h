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
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LIBCFS_LINUX_PORTALS_COMPAT_H__
#define __LIBCFS_LINUX_PORTALS_COMPAT_H__

#ifndef __user
#define __user
#endif

#ifdef HAVE_5ARGS_SYSCTL_PROC_HANDLER
#define ll_proc_dointvec(table, write, filp, buffer, lenp, ppos)        \
        proc_dointvec(table, write, buffer, lenp, ppos);

#define ll_proc_dolongvec(table, write, filp, buffer, lenp, ppos)        \
        proc_doulongvec_minmax(table, write, buffer, lenp, ppos);
#define ll_proc_dostring(table, write, filp, buffer, lenp, ppos)        \
        proc_dostring(table, write, buffer, lenp, ppos);
#define LL_PROC_PROTO(name)                                             \
        name(cfs_sysctl_table_t *table, int write,                      \
             void __user *buffer, size_t *lenp, loff_t *ppos)
#else
#define ll_proc_dointvec(table, write, filp, buffer, lenp, ppos)        \
        proc_dointvec(table, write, filp, buffer, lenp, ppos);

#define ll_proc_dolongvec(table, write, filp, buffer, lenp, ppos)        \
        proc_doulongvec_minmax(table, write, filp, buffer, lenp, ppos);
#define ll_proc_dostring(table, write, filp, buffer, lenp, ppos)        \
        proc_dostring(table, write, filp, buffer, lenp, ppos);
#define LL_PROC_PROTO(name)                                             \
        name(cfs_sysctl_table_t *table, int write, struct file *filp,   \
             void __user *buffer, size_t *lenp, loff_t *ppos)
#endif
#define DECLARE_LL_PROC_PPOS_DECL

/* helper for sysctl handlers */
int proc_call_handler(void *data, int write,
                      loff_t *ppos, void *buffer, size_t *lenp,
                      int (*handler)(void *data, int write,
                                     loff_t pos, void *buffer, int len));

#ifdef HAVE_INIT_NET
# define DEFAULT_NET	(&init_net)
#else
/* some broken backports */
# define DEFAULT_NET	(NULL)
#endif

#endif /* _PORTALS_COMPAT_H */
