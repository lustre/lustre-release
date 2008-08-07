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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/include/libcfs/curproc.h
 *
 * Lustre curproc API declaration
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_CURPROC_H__
#define __LIBCFS_CURPROC_H__

#ifdef __KERNEL__
/*
 * Portable API to access common characteristics of "current" UNIX process.
 *
 * Implemented in portals/include/libcfs/<os>/
 */
uid_t  cfs_curproc_uid(void);
gid_t  cfs_curproc_gid(void);
uid_t  cfs_curproc_fsuid(void);
gid_t  cfs_curproc_fsgid(void);
pid_t  cfs_curproc_pid(void);
int    cfs_curproc_groups_nr(void);
int    cfs_curproc_is_in_groups(gid_t group);
void   cfs_curproc_groups_dump(gid_t *array, int size);
mode_t cfs_curproc_umask(void);
char  *cfs_curproc_comm(void);


/*
 * Plus, platform-specific constant
 *
 * CFS_CURPROC_COMM_MAX,
 *
 * and opaque scalar type
 *
 * cfs_kernel_cap_t
 */
cfs_kernel_cap_t cfs_curproc_cap_get(void);
void cfs_curproc_cap_set(cfs_kernel_cap_t cap);
#endif

/* __LIBCFS_CURPROC_H__ */
#endif
/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
