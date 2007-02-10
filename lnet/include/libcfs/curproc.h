/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre curproc API declaration
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 * Author: Nikita Danilov <nikita@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation. Lustre is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details. You should have received a copy of the GNU
 * General Public License along with Lustre; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
