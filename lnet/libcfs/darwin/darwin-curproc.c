/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre curproc API implementation for XNU kernel
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

#define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/libcfs.h>
#include <libcfs/kp30.h>

/*
 * Implementation of cfs_curproc API (see portals/include/libcfs/curproc.h)
 * for XNU kernel.
 */

static inline struct ucred *curproc_ucred(void)
{
        return current_proc()->p_cred->pc_ucred;
}

uid_t  cfs_curproc_uid(void)
{
        return curproc_ucred()->cr_uid;
}

gid_t  cfs_curproc_gid(void)
{
        LASSERT(curproc_ucred()->cr_ngroups > 0);
        return curproc_ucred()->cr_groups[0];
}

uid_t  cfs_curproc_fsuid(void)
{
        return current_proc()->p_cred->p_ruid;
}

gid_t  cfs_curproc_fsgid(void)
{
        return current_proc()->p_cred->p_rgid;
}

pid_t  cfs_curproc_pid(void)
{
        return current_proc()->p_pid;
}

int    cfs_curproc_groups_nr(void)
{
        LASSERT(curproc_ucred()->cr_ngroups > 0);
        return curproc_ucred()->cr_ngroups - 1;
}

int    cfs_curproc_is_in_groups(gid_t gid)
{
        int i;
        struct ucred *cr;

        cr = curproc_ucred();
        LASSERT(cr != NULL);

        for (i = 0; i < cr->cr_ngroups; ++ i) {
                if (cr->cr_groups[i] == gid)
                        return 1;
        }
        return 0;
}

void   cfs_curproc_groups_dump(gid_t *array, int size)
{
        struct ucred *cr;

        cr = curproc_ucred();
        LASSERT(cr != NULL);
        CLASSERT(sizeof array[0] == sizeof (__u32));

        size = min_t(int, size, cr->cr_ngroups);
        memcpy(array, &cr->cr_groups[1], size * sizeof(gid_t));
}

mode_t cfs_curproc_umask(void)
{
        return current_proc()->p_fd->fd_cmask;
}

char  *cfs_curproc_comm(void)
{
        return current_proc()->p_comm;
}

cfs_kernel_cap_t cfs_curproc_cap_get(void)
{
        return 0;
}

void cfs_curproc_cap_set(cfs_kernel_cap_t cap)
{
        return;
}


/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
