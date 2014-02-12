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
 *
 * libcfs/libcfs/darwin/darwin-curproc.c
 *
 * Lustre curproc API implementation for XNU kernel
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

/*
 * Implementation of cfs_curproc API (see lnet/include/libcfs/curproc.h)
 * for XNU kernel.
 */

static inline struct ucred *curproc_ucred(void)
{
#ifdef __DARWIN8__
        return proc_ucred(current_proc());
#else
        return current_proc()->p_cred->pc_ucred;
#endif
}

uid_t  current_uid(void)
{
        return curproc_ucred()->cr_uid;
}

gid_t  current_gid(void)
{
        LASSERT(curproc_ucred()->cr_ngroups > 0);
        return curproc_ucred()->cr_groups[0];
}

uid_t  current_fsuid(void)
{
#ifdef __DARWIN8__
        return curproc_ucred()->cr_ruid;
#else
        return current_proc()->p_cred->p_ruid;
#endif
}

gid_t  current_fsgid(void)
{
#ifdef __DARWIN8__
        return curproc_ucred()->cr_rgid;
#else
        return current_proc()->p_cred->p_rgid;
#endif
}

pid_t  current_pid(void)
{
#ifdef __DARWIN8__
        /* no pid for each thread, return address of thread struct */
        return (pid_t)current_thread();
#else
        return current_proc()->p_pid;
#endif
}

int    in_group_p(gid_t gid)
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

mode_t current_umask(void)
{
#ifdef __DARWIN8__
        /*
         * XXX Liang:
         *
         * fd_cmask is not available in kexts, so we just assume 
         * verything is permited.
         */
        return -1;
#else
        return current_proc()->p_fd->fd_cmask;
#endif
}

char  *current_comm(void)
{
#ifdef __DARWIN8__
        /*
         * Writing to proc->p_comm is not permited in Darwin8,
         * because proc_selfname() only return a copy of proc->p_comm,
         * so this function is not really working while user try to 
         * change comm of current process.
         */
        static char     pcomm[MAXCOMLEN+1];

        proc_selfname(pcomm, MAXCOMLEN+1);
        return pcomm;
#else
        return current_proc()->p_comm;
#endif
}

struct user_namespace init_user_ns __read_mostly;
EXPORT_SYMBOL(init_user_ns);

void cfs_cap_raise(cfs_cap_t cap) {}
void cfs_cap_lower(cfs_cap_t cap) {}

int cfs_cap_raised(cfs_cap_t cap)
{
        return 1;
}

cfs_cap_t cfs_curproc_cap_pack(void) {
        return -1;
}

void cfs_curproc_cap_unpack(cfs_cap_t cap) {
}

int cfs_capable(cfs_cap_t cap)
{
        return cap == CFS_CAP_SYS_BOOT ? is_suser(): is_suser1();
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
