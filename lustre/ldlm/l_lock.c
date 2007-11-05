/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifdef __KERNEL__
#include <libcfs/libcfs.h>
#else 
#include <liblustre.h>
#endif

#include <lustre_dlm.h>
#include <lustre_lib.h>

/*
 * ldlm locking uses resource to serialize access to locks
 * but there is a case when we change resource of lock upon
 * enqueue reply. we rely on that lock->l_resource = new_res
 * is atomic
 */
struct ldlm_resource * lock_res_and_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;

        if (ns_is_server(res->lr_namespace)) {
                /* on server-side resource of lock doesn't change */
                lock_res(res);
                return res;
        } 

        spin_lock(&lock->l_lock);
        res = lock->l_resource;
        lock_res(res);
        return res;
}

void unlock_res_and_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;

        if (ns_is_server(res->lr_namespace)) {
                /* on server-side resource of lock doesn't change */
                unlock_res(res);
                return;
        }

        unlock_res(res);
        spin_unlock(&lock->l_lock);
}

