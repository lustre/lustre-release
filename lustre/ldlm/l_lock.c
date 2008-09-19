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
