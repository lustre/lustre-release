/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.sf.net/projects/lustre/
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifdef __KERNEL__
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/version.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp_lock.h>
#else 
#include <liblustre.h>
#endif

#include <linux/lustre_dlm.h>
#include <linux/lustre_lib.h>

/*
 * ldlm locking uses resource to serialize access to locks
 * but there is a case when we change resource of lock upon
 * enqueue reply. we rely on that lock->l_resource = new_res
 * is atomic
 */
struct ldlm_resource * lock_res_and_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;

        if (!res->lr_namespace->ns_client) {
                /* on server-side resource of lock doesn't change */
                lock_res(res);
                return res;
        } 

        bit_spin_lock(LDLM_FL_LOCK_PROTECT_BIT, (void *) &lock->l_flags);
        LASSERT(lock->l_pidb == 0);
        res = lock->l_resource;
        lock->l_pidb = current->pid;
        lock_res(res);
        return res;
}

void unlock_bitlock(struct ldlm_lock *lock)
{
        LASSERT(lock->l_pidb == current->pid);
        lock->l_pidb = 0;
        bit_spin_unlock(LDLM_FL_LOCK_PROTECT_BIT, (void *) &lock->l_flags);
}

void unlock_res_and_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;

        if (!res->lr_namespace->ns_client) {
                /* on server-side resource of lock doesn't change */
                unlock_res(res);
                return;
        }

        unlock_res(res);
        unlock_bitlock(lock);
}

