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



#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
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

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/obd_class.h>
#include <linux/lustre_lib.h>

/* invariants:
 - only the owner of the lock changes l_owner/l_depth
 - before changing or checking the variables a spin lock is taken
*/

void l_lock_init(struct lustre_lock *lock)
{
        sema_init(&lock->l_sem, 1);
        spin_lock_init(&lock->l_spin);
}

void l_lock(struct lustre_lock *lock)
{
        int owner = 0;
        spin_lock(&lock->l_spin);
        if (lock->l_owner == current) { 
                owner = 1;
        }
        spin_unlock(&lock->l_spin);
        if (owner)
                 ++lock->l_depth;
        else { 
                down(&lock->l_sem);
                spin_lock(&lock->l_spin);
                lock->l_owner = current;
                lock->l_depth = 0;
                spin_unlock(&lock->l_spin);
        }
}

void l_unlock(struct lustre_lock *lock)
{
        if (lock->l_owner != current)
                LBUG();
        if (lock->l_depth < 0)
                LBUG();

        spin_lock(&lock->l_spin); 
        if (--lock->l_depth < 0) { 
                lock->l_owner = NULL;
                spin_unlock(&lock->l_spin);
                up(&lock->l_sem);
                return ;
        }
        spin_unlock(&lock->l_spin);
}
