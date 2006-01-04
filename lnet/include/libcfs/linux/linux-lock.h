/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
 * Basic library routines.
 *
 */

#ifndef __LIBCFS_LINUX_CFS_LOCK_H__
#define __LIBCFS_LINUX_CFS_LOCK_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__
#include <linux/smp_lock.h>

/*
 * IMPORTANT !!!!!!!!
 *
 * All locks' declaration are not guaranteed to be initialized,
 * Althought some of they are initialized in Linux. All locks
 * declared by CFS_DECL_* should be initialized explicitly.
 */


/*
 * spin_lock (use Linux kernel's primitives)
 *
 * - spin_lock_init(x)
 * - spin_lock(x)
 * - spin_unlock(x)
 * - spin_trylock(x)
 *
 * - spin_lock_irqsave(x, f)
 * - spin_unlock_irqrestore(x, f)
 */

/*
 * rw_semaphore (use Linux kernel's primitives)
 *
 * - init_rwsem(x)
 * - down_read(x)
 * - up_read(x)
 * - down_write(x)
 * - up_write(x)
 */

/*
 * rwlock_t (use Linux kernel's primitives)
 *
 * - rwlock_init(x)
 * - read_lock(x)
 * - read_unlock(x)
 * - write_lock(x)
 * - write_unlock(x)
 */

/*
 * mutex:
 *
 * - init_mutex(x)
 * - init_mutex_locked(x)
 * - mutex_up(x)
 * - mutex_down(x)
 */
#define init_mutex(x)                   init_MUTEX(x)
#define init_mutex_locked(x)            init_MUTEX_LOCKED(x)
#define mutex_up(x)                     up(x)
#define mutex_down(x)                   down(x)

/*
 * completion (use Linux kernel's primitives)
 *
 * - init_complition(c)
 * - complete(c)
 * - wait_for_completion(c)
 */

/* __KERNEL__ */
#else

#include "../user-lock.h"

/* __KERNEL__ */
#endif
#endif
