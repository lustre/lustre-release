/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
 * Author: Nikita Danilov <nikita@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org.
 *
 * Lustre is free software; you can redistribute it and/or modify it under the
 * terms of version 2 of the GNU General Public License as published by the
 * Free Software Foundation.
 *
 * Lustre is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with Lustre; if not, write to the Free Software Foundation, Inc., 675 Mass
 * Ave, Cambridge, MA 02139, USA.
 *
 * Implementation of portable time API for user-level.
 *
 */

/* Implementations of portable synchronization APIs for liblustre */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 *
 * XXX Liang: There are several branches share lnet with b_hd_newconfig,
 * if we define lock APIs at here, there will be conflict with liblustre
 * in other branches.
 */

#ifndef __KERNEL__

#include <stdlib.h>
#include <libcfs/libcfs.h>
/*
 * Optional debugging (magic stamping and checking ownership) can be added.
 */

#if 0
/*
 * spin_lock
 *
 * - spin_lock_init(x)
 * - spin_lock(x)
 * - spin_unlock(x)
 * - spin_trylock(x)
 *
 * - spin_lock_irqsave(x, f)
 * - spin_unlock_irqrestore(x, f)
 *
 * No-op implementation.
 */

void spin_lock_init(spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

void spin_lock(spinlock_t *lock)
{
        (void)lock;
}

void spin_unlock(spinlock_t *lock)
{
        (void)lock;
}

int spin_trylock(spinlock_t *lock)
{
        (void)lock;
	return 1;
}

void spin_lock_bh_init(spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

void spin_lock_bh(spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

void spin_unlock_bh(spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

/*
 * Semaphore
 *
 * - sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */
struct semaphore {};

void sema_init(struct semaphore *s, int val)
{
        LASSERT(s != NULL);
        (void)s;
        (void)val;
}

void __down(struct semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}

void __up(struct semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}

/*
 * Mutex:
 *
 * - init_mutex(x)
 * - init_mutex_locked(x)
 * - mutex_up(x)
 * - mutex_down(x)
 */

#define mutex_up(s)			__up(s)
#define mutex_down(s)			__down(s)

#define init_mutex(x)			sema_init(x, 1)
#define init_mutex_locked(x)		sema_init(x, 0)

/*
 * Completion:
 *
 * - init_completion(c)
 * - complete(c)
 * - wait_for_completion(c)
 */
struct completion {};

void init_completion(struct completion *c)
{
        LASSERT(c != NULL);
        (void)c;
}

void complete(struct completion *c)
{
        LASSERT(c != NULL);
        (void)c;
}

void wait_for_completion(struct completion *c)
{
        LASSERT(c != NULL);
        (void)c;
}

/*
 * rw_semaphore:
 *
 * - DECLARE_RWSEM(x)
 * - init_rwsem(x)
 * - down_read(x)
 * - up_read(x)
 * - down_write(x)
 * - up_write(x)
 */
struct rw_semaphore {};

void init_rwsem(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}

void down_read(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}

int down_read_trylock(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
	return 1;
}

void down_write(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}

int down_write_trylock(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
	return 1;
}

void up_read(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}

void up_write(struct rw_semaphore *s)
{
        LASSERT(s != NULL);
        (void)s;
}
#endif

/* !__KERNEL__ */
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
