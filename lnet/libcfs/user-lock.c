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
 * lnet/libcfs/user-lock.c
 *
 * Implementations of portable synchronization APIs for liblustre
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

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
#include <libcfs/kp30.h>

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

#ifdef HAVE_LIBPTHREAD

/*
 * Completion
 */

void cfs_init_completion(struct cfs_completion *c)
{
        LASSERT(c != NULL);
        c->c_done = 0;
        pthread_mutex_init(&c->c_mut, NULL);
        pthread_cond_init(&c->c_cond, NULL);
}

void cfs_fini_completion(struct cfs_completion *c)
{
        LASSERT(c != NULL);
        pthread_mutex_destroy(&c->c_mut);
        pthread_cond_destroy(&c->c_cond);
}

void cfs_complete(struct cfs_completion *c)
{
        LASSERT(c != NULL);
        pthread_mutex_lock(&c->c_mut);
        c->c_done++;
        pthread_cond_signal(&c->c_cond);
        pthread_mutex_unlock(&c->c_mut);
}

void cfs_wait_for_completion(struct cfs_completion *c)
{
        LASSERT(c != NULL);
        pthread_mutex_lock(&c->c_mut);
        while (c->c_done == 0)
                pthread_cond_wait(&c->c_cond, &c->c_mut);
        c->c_done--;
        pthread_mutex_unlock(&c->c_mut);
}

/*
 * atomic primitives
 */

static pthread_mutex_t atomic_guard_lock = PTHREAD_MUTEX_INITIALIZER;

int cfs_atomic_read(cfs_atomic_t *a)
{
        int r;

        pthread_mutex_lock(&atomic_guard_lock);
        r = a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
        return r;
}

void cfs_atomic_set(cfs_atomic_t *a, int b)
{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter = b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

int cfs_atomic_dec_and_test(cfs_atomic_t *a)
{
        int r;

        pthread_mutex_lock(&atomic_guard_lock);
        r = --a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
        return (r == 0);
}

void cfs_atomic_inc(cfs_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        ++a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
}

void cfs_atomic_dec(cfs_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        --a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
}
void cfs_atomic_add(int b, cfs_atomic_t *a)

{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter += b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

void cfs_atomic_sub(int b, cfs_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter -= b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

#endif /* HAVE_LIBPTHREAD */


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
