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
 * libcfs/libcfs/user-lock.c
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
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

#include <libcfs/libcfs.h>

/*
 * Optional debugging (magic stamping and checking ownership) can be added.
 */

/*
 * spin_lock
 *
 * - spin_lock_init(x)
 * - spin_lock(x)
 * - spin_lock_nested(x, subclass)
 * - spin_unlock(x)
 * - spin_trylock(x)
 *
 * - spin_lock_irqsave(x, f)
 * - spin_unlock_irqrestore(x, f)
 *
 * No-op implementation.
 */

void cfs_spin_lock_init(cfs_spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

void cfs_spin_lock(cfs_spinlock_t *lock)
{
        (void)lock;
}

void cfs_spin_unlock(cfs_spinlock_t *lock)
{
        (void)lock;
}

int cfs_spin_trylock(cfs_spinlock_t *lock)
{
        (void)lock;
	return 1;
}

void cfs_spin_lock_bh_init(cfs_spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

void cfs_spin_lock_bh(cfs_spinlock_t *lock)
{
        LASSERT(lock != NULL);
        (void)lock;
}

void cfs_spin_unlock_bh(cfs_spinlock_t *lock)
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

void cfs_sema_init(cfs_semaphore_t *s, int val)
{
        LASSERT(s != NULL);
        (void)s;
        (void)val;
}

void __down(cfs_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

int __down_interruptible(cfs_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
        return 0;
}

void __up(cfs_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}


/*
 * Completion:
 *
 * - init_completion(c)
 * - complete(c)
 * - wait_for_completion(c)
 */

static cfs_wait_handler_t wait_handler;

void cfs_init_completion_module(cfs_wait_handler_t handler)
{
        wait_handler = handler;
}

int cfs_call_wait_handler(int timeout)
{
        if (!wait_handler)
                return -ENOSYS;
        return wait_handler(timeout);
}

void cfs_init_completion(cfs_completion_t *c)
{
        LASSERT(c != NULL);
        c->done = 0;
        cfs_waitq_init(&c->wait);
}

void cfs_complete(cfs_completion_t *c)
{
        LASSERT(c != NULL);
        c->done  = 1;
        cfs_waitq_signal(&c->wait);
}

void cfs_wait_for_completion(cfs_completion_t *c)
{
        LASSERT(c != NULL);
        do {
                if (cfs_call_wait_handler(1000) < 0)
                        break;
        } while (c->done == 0);
}

int cfs_wait_for_completion_interruptible(cfs_completion_t *c)
{
        LASSERT(c != NULL);
        do {
                if (cfs_call_wait_handler(1000) < 0)
                        break;
        } while (c->done == 0);
        return 0;
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

void cfs_init_rwsem(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

void cfs_down_read(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

int cfs_down_read_trylock(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
	return 1;
}

void cfs_down_write(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

int cfs_down_write_trylock(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
	return 1;
}

void cfs_up_read(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

void cfs_up_write(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

void cfs_fini_rwsem(cfs_rw_semaphore_t *s)
{
        LASSERT(s != NULL);
        (void)s;
}

#ifdef HAVE_LIBPTHREAD

/*
 * Multi-threaded user space completion
 */

void cfs_mt_init_completion(cfs_mt_completion_t *c)
{
        LASSERT(c != NULL);
        c->c_done = 0;
        pthread_mutex_init(&c->c_mut, NULL);
        pthread_cond_init(&c->c_cond, NULL);
}

void cfs_mt_fini_completion(cfs_mt_completion_t *c)
{
        LASSERT(c != NULL);
        pthread_mutex_destroy(&c->c_mut);
        pthread_cond_destroy(&c->c_cond);
}

void cfs_mt_complete(cfs_mt_completion_t *c)
{
        LASSERT(c != NULL);
        pthread_mutex_lock(&c->c_mut);
        c->c_done++;
        pthread_cond_signal(&c->c_cond);
        pthread_mutex_unlock(&c->c_mut);
}

void cfs_mt_wait_for_completion(cfs_mt_completion_t *c)
{
        LASSERT(c != NULL);
        pthread_mutex_lock(&c->c_mut);
        while (c->c_done == 0)
                pthread_cond_wait(&c->c_cond, &c->c_mut);
        c->c_done--;
        pthread_mutex_unlock(&c->c_mut);
}

/*
 * Multi-threaded user space atomic primitives
 */

static pthread_mutex_t atomic_guard_lock = PTHREAD_MUTEX_INITIALIZER;

int cfs_mt_atomic_read(cfs_mt_atomic_t *a)
{
        int r;

        pthread_mutex_lock(&atomic_guard_lock);
        r = a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
        return r;
}

void cfs_mt_atomic_set(cfs_mt_atomic_t *a, int b)
{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter = b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

int cfs_mt_atomic_dec_and_test(cfs_mt_atomic_t *a)
{
        int r;

        pthread_mutex_lock(&atomic_guard_lock);
        r = --a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
        return (r == 0);
}

void cfs_mt_atomic_inc(cfs_mt_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        ++a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
}

void cfs_mt_atomic_dec(cfs_mt_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        --a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
}
void cfs_mt_atomic_add(int b, cfs_mt_atomic_t *a)

{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter += b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

void cfs_mt_atomic_sub(int b, cfs_mt_atomic_t *a)
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
