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
 *
 * Copyright (c) 2012, Intel Corporation.
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

int __down_interruptible(struct semaphore *s)
{
	LASSERT(s != NULL);
	(void)s;
	return 0;
}

void __up(struct semaphore *s)
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
static wait_handler_t wait_handler;

void init_completion_module(wait_handler_t handler)
{
	wait_handler = handler;
}

int call_wait_handler(int timeout)
{
	if (!wait_handler)
		return -ENOSYS;
	return wait_handler(timeout);
}

#ifndef HAVE_LIBPTHREAD
void init_completion(struct completion *c)
{
	LASSERT(c != NULL);
	c->done = 0;
	cfs_waitq_init(&c->wait);
}

void fini_completion(struct completion *c)
{
}

void complete(struct completion *c)
{
	LASSERT(c != NULL);
	c->done  = 1;
	cfs_waitq_signal(&c->wait);
}

void wait_for_completion(struct completion *c)
{
	LASSERT(c != NULL);
	do {
		if (call_wait_handler(1000) < 0)
			break;
	} while (c->done == 0);
}

int wait_for_completion_interruptible(struct completion *c)
{
	LASSERT(c != NULL);
	do {
		if (call_wait_handler(1000) < 0)
			break;
	} while (c->done == 0);
	return 0;
}
#endif /* HAVE_LIBPTHREAD */

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

void fini_rwsem(struct rw_semaphore *s)
{
	LASSERT(s != NULL);
	(void)s;
}

#ifdef HAVE_LIBPTHREAD

/*
 * Multi-threaded user space completion
 */

void init_completion(struct completion *c)
{
        LASSERT(c != NULL);
        c->c_done = 0;
        pthread_mutex_init(&c->c_mut, NULL);
        pthread_cond_init(&c->c_cond, NULL);
}

void fini_completion(struct completion *c)
{
        LASSERT(c != NULL);
        pthread_mutex_destroy(&c->c_mut);
        pthread_cond_destroy(&c->c_cond);
}

void complete(struct completion *c)
{
        LASSERT(c != NULL);
        pthread_mutex_lock(&c->c_mut);
        c->c_done++;
        pthread_cond_signal(&c->c_cond);
        pthread_mutex_unlock(&c->c_mut);
}

void wait_for_completion(struct completion *c)
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

int mt_atomic_read(mt_atomic_t *a)
{
        int r;

        pthread_mutex_lock(&atomic_guard_lock);
        r = a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
        return r;
}

void mt_atomic_set(mt_atomic_t *a, int b)
{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter = b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

int mt_atomic_dec_and_test(mt_atomic_t *a)
{
        int r;

        pthread_mutex_lock(&atomic_guard_lock);
        r = --a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
        return (r == 0);
}

void mt_atomic_inc(mt_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        ++a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
}

void mt_atomic_dec(mt_atomic_t *a)
{
        pthread_mutex_lock(&atomic_guard_lock);
        --a->counter;
        pthread_mutex_unlock(&atomic_guard_lock);
}
void mt_atomic_add(int b, mt_atomic_t *a)

{
        pthread_mutex_lock(&atomic_guard_lock);
        a->counter += b;
        pthread_mutex_unlock(&atomic_guard_lock);
}

void mt_atomic_sub(int b, mt_atomic_t *a)
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
