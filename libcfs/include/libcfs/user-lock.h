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
 * libcfs/include/libcfs/user-lock.h
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LIBCFS_USER_LOCK_H__
#define __LIBCFS_USER_LOCK_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* Implementations of portable synchronization APIs for liblustre */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 *
 * XXX Liang: There are several branches share lnet with b_hd_newconfig,
 * if we define lock APIs at here, there will be conflict with liblustre
 * in other branches.
 */

#ifndef __KERNEL__

/*
 * The userspace implementations of linux/spinlock.h vary; we just
 * include our own for all of them
 */
#define __LINUX_SPINLOCK_H

/*
 * Optional debugging (magic stamping and checking ownership) can be added.
 */

/*
 * cfs_spin_lock
 *
 * - cfs_spin_lock_init(x)
 * - cfs_spin_lock(x)
 * - cfs_spin_unlock(x)
 * - cfs_spin_trylock(x)
 * - cfs_spin_lock_bh_init(x)
 * - cfs_spin_lock_bh(x)
 * - cfs_spin_unlock_bh(x)
 *
 * - cfs_spin_is_locked(x)
 * - cfs_spin_lock_irqsave(x, f)
 * - cfs_spin_unlock_irqrestore(x, f)
 *
 * No-op implementation.
 */
struct cfs_spin_lock {int foo;};

typedef struct cfs_spin_lock cfs_spinlock_t;

#define DEFINE_SPINLOCK(lock)		cfs_spinlock_t lock = { }
#define LASSERT_SPIN_LOCKED(lock) do {(void)sizeof(lock);} while(0)
#define LINVRNT_SPIN_LOCKED(lock) do {(void)sizeof(lock);} while(0)
#define LASSERT_SEM_LOCKED(sem) do {(void)sizeof(sem);} while(0)
#define LASSERT_MUTEX_LOCKED(x) do {(void)sizeof(x);} while(0)

void cfs_spin_lock_init(cfs_spinlock_t *lock);
void cfs_spin_lock(cfs_spinlock_t *lock);
void cfs_spin_unlock(cfs_spinlock_t *lock);
int cfs_spin_trylock(cfs_spinlock_t *lock);
void cfs_spin_lock_bh_init(cfs_spinlock_t *lock);
void cfs_spin_lock_bh(cfs_spinlock_t *lock);
void cfs_spin_unlock_bh(cfs_spinlock_t *lock);

static inline int cfs_spin_is_locked(cfs_spinlock_t *l) {return 1;}
static inline void cfs_spin_lock_irqsave(cfs_spinlock_t *l, unsigned long f){}
static inline void cfs_spin_unlock_irqrestore(cfs_spinlock_t *l,
                                              unsigned long f){}

/*
 * Semaphore
 *
 * - cfs_sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */
typedef struct cfs_semaphore {
    int foo;
} cfs_semaphore_t;

void cfs_sema_init(cfs_semaphore_t *s, int val);
void __up(cfs_semaphore_t *s);
void __down(cfs_semaphore_t *s);
int __down_interruptible(cfs_semaphore_t *s);

#define CFS_DEFINE_SEMAPHORE(name)      cfs_semaphore_t name = { 1 }

#define cfs_up(s)                       __up(s)
#define cfs_down(s)                     __down(s)
#define cfs_down_interruptible(s)       __down_interruptible(s)

static inline int cfs_down_trylock(cfs_semaphore_t *sem)
{
        return 0;
}

/*
 * Completion:
 *
 * - cfs_init_completion_module(c)
 * - cfs_call_wait_handler(t)
 * - cfs_init_completion(c)
 * - cfs_complete(c)
 * - cfs_wait_for_completion(c)
 * - cfs_wait_for_completion_interruptible(c)
 */
typedef struct {
        unsigned int done;
        cfs_waitq_t wait;
} cfs_completion_t;

typedef int (*cfs_wait_handler_t) (int timeout);
void cfs_init_completion_module(cfs_wait_handler_t handler);
int  cfs_call_wait_handler(int timeout);
void cfs_init_completion(cfs_completion_t *c);
void cfs_complete(cfs_completion_t *c);
void cfs_wait_for_completion(cfs_completion_t *c);
int cfs_wait_for_completion_interruptible(cfs_completion_t *c);

#define CFS_COMPLETION_INITIALIZER(work) \
        { 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }

#define CFS_DECLARE_COMPLETION(work) \
        cfs_completion_t work = CFS_COMPLETION_INITIALIZER(work)

#define CFS_INIT_COMPLETION(x)      ((x).done = 0)


/*
 * cfs_rw_semaphore:
 *
 * - cfs_init_rwsem(x)
 * - cfs_down_read(x)
 * - cfs_down_read_trylock(x)
 * - cfs_down_write(struct cfs_rw_semaphore *s);
 * - cfs_down_write_trylock(struct cfs_rw_semaphore *s);
 * - cfs_up_read(x)
 * - cfs_up_write(x)
 * - cfs_fini_rwsem(x)
 */
typedef struct cfs_rw_semaphore {
        int foo;
} cfs_rw_semaphore_t;

void cfs_init_rwsem(cfs_rw_semaphore_t *s);
void cfs_down_read(cfs_rw_semaphore_t *s);
int cfs_down_read_trylock(cfs_rw_semaphore_t *s);
void cfs_down_write(cfs_rw_semaphore_t *s);
int cfs_down_write_trylock(cfs_rw_semaphore_t *s);
void cfs_up_read(cfs_rw_semaphore_t *s);
void cfs_up_write(cfs_rw_semaphore_t *s);
void cfs_fini_rwsem(cfs_rw_semaphore_t *s);
#define CFS_DECLARE_RWSEM(name)  cfs_rw_semaphore_t name = { }

/*
 * read-write lock : Need to be investigated more!!
 * XXX nikita: for now, let rwlock_t to be identical to rw_semaphore
 *
 * - cfs_rwlock_init(x)
 * - cfs_read_lock(x)
 * - cfs_read_unlock(x)
 * - cfs_write_lock(x)
 * - cfs_write_unlock(x)
 * - cfs_write_lock_irqsave(x)
 * - cfs_write_unlock_irqrestore(x)
 * - cfs_read_lock_irqsave(x)
 * - cfs_read_unlock_irqrestore(x)
 */
typedef cfs_rw_semaphore_t cfs_rwlock_t;
#define DEFINE_RWLOCK(lock)	cfs_rwlock_t lock = { }

#define cfs_rwlock_init(pl)         cfs_init_rwsem(pl)

#define cfs_read_lock(l)            cfs_down_read(l)
#define cfs_read_unlock(l)          cfs_up_read(l)
#define cfs_write_lock(l)           cfs_down_write(l)
#define cfs_write_unlock(l)         cfs_up_write(l)

static inline void
cfs_write_lock_irqsave(cfs_rwlock_t *l, unsigned long f) { cfs_write_lock(l); }
static inline void
cfs_write_unlock_irqrestore(cfs_rwlock_t *l, unsigned long f) { cfs_write_unlock(l); }

static inline void
cfs_read_lock_irqsave(cfs_rwlock_t *l, unsigned long f) { cfs_read_lock(l); }
static inline void
cfs_read_unlock_irqrestore(cfs_rwlock_t *l, unsigned long f) { cfs_read_unlock(l); }

/*
 * Atomic for single-threaded user-space
 */
typedef struct { volatile int counter; } cfs_atomic_t;

#define CFS_ATOMIC_INIT(i) { (i) }

#define cfs_atomic_read(a) ((a)->counter)
#define cfs_atomic_set(a,b) do {(a)->counter = b; } while (0)
#define cfs_atomic_dec_and_test(a) ((--((a)->counter)) == 0)
#define cfs_atomic_dec_and_lock(a,b) ((--((a)->counter)) == 0)
#define cfs_atomic_inc(a)  (((a)->counter)++)
#define cfs_atomic_dec(a)  do { (a)->counter--; } while (0)
#define cfs_atomic_add(b,a)  do {(a)->counter += b;} while (0)
#define cfs_atomic_add_return(n,a) ((a)->counter += n)
#define cfs_atomic_inc_return(a) cfs_atomic_add_return(1,a)
#define cfs_atomic_sub(b,a)  do {(a)->counter -= b;} while (0)
#define cfs_atomic_sub_return(n,a) ((a)->counter -= n)
#define cfs_atomic_dec_return(a)  cfs_atomic_sub_return(1,a)
#define cfs_atomic_add_unless(v, a, u) \
        ((v)->counter != u ? (v)->counter += a : 0)
#define cfs_atomic_inc_not_zero(v) cfs_atomic_add_unless((v), 1, 0)
#define cfs_atomic_cmpxchg(v, ov, nv) \
	((v)->counter == ov ? ((v)->counter = nv, ov) : (v)->counter)

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>

/*
 * Multi-threaded user space completion APIs
 */

typedef struct {
        int c_done;
        pthread_cond_t c_cond;
        pthread_mutex_t c_mut;
} cfs_mt_completion_t;

void cfs_mt_init_completion(cfs_mt_completion_t *c);
void cfs_mt_fini_completion(cfs_mt_completion_t *c);
void cfs_mt_complete(cfs_mt_completion_t *c);
void cfs_mt_wait_for_completion(cfs_mt_completion_t *c);

/*
 * Multi-threaded user space atomic APIs
 */

typedef struct { volatile int counter; } cfs_mt_atomic_t;

int cfs_mt_atomic_read(cfs_mt_atomic_t *a);
void cfs_mt_atomic_set(cfs_mt_atomic_t *a, int b);
int cfs_mt_atomic_dec_and_test(cfs_mt_atomic_t *a);
void cfs_mt_atomic_inc(cfs_mt_atomic_t *a);
void cfs_mt_atomic_dec(cfs_mt_atomic_t *a);
void cfs_mt_atomic_add(int b, cfs_mt_atomic_t *a);
void cfs_mt_atomic_sub(int b, cfs_mt_atomic_t *a);

#endif /* HAVE_LIBPTHREAD */

/**************************************************************************
 *
 * Mutex interface.
 *
 **************************************************************************/
typedef struct cfs_semaphore cfs_mutex_t;

#define CFS_DEFINE_MUTEX(m) CFS_DEFINE_SEMAPHORE(m)

static inline void cfs_mutex_init(cfs_mutex_t *mutex)
{
        cfs_sema_init(mutex, 1);
}

static inline void cfs_mutex_lock(cfs_mutex_t *mutex)
{
        cfs_down(mutex);
}

static inline void cfs_mutex_unlock(cfs_mutex_t *mutex)
{
        cfs_up(mutex);
}

static inline int cfs_mutex_lock_interruptible(cfs_mutex_t *mutex)
{
        return cfs_down_interruptible(mutex);
}

/**
 * Try-lock this mutex.
 *
 * Note, return values are negation of what is expected from down_trylock() or
 * pthread_mutex_trylock().
 *
 * \retval 1 try-lock succeeded (lock acquired).
 * \retval 0 indicates lock contention.
 */
static inline int cfs_mutex_trylock(cfs_mutex_t *mutex)
{
        return !cfs_down_trylock(mutex);
}

static inline void cfs_mutex_destroy(cfs_mutex_t *lock)
{
}

/*
 * This is for use in assertions _only_, i.e., this function should always
 * return 1.
 *
 * \retval 1 mutex is locked.
 *
 * \retval 0 mutex is not locked. This should never happen.
 */
static inline int cfs_mutex_is_locked(cfs_mutex_t *lock)
{
        return 1;
}


/**************************************************************************
 *
 * Lockdep "implementation". Also see lustre_compat25.h
 *
 **************************************************************************/

typedef struct cfs_lock_class_key {
        int foo;
} cfs_lock_class_key_t;

static inline void cfs_lockdep_set_class(void *lock,
                                         cfs_lock_class_key_t *key)
{
}

static inline void cfs_lockdep_off(void)
{
}

static inline void cfs_lockdep_on(void)
{
}

#define cfs_mutex_lock_nested(mutex, subclass) cfs_mutex_lock(mutex)
#define cfs_spin_lock_nested(lock, subclass) cfs_spin_lock(lock)
#define cfs_down_read_nested(lock, subclass) cfs_down_read(lock)
#define cfs_down_write_nested(lock, subclass) cfs_down_write(lock)


/* !__KERNEL__ */
#endif

/* __LIBCFS_USER_LOCK_H__ */
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
