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
 * Copyright (c) 2012, 2013, Intel Corporation.
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
 * spin_lock
 *
 * - spin_lock_init(x)
 * - spin_lock(x)
 * - spin_unlock(x)
 * - spin_trylock(x)
 * - spin_lock_bh_init(x)
 * - spin_lock_bh(x)
 * - spin_unlock_bh(x)
 *
 * - assert_spin_locked(x)
 * - spin_lock_irqsave(x, f)
 * - spin_unlock_irqrestore(x, f)
 *
 * No-op implementation.
 */
struct spin_lock { int foo; };

typedef struct spin_lock spinlock_t;

#define DEFINE_SPINLOCK(lock)		spinlock_t lock = { }
#define __SPIN_LOCK_UNLOCKED(x)		((spinlock_t) {})

void spin_lock_init(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
int  spin_trylock(spinlock_t *lock);
void spin_lock_bh_init(spinlock_t *lock);
void spin_lock_bh(spinlock_t *lock);
void spin_unlock_bh(spinlock_t *lock);

static inline void spin_lock_irqsave(spinlock_t *l, unsigned long f) {}
static inline void spin_unlock_irqrestore(spinlock_t *l, unsigned long f) {}

#define assert_spin_locked(lock)	do { (void)(lock); } while (0)

/*
 * Semaphore
 *
 * - sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */
struct semaphore {
	int foo;
};

void sema_init(struct semaphore *s, int val);
void __up(struct semaphore *s);
void __down(struct semaphore *s);
int __down_interruptible(struct semaphore *s);

#define DEFINE_SEMAPHORE(name)      struct semaphore name = { 1 }

#define up(s)				__up(s)
#define down(s)			__down(s)
#define down_interruptible(s)		__down_interruptible(s)

static inline int down_trylock(struct semaphore *sem)
{
        return 0;
}

/*
 * Completion:
 *
 * - init_completion_module(c)
 * - call_wait_handler(t)
 * - init_completion(c)
 * - complete(c)
 * - wait_for_completion(c)
 * - wait_for_completion_interruptible(c)
 */
#ifdef HAVE_LIBPTHREAD
#include <pthread.h>

/*
 * Multi-threaded user space completion APIs
 */

struct completion {
	int		c_done;
	pthread_cond_t	c_cond;
	pthread_mutex_t	c_mut;
};

#else /* !HAVE_LIBPTHREAD */

struct completion {
	unsigned int	done;
	wait_queue_head_t	wait;
};
#endif /* HAVE_LIBPTHREAD */

typedef int (*wait_handler_t) (int timeout);
void init_completion_module(wait_handler_t handler);
int  call_wait_handler(int timeout);
void init_completion(struct completion *c);
void fini_completion(struct completion *c);
void complete(struct completion *c);
void wait_for_completion(struct completion *c);
int wait_for_completion_interruptible(struct completion *c);

#define COMPLETION_INITIALIZER(work) \
	{ 0, __WAIT_QUEUE_HEAD_INITIALIZER((work).wait) }


#define INIT_COMPLETION(x)	((x).done = 0)


/*
 * rw_semaphore:
 *
 * - init_rwsem(x)
 * - down_read(x)
 * - down_read_trylock(x)
 * - down_write(struct rw_semaphore *s);
 * - down_write_trylock(struct rw_semaphore *s);
 * - up_read(x)
 * - up_write(x)
 * - fini_rwsem(x)
 */
struct rw_semaphore {
	int foo;
};

void init_rwsem(struct rw_semaphore *s);
void down_read(struct rw_semaphore *s);
int down_read_trylock(struct rw_semaphore *s);
void down_write(struct rw_semaphore *s);
void downgrade_write(struct rw_semaphore *s);
int down_write_trylock(struct rw_semaphore *s);
void up_read(struct rw_semaphore *s);
void up_write(struct rw_semaphore *s);
void fini_rwsem(struct rw_semaphore *s);
#define DECLARE_RWSEM(name)  struct rw_semaphore name = { }

/*
 * read-write lock : Need to be investigated more!!
 * XXX nikita: for now, let rwlock_t to be identical to rw_semaphore
 *
 * - rwlock_init(x)
 * - read_lock(x)
 * - read_unlock(x)
 * - write_lock(x)
 * - write_unlock(x)
 * - write_lock_irqsave(x)
 * - write_unlock_irqrestore(x)
 * - read_lock_irqsave(x)
 * - read_unlock_irqrestore(x)
 */
#define rwlock_t		struct rw_semaphore
#define DEFINE_RWLOCK(lock)	rwlock_t lock = { }

#define rwlock_init(pl)		init_rwsem(pl)

#define read_lock(l)		down_read(l)
#define read_unlock(l)		up_read(l)
#define write_lock(l)		down_write(l)
#define write_unlock(l)		up_write(l)

static inline void write_lock_irqsave(rwlock_t *l, unsigned long f)
{
	write_lock(l);
}

static inline void write_unlock_irqrestore(rwlock_t *l, unsigned long f)
{
	write_unlock(l);
}

static inline void read_lock_irqsave(rwlock_t *l, unsigned long f)
{
	read_lock(l);
}

static inline void read_unlock_irqrestore(rwlock_t *l, unsigned long f)
{
	read_unlock(l);
}

/*
 * Atomic for single-threaded user-space
 */
typedef struct { volatile int counter; } atomic_t;

#define ATOMIC_INIT(i) { (i) }

#define atomic_read(a) ((a)->counter)
#define atomic_set(a,b) do {(a)->counter = b; } while (0)
#define atomic_dec_and_test(a) ((--((a)->counter)) == 0)
#define atomic_dec_and_lock(a,b) ((--((a)->counter)) == 0)
#define atomic_inc(a)  (((a)->counter)++)
#define atomic_dec(a)  do { (a)->counter--; } while (0)
#define atomic_add(b,a)  do {(a)->counter += b;} while (0)
#define atomic_add_return(n,a) ((a)->counter += n)
#define atomic_inc_return(a) atomic_add_return(1,a)
#define atomic_sub(b,a)  do {(a)->counter -= b;} while (0)
#define atomic_sub_return(n,a) ((a)->counter -= n)
#define atomic_dec_return(a)  atomic_sub_return(1,a)
#define atomic_add_unless(v, a, u) \
        ((v)->counter != u ? (v)->counter += a : 0)
#define atomic_inc_not_zero(v) atomic_add_unless((v), 1, 0)
#define atomic_cmpxchg(v, ov, nv) \
	((v)->counter == ov ? ((v)->counter = nv, ov) : (v)->counter)

typedef struct { volatile long counter; } atomic_long_t;

#define ATOMIC_LONG_INIT(i) { (i) }

#define atomic_long_read(a) ((a)->counter)
#define atomic_long_set(a, b) do {(a)->counter = b; } while (0)
#define atomic_long_dec_and_test(a) ((--((a)->counter)) == 0)
#define atomic_long_dec_and_lock(a, b) ((--((a)->counter)) == 0)
#define atomic_long_inc(a)  (((a)->counter)++)
#define atomic_long_dec(a)  do { (a)->counter--; } while (0)
#define atomic_long_add(b, a)  do {(a)->counter += b; } while (0)
#define atomic_long_add_return(n, a) ((a)->counter += n)
#define atomic_long_inc_return(a) atomic_long_add_return(1, a)
#define atomic_long_sub(b, a)  do {(a)->counter -= b; } while (0)
#define atomic_long_sub_return(n, a) ((a)->counter -= n)
#define atomic_long_dec_return(a)  atomic_long_sub_return(1, a)
#define atomic_long_add_unless(v, a, u) \
	((v)->counter != u ? (v)->counter += a : 0)
#define atomic_long_inc_not_zero(v) atomic_long_add_unless((v), 1, 0)
#define atomic_long_cmpxchg(v, ov, nv) \
	((v)->counter == ov ? ((v)->counter = nv, ov) : (v)->counter)

#ifdef HAVE_LIBPTHREAD
#include <pthread.h>

/*
 * Multi-threaded user space atomic APIs
 */

typedef struct { volatile int counter; } mt_atomic_t;

int mt_atomic_read(mt_atomic_t *a);
void mt_atomic_set(mt_atomic_t *a, int b);
int mt_atomic_dec_and_test(mt_atomic_t *a);
void mt_atomic_inc(mt_atomic_t *a);
void mt_atomic_dec(mt_atomic_t *a);
void mt_atomic_add(int b, mt_atomic_t *a);
void mt_atomic_sub(int b, mt_atomic_t *a);

#endif /* HAVE_LIBPTHREAD */

/**************************************************************************
 *
 * Mutex interface.
 *
 **************************************************************************/
#define mutex semaphore

#define DEFINE_MUTEX(m) DEFINE_SEMAPHORE(m)

static inline void mutex_init(struct mutex *mutex)
{
	sema_init(mutex, 1);
}

static inline void mutex_lock(struct mutex *mutex)
{
	down(mutex);
}

static inline void mutex_unlock(struct mutex *mutex)
{
	up(mutex);
}

static inline int mutex_lock_interruptible(struct mutex *mutex)
{
	return down_interruptible(mutex);
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
static inline int mutex_trylock(struct mutex *mutex)
{
	return !down_trylock(mutex);
}

static inline void mutex_destroy(struct mutex *lock)
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
static inline int mutex_is_locked(struct mutex *lock)
{
        return 1;
}


/**************************************************************************
 *
 * Lockdep "implementation". Also see lustre_compat25.h
 *
 **************************************************************************/

struct lock_class_key {
        int foo;
};

static inline void lockdep_set_class(void *lock, struct lock_class_key *key)
{
}

static inline void lockdep_off(void)
{
}

static inline void lockdep_on(void)
{
}

#define mutex_lock_nested(mutex, subclass) mutex_lock(mutex)
#define spin_lock_nested(lock, subclass) spin_lock(lock)
#define down_read_nested(lock, subclass) down_read(lock)
#define down_write_nested(lock, subclass) down_write(lock)


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
