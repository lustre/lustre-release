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

#ifndef __LIBCFS_USER_LOCK_H__
#define __LIBCFS_USER_LOCK_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

/* Implementations of portable synchronization APIs for liblustre */

/*
 * liblustre is single-threaded, so most "synchronization" APIs are trivial.
 */

#ifndef __KERNEL__

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
 *
 * - spin_lock_irqsave(x, f)
 * - spin_unlock_irqrestore(x, f)
 *
 * No-op implementation.
 */
struct spin_lock {};

typedef struct spin_lock spinlock_t;

void spin_lock_init(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
int spin_trylock(spinlock_t *lock);
void spin_lock_bh_init(spinlock_t *lock);
void spin_lock_bh(spinlock_t *lock);
void spin_unlock_bh(spinlock_t *lock);

static inline void 
spin_lock_irqsave(spinlock_t *l, unsigned long f) { spin_lock(l); }
static inline void 
spin_unlock_irqrestore(spinlock_t *l, unsigned long f) { spin_unlock(l); }

/*
 * Semaphore
 *
 * - sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */
struct semaphore {};

void sema_init(struct semaphore *s, int val);
void __down(struct semaphore *s);
void __up(struct semaphore *s);

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

void init_completion(struct completion *c);
void complete(struct completion *c);
void wait_for_completion(struct completion *c);

/*
 * rw_semaphore:
 *
 * - init_rwsem(x)
 * - down_read(x)
 * - up_read(x)
 * - down_write(x)
 * - up_write(x)
 */
struct rw_semaphore {};

void init_rwsem(struct rw_semaphore *s);
void down_read(struct rw_semaphore *s);
int down_read_trylock(struct rw_semaphore *s);
void down_write(struct rw_semaphore *s);
int down_write_trylock(struct rw_semaphore *s);
void up_read(struct rw_semaphore *s);
void up_write(struct rw_semaphore *s);

/*
 * read-write lock : Need to be investigated more!!
 * XXX nikita: for now, let rwlock_t to be identical to rw_semaphore
 *
 * - DECLARE_RWLOCK(l)
 * - rwlock_init(x)
 * - read_lock(x)
 * - read_unlock(x)
 * - write_lock(x)
 * - write_unlock(x)
 */
typedef struct rw_semaphore rwlock_t;

#define rwlock_init(pl)		init_rwsem(pl)

#define read_lock(l)		down_read(l)
#define read_unlock(l)		up_read(l)
#define write_lock(l)		down_write(l)
#define write_unlock(l)		up_write(l)

static inline void
write_lock_irqsave(rwlock_t *l, unsigned long f) { write_lock(l); }
static inline void
write_unlock_irqrestore(rwlock_t *l, unsigned long f) { write_unlock(l); }

static inline void 
read_lock_irqsave(rwlock_t *l, unsigned long f) { read_lock(l); }
static inline void
read_unlock_irqrestore(rwlock_t *l, unsigned long f) { read_unlock(l); }

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
