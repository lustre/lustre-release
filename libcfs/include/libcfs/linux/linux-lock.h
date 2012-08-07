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
 * libcfs/include/libcfs/linux/linux-lock.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_LINUX_CFS_LOCK_H__
#define __LIBCFS_LINUX_CFS_LOCK_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifndef __KERNEL__
#error This include is only for kernel use.
#endif

#include <linux/mutex.h>

/*
 * IMPORTANT !!!!!!!!
 *
 * All locks' declaration are not guaranteed to be initialized,
 * Althought some of they are initialized in Linux. All locks
 * declared by CFS_DECL_* should be initialized explicitly.
 */

/*
 * spin_lock "implementation" (use Linux kernel's primitives)
 *
 * - spin_lock_init(x)
 * - spin_lock(x)
 * - spin_lock_bh(x)
 * - spin_lock_bh_init(x)
 * - spin_unlock(x)
 * - spin_unlock_bh(x)
 * - spin_trylock(x)
 * - spin_is_locked(x)
 *
 * - spin_lock_irq(x)
 * - spin_lock_irqsave(x, f)
 * - spin_unlock_irqrestore(x, f)
 * - read_lock_irqsave(lock, f)
 * - write_lock_irqsave(lock, f)
 * - write_unlock_irqrestore(lock, f)
 */

/*
 * spinlock "implementation"
 */

typedef spinlock_t cfs_spinlock_t;

#define cfs_spin_lock_init(lock)             spin_lock_init(lock)
#define cfs_spin_lock(lock)                  spin_lock(lock)
#define cfs_spin_lock_bh(lock)               spin_lock_bh(lock)
#define cfs_spin_lock_bh_init(lock)          spin_lock_bh_init(lock)
#define cfs_spin_unlock(lock)                spin_unlock(lock)
#define cfs_spin_unlock_bh(lock)             spin_unlock_bh(lock)
#define cfs_spin_trylock(lock)               spin_trylock(lock)
#define cfs_spin_is_locked(lock)             spin_is_locked(lock)

#define cfs_spin_lock_irq(lock)              spin_lock_irq(lock)
#define cfs_spin_unlock_irq(lock)            spin_unlock_irq(lock)
#define cfs_read_lock_irqsave(lock, f)       read_lock_irqsave(lock, f)
#define cfs_write_lock_irqsave(lock, f)      write_lock_irqsave(lock, f)
#define cfs_write_unlock_irqrestore(lock, f) write_unlock_irqrestore(lock, f)
#define cfs_spin_lock_irqsave(lock, f)       spin_lock_irqsave(lock, f)
#define cfs_spin_unlock_irqrestore(lock, f)  spin_unlock_irqrestore(lock, f)

/*
 * rw_semaphore "implementation" (use Linux kernel's primitives)
 *
 * - sema_init(x)
 * - init_rwsem(x)
 * - down_read(x)
 * - up_read(x)
 * - down_write(x)
 * - up_write(x)
 */
typedef struct rw_semaphore cfs_rw_semaphore_t;

#define cfs_init_rwsem(s)         init_rwsem(s)
#define cfs_down_read(s)          down_read(s)
#define cfs_down_read_trylock(s)  down_read_trylock(s)
#define cfs_up_read(s)            up_read(s)
#define cfs_down_write(s)         down_write(s)
#define cfs_down_write_trylock(s) down_write_trylock(s)
#define cfs_up_write(s)           up_write(s)

#define cfs_fini_rwsem(s)         do {} while(0)

#define CFS_DECLARE_RWSEM(name)   DECLARE_RWSEM(name)

/*
 * rwlock_t "implementation" (use Linux kernel's primitives)
 *
 * - rwlock_init(x)
 * - read_lock(x)
 * - read_unlock(x)
 * - write_lock(x)
 * - write_unlock(x)
 * - write_lock_bh(x)
 * - write_unlock_bh(x)
 *
 * - RW_LOCK_UNLOCKED
 */
typedef rwlock_t cfs_rwlock_t;

#define cfs_rwlock_init(lock)                  rwlock_init(lock)
#define cfs_read_lock(lock)                    read_lock(lock)
#define cfs_read_unlock(lock)                  read_unlock(lock)
#define cfs_read_unlock_irqrestore(lock,flags) \
        read_unlock_irqrestore(lock, flags)
#define cfs_write_lock(lock)                   write_lock(lock)
#define cfs_write_unlock(lock)                 write_unlock(lock)
#define cfs_write_lock_bh(lock)                write_lock_bh(lock)
#define cfs_write_unlock_bh(lock)              write_unlock_bh(lock)

#ifndef DEFINE_RWLOCK
#define DEFINE_RWLOCK(lock)	rwlock_t lock = __RW_LOCK_UNLOCKED(lock)
#endif

/*
 * completion "implementation" (use Linux kernel's primitives)
 *
 * - DECLARE_COMPLETION(work)
 * - INIT_COMPLETION(c)
 * - COMPLETION_INITIALIZER(work)
 * - init_completion(c)
 * - complete(c)
 * - wait_for_completion(c)
 * - wait_for_completion_interruptible(c)
 * - fini_completion(c)
 */
typedef struct completion cfs_completion_t;

#define CFS_DECLARE_COMPLETION(work)             DECLARE_COMPLETION(work)
#define CFS_INIT_COMPLETION(c)                   INIT_COMPLETION(c)
#define CFS_COMPLETION_INITIALIZER(work)         COMPLETION_INITIALIZER(work)
#define cfs_init_completion(c)                   init_completion(c)
#define cfs_complete(c)                          complete(c)
#define cfs_wait_for_completion(c)               wait_for_completion(c)
#define cfs_wait_for_completion_interruptible(c) \
        wait_for_completion_interruptible(c)
#define cfs_complete_and_exit(c, code)           complete_and_exit(c, code)
#define cfs_fini_completion(c)                   do { } while (0)

/*
 * semaphore "implementation" (use Linux kernel's primitives)
 * - DEFINE_SEMAPHORE(name)
 * - sema_init(sem, val)
 * - up(sem)
 * - down(sem)
 * - down_interruptible(sem)
 * - down_trylock(sem)
 */
typedef struct semaphore      cfs_semaphore_t;

#ifdef DEFINE_SEMAPHORE
#define CFS_DEFINE_SEMAPHORE(name)          DEFINE_SEMAPHORE(name)
#else
#define CFS_DEFINE_SEMAPHORE(name)          DECLARE_MUTEX(name)
#endif

#define cfs_sema_init(sem, val)             sema_init(sem, val)
#define cfs_up(x)                           up(x)
#define cfs_down(x)                         down(x)
#define cfs_down_interruptible(x)           down_interruptible(x)
#define cfs_down_trylock(x)                 down_trylock(x)

/*
 * mutex "implementation" (use Linux kernel's primitives)
 *
 * - DEFINE_MUTEX(name)
 * - mutex_init(x)
 * - mutex_lock(x)
 * - mutex_unlock(x)
 * - mutex_trylock(x)
 * - mutex_is_locked(x)
 * - mutex_destroy(x)
 */
typedef struct mutex cfs_mutex_t;

#define CFS_DEFINE_MUTEX(name)             DEFINE_MUTEX(name)

#define cfs_mutex_init(x)                   mutex_init(x)
#define cfs_mutex_lock(x)                   mutex_lock(x)
#define cfs_mutex_unlock(x)                 mutex_unlock(x)
#define cfs_mutex_lock_interruptible(x)     mutex_lock_interruptible(x)
#define cfs_mutex_trylock(x)                mutex_trylock(x)
#define cfs_mutex_is_locked(x)              mutex_is_locked(x)
#define cfs_mutex_destroy(x)                mutex_destroy(x)

#ifndef lockdep_set_class

/**************************************************************************
 *
 * Lockdep "implementation". Also see liblustre.h
 *
 **************************************************************************/

typedef struct cfs_lock_class_key {
        ;
} cfs_lock_class_key_t;

#define cfs_lockdep_set_class(lock, key) \
        do { (void)sizeof (lock);(void)sizeof (key); } while (0)
/* This has to be a macro, so that `subclass' can be undefined in kernels that
 * do not support lockdep. */


static inline void cfs_lockdep_off(void)
{
}

static inline void cfs_lockdep_on(void)
{
}
#else
typedef struct lock_class_key cfs_lock_class_key_t;

#define cfs_lockdep_set_class(lock, key) lockdep_set_class(lock, key)
#define cfs_lockdep_off()                lockdep_off()
#define cfs_lockdep_on()                 lockdep_on()
#endif /* lockdep_set_class */

#ifndef CONFIG_DEBUG_LOCK_ALLOC
#ifndef mutex_lock_nested
#define cfs_mutex_lock_nested(mutex, subclass) mutex_lock(mutex)
#else
#define cfs_mutex_lock_nested(mutex, subclass) \
        mutex_lock_nested(mutex, subclass)
#endif

#ifndef spin_lock_nested
#define cfs_spin_lock_nested(lock, subclass) spin_lock(lock)
#else
#define cfs_spin_lock_nested(lock, subclass) spin_lock_nested(lock, subclass)
#endif

#ifndef down_read_nested
#define cfs_down_read_nested(lock, subclass) down_read(lock)
#else
#define cfs_down_read_nested(lock, subclass) down_read_nested(lock, subclass)
#endif

#ifndef down_write_nested
#define cfs_down_write_nested(lock, subclass) down_write(lock)
#else
#define cfs_down_write_nested(lock, subclass) down_write_nested(lock, subclass)
#endif
#else /* CONFIG_DEBUG_LOCK_ALLOC is defined */
#define cfs_mutex_lock_nested(mutex, subclass) \
        mutex_lock_nested(mutex, subclass)
#define cfs_spin_lock_nested(lock, subclass) spin_lock_nested(lock, subclass)
#define cfs_down_read_nested(lock, subclass) down_read_nested(lock, subclass)
#define cfs_down_write_nested(lock, subclass) down_write_nested(lock, subclass)
#endif /* CONFIG_DEBUG_LOCK_ALLOC */


#endif /* __LIBCFS_LINUX_CFS_LOCK_H__ */
