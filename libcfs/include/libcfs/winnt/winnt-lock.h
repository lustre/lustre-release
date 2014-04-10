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
 * libcfs/include/libcfs/winnt/winnt-lock.h
 *
 * Basic library routines.
 */

#ifndef __LIBCFS_WINNT_CFS_LOCK_H__
#define __LIBCFS_WINNT_CFS_LOCK_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#ifdef __KERNEL__


/*
 * IMPORTANT !!!!!!!!
 *
 * All locks' declaration are not guaranteed to be initialized,
 * Althought some of they are initialized in Linux. All locks
 * declared by CFS_DECL_* should be initialized explicitly.
 */

/*
 *  spinlock & event definitions
 */

typedef struct spin_lock spinlock_t;

/* atomic */

typedef struct { volatile int counter; } atomic_t;

#define ATOMIC_INIT(i)	{ i }

#define atomic_read(v)	((v)->counter)
#define atomic_set(v,i)	(((v)->counter) = (i))

void FASTCALL atomic_add(int i, atomic_t *v);
void FASTCALL atomic_sub(int i, atomic_t *v);

int FASTCALL atomic_sub_and_test(int i, atomic_t *v);

void FASTCALL atomic_inc(atomic_t *v);
void FASTCALL atomic_dec(atomic_t *v);

int FASTCALL atomic_dec_and_test(atomic_t *v);
int FASTCALL atomic_inc_and_test(atomic_t *v);

int FASTCALL atomic_add_return(int i, atomic_t *v);
int FASTCALL atomic_sub_return(int i, atomic_t *v);

#define atomic_inc_return(v)  atomic_add_return(1, v)
#define atomic_dec_return(v)  atomic_sub_return(1, v)

int FASTCALL atomic_dec_and_lock(atomic_t *v, spinlock_t *lock);

/* event */

typedef KEVENT          event_t;

/*
 * cfs_init_event
 *   To initialize the event object
 *
 * Arguments:
 *   event:  pointer to the event object
 *   type:   Non Zero: SynchronizationEvent
 *           Zero: NotificationEvent
 *   status: the initial stats of the event
 *           Non Zero: signaled
 *           Zero: un-signaled
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */
static inline void
cfs_init_event(event_t *event, int type, int status)
{
    KeInitializeEvent(
            event,
            (type) ? SynchronizationEvent: NotificationEvent,
            (status) ? TRUE : FALSE
            );
}

/*
 * cfs_wait_event_internal
 *   To wait on an event to syncrhonize the process
 *
 * Arguments:
 *   event:  pointer to the event object
 *   timeout: the timeout for waitting or 0 means infinite time.
 *
 * Return Value:
 *   Zero:   waiting timeouts
 *   Non Zero: event signaled ...
 *
 * Notes:
 *   N/A
 */

static inline int64_t
cfs_wait_event_internal(event_t * event, int64_t timeout)
{
    NTSTATUS        Status;
    LARGE_INTEGER   TimeOut;

    TimeOut.QuadPart = -1 * (10000000/HZ) * timeout;

    Status = KeWaitForSingleObject(
                event,
                Executive,
                KernelMode,
                FALSE,
                (timeout != 0) ? (&TimeOut) : (NULL)
                );

    if (Status == STATUS_TIMEOUT)  {
        return 0;
    }

    return TRUE; // signaled case
}

/*
 * cfs_wake_event
 *   To signal the event object
 *
 * Arguments:
 *   event:  pointer to the event object
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline int
cfs_wake_event(event_t * event)
{
    return (KeSetEvent(event, 0, FALSE) != 0);
}

/*
 * cfs_clear_event
 *   To clear/reset the status of the event object
 *
 * Arguments:
 *   event:  pointer to the event object
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void
cfs_clear_event(event_t * event)
{
    KeResetEvent(event);
}

/*
 * spin lock defintions / routines
 */

/*
 * Warning:
 *
 * for spinlock operations, try to grab nesting acquisition of
 * spinlock will cause dead-lock in MP system and current irql
 * overwritten for UP system. (UP system could allow nesting spin
 * acqisition, because it's not spin at all just raising the irql.)
 *
 */

struct spin_lock {
	KSPIN_LOCK	lock;
	KIRQL		irql;
};

#define CFS_DECL_SPIN(name)		spinlock_t name;
#define CFS_DECL_SPIN_EXTERN(name)	extern spinlock_t name;

#define DEFINE_SPINLOCK {0}

static inline void spin_lock_init(spinlock_t *lock)
{
	KeInitializeSpinLock(&(lock->lock));
}

static inline void spin_lock(spinlock_t *lock)
{
	KeAcquireSpinLock(&(lock->lock), &(lock->irql));
}

static inline void spin_lock_nested(spinlock_t *lock, unsigned subclass)
{
	KeAcquireSpinLock(&(lock->lock), &(lock->irql));
}

static inline void spin_unlock(spinlock_t *lock)
{
	KIRQL	irql = lock->irql;
	KeReleaseSpinLock(&(lock->lock), irql);
}


#define spin_lock_irqsave(lock, flags)  \
	do { (flags) = 0; spin_lock(lock); } while (0)

#define spin_unlock_irqrestore(lock, flags) \
	do { spin_unlock(lock); } while (0)


/* There's no  corresponding routine in windows kernel.
   We must realize a light one of our own.  But there's
   no way to identify the system is MP build or UP build
   on the runtime. We just uses a workaround for it. */

extern int libcfs_mp_system;

static int spin_trylock(spinlock_t *lock)
{
	KIRQL   Irql;
	int     rc = 0;

	ASSERT(lock != NULL);

	KeRaiseIrql(DISPATCH_LEVEL, &Irql);

	if (libcfs_mp_system) {
		if (0 == (ulong_ptr_t)lock->lock) {
#if _X86_
			__asm {
				mov  edx, dword ptr [ebp + 8]
				lock bts dword ptr[edx], 0
				jb   lock_failed
				mov  rc, TRUE
				lock_failed:
			}
#else
			KdBreakPoint();
#endif

		}
	} else {
		rc = TRUE;
	}

	if (rc) {
		lock->irql = Irql;
	} else {
		KeLowerIrql(Irql);
	}

	return rc;
}

static int assert_spin_locked(spinlock_t *lock)
{
#if _WIN32_WINNT >= 0x502
	/* KeTestSpinLock only avalilable on 2k3 server or later */
	return !KeTestSpinLock(&lock->lock);
#else
	return (int) (lock->lock);
#endif
}

/* synchronization between cpus: it will disable all DPCs
   kernel task scheduler on the CPU */
#define spin_lock_bh(x)		spin_lock(x)
#define spin_unlock_bh(x)	spin_unlock(x)
#define spin_lock_bh_init(x)	spin_lock_init(x)

/*
 * rw_semaphore (using ERESOURCE)
 */


struct rw_semaphore {
	ERESOURCE	rwsem;
};


#define DECLARE_RWSEM(name) struct rw_semaphore name
#define CFS_DECLARE_RWSEM_EXTERN(name) extern struct rw_semaphore name

/*
 * init_rwsem
 *   To initialize the the rw_semaphore structure
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void init_rwsem(struct rw_semaphore *s)
{
	ExInitializeResourceLite(&s->rwsem);
}
#define rwsem_init init_rwsem

/*
 * fini_rwsem
 *   To finilize/destroy the the rw_semaphore structure
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   For winnt system, we need this routine to delete the ERESOURCE.
 *   Just define it NULL for other systems.
 */

static inline void fini_rwsem(struct rw_semaphore *s)
{
	ExDeleteResourceLite(&s->rwsem);
}

/*
 * down_read
 *   To acquire read-lock of the rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the struct rw_semaphore
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void down_read(struct rw_semaphore *s)
{
	ExAcquireResourceSharedLite(&s->rwsem, TRUE);
}
#define down_read_nested down_read


/*
 * down_read_trylock
 *   To acquire read-lock of the rw_semaphore without blocking
 *
 * Arguments:
 *   rwsem:  pointer to the struct rw_semaphore
 *
 * Return Value:
 *   Zero: failed to acquire the read lock
 *   Non-Zero: succeeded to acquire the read lock
 *
 * Notes:
 *   This routine will return immediately without waiting.
 */

static inline int down_read_trylock(struct rw_semaphore *s)
{
	return ExAcquireResourceSharedLite(&s->rwsem, FALSE);
}


/*
 * down_write
 *   To acquire write-lock of the struct rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the struct rw_semaphore
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void down_write(struct rw_semaphore *s)
{
	ExAcquireResourceExclusiveLite(&(s->rwsem), TRUE);
}
#define down_write_nested down_write

/*
 * down_write_trylock
 *   To acquire write-lock of the rw_semaphore without blocking
 *
 * Arguments:
 *   rwsem:  pointer to the struct rw_semaphore
 *
 * Return Value:
 *   Zero: failed to acquire the write lock
 *   Non-Zero: succeeded to acquire the read lock
 *
 * Notes:
 *   This routine will return immediately without waiting.
 */

static inline int down_write_trylock(struct rw_semaphore *s)
{
	return ExAcquireResourceExclusiveLite(&(s->rwsem), FALSE);
}


/*
 * up_read
 *   To release read-lock of the rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the struct rw_semaphore
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void up_read(struct rw_semaphore *s)
{
	ExReleaseResourceForThreadLite(&(s->rwsem),
				       ExGetCurrentResourceThread());
}


/*
 * up_write
 *   To release write-lock of the rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the struct rw_semaphore
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void up_write(struct rw_semaphore *s)
{
	ExReleaseResourceForThreadLite(&(s->rwsem),
				       ExGetCurrentResourceThread());
}

/*
 * rwlock_t (using sempahore)
 *
 * - rwlock_init(x)
 * - read_lock(x)
 * - read_unlock(x)
 * - write_lock(x)
 * - write_unlock(x)
 */

typedef struct {
	spinlock_t	guard;
	int		count;
} rwlock_t;

void rwlock_init(rwlock_t *rwlock);
void cfs_rwlock_fini(rwlock_t *rwlock);

void read_lock(rwlock_t *rwlock);
void read_unlock(rwlock_t *rwlock);
void write_lock(rwlock_t *rwlock);
void write_unlock(rwlock_t *rwlock);

#define write_lock_irqsave(l, f)	do { f = 0; write_lock(l); } while (0)
#define write_unlock_irqrestore(l, f)	do { write_unlock(l); } while (0)
#define read_lock_irqsave(l, f)		do { f = 0; read_lock(l); } while (0)
#define read_unlock_irqrestore(l, f)	do { read_unlock(l); } while (0)

#define write_lock_bh		write_lock
#define write_unlock_bh	write_unlock

struct lock_class_key {
	int foo;
};

#define lockdep_set_class(lock, class) do {} while (0)

static inline void lockdep_off(void)
{
}

static inline void lockdep_on(void)
{
}

/*
 * Semaphore
 *
 * - sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */

struct semaphore {
	KSEMAPHORE sem;
};

static inline void sema_init(struct semaphore *s, int val)
{
	KeInitializeSemaphore(&s->sem, val, val);
}

static inline void __down(struct semaphore *s)
{
	KeWaitForSingleObject(&(s->sem), Executive, KernelMode, FALSE, NULL);

}
static inline void __up(struct semaphore *s)
{
	KeReleaseSemaphore(&s->sem, 0, 1, FALSE);
}

static inline int down_trylock(struct semaphore *s)
{
	LARGE_INTEGER  timeout = {0};
	NTSTATUS status = KeWaitForSingleObject(&(s->sem), Executive,
						KernelMode, FALSE, &timeout);

	if (status == STATUS_SUCCESS)
		return 0;

	return 1;
}

/*
 * mutex_t:
 *
 * - init_mutex(x)
 * - init_mutex_locked(x)
 * - mutex_unlock(x)
 * - mutex_lock(x)
 */

#define mutex semaphore

#define CFS_DECLARE_MUTEX(x) struct mutex x

/*
 * init_mutex
 *   To initialize a mutex_t structure
 *
 * Arguments:
 *   mutex:  pointer to the mutex_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */
#define mutex_init cfs_init_mutex
static inline void cfs_init_mutex(struct mutex *mutex)
{
	sema_init(mutex, 1);
}

/*
 * mutex_down
 *   To acquire the mutex lock
 *
 * Arguments:
 *   mutex:  pointer to the mutex_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_mutex_down(struct mutex *mutex)
{
	__down(mutex);
}

static inline int cfs_mutex_down_interruptible(struct mutex *mutex)
{
	__down(mutex);
	return 0;
}

#define mutex_lock(m)		cfs_mutex_down(m)
#define mutex_trylock(s)	down_trylock(s)
#define mutex_lock_nested(m)	cfs_mutex_down(m)
#define down(m)			cfs_mutex_down(m)
#define down_interruptible(m)	cfs_mutex_down_interruptible(m)

/*
 * mutex_up
 *   To release the mutex lock (acquired already)
 *
 * Arguments:
 *   mutex:  pointer to the mutex_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_mutex_up(struct mutex *mutex)
{
	__up(mutex);
}

#define mutex_unlock(m)		cfs_mutex_up(m)
#define up(m)			cfs_mutex_up(m)

/*
 * init_mutex_locked
 *   To initialize the mutex as acquired state
 *
 * Arguments:
 *   mutex:  pointer to the mutex_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_init_mutex_locked(struct mutex *mutex)
{
	cfs_init_mutex(mutex);
	cfs_mutex_down(mutex);
}

static inline void mutex_destroy(struct mutex *mutex)
{
}

/*
 * completion
 *
 * - init_complition(c)
 * - complete(c)
 * - wait_for_completion(c)
 */

struct completion{
	event_t  event;
};


/*
 * init_completion
 *   To initialize the completion object
 *
 * Arguments:
 *   c:  pointer to the completion structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void init_completion(struct completion *c)
{
	cfs_init_event(&(c->event), 1, FALSE);
}


/*
 * complete
 *   To complete/signal the completion object
 *
 * Arguments:
 *   c:  pointer to the completion structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void complete(struct completion *c)
{
	cfs_wake_event(&(c->event));
}

/*
 * wait_for_completion
 *   To wait on the completion object. If the event is signaled,
 *   this function will return to the call with the event un-singled.
 *
 * Arguments:
 *   c:  pointer to the completion structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void wait_for_completion(struct completion *c)
{
	cfs_wait_event_internal(&(c->event), 0);
}

static inline int wait_for_completion_interruptible(struct completion *c)
{
	cfs_wait_event_internal(&(c->event), 0);
	return 0;
}

#endif /* !__KERNEL__ */
#endif
