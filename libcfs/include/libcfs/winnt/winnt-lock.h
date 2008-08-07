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
 *  nt specific part ...
 */


/* atomic */

typedef struct { volatile int counter; } atomic_t;

#define ATOMIC_INIT(i)	{ i }

#define atomic_read(v)	((v)->counter)
#define atomic_set(v,i)		(((v)->counter) = (i))

void FASTCALL atomic_add(int i, atomic_t *v);
void FASTCALL atomic_sub(int i, atomic_t *v);

int FASTCALL atomic_sub_and_test(int i, atomic_t *v);

void FASTCALL atomic_inc(atomic_t *v);
void FASTCALL atomic_dec(atomic_t *v);

int FASTCALL atomic_dec_and_test(atomic_t *v);
int FASTCALL atomic_inc_and_test(atomic_t *v);


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
 * cfs_wait_event
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
cfs_wait_event(event_t * event, int64_t timeout)
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
 * IMPORTANT !!!!!!!!
 *
 * All locks' declaration are not guaranteed to be initialized,
 * Althought some of they are initialized in Linux. All locks
 * declared by CFS_DECL_* should be initialized explicitly.
 */


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

typedef struct spin_lock {

    KSPIN_LOCK lock;
    KIRQL      irql;

} spinlock_t;


#define CFS_DECL_SPIN(name)  spinlock_t name;
#define CFS_DECL_SPIN_EXTERN(name)  extern spinlock_t name;


static inline void spin_lock_init(spinlock_t *lock)
{
    KeInitializeSpinLock(&(lock->lock));
}


static inline void spin_lock(spinlock_t *lock)
{
    KeAcquireSpinLock(&(lock->lock), &(lock->irql));
}

static inline void spin_unlock(spinlock_t *lock)
{
    KIRQL       irql = lock->irql;
    KeReleaseSpinLock(&(lock->lock), irql);
}


#define spin_lock_irqsave(lock, flags)		do {(flags) = 0; spin_lock(lock);} while(0)
#define spin_unlock_irqrestore(lock, flags)	do {spin_unlock(lock);} while(0)


/* There's no  corresponding routine in windows kernel.
   We must realize a light one of our own.  But there's
   no way to identify the system is MP build or UP build
   on the runtime. We just uses a workaround for it. */

extern int MPSystem;

static int spin_trylock(spinlock_t *lock)
{
    KIRQL   Irql;
    int     rc = 0;

    ASSERT(lock != NULL);

    KeRaiseIrql(DISPATCH_LEVEL, &Irql);

    if (MPSystem) {
        if (0 == (ulong_ptr)lock->lock) {
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

/* synchronization between cpus: it will disable all DPCs
   kernel task scheduler on the CPU */
#define spin_lock_bh(x)		    spin_lock(x)
#define spin_unlock_bh(x)	    spin_unlock(x)
#define spin_lock_bh_init(x)	spin_lock_init(x)

/*
 * rw_semaphore (using ERESOURCE)
 */


typedef struct rw_semaphore {
    ERESOURCE   rwsem;
} rw_semaphore_t;


#define CFS_DECL_RWSEM(name) rw_semaphore_t name
#define CFS_DECL_RWSEM_EXTERN(name) extern rw_semaphore_t name


/*
 * init_rwsem
 *   To initialize the the rw_semaphore_t structure
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

static inline void init_rwsem(rw_semaphore_t *s)
{
	ExInitializeResourceLite(&s->rwsem);
}


/*
 * fini_rwsem
 *   To finilize/destroy the the rw_semaphore_t structure
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   For winnt system, we need this routine to delete the ERESOURCE.
 *   Just define it NULL for other systems.
 */

static inline void fini_rwsem(rw_semaphore_t *s)
{
    ExDeleteResourceLite(&s->rwsem);
}

/*
 * down_read
 *   To acquire read-lock of the rw_semahore
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
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


/*
 * down_read_trylock
 *   To acquire read-lock of the rw_semahore without blocking
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
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
 *   To acquire write-lock of the rw_semahore
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
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


/*
 * down_write_trylock
 *   To acquire write-lock of the rw_semahore without blocking
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
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
 *   To release read-lock of the rw_semahore
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

static inline void up_read(struct rw_semaphore *s)
{
    ExReleaseResourceForThreadLite(
            &(s->rwsem),
            ExGetCurrentResourceThread());
}


/*
 * up_write
 *   To release write-lock of the rw_semahore
 *
 * Arguments:
 *   rwsem:  pointer to the rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes: 
 *   N/A
 */

static inline void up_write(struct rw_semaphore *s)
{
    ExReleaseResourceForThreadLite(
                &(s->rwsem),
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
    spinlock_t guard;
    int        count;
} rwlock_t;

void rwlock_init(rwlock_t * rwlock);
void rwlock_fini(rwlock_t * rwlock);

void read_lock(rwlock_t * rwlock);
void read_unlock(rwlock_t * rwlock);
void write_lock(rwlock_t * rwlock);
void write_unlock(rwlock_t * rwlock);

#define write_lock_irqsave(l, f)        do {f = 0; write_lock(l);} while(0)
#define write_unlock_irqrestore(l, f)   do {write_unlock(l);} while(0)
#define read_lock_irqsave(l, f)	        do {f=0; read_lock(l);} while(0)
#define read_unlock_irqrestore(l, f)    do {read_unlock(l);} while(0)


/*
 * Semaphore
 *
 * - sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */

typedef struct semaphore {
	KSEMAPHORE sem;
} mutex_t;

static inline void sema_init(struct semaphore *s, int val)
{
	KeInitializeSemaphore(&s->sem, val, val);
}

static inline void __down(struct semaphore *s)
{
   KeWaitForSingleObject( &(s->sem), Executive,
                          KernelMode, FALSE, NULL );

}

static inline void __up(struct semaphore *s)
{
	KeReleaseSemaphore(&s->sem, 0, 1, FALSE);
}

/*
 * mutex_t:
 *
 * - init_mutex(x)
 * - init_mutex_locked(x)
 * - mutex_up(x)
 * - mutex_down(x)
 */


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

static inline void init_mutex(mutex_t *mutex)
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

static inline void mutex_down(mutex_t *mutex)
{
    __down(mutex);
}


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

static inline void mutex_up(mutex_t *mutex)
{
    __up(mutex);
}


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

static inline init_mutex_locked(mutex_t *mutex)
{
    init_mutex(mutex);
    mutex_down(mutex);
}

/*
 * completion
 *
 * - init_complition(c)
 * - complete(c)
 * - wait_for_completion(c)
 */

struct completion {
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
    cfs_wait_event(&(c->event), 0);
}

/* __KERNEL__ */
#else

#include "../user-lock.h"

/* __KERNEL__ */
#endif
#endif
