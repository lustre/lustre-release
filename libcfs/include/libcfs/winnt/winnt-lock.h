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

typedef struct cfs_spin_lock cfs_spinlock_t;

/* atomic */

typedef struct { volatile int counter; } cfs_atomic_t;

#define CFS_ATOMIC_INIT(i)	{ i }

#define cfs_atomic_read(v)	((v)->counter)
#define cfs_atomic_set(v,i)	(((v)->counter) = (i))

void FASTCALL cfs_atomic_add(int i, cfs_atomic_t *v);
void FASTCALL cfs_atomic_sub(int i, cfs_atomic_t *v);

int FASTCALL cfs_atomic_sub_and_test(int i, cfs_atomic_t *v);

void FASTCALL cfs_atomic_inc(cfs_atomic_t *v);
void FASTCALL cfs_atomic_dec(cfs_atomic_t *v);

int FASTCALL cfs_atomic_dec_and_test(cfs_atomic_t *v);
int FASTCALL cfs_atomic_inc_and_test(cfs_atomic_t *v);

int FASTCALL cfs_atomic_add_return(int i, cfs_atomic_t *v);
int FASTCALL cfs_atomic_sub_return(int i, cfs_atomic_t *v);

#define cfs_atomic_inc_return(v)  cfs_atomic_add_return(1, v)
#define cfs_atomic_dec_return(v)  cfs_atomic_sub_return(1, v)

int FASTCALL cfs_atomic_dec_and_lock(cfs_atomic_t *v, cfs_spinlock_t *lock);

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

    TimeOut.QuadPart = -1 * (10000000/CFS_HZ) * timeout;

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

struct cfs_spin_lock {
    KSPIN_LOCK lock;
    KIRQL      irql;
};

#define CFS_DECL_SPIN(name)  cfs_spinlock_t name;
#define CFS_DECL_SPIN_EXTERN(name)  extern cfs_spinlock_t name;

#define DEFINE_SPINLOCK {0}

static inline void cfs_spin_lock_init(cfs_spinlock_t *lock)
{
    KeInitializeSpinLock(&(lock->lock));
}

static inline void cfs_spin_lock(cfs_spinlock_t *lock)
{
    KeAcquireSpinLock(&(lock->lock), &(lock->irql));
}

static inline void cfs_spin_lock_nested(cfs_spinlock_t *lock, unsigned subclass)
{
    KeAcquireSpinLock(&(lock->lock), &(lock->irql));
}

static inline void cfs_spin_unlock(cfs_spinlock_t *lock)
{
    KIRQL       irql = lock->irql;
    KeReleaseSpinLock(&(lock->lock), irql);
}


#define cfs_spin_lock_irqsave(lock, flags)  \
do {(flags) = 0; cfs_spin_lock(lock);} while(0)

#define cfs_spin_unlock_irqrestore(lock, flags) \
do {cfs_spin_unlock(lock);} while(0)


/* There's no  corresponding routine in windows kernel.
   We must realize a light one of our own.  But there's
   no way to identify the system is MP build or UP build
   on the runtime. We just uses a workaround for it. */

extern int libcfs_mp_system;

static int cfs_spin_trylock(cfs_spinlock_t *lock)
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

static int cfs_spin_is_locked(cfs_spinlock_t *lock)
{
#if _WIN32_WINNT >= 0x502
    /* KeTestSpinLock only avalilable on 2k3 server or later */
    return (!KeTestSpinLock(&lock->lock));
#else
    return (int) (lock->lock);
#endif
}

/* synchronization between cpus: it will disable all DPCs
   kernel task scheduler on the CPU */
#define cfs_spin_lock_bh(x)		    cfs_spin_lock(x)
#define cfs_spin_unlock_bh(x)	    cfs_spin_unlock(x)
#define cfs_spin_lock_bh_init(x)	cfs_spin_lock_init(x)

/*
 * cfs_rw_semaphore (using ERESOURCE)
 */


typedef struct cfs_rw_semaphore {
    ERESOURCE   rwsem;
} cfs_rw_semaphore_t;


#define CFS_DECLARE_RWSEM(name) cfs_rw_semaphore_t name
#define CFS_DECLARE_RWSEM_EXTERN(name) extern cfs_rw_semaphore_t name

/*
 * cfs_init_rwsem
 *   To initialize the the cfs_rw_semaphore_t structure
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_init_rwsem(cfs_rw_semaphore_t *s)
{
	ExInitializeResourceLite(&s->rwsem);
}
#define rwsem_init cfs_init_rwsem

/*
 * cfs_fini_rwsem
 *   To finilize/destroy the the cfs_rw_semaphore_t structure
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   For winnt system, we need this routine to delete the ERESOURCE.
 *   Just define it NULL for other systems.
 */

static inline void cfs_fini_rwsem(cfs_rw_semaphore_t *s)
{
    ExDeleteResourceLite(&s->rwsem);
}

/*
 * cfs_down_read
 *   To acquire read-lock of the cfs_rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_down_read(cfs_rw_semaphore_t *s)
{
	ExAcquireResourceSharedLite(&s->rwsem, TRUE);
}
#define cfs_down_read_nested cfs_down_read


/*
 * cfs_down_read_trylock
 *   To acquire read-lock of the cfs_rw_semaphore without blocking
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   Zero: failed to acquire the read lock
 *   Non-Zero: succeeded to acquire the read lock
 *
 * Notes:
 *   This routine will return immediately without waiting.
 */

static inline int cfs_down_read_trylock(cfs_rw_semaphore_t *s)
{
	return ExAcquireResourceSharedLite(&s->rwsem, FALSE);
}


/*
 * cfs_down_write
 *   To acquire write-lock of the cfs_rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_down_write(cfs_rw_semaphore_t *s)
{
	ExAcquireResourceExclusiveLite(&(s->rwsem), TRUE);
}
#define cfs_down_write_nested cfs_down_write

/*
 * down_write_trylock
 *   To acquire write-lock of the cfs_rw_semaphore without blocking
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   Zero: failed to acquire the write lock
 *   Non-Zero: succeeded to acquire the read lock
 *
 * Notes:
 *   This routine will return immediately without waiting.
 */

static inline int cfs_down_write_trylock(cfs_rw_semaphore_t *s)
{
    return ExAcquireResourceExclusiveLite(&(s->rwsem), FALSE);
}


/*
 * cfs_up_read
 *   To release read-lock of the cfs_rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_up_read(cfs_rw_semaphore_t *s)
{
    ExReleaseResourceForThreadLite(
            &(s->rwsem),
            ExGetCurrentResourceThread());
}


/*
 * cfs_up_write
 *   To release write-lock of the cfs_rw_semaphore
 *
 * Arguments:
 *   rwsem:  pointer to the cfs_rw_semaphore_t structure
 *
 * Return Value:
 *   N/A
 *
 * Notes:
 *   N/A
 */

static inline void cfs_up_write(cfs_rw_semaphore_t *s)
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
    cfs_spinlock_t guard;
    int            count;
} cfs_rwlock_t;

void cfs_rwlock_init(cfs_rwlock_t * rwlock);
void cfs_rwlock_fini(cfs_rwlock_t * rwlock);

void cfs_read_lock(cfs_rwlock_t * rwlock);
void cfs_read_unlock(cfs_rwlock_t * rwlock);
void cfs_write_lock(cfs_rwlock_t * rwlock);
void cfs_write_unlock(cfs_rwlock_t * rwlock);

#define cfs_write_lock_irqsave(l, f)     do {f = 0; cfs_write_lock(l);} while(0)
#define cfs_write_unlock_irqrestore(l, f)   do {cfs_write_unlock(l);} while(0)
#define cfs_read_lock_irqsave(l, f	    do {f=0; cfs_read_lock(l);} while(0)
#define cfs_read_unlock_irqrestore(l, f)    do {cfs_read_unlock(l);} while(0)

#define cfs_write_lock_bh   cfs_write_lock
#define cfs_write_unlock_bh cfs_write_unlock

typedef struct cfs_lock_class_key {
        int foo;
} cfs_lock_class_key_t;

#define cfs_lockdep_set_class(lock, class) do {} while(0)

static inline void cfs_lockdep_off(void)
{
}

static inline void cfs_lockdep_on(void)
{
}

/*
 * Semaphore
 *
 * - sema_init(x, v)
 * - __down(x)
 * - __up(x)
 */

typedef struct cfs_semaphore {
	KSEMAPHORE sem;
} cfs_semaphore_t;

static inline void cfs_sema_init(cfs_semaphore_t *s, int val)
{
	KeInitializeSemaphore(&s->sem, val, val);
}

static inline void __down(cfs_semaphore_t *s)
{
   KeWaitForSingleObject( &(s->sem), Executive,
                          KernelMode, FALSE, NULL );

}
static inline void __up(cfs_semaphore_t *s)
{
	KeReleaseSemaphore(&s->sem, 0, 1, FALSE);
}

static inline int down_trylock(cfs_semaphore_t *s)
{
    LARGE_INTEGER  timeout = {0};
    NTSTATUS status =
        KeWaitForSingleObject( &(s->sem), Executive,
                               KernelMode, FALSE, &timeout);

    if (status == STATUS_SUCCESS) {
        return 0;
    }

    return 1;
}

/*
 * mutex_t:
 *
 * - init_mutex(x)
 * - init_mutex_locked(x)
 * - mutex_up(x)
 * - mutex_down(x)
 */

typedef struct cfs_semaphore cfs_mutex_t;

#define CFS_DECLARE_MUTEX(x) cfs_mutex_t x

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
#define cfs_mutex_init cfs_init_mutex
static inline void cfs_init_mutex(cfs_mutex_t *mutex)
{
    cfs_sema_init(mutex, 1);
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

static inline void cfs_mutex_down(cfs_mutex_t *mutex)
{
    __down(mutex);
}

static inline int cfs_mutex_down_interruptible(cfs_mutex_t *mutex)
{
    __down(mutex);
    return 0;
}

#define cfs_mutex_lock(m)         cfs_mutex_down(m)
#define cfs_mutex_trylock(s)      down_trylock(s)
#define cfs_mutex_lock_nested(m)  cfs_mutex_down(m)
#define cfs_down(m)               cfs_mutex_down(m)
#define cfs_down_interruptible(m) cfs_mutex_down_interruptible(m)

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

static inline void cfs_mutex_up(cfs_mutex_t *mutex)
{
    __up(mutex);
}

#define cfs_mutex_unlock(m) cfs_mutex_up(m)
#define cfs_up(m)           cfs_mutex_up(m)

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

static inline void cfs_init_mutex_locked(cfs_mutex_t *mutex)
{
    cfs_init_mutex(mutex);
    cfs_mutex_down(mutex);
}

static inline void cfs_mutex_destroy(cfs_mutex_t *mutex)
{
}

/*
 * completion
 *
 * - init_complition(c)
 * - complete(c)
 * - wait_for_completion(c)
 */

typedef struct {
	event_t  event;
} cfs_completion_t;


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

static inline void cfs_init_completion(cfs_completion_t *c)
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

static inline void cfs_complete(cfs_completion_t *c)
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

static inline void cfs_wait_for_completion(cfs_completion_t *c)
{
    cfs_wait_event_internal(&(c->event), 0);
}

static inline int cfs_wait_for_completion_interruptible(cfs_completion_t *c)
{
    cfs_wait_event_internal(&(c->event), 0);
    return 0;
}

#else  /* !__KERNEL__ */
#endif /* !__KERNEL__ */
#endif
