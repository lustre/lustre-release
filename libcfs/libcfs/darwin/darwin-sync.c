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
 * libcfs/libcfs/darwin/darwin-sync.c
 *
 * XNU synchronization primitives.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

/*
 * This file contains very simplistic implementations of (saner) API for
 * basic synchronization primitives:
 *
 *     - spin-lock          (kspin)
 *
 *     - semaphore          (ksem)
 *
 *     - mutex              (kmut)
 *
 *     - condition variable (kcond)
 *
 *     - wait-queue         (ksleep_chan and ksleep_link)
 *
 *     - timer              (ktimer)
 *
 * A lot can be optimized here.
 */

#define DEBUG_SUBSYSTEM S_LNET

#ifdef __DARWIN8__
# include <kern/locks.h>
#else
# include <mach/mach_types.h>
# include <sys/types.h>
# include <kern/simple_lock.h>
#endif

#include <libcfs/libcfs.h>

#define SLASSERT(e) ON_SYNC_DEBUG(LASSERT(e))

#ifdef HAVE_GET_PREEMPTION_LEVEL
extern int get_preemption_level(void);
#else
#define get_preemption_level() (0)
#endif

#if SMP
#ifdef __DARWIN8__

static lck_grp_t       *cfs_lock_grp = NULL;
#warning "Verify definition of lck_spin_t hasn't been changed while building!"

/* hw_lock_* are not exported by Darwin8 */
static inline void xnu_spin_init(xnu_spin_t *s)
{
        SLASSERT(cfs_lock_grp != NULL);
        //*s = lck_spin_alloc_init(cfs_lock_grp, LCK_ATTR_NULL);
        lck_spin_init((lck_spin_t *)s, cfs_lock_grp, LCK_ATTR_NULL);
}

static inline void xnu_spin_done(xnu_spin_t *s)
{
        SLASSERT(cfs_lock_grp != NULL);
        //lck_spin_free(*s, cfs_lock_grp);
        //*s = NULL;
        lck_spin_destroy((lck_spin_t *)s, cfs_lock_grp);
}

#define xnu_spin_lock(s)        lck_spin_lock((lck_spin_t *)(s))
#define xnu_spin_unlock(s)      lck_spin_unlock((lck_spin_t *)(s))

#warning "Darwin8 does not export lck_spin_try_lock"
#define xnu_spin_try(s)         (1)

#else /* DARWIN8 */
extern void			hw_lock_init(hw_lock_t);
extern void			hw_lock_lock(hw_lock_t);
extern void			hw_lock_unlock(hw_lock_t);
extern unsigned int		hw_lock_to(hw_lock_t, unsigned int);
extern unsigned int		hw_lock_try(hw_lock_t);
extern unsigned int		hw_lock_held(hw_lock_t);

#define xnu_spin_init(s)        hw_lock_init(s)
#define xnu_spin_done(s)        do {} while (0)
#define xnu_spin_lock(s)        hw_lock_lock(s)
#define xnu_spin_unlock(s)      hw_lock_unlock(s)
#define xnu_spin_try(s)         hw_lock_try(s)
#endif /* DARWIN8 */

#else /* SMP */
#define xnu_spin_init(s)        do {} while (0)
#define xnu_spin_done(s)        do {} while (0)
#define xnu_spin_lock(s)        do {} while (0)
#define xnu_spin_unlock(s)      do {} while (0)
#define xnu_spin_try(s)         (1)
#endif /* SMP */

/*
 * Warning: low level libcfs debugging code (libcfs_debug_msg(), for
 * example), uses spin-locks, so debugging output here may lead to nasty
 * surprises.
 *
 * In uniprocessor version of spin-lock. Only checks.
 */

void kspin_init(struct kspin *spin)
{
	SLASSERT(spin != NULL);
	xnu_spin_init(&spin->lock);
	ON_SYNC_DEBUG(spin->magic = KSPIN_MAGIC);
	ON_SYNC_DEBUG(spin->owner = NULL);
}

void kspin_done(struct kspin *spin)
{
	SLASSERT(spin != NULL);
	SLASSERT(spin->magic == KSPIN_MAGIC);
	SLASSERT(spin->owner == NULL);
        xnu_spin_done(&spin->lock);
}

void kspin_lock(struct kspin *spin)
{
	SLASSERT(spin != NULL);
	SLASSERT(spin->magic == KSPIN_MAGIC);
	SLASSERT(spin->owner != current_thread());

	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	xnu_spin_lock(&spin->lock);
	SLASSERT(spin->owner == NULL);
	ON_SYNC_DEBUG(spin->owner = current_thread());
}

void kspin_unlock(struct kspin *spin)
{
	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	SLASSERT(spin != NULL);
	SLASSERT(spin->magic == KSPIN_MAGIC);
	SLASSERT(spin->owner == current_thread());
	ON_SYNC_DEBUG(spin->owner = NULL);
	xnu_spin_unlock(&spin->lock);
}

int  kspin_trylock(struct kspin *spin)
{
	SLASSERT(spin != NULL);
	SLASSERT(spin->magic == KSPIN_MAGIC);

	if (xnu_spin_try(&spin->lock)) {
		SLASSERT(spin->owner == NULL);
		ON_SYNC_DEBUG(spin->owner = current_thread());
		return 1;
	} else
		return 0;
}

#if XNU_SYNC_DEBUG
int kspin_islocked(struct kspin *spin)
{
	SLASSERT(spin != NULL);
	SLASSERT(spin->magic == KSPIN_MAGIC);
	return spin->owner == current_thread();
}

int kspin_isnotlocked(struct kspin *spin)
{
	SLASSERT(spin != NULL);
	SLASSERT(spin->magic == KSPIN_MAGIC);
	return spin->owner != current_thread();
}
#endif

/*
 * read/write spin-lock
 */
void krw_spin_init(struct krw_spin *rwspin)
{
	SLASSERT(rwspin != NULL);

	kspin_init(&rwspin->guard);
	rwspin->count = 0;
	ON_SYNC_DEBUG(rwspin->magic = KRW_SPIN_MAGIC);
}

void krw_spin_done(struct krw_spin *rwspin)
{
	SLASSERT(rwspin != NULL);
	SLASSERT(rwspin->magic == KRW_SPIN_MAGIC);
	SLASSERT(rwspin->count == 0);
	kspin_done(&rwspin->guard);
}

void krw_spin_down_r(struct krw_spin *rwspin)
{
        int i;
	SLASSERT(rwspin != NULL);
	SLASSERT(rwspin->magic == KRW_SPIN_MAGIC);

	kspin_lock(&rwspin->guard);
        while(rwspin->count < 0) {
                i = -1;
	        kspin_unlock(&rwspin->guard);
                while (--i != 0 && rwspin->count < 0)
                        continue;
                kspin_lock(&rwspin->guard);
        }
	++ rwspin->count;
	kspin_unlock(&rwspin->guard);
}

void krw_spin_down_w(struct krw_spin *rwspin)
{
        int i;
	SLASSERT(rwspin != NULL);
	SLASSERT(rwspin->magic == KRW_SPIN_MAGIC);

	kspin_lock(&rwspin->guard);
        while (rwspin->count != 0) {
                i = -1;
	        kspin_unlock(&rwspin->guard);
                while (--i != 0 && rwspin->count != 0)
                        continue;
	        kspin_lock(&rwspin->guard);
        }
	rwspin->count = -1;
	kspin_unlock(&rwspin->guard);
}

void krw_spin_up_r(struct krw_spin *rwspin)
{
	SLASSERT(rwspin != NULL);
	SLASSERT(rwspin->magic == KRW_SPIN_MAGIC);
	SLASSERT(rwspin->count > 0);

	kspin_lock(&rwspin->guard);
	-- rwspin->count;
	kspin_unlock(&rwspin->guard);
}

void krw_spin_up_w(struct krw_spin *rwspin)
{
	SLASSERT(rwspin != NULL);
	SLASSERT(rwspin->magic == KRW_SPIN_MAGIC);
	SLASSERT(rwspin->count == -1);

	kspin_lock(&rwspin->guard);
	rwspin->count = 0;
	kspin_unlock(&rwspin->guard);
}

/*
 * semaphore 
 */
#ifdef __DARWIN8__

#define xnu_waitq_init(q, a)            do {} while (0)
#define xnu_waitq_done(q)               do {} while (0)
#define xnu_waitq_wakeup_one(q, e, s)   ({wakeup_one((void *)(e)); KERN_SUCCESS;})
#define xnu_waitq_wakeup_all(q, e, s)   ({wakeup((void *)(e)); KERN_SUCCESS;})
#define xnu_waitq_assert_wait(q, e, s)  assert_wait((e), s)

#else /* DARWIN8 */

#define xnu_waitq_init(q, a)            wait_queue_init((q), a)
#define xnu_waitq_done(q)               do {} while (0)
#define xnu_waitq_wakeup_one(q, e, s)   wait_queue_wakeup_one((q), (event_t)(e), s)
#define xnu_waitq_wakeup_all(q, e, s)   wait_queue_wakeup_all((q), (event_t)(e), s)
#define xnu_waitq_assert_wait(q, e, s)  wait_queue_assert_wait((q), (event_t)(e), s)

#endif /* DARWIN8 */
void ksem_init(struct ksem *sem, int value)
{
	SLASSERT(sem != NULL);
	kspin_init(&sem->guard);
	xnu_waitq_init(&sem->q, SYNC_POLICY_FIFO);
	sem->value = value;
	ON_SYNC_DEBUG(sem->magic = KSEM_MAGIC);
}

void ksem_done(struct ksem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KSEM_MAGIC);
	/*
	 * XXX nikita: cannot check that &sem->q is empty because
	 * wait_queue_empty() is Apple private API.
	 */
	kspin_done(&sem->guard);
}

int ksem_up(struct ksem *sem, int value)
{
	int result;

	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KSEM_MAGIC);
	SLASSERT(value >= 0);

	kspin_lock(&sem->guard);
	sem->value += value;
	if (sem->value == 0)
		result = xnu_waitq_wakeup_one(&sem->q, sem,
					      THREAD_AWAKENED);
	else
		result = xnu_waitq_wakeup_all(&sem->q, sem,
					      THREAD_AWAKENED);
	kspin_unlock(&sem->guard);
	SLASSERT(result == KERN_SUCCESS || result == KERN_NOT_WAITING);
	return (result == KERN_SUCCESS) ? 0 : 1;
}

void ksem_down(struct ksem *sem, int value)
{
	int result;

	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KSEM_MAGIC);
	SLASSERT(value >= 0);
	SLASSERT(get_preemption_level() == 0);

	kspin_lock(&sem->guard);
	while (sem->value < value) {
		result = xnu_waitq_assert_wait(&sem->q, sem,
					       THREAD_UNINT);
		SLASSERT(result == THREAD_AWAKENED || result == THREAD_WAITING);
		kspin_unlock(&sem->guard);
		if (result == THREAD_WAITING)
			thread_block(THREAD_CONTINUE_NULL);
		kspin_lock(&sem->guard);
	}
	sem->value -= value;
	kspin_unlock(&sem->guard);
}

int ksem_trydown(struct ksem *sem, int value)
{
	int result;

	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KSEM_MAGIC);
	SLASSERT(value >= 0);

	kspin_lock(&sem->guard);
	if (sem->value >= value) {
		sem->value -= value;
		result = 0;
	} else
		result = -EBUSY;
	kspin_unlock(&sem->guard);
	return result;
}

void kmut_init(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	ksem_init(&mut->s, 1);
	ON_SYNC_DEBUG(mut->magic = KMUT_MAGIC);
	ON_SYNC_DEBUG(mut->owner = NULL);
}

void kmut_done(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	SLASSERT(mut->magic == KMUT_MAGIC);
	SLASSERT(mut->owner == NULL);
	ksem_done(&mut->s);
}

void kmut_lock(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	SLASSERT(mut->magic == KMUT_MAGIC);
	SLASSERT(mut->owner != current_thread());
	SLASSERT(get_preemption_level() == 0);

	ksem_down(&mut->s, 1);
	ON_SYNC_DEBUG(mut->owner = current_thread());
}

void kmut_unlock(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	SLASSERT(mut->magic == KMUT_MAGIC);
	SLASSERT(mut->owner == current_thread());

	ON_SYNC_DEBUG(mut->owner = NULL);
	ksem_up(&mut->s, 1);
}

int kmut_trylock(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	SLASSERT(mut->magic == KMUT_MAGIC);
	return ksem_trydown(&mut->s, 1);
}

#if XNU_SYNC_DEBUG
int kmut_islocked(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	SLASSERT(mut->magic == KMUT_MAGIC);
	return mut->owner == current_thread();
}

int kmut_isnotlocked(struct kmut *mut)
{
	SLASSERT(mut != NULL);
	SLASSERT(mut->magic == KMUT_MAGIC);
	return mut->owner != current_thread();
}
#endif


void kcond_init(struct kcond *cond)
{
	SLASSERT(cond != NULL);

	kspin_init(&cond->guard);
	cond->waiters = NULL;
	ON_SYNC_DEBUG(cond->magic = KCOND_MAGIC);
}

void kcond_done(struct kcond *cond)
{
	SLASSERT(cond != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);
	SLASSERT(cond->waiters == NULL);
	kspin_done(&cond->guard);
}

void kcond_wait(struct kcond *cond, struct kspin *lock)
{
	struct kcond_link link;

	SLASSERT(cond != NULL);
	SLASSERT(lock != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);
	SLASSERT(kspin_islocked(lock));

	ksem_init(&link.sem, 0);
	kspin_lock(&cond->guard);
	link.next = cond->waiters;
	cond->waiters = &link;
	kspin_unlock(&cond->guard);
	kspin_unlock(lock);

	ksem_down(&link.sem, 1);

	kspin_lock(&cond->guard);
	kspin_unlock(&cond->guard);
	kspin_lock(lock);
}

void kcond_wait_guard(struct kcond *cond)
{
	struct kcond_link link;

	SLASSERT(cond != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);
	SLASSERT(kspin_islocked(&cond->guard));

	ksem_init(&link.sem, 0);
	link.next = cond->waiters;
	cond->waiters = &link;
	kspin_unlock(&cond->guard);

	ksem_down(&link.sem, 1);

	kspin_lock(&cond->guard);
}

void kcond_signal_guard(struct kcond *cond)
{
	struct kcond_link *link;

	SLASSERT(cond != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);
	SLASSERT(kspin_islocked(&cond->guard));

	link = cond->waiters;
	if (link != NULL) {
		cond->waiters = link->next;
		ksem_up(&link->sem, 1);
	}
}

void kcond_signal(struct kcond *cond)
{
	SLASSERT(cond != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);

	kspin_lock(&cond->guard);
	kcond_signal_guard(cond);
	kspin_unlock(&cond->guard);
}

void kcond_broadcast_guard(struct kcond *cond)
{
	struct kcond_link *link;

	SLASSERT(cond != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);
	SLASSERT(kspin_islocked(&cond->guard));

	for (link = cond->waiters; link != NULL; link = link->next)
		ksem_up(&link->sem, 1);
	cond->waiters = NULL;
}

void kcond_broadcast(struct kcond *cond)
{
	SLASSERT(cond != NULL);
	SLASSERT(cond->magic == KCOND_MAGIC);

	kspin_lock(&cond->guard);
	kcond_broadcast_guard(cond);
	kspin_unlock(&cond->guard);
}

void krw_sem_init(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);

	kcond_init(&sem->cond);
	sem->count = 0;
	ON_SYNC_DEBUG(sem->magic = KRW_MAGIC);
}

void krw_sem_done(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);
	SLASSERT(sem->count == 0);
	kcond_done(&sem->cond);
}

void krw_sem_down_r(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);
	SLASSERT(get_preemption_level() == 0);

	kspin_lock(&sem->cond.guard);
	while (sem->count < 0)
		kcond_wait_guard(&sem->cond);
	++ sem->count;
	kspin_unlock(&sem->cond.guard);
}

int krw_sem_down_r_try(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);

	kspin_lock(&sem->cond.guard);
	if (sem->count < 0) {
	        kspin_unlock(&sem->cond.guard);
                return -EBUSY;
        }
	++ sem->count;
	kspin_unlock(&sem->cond.guard);
        return 0;
}

void krw_sem_down_w(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);
	SLASSERT(get_preemption_level() == 0);

	kspin_lock(&sem->cond.guard);
	while (sem->count != 0)
		kcond_wait_guard(&sem->cond);
	sem->count = -1;
	kspin_unlock(&sem->cond.guard);
}

int krw_sem_down_w_try(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);

	kspin_lock(&sem->cond.guard);
	if (sem->count != 0) {
	        kspin_unlock(&sem->cond.guard);
                return -EBUSY;
        }
	sem->count = -1;
	kspin_unlock(&sem->cond.guard);
        return 0;
}

void krw_sem_up_r(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);
	SLASSERT(sem->count > 0);

	kspin_lock(&sem->cond.guard);
	-- sem->count;
	if (sem->count == 0)
		kcond_broadcast_guard(&sem->cond);
	kspin_unlock(&sem->cond.guard);
}

void krw_sem_up_w(struct krw_sem *sem)
{
	SLASSERT(sem != NULL);
	SLASSERT(sem->magic == KRW_MAGIC);
	SLASSERT(sem->count == -1);

	kspin_lock(&sem->cond.guard);
	sem->count = 0;
	kspin_unlock(&sem->cond.guard);
	kcond_broadcast(&sem->cond);
}

void ksleep_chan_init(struct ksleep_chan *chan)
{
	SLASSERT(chan != NULL);

	kspin_init(&chan->guard);
	CFS_INIT_LIST_HEAD(&chan->waiters);
	ON_SYNC_DEBUG(chan->magic = KSLEEP_CHAN_MAGIC);
}

void ksleep_chan_done(struct ksleep_chan *chan)
{
	SLASSERT(chan != NULL);
	SLASSERT(chan->magic == KSLEEP_CHAN_MAGIC);
	SLASSERT(list_empty(&chan->waiters));
	kspin_done(&chan->guard);
}

void ksleep_link_init(struct ksleep_link *link)
{
	SLASSERT(link != NULL);

	CFS_INIT_LIST_HEAD(&link->linkage);
	link->flags = 0;
	link->event = current_thread();
	link->hits  = 0;
	link->forward = NULL;
	ON_SYNC_DEBUG(link->magic = KSLEEP_LINK_MAGIC);
}

void ksleep_link_done(struct ksleep_link *link)
{
	SLASSERT(link != NULL);
	SLASSERT(link->magic == KSLEEP_LINK_MAGIC);
	SLASSERT(list_empty(&link->linkage));
}

void ksleep_add(struct ksleep_chan *chan, struct ksleep_link *link)
{
	SLASSERT(chan != NULL);
	SLASSERT(link != NULL);
	SLASSERT(chan->magic == KSLEEP_CHAN_MAGIC);
	SLASSERT(link->magic == KSLEEP_LINK_MAGIC);
	SLASSERT(list_empty(&link->linkage));

	kspin_lock(&chan->guard);
        if (link->flags & KSLEEP_EXCLUSIVE)
                list_add_tail(&link->linkage, &chan->waiters);
        else
	        list_add(&link->linkage, &chan->waiters);
	kspin_unlock(&chan->guard);
}

void ksleep_del(struct ksleep_chan *chan, struct ksleep_link *link)
{
	SLASSERT(chan != NULL);
	SLASSERT(link != NULL);
	SLASSERT(chan->magic == KSLEEP_CHAN_MAGIC);
	SLASSERT(link->magic == KSLEEP_LINK_MAGIC);

	kspin_lock(&chan->guard);
	list_del_init(&link->linkage);
	kspin_unlock(&chan->guard);
}

static int has_hits(struct ksleep_chan *chan, event_t event)
{
	struct ksleep_link *scan;

	SLASSERT(kspin_islocked(&chan->guard));
	list_for_each_entry(scan, &chan->waiters, linkage) {
		if (scan->event == event && scan->hits > 0) {
			/* consume hit */
			-- scan->hits;
			return 1;
		}
	}
	return 0;
}

static void add_hit(struct ksleep_chan *chan, event_t event)
{
	struct ksleep_link *scan;

	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	SLASSERT(kspin_islocked(&chan->guard));
	list_for_each_entry(scan, &chan->waiters, linkage) {
		if (scan->event == event) {
			++ scan->hits;
			break;
		}
	}
}

void ksleep_wait(struct ksleep_chan *chan, cfs_task_state_t state)
{
	event_t event;
	int     result;

	ENTRY;

	SLASSERT(chan != NULL);
	SLASSERT(chan->magic == KSLEEP_CHAN_MAGIC);
	SLASSERT(get_preemption_level() == 0);

	event = current_thread();
	kspin_lock(&chan->guard);
	if (!has_hits(chan, event)) {
		result = assert_wait(event, state);
		kspin_unlock(&chan->guard);
		SLASSERT(result == THREAD_AWAKENED || result == THREAD_WAITING);
		if (result == THREAD_WAITING)
			thread_block(THREAD_CONTINUE_NULL);
	} else
		kspin_unlock(&chan->guard);
	EXIT;
}

/*
 * Sleep on @chan for no longer than @timeout nano-seconds. Return remaining
 * sleep time (non-zero only if thread was waken by a signal (not currently
 * implemented), or waitq was already in the "signalled" state).
 */
int64_t ksleep_timedwait(struct ksleep_chan *chan, 
                         cfs_task_state_t state,
                         __u64 timeout)
{
	event_t event;

	ENTRY;

	SLASSERT(chan != NULL);
	SLASSERT(chan->magic == KSLEEP_CHAN_MAGIC);
	SLASSERT(get_preemption_level() == 0);

	event = current_thread();
	kspin_lock(&chan->guard);
	if (!has_hits(chan, event)) {
                int      result;
                __u64 expire;
		result = assert_wait(event, state);
		if (timeout > 0) {
			/*
			 * arm a timer. thread_set_timer()'s first argument is
			 * uint32_t, so we have to cook deadline ourselves.
			 */
			nanoseconds_to_absolutetime(timeout, &expire);
                        clock_absolutetime_interval_to_deadline(expire, &expire);
			thread_set_timer_deadline(expire);
		}
		kspin_unlock(&chan->guard);
		SLASSERT(result == THREAD_AWAKENED || result == THREAD_WAITING);
		if (result == THREAD_WAITING)
			result = thread_block(THREAD_CONTINUE_NULL);
		thread_cancel_timer();

		if (result == THREAD_TIMED_OUT)
                        timeout = 0;
		else {
                        __u64 now;
                        clock_get_uptime(&now);
                        if (expire > now)
			        absolutetime_to_nanoseconds(expire - now, &timeout);
                        else
                                timeout = 0;
		}
	} else  {
                /* just return timeout, because I've got event and don't need to wait */
		kspin_unlock(&chan->guard);
        }

        RETURN(timeout);
}

/*
 * wake up single exclusive waiter (plus some arbitrary number of *
 * non-exclusive)
 */
void ksleep_wake(struct ksleep_chan *chan)
{
	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */
	ksleep_wake_nr(chan, 1);
}

/*
 * wake up all waiters on @chan
 */
void ksleep_wake_all(struct ksleep_chan *chan)
{
	ENTRY;
	ksleep_wake_nr(chan, 0);
	EXIT;
}

/*
 * wakeup no more than @nr exclusive waiters from @chan, plus some arbitrary
 * number of non-exclusive. If @nr is 0, wake up all waiters.
 */
void ksleep_wake_nr(struct ksleep_chan *chan, int nr)
{
	struct ksleep_link *scan;
	int result;

	/*
	 * XXX nikita: do NOT call libcfs_debug_msg() (CDEBUG/ENTRY/EXIT)
	 * from here: this will lead to infinite recursion.
	 */

	SLASSERT(chan != NULL);
	SLASSERT(chan->magic == KSLEEP_CHAN_MAGIC);

	kspin_lock(&chan->guard);
	list_for_each_entry(scan, &chan->waiters, linkage) {
		struct ksleep_chan *forward;

		forward = scan->forward;
		if (forward != NULL)
			kspin_lock(&forward->guard);
		result = thread_wakeup(scan->event);
		SLASSERT(result == KERN_SUCCESS || result == KERN_NOT_WAITING);
		if (result == KERN_NOT_WAITING) {
			++ scan->hits;
			if (forward != NULL)
				add_hit(forward, scan->event);
		}
		if (forward != NULL)
			kspin_unlock(&forward->guard);
		if ((scan->flags & KSLEEP_EXCLUSIVE) && --nr == 0)
			break;
	}
	kspin_unlock(&chan->guard);
}

void ktimer_init(struct ktimer *t, void (*func)(void *), void *arg)
{
	SLASSERT(t != NULL);
	SLASSERT(func != NULL);

	kspin_init(&t->guard);
	t->func = func;
	t->arg  = arg;
	ON_SYNC_DEBUG(t->magic = KTIMER_MAGIC);
}

void ktimer_done(struct ktimer *t)
{
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);
	kspin_done(&t->guard);
	ON_SYNC_DEBUG(t->magic = 0);
}

static void ktimer_actor(void *arg0, void *arg1)
{
	struct ktimer *t;
	int            armed;

	t = arg0;
	/*
	 * this assumes that ktimer's are never freed.
	 */
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);

	/*
	 * call actual timer function
	 */
	kspin_lock(&t->guard);
	armed = t->armed;
	t->armed = 0;
	kspin_unlock(&t->guard);

	if (armed)
		t->func(t->arg);
}

extern boolean_t thread_call_func_cancel(thread_call_func_t, thread_call_param_t, boolean_t);
extern void thread_call_func_delayed(thread_call_func_t, thread_call_param_t, __u64);

static void ktimer_disarm_locked(struct ktimer *t)
{
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);

	thread_call_func_cancel(ktimer_actor, t, FALSE);
}

/*
 * Received deadline is nanoseconds, but time checked by 
 * thread_call is absolute time (The abstime unit is equal to 
 * the length of one bus cycle, so the duration is dependent 
 * on the bus speed of the computer), so we need to convert
 * nanotime to abstime by nanoseconds_to_absolutetime().
 *
 * Refer to _delayed_call_timer(...)
 *
 * if thread_call_func_delayed is not exported in the future,
 * we can use timeout() or bsd_timeout() to replace it.
 */
void ktimer_arm(struct ktimer *t, u_int64_t deadline)
{
        cfs_time_t    abstime;
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);

	kspin_lock(&t->guard);
	ktimer_disarm_locked(t);
	t->armed = 1;
        nanoseconds_to_absolutetime(deadline, &abstime);
	thread_call_func_delayed(ktimer_actor, t, deadline);
	kspin_unlock(&t->guard);
}

void ktimer_disarm(struct ktimer *t)
{
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);

	kspin_lock(&t->guard);
	t->armed = 0;
	ktimer_disarm_locked(t);
	kspin_unlock(&t->guard);
}

int ktimer_is_armed(struct ktimer *t)
{
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);

	/*
	 * no locking---result is only a hint anyway.
	 */
	return t->armed;
}

u_int64_t ktimer_deadline(struct ktimer *t)
{
	SLASSERT(t != NULL);
	SLASSERT(t->magic == KTIMER_MAGIC);

	return t->deadline;
}

void cfs_sync_init(void) 
{
#ifdef __DARWIN8__
        /* Initialize lock group */
        cfs_lock_grp = lck_grp_alloc_init("libcfs sync", LCK_GRP_ATTR_NULL);
#endif
}

void cfs_sync_fini(void)
{
#ifdef __DARWIN8__
        /* 
         * XXX Liang: destroy lock group. As we haven't called lock_done
         * for all locks, cfs_lock_grp may not be freed by kernel(reference 
         * count > 1).
         */
        lck_grp_free(cfs_lock_grp);
        cfs_lock_grp = NULL;
#endif
}
/*
 * Local variables:
 * c-indentation-style: "K&R"
 * c-basic-offset: 8
 * tab-width: 8
 * fill-column: 80
 * scroll-step: 1
 * End:
 */
