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
 * libcfs/include/libcfs/darwin/darwin-sync.h
 *
 * Prototypes of XNU synchronization primitives.
 */

#ifndef __LIBCFS_DARWIN_XNU_SYNC_H__
#define __LIBCFS_DARWIN_XNU_SYNC_H__

#ifndef __LIBCFS_LIBCFS_H__
#error Do not #include this file directly. #include <libcfs/libcfs.h> instead
#endif

#define XNU_SYNC_DEBUG (1)

#if XNU_SYNC_DEBUG
#define ON_SYNC_DEBUG(e) e
#else
#define ON_SYNC_DEBUG(e)
#endif

enum {
        /* "egrep -i '^(o?x)?[abcdeflo]*$' /usr/dict/words" is your friend */
	KMUT_MAGIC  = 0x0bac0cab, /* [a, [b, c]] = b (a, c) - c (a, b) */
	KSEM_MAGIC  = 0x1abe11ed,
	KCOND_MAGIC = 0xb01dface,
	KRW_MAGIC   = 0xdabb1edd,
	KSPIN_MAGIC = 0xca11ab1e,
        KRW_SPIN_MAGIC    = 0xbabeface,
	KSLEEP_CHAN_MAGIC = 0x0debac1e,
	KSLEEP_LINK_MAGIC = 0xacc01ade,
	KTIMER_MAGIC      = 0xbefadd1e
};

/* ------------------------- spin lock ------------------------- */

/*
 * XXX nikita: don't use NCPUS it's hardcoded to (1) in cpus.h
 */
#define SMP (1)

#include <libcfs/list.h>

#ifdef __DARWIN8__

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <kern/locks.h>

/*
 * hw_lock is not available in Darwin8 (hw_lock_* are not exported at all), 
 * so use lck_spin_t. we can hack out lck_spin_t easily, it's the only 
 * hacking in Darwin8.x. We did so because it'll take a lot of time to 
 * add lock_done for all locks, maybe it should be done in the future.
 * If lock_done for all locks were added, we can:
 *
 * typedef lck_spin_t      *xnu_spin_t;
 */
#if defined (__ppc__)
typedef struct {
        unsigned int    opaque[3];
} xnu_spin_t;
#elif defined (__i386__)
typedef struct {
        unsigned int    opaque[10];
} xnu_spin_t;
#endif

/* 
 * wait_queue is not available in Darwin8 (wait_queue_* are not exported), 
 * use assert_wait/wakeup/wake_one (wait_queue in kernel hash).
 */
typedef void * xnu_wait_queue_t;

/* DARWIN8 */
#else

#include <mach/mach_types.h>
#include <sys/types.h>
#include <kern/simple_lock.h>

typedef hw_lock_data_t          xnu_spin_t;
typedef struct wait_queue       xnu_wait_queue_t;

/* DARWIN8 */
#endif

struct kspin {
#if SMP
	xnu_spin_t      lock;
#endif
#if XNU_SYNC_DEBUG
	unsigned        magic;
	thread_t        owner;
#endif
};

void kspin_init(struct kspin *spin);
void kspin_done(struct kspin *spin);
void kspin_lock(struct kspin *spin);
void kspin_unlock(struct kspin *spin);
int  kspin_trylock(struct kspin *spin);

#if XNU_SYNC_DEBUG
/*
 * two functions below are for use in assertions
 */
/* true, iff spin-lock is locked by the current thread */
int kspin_islocked(struct kspin *spin);
/* true, iff spin-lock is not locked by the current thread */
int kspin_isnotlocked(struct kspin *spin);
#else
#define kspin_islocked(s) (1)
#define kspin_isnotlocked(s) (1)
#endif

/* ------------------------- rw spinlock ----------------------- */
struct krw_spin {
        struct kspin      guard;
        int               count;
#if XNU_SYNC_DEBUG
        unsigned          magic;
#endif
};

void krw_spin_init(struct krw_spin *sem);
void krw_spin_done(struct krw_spin *sem);
void krw_spin_down_r(struct krw_spin *sem);
void krw_spin_down_w(struct krw_spin *sem);
void krw_spin_up_r(struct krw_spin *sem);
void krw_spin_up_w(struct krw_spin *sem);

/* ------------------------- semaphore ------------------------- */

struct ksem {
        struct kspin      guard;
        xnu_wait_queue_t  q;
        int               value;
#if XNU_SYNC_DEBUG
        unsigned          magic;
#endif
};

void ksem_init(struct ksem *sem, int value);
void ksem_done(struct ksem *sem);
int  ksem_up  (struct ksem *sem, int value);
void ksem_down(struct ksem *sem, int value);
int  ksem_trydown(struct ksem *sem, int value);

/* ------------------------- mutex ------------------------- */

struct kmut {
	struct ksem s;
#if XNU_SYNC_DEBUG
        unsigned    magic;
        thread_t    owner;
#endif
};

void kmut_init(struct kmut *mut);
void kmut_done(struct kmut *mut);

void kmut_lock   (struct kmut *mut);
void kmut_unlock (struct kmut *mut);
int  kmut_trylock(struct kmut *mut);

#if XNU_SYNC_DEBUG
/*
 * two functions below are for use in assertions
 */
/* true, iff mutex is locked by the current thread */
int kmut_islocked(struct kmut *mut);
/* true, iff mutex is not locked by the current thread */
int kmut_isnotlocked(struct kmut *mut);
#else
#define kmut_islocked(m) (1)
#define kmut_isnotlocked(m) (1)
#endif

/* ------------------------- condition variable ------------------------- */

struct kcond_link {
	struct kcond_link *next;
        struct ksem        sem;
};

struct kcond {
        struct kspin       guard;
        struct kcond_link *waiters;
#if XNU_SYNC_DEBUG
        unsigned           magic;
#endif
};

void kcond_init(struct kcond *cond);
void kcond_done(struct kcond *cond);
void kcond_wait(struct kcond *cond, struct kspin *lock);
void kcond_signal(struct kcond *cond);
void kcond_broadcast(struct kcond *cond);

void kcond_wait_guard(struct kcond *cond);
void kcond_signal_guard(struct kcond *cond);
void kcond_broadcast_guard(struct kcond *cond);

/* ------------------------- read-write semaphore ------------------------- */

struct krw_sem {
	int          count;
	struct kcond cond;
#if XNU_SYNC_DEBUG
	unsigned     magic;
#endif
};

void krw_sem_init(struct krw_sem *sem);
void krw_sem_done(struct krw_sem *sem);
void krw_sem_down_r(struct krw_sem *sem);
int krw_sem_down_r_try(struct krw_sem *sem);
void krw_sem_down_w(struct krw_sem *sem);
int krw_sem_down_w_try(struct krw_sem *sem);
void krw_sem_up_r(struct krw_sem *sem);
void krw_sem_up_w(struct krw_sem *sem);

/* ------------------------- sleep-channel ------------------------- */

struct ksleep_chan {
	struct kspin     guard;
	struct list_head waiters;
#if XNU_SYNC_DEBUG
	unsigned     magic;
#endif
};

#define KSLEEP_CHAN_INITIALIZER         {{{0}}}

struct ksleep_link {
	int                 flags;
	event_t             event;
	int                 hits;
	struct ksleep_chan *forward;
	struct list_head    linkage;
#if XNU_SYNC_DEBUG
	unsigned     magic;
#endif
};

enum {
	KSLEEP_EXCLUSIVE = 1
};

void ksleep_chan_init(struct ksleep_chan *chan);
void ksleep_chan_done(struct ksleep_chan *chan);

void ksleep_link_init(struct ksleep_link *link);
void ksleep_link_done(struct ksleep_link *link);

void ksleep_add(struct ksleep_chan *chan, struct ksleep_link *link);
void ksleep_del(struct ksleep_chan *chan, struct ksleep_link *link);

void ksleep_wait(struct ksleep_chan *chan, int state);
int64_t  ksleep_timedwait(struct ksleep_chan *chan, int state, __u64 timeout);

void ksleep_wake(struct ksleep_chan *chan);
void ksleep_wake_all(struct ksleep_chan *chan);
void ksleep_wake_nr(struct ksleep_chan *chan, int nr);

#define KSLEEP_LINK_DECLARE(name)               \
{                                               \
	.flags   = 0,                           \
	.event   = 0,                           \
	.hits    = 0,                           \
	.linkage = CFS_LIST_HEAD(name.linkage),	\
	.magic   = KSLEEP_LINK_MAGIC            \
}

/* ------------------------- timer ------------------------- */

struct ktimer {
	struct kspin   guard;
	void         (*func)(void *);
	void          *arg;
	u_int64_t      deadline; /* timer deadline in absolute nanoseconds */
	int            armed;
#if XNU_SYNC_DEBUG
	unsigned     magic;
#endif
};

void ktimer_init(struct ktimer *t, void (*func)(void *), void *arg);
void ktimer_done(struct ktimer *t);
void ktimer_arm(struct ktimer *t, u_int64_t deadline);
void ktimer_disarm(struct ktimer *t);
int  ktimer_is_armed(struct ktimer *t);

u_int64_t ktimer_deadline(struct ktimer *t);

/* __XNU_SYNC_H__ */
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
