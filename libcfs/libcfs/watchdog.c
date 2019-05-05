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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/watchdog.c
 *
 * Author: Jacob Berkman <jacob@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/kthread.h>
#include <libcfs/libcfs.h>
#include "tracefile.h"

#ifndef WITH_WATCHDOG
#define WITH_WATCHDOG
#endif

struct lc_watchdog {
	spinlock_t		lcw_lock;	/* check or change lcw_list */
	int			lcw_refcount;	/* must hold lcw_pending_timers_lock */
	struct timer_list	lcw_timer;	/* kernel timer */
	struct list_head	lcw_list;	/* chain on pending list */
	ktime_t			lcw_last_touched;/* last touched stamp */
	struct task_struct     *lcw_task;	/* owner task */
	void			(*lcw_callback)(pid_t, void *);
	void			*lcw_data;

	pid_t			lcw_pid;

	enum {
		LC_WATCHDOG_DISABLED,
		LC_WATCHDOG_ENABLED,
		LC_WATCHDOG_EXPIRED
	} lcw_state;
};

#ifdef WITH_WATCHDOG
/*
 * The dispatcher will complete lcw_start_completion when it starts,
 * and lcw_stop_completion when it exits.
 * Wake lcw_event_waitq to signal timer callback dispatches.
 */
static struct completion lcw_start_completion;
static struct completion  lcw_stop_completion;
static wait_queue_head_t lcw_event_waitq;

/*
 * Set this and wake lcw_event_waitq to stop the dispatcher.
 */
enum {
        LCW_FLAG_STOP = 0
};
static unsigned long lcw_flags = 0;

/*
 * Number of outstanding watchdogs.
 * When it hits 1, we start the dispatcher.
 * When it hits 0, we stop the dispatcher.
 */
static __u32         lcw_refcount = 0;
static DEFINE_MUTEX(lcw_refcount_mutex);

/*
 * List of timers that have fired that need their callbacks run by the
 * dispatcher.
 */
/* BH lock! */
static DEFINE_SPINLOCK(lcw_pending_timers_lock);
static struct list_head lcw_pending_timers = LIST_HEAD_INIT(lcw_pending_timers);

/* Last time a watchdog expired */
static time64_t lcw_last_watchdog_time;
static int lcw_recent_watchdog_count;

static void
lcw_dump(struct lc_watchdog *lcw)
{
        ENTRY;
        rcu_read_lock();
       if (lcw->lcw_task == NULL) {
		LCONSOLE_WARN("Process %d was not found in the task "
                              "list; watchdog callback may be incomplete\n",
                              (int)lcw->lcw_pid);
        } else {
                libcfs_debug_dumpstack(lcw->lcw_task);
        }

        rcu_read_unlock();
        EXIT;
}

static void lcw_cb(cfs_timer_cb_arg_t data)
{
	struct lc_watchdog *lcw = cfs_from_timer(lcw, data, lcw_timer);
        ENTRY;

        if (lcw->lcw_state != LC_WATCHDOG_ENABLED) {
                EXIT;
                return;
        }

        lcw->lcw_state = LC_WATCHDOG_EXPIRED;

	spin_lock_bh(&lcw->lcw_lock);
	LASSERT(list_empty(&lcw->lcw_list));

	spin_lock_bh(&lcw_pending_timers_lock);
	lcw->lcw_refcount++; /* +1 for pending list */
	list_add(&lcw->lcw_list, &lcw_pending_timers);
	wake_up(&lcw_event_waitq);

	spin_unlock_bh(&lcw_pending_timers_lock);
	spin_unlock_bh(&lcw->lcw_lock);
	EXIT;
}

static int is_watchdog_fired(void)
{
	int rc;

	if (test_bit(LCW_FLAG_STOP, &lcw_flags))
		return 1;

	spin_lock_bh(&lcw_pending_timers_lock);
	rc = !list_empty(&lcw_pending_timers);
	spin_unlock_bh(&lcw_pending_timers_lock);
	return rc;
}

static void lcw_dump_stack(struct lc_watchdog *lcw)
{
	time64_t current_time = ktime_get_seconds();
	struct timespec64 timediff;
	time64_t delta_time;

	timediff = ktime_to_timespec64(ktime_sub(ktime_get(),
				       lcw->lcw_last_touched));

	/* LU-9235: Don't dump stack if the thread is just touched. */
	if (timediff.tv_sec == 0)
		return;

	/*
	 * Check to see if we should throttle the watchdog timer to avoid
	 * too many dumps going to the console thus triggering an NMI.
	 */
	delta_time = current_time - lcw_last_watchdog_time;
	if (delta_time < libcfs_watchdog_ratelimit &&
	    lcw_recent_watchdog_count > 3) {
		LCONSOLE_WARN("Service thread pid %u was inactive for %llu.%.02lus. Watchdog stack traces are limited to 3 per %d seconds, skipping this one.\n",
			      (int)lcw->lcw_pid,
			      (unsigned long long)timediff.tv_sec,
			      timediff.tv_nsec / (NSEC_PER_SEC / 100),
			      libcfs_watchdog_ratelimit);
	} else {
		if (delta_time < libcfs_watchdog_ratelimit) {
			lcw_recent_watchdog_count++;
		} else {
			memcpy(&lcw_last_watchdog_time, &current_time,
			       sizeof(current_time));
			lcw_recent_watchdog_count = 0;
		}

		LCONSOLE_WARN("Service thread pid %u was inactive for %llu.%.02lus. The thread might be hung, or it might only be slow and will resume later. Dumping the stack trace for debugging purposes:\n",
			      (int)lcw->lcw_pid,
			      (unsigned long long)timediff.tv_sec,
			      timediff.tv_nsec / (NSEC_PER_SEC / 100));
		lcw_dump(lcw);
	}
}

/*
 * Provided watchdog handlers
 */

static void lc_watchdog_dumplog(pid_t pid, void *data)
{
	libcfs_debug_dumplog_internal((void *)((uintptr_t)pid));
}

static int lcw_dispatch_main(void *data)
{
        int                 rc = 0;
        struct lc_watchdog *lcw;
	struct list_head zombies = LIST_HEAD_INIT(zombies);

        ENTRY;

	complete(&lcw_start_completion);

        while (1) {
                int dumplog = 1;

		rc = wait_event_interruptible(lcw_event_waitq,
					      is_watchdog_fired());
                CDEBUG(D_INFO, "Watchdog got woken up...\n");
		if (test_bit(LCW_FLAG_STOP, &lcw_flags)) {
			CDEBUG(D_INFO, "LCW_FLAG_STOP set, shutting down...\n");

			spin_lock_bh(&lcw_pending_timers_lock);
			rc = !list_empty(&lcw_pending_timers);
			spin_unlock_bh(&lcw_pending_timers_lock);
			if (rc) {
				CERROR("pending timers list was not empty at "
				       "time of watchdog dispatch shutdown\n");
			}
			break;
		}

		spin_lock_bh(&lcw_pending_timers_lock);
		while (!list_empty(&lcw_pending_timers)) {
			int is_dumplog;

			lcw = list_entry(lcw_pending_timers.next,
					 struct lc_watchdog, lcw_list);
			/* +1 ref for callback to make sure lwc wouldn't be
			 * deleted after releasing lcw_pending_timers_lock */
			lcw->lcw_refcount++;
			spin_unlock_bh(&lcw_pending_timers_lock);

			/* lock ordering */
			spin_lock_bh(&lcw->lcw_lock);
			spin_lock_bh(&lcw_pending_timers_lock);

			if (list_empty(&lcw->lcw_list)) {
				/* already removed from pending list */
				lcw->lcw_refcount--; /* -1 ref for callback */
				if (lcw->lcw_refcount == 0)
					list_add(&lcw->lcw_list, &zombies);
				spin_unlock_bh(&lcw->lcw_lock);
				/* still hold lcw_pending_timers_lock */
				continue;
			}

			list_del_init(&lcw->lcw_list);
			lcw->lcw_refcount--; /* -1 ref for pending list */

			spin_unlock_bh(&lcw_pending_timers_lock);
			spin_unlock_bh(&lcw->lcw_lock);

			CDEBUG(D_INFO, "found lcw for pid %d\n",
                               lcw->lcw_pid);
                        lcw_dump_stack(lcw);

                        is_dumplog = lcw->lcw_callback == lc_watchdog_dumplog;
                        if (lcw->lcw_state != LC_WATCHDOG_DISABLED &&
                            (dumplog || !is_dumplog)) {
                                lcw->lcw_callback(lcw->lcw_pid, lcw->lcw_data);
                                if (dumplog && is_dumplog)
                                        dumplog = 0;
                        }

			spin_lock_bh(&lcw_pending_timers_lock);
			lcw->lcw_refcount--; /* -1 ref for callback */
			if (lcw->lcw_refcount == 0)
				list_add(&lcw->lcw_list, &zombies);
		}
		spin_unlock_bh(&lcw_pending_timers_lock);

		while (!list_empty(&zombies)) {
			lcw = list_entry(zombies.next,
					     struct lc_watchdog, lcw_list);
			list_del_init(&lcw->lcw_list);
			LIBCFS_FREE(lcw, sizeof(*lcw));
		}
	}

	complete(&lcw_stop_completion);

	RETURN(rc);
}

static void lcw_dispatch_start(void)
{
	struct task_struct *task;

	ENTRY;
	LASSERT(lcw_refcount == 1);

	init_completion(&lcw_stop_completion);
	init_completion(&lcw_start_completion);
	init_waitqueue_head(&lcw_event_waitq);

	CDEBUG(D_INFO, "starting dispatch thread\n");
	task = kthread_run(lcw_dispatch_main, NULL, "lc_watchdogd");
	if (IS_ERR(task)) {
		CERROR("error spawning watchdog dispatch thread: %ld\n",
			PTR_ERR(task));
		EXIT;
		return;
	}
	wait_for_completion(&lcw_start_completion);
	CDEBUG(D_INFO, "watchdog dispatcher initialization complete.\n");

	EXIT;
}

static void lcw_dispatch_stop(void)
{
	ENTRY;
	LASSERT(lcw_refcount == 0);

	CDEBUG(D_INFO, "trying to stop watchdog dispatcher.\n");

	set_bit(LCW_FLAG_STOP, &lcw_flags);
	wake_up(&lcw_event_waitq);

	wait_for_completion(&lcw_stop_completion);
	clear_bit(LCW_FLAG_STOP, &lcw_flags);

	CDEBUG(D_INFO, "watchdog dispatcher has shut down.\n");

	EXIT;
}

struct lc_watchdog *lc_watchdog_add(int timeout,
                                    void (*callback)(pid_t, void *),
                                    void *data)
{
        struct lc_watchdog *lcw = NULL;
        ENTRY;

        LIBCFS_ALLOC(lcw, sizeof(*lcw));
        if (lcw == NULL) {
                CDEBUG(D_INFO, "Could not allocate new lc_watchdog\n");
                RETURN(ERR_PTR(-ENOMEM));
        }

	spin_lock_init(&lcw->lcw_lock);
	lcw->lcw_refcount = 1; /* refcount for owner */
	lcw->lcw_task     = current;
	lcw->lcw_pid      = current_pid();
	lcw->lcw_callback = (callback != NULL) ? callback : lc_watchdog_dumplog;
	lcw->lcw_data     = data;
	lcw->lcw_state    = LC_WATCHDOG_DISABLED;

	INIT_LIST_HEAD(&lcw->lcw_list);
	cfs_timer_setup(&lcw->lcw_timer, lcw_cb, (unsigned long)lcw, 0);

	mutex_lock(&lcw_refcount_mutex);
	if (++lcw_refcount == 1)
		lcw_dispatch_start();
	mutex_unlock(&lcw_refcount_mutex);

	/* Keep this working in case we enable them by default */
	if (lcw->lcw_state == LC_WATCHDOG_ENABLED) {
		lcw->lcw_last_touched = ktime_get();
		mod_timer(&lcw->lcw_timer, cfs_time_seconds(timeout) +
			  jiffies);
	}

        RETURN(lcw);
}
EXPORT_SYMBOL(lc_watchdog_add);

static void lcw_update_time(struct lc_watchdog *lcw, const char *message)
{
	ktime_t newtime = ktime_get();

	if (lcw->lcw_state == LC_WATCHDOG_EXPIRED) {
		ktime_t lapse = ktime_sub(newtime, lcw->lcw_last_touched);
		struct timespec64 timediff;

		timediff = ktime_to_timespec64(lapse);
		LCONSOLE_WARN("Service thread pid %u %s after %llu.%.02lus. This indicates the system was overloaded (too many service threads, or there were not enough hardware resources).\n",
			      lcw->lcw_pid, message,
			      (unsigned long long)timediff.tv_sec,
			      timediff.tv_nsec / (NSEC_PER_SEC / 100));
	}
	lcw->lcw_last_touched = newtime;
}

static void lc_watchdog_del_pending(struct lc_watchdog *lcw)
{
	spin_lock_bh(&lcw->lcw_lock);
	if (unlikely(!list_empty(&lcw->lcw_list))) {
		spin_lock_bh(&lcw_pending_timers_lock);
		list_del_init(&lcw->lcw_list);
		lcw->lcw_refcount--; /* -1 ref for pending list */
		spin_unlock_bh(&lcw_pending_timers_lock);
	}

	spin_unlock_bh(&lcw->lcw_lock);
}

void lc_watchdog_touch(struct lc_watchdog *lcw, int timeout)
{
	ENTRY;
	LASSERT(lcw != NULL);

	lc_watchdog_del_pending(lcw);

	lcw_update_time(lcw, "resumed");

	mod_timer(&lcw->lcw_timer, jiffies + cfs_time_seconds(timeout));
	lcw->lcw_state = LC_WATCHDOG_ENABLED;

	EXIT;
}
EXPORT_SYMBOL(lc_watchdog_touch);

void lc_watchdog_disable(struct lc_watchdog *lcw)
{
        ENTRY;
        LASSERT(lcw != NULL);

        lc_watchdog_del_pending(lcw);

        lcw_update_time(lcw, "completed");
        lcw->lcw_state = LC_WATCHDOG_DISABLED;

        EXIT;
}
EXPORT_SYMBOL(lc_watchdog_disable);

void lc_watchdog_delete(struct lc_watchdog *lcw)
{
        int dead;

        ENTRY;
        LASSERT(lcw != NULL);

	del_timer(&lcw->lcw_timer);

        lcw_update_time(lcw, "stopped");

	spin_lock_bh(&lcw->lcw_lock);
	spin_lock_bh(&lcw_pending_timers_lock);
	if (unlikely(!list_empty(&lcw->lcw_list))) {
		list_del_init(&lcw->lcw_list);
		lcw->lcw_refcount--; /* -1 ref for pending list */
	}

	lcw->lcw_refcount--; /* -1 ref for owner */
	dead = lcw->lcw_refcount == 0;
	spin_unlock_bh(&lcw_pending_timers_lock);
	spin_unlock_bh(&lcw->lcw_lock);

	if (dead)
		LIBCFS_FREE(lcw, sizeof(*lcw));

	mutex_lock(&lcw_refcount_mutex);
	if (--lcw_refcount == 0)
		lcw_dispatch_stop();
	mutex_unlock(&lcw_refcount_mutex);

	EXIT;
}
EXPORT_SYMBOL(lc_watchdog_delete);

#else   /* !defined(WITH_WATCHDOG) */

struct lc_watchdog *lc_watchdog_add(int timeout,
                                    void (*callback)(pid_t pid, void *),
                                    void *data)
{
        static struct lc_watchdog      watchdog;
        return &watchdog;
}
EXPORT_SYMBOL(lc_watchdog_add);

void lc_watchdog_touch(struct lc_watchdog *lcw, int timeout)
{
}
EXPORT_SYMBOL(lc_watchdog_touch);

void lc_watchdog_disable(struct lc_watchdog *lcw)
{
}
EXPORT_SYMBOL(lc_watchdog_disable);

void lc_watchdog_delete(struct lc_watchdog *lcw)
{
}
EXPORT_SYMBOL(lc_watchdog_delete);

#endif
