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
 * lnet/libcfs/watchdog.c
 *
 * Author: Jacob Berkman <jacob@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>
#include "tracefile.h"

struct lc_watchdog {
        cfs_timer_t       lcw_timer; /* kernel timer */
        struct list_head  lcw_list;
        cfs_time_t        lcw_last_touched;
        cfs_task_t       *lcw_task;

        void            (*lcw_callback)(pid_t, void *);
        void             *lcw_data;

        pid_t             lcw_pid;

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
static struct completion lcw_stop_completion;
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
 * When it hits 0, we stop the distpatcher.
 */
static __u32         lcw_refcount = 0;
static DECLARE_MUTEX(lcw_refcount_sem);

/*
 * List of timers that have fired that need their callbacks run by the
 * dispatcher.
 */
static spinlock_t lcw_pending_timers_lock = SPIN_LOCK_UNLOCKED; /* BH lock! */
static struct list_head lcw_pending_timers = \
        LIST_HEAD_INIT(lcw_pending_timers);

/* Last time a watchdog expired */
static cfs_time_t lcw_last_watchdog_time;
static int lcw_recent_watchdog_count;
static spinlock_t lcw_last_watchdog_lock = SPIN_LOCK_UNLOCKED;

static void
lcw_dump(struct lc_watchdog *lcw)
{
        ENTRY;

#if defined(HAVE_TASKLIST_LOCK)
        read_lock(&tasklist_lock);
#elif defined(HAVE_TASK_RCU)
        rcu_read_lock();
#else
        CERROR("unable to dump stack because of missing export\n"); 
        RETURN_EXIT;
#endif
        if (lcw->lcw_task == NULL) {
                CWARN("Process %d was not found in the task list; "
                      "watchdog callback may be incomplete\n",
                      (int)lcw->lcw_pid);
        } else {
                libcfs_debug_dumpstack(lcw->lcw_task);
        }

#if defined(HAVE_TASKLIST_LOCK)
        read_unlock(&tasklist_lock);
#elif defined(HAVE_TASK_RCU)
        rcu_read_unlock();
#endif
        EXIT;
}

static void lcw_cb(unsigned long data)
{
        struct lc_watchdog *lcw = (struct lc_watchdog *)data;
        cfs_time_t current_time;
        cfs_duration_t delta_time;
        struct timeval timediff;

        ENTRY;

        if (lcw->lcw_state != LC_WATCHDOG_ENABLED) {
                EXIT;
                return;
        }

        lcw->lcw_state = LC_WATCHDOG_EXPIRED;
        current_time = cfs_time_current();

        delta_time = cfs_time_sub(current_time, lcw->lcw_last_touched);
        cfs_duration_usec(delta_time, &timediff);

        /* Check to see if we should throttle the watchdog timer to avoid
         * too many dumps going to the console thus triggering an NMI.
         * Normally we would not hold the spin lock over the CWARN but in
         * this case we hold it to ensure non ratelimited lcw_dumps are not
         * interleaved on the console making them hard to read. */
        spin_lock_bh(&lcw_last_watchdog_lock);
        delta_time = cfs_duration_sec(cfs_time_sub(current_time,
                                                   lcw_last_watchdog_time));

        if (delta_time < libcfs_watchdog_ratelimit &&
            lcw_recent_watchdog_count > 3) {
                CWARN("Refusing to fire watchdog for pid %d: it was inactive "
                      "for %lu.%.02lus. Rate limiting 1 per %d seconds.\n",
                      (int)lcw->lcw_pid, timediff.tv_sec,
                      timediff.tv_usec / 10000, libcfs_watchdog_ratelimit);
        } else {
                if (delta_time < libcfs_watchdog_ratelimit) {
                        lcw_recent_watchdog_count++;
                } else {
                        memcpy(&lcw_last_watchdog_time, &current_time,
                               sizeof(current_time));
                        lcw_recent_watchdog_count = 0;
                }

		/* This warning should appear on the console, but may not get
		 * into the logs since we're running in a softirq handler */
                CWARN("Watchdog triggered for pid %d: it was inactive for "
                      "%lu.%.02lus\n", (int)lcw->lcw_pid, timediff.tv_sec,
                      timediff.tv_usec / 10000);
                lcw_dump(lcw);
	}

        spin_unlock_bh(&lcw_last_watchdog_lock);
        spin_lock_bh(&lcw_pending_timers_lock);

        if (list_empty(&lcw->lcw_list)) {
                list_add(&lcw->lcw_list, &lcw_pending_timers);
                wake_up(&lcw_event_waitq);
        }

        spin_unlock_bh(&lcw_pending_timers_lock);

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

static int lcw_dispatch_main(void *data)
{
        int                 rc = 0;
        unsigned long       flags;
        struct lc_watchdog *lcw;

        ENTRY;

        cfs_daemonize("lc_watchdogd");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        complete(&lcw_start_completion);

        while (1) {
                wait_event_interruptible(lcw_event_waitq, is_watchdog_fired());
                CDEBUG(D_INFO, "Watchdog got woken up...\n");
                if (test_bit(LCW_FLAG_STOP, &lcw_flags)) {
                        CDEBUG(D_INFO, "LCW_FLAG_STOP was set, shutting down...\n");

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

                        lcw = list_entry(lcw_pending_timers.next,
                                         struct lc_watchdog,
                                         lcw_list);
                        list_del_init(&lcw->lcw_list);
                        spin_unlock_bh(&lcw_pending_timers_lock);

                        CDEBUG(D_INFO, "found lcw for pid %d\n",
                               (int)lcw->lcw_pid);

                        if (lcw->lcw_state != LC_WATCHDOG_DISABLED)
                                lcw->lcw_callback(lcw->lcw_pid, lcw->lcw_data);

                        spin_lock_bh(&lcw_pending_timers_lock);
                }
                spin_unlock_bh(&lcw_pending_timers_lock);
        }

        complete(&lcw_stop_completion);

        RETURN(rc);
}

static void lcw_dispatch_start(void)
{
        int rc;

        ENTRY;
        LASSERT(lcw_refcount == 1);

        init_completion(&lcw_stop_completion);
        init_completion(&lcw_start_completion);
        init_waitqueue_head(&lcw_event_waitq);

        CDEBUG(D_INFO, "starting dispatch thread\n");
        rc = kernel_thread(lcw_dispatch_main, NULL, 0);
        if (rc < 0) {
                CERROR("error spawning watchdog dispatch thread: %d\n", rc);
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

        lcw->lcw_task     = cfs_current();
        lcw->lcw_pid      = cfs_curproc_pid();
        lcw->lcw_callback = (callback != NULL) ? callback : lc_watchdog_dumplog;
        lcw->lcw_data     = data;
        lcw->lcw_state    = LC_WATCHDOG_DISABLED;

        INIT_LIST_HEAD(&lcw->lcw_list);

        lcw->lcw_timer.function = lcw_cb;
        lcw->lcw_timer.data = (unsigned long)lcw;
        lcw->lcw_timer.expires = jiffies + cfs_time_seconds(timeout);
        init_timer(&lcw->lcw_timer);

        down(&lcw_refcount_sem);
        if (++lcw_refcount == 1)
                lcw_dispatch_start();
        up(&lcw_refcount_sem);

        /* Keep this working in case we enable them by default */
        if (lcw->lcw_state == LC_WATCHDOG_ENABLED) {
                lcw->lcw_last_touched = cfs_time_current();
                add_timer(&lcw->lcw_timer);
        }

        RETURN(lcw);
}
EXPORT_SYMBOL(lc_watchdog_add);

static void lcw_update_time(struct lc_watchdog *lcw, const char *message)
{
        cfs_time_t newtime = cfs_time_current();;

        if (lcw->lcw_state == LC_WATCHDOG_EXPIRED) {
                struct timeval timediff;
                cfs_time_t delta_time = cfs_time_sub(newtime,
                                                     lcw->lcw_last_touched);
                cfs_duration_usec(delta_time, &timediff);

                CWARN("Expired watchdog for pid %d %s after %lu.%.02lus\n",
                      lcw->lcw_pid, message, timediff.tv_sec,
                      timediff.tv_usec / 10000);
        }
        lcw->lcw_last_touched = newtime;
}

void lc_watchdog_touch(struct lc_watchdog *lcw, int timeout)
{
        ENTRY;
        LASSERT(lcw != NULL);

        spin_lock_bh(&lcw_pending_timers_lock);
        list_del_init(&lcw->lcw_list);
        spin_unlock_bh(&lcw_pending_timers_lock);

        lcw_update_time(lcw, "touched");
        lcw->lcw_state = LC_WATCHDOG_ENABLED;

        mod_timer(&lcw->lcw_timer, jiffies + cfs_time_seconds(timeout));

        EXIT;
}
EXPORT_SYMBOL(lc_watchdog_touch);

void lc_watchdog_disable(struct lc_watchdog *lcw)
{
        ENTRY;
        LASSERT(lcw != NULL);

        spin_lock_bh(&lcw_pending_timers_lock);
        if (!list_empty(&lcw->lcw_list))
                list_del_init(&lcw->lcw_list);
        spin_unlock_bh(&lcw_pending_timers_lock);

        lcw_update_time(lcw, "disabled");
        lcw->lcw_state = LC_WATCHDOG_DISABLED;

        EXIT;
}
EXPORT_SYMBOL(lc_watchdog_disable);

void lc_watchdog_delete(struct lc_watchdog *lcw)
{
        ENTRY;
        LASSERT(lcw != NULL);

        del_timer(&lcw->lcw_timer);

        lcw_update_time(lcw, "deleted");

        spin_lock_bh(&lcw_pending_timers_lock);
        if (!list_empty(&lcw->lcw_list))
                list_del_init(&lcw->lcw_list);
        spin_unlock_bh(&lcw_pending_timers_lock);

        down(&lcw_refcount_sem);
        if (--lcw_refcount == 0)
                lcw_dispatch_stop();
        up(&lcw_refcount_sem);

        LIBCFS_FREE(lcw, sizeof(*lcw));

        EXIT;
}
EXPORT_SYMBOL(lc_watchdog_delete);

/*
 * Provided watchdog handlers
 */

void lc_watchdog_dumplog(pid_t pid, void *data)
{
        libcfs_debug_dumplog_internal((void *)((unsigned long)pid));
}
EXPORT_SYMBOL(lc_watchdog_dumplog);

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
