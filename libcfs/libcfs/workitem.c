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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * libcfs/libcfs/workitem.c
 *
 * Author: Isaac Huang <isaac@clusterfs.com>
 *         Liang Zhen  <zhen.liang@sun.com>
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>

typedef struct cfs_wi_sched {
#ifdef __KERNEL__
        /** serialised workitems */
        cfs_spinlock_t  ws_lock;
        /** where schedulers sleep */
        cfs_waitq_t     ws_waitq;
#endif
        /** concurrent workitems */
        cfs_list_t      ws_runq;
        /** rescheduled running-workitems */
        cfs_list_t      ws_rerunq;
        /** shutting down */
        int             ws_shuttingdown;
} cfs_wi_sched_t;

#ifdef __KERNEL__
/**
 * we have 2 cfs_wi_sched_t so far:
 * one for CFS_WI_SCHED_ANY, another for CFS_WI_SCHED_SERIAL
 * per-cpu implementation will be added for SMP scalability
 */

#define CFS_WI_NSCHED   2
#else
/** always 2 for userspace */
#define CFS_WI_NSCHED   2
#endif /* __KERNEL__ */

struct cfs_workitem_data {
        /** serialize */
        cfs_spinlock_t  wi_glock;
        /** number of cfs_wi_sched_t */
        int             wi_nsched;
        /** number of threads (all schedulers) */
        int             wi_nthreads;
        /** default scheduler */
        cfs_wi_sched_t *wi_scheds;
} cfs_wi_data;

static inline cfs_wi_sched_t *
cfs_wi_to_sched(cfs_workitem_t *wi)
{
        LASSERT(wi->wi_sched_id == CFS_WI_SCHED_ANY ||
                wi->wi_sched_id == CFS_WI_SCHED_SERIAL ||
                (wi->wi_sched_id >= 0 &&
                 wi->wi_sched_id < cfs_wi_data.wi_nsched));

        if (wi->wi_sched_id == CFS_WI_SCHED_ANY)
                return &cfs_wi_data.wi_scheds[0];
        if (wi->wi_sched_id == CFS_WI_SCHED_SERIAL)
                return &cfs_wi_data.wi_scheds[cfs_wi_data.wi_nsched - 1];

        return &cfs_wi_data.wi_scheds[wi->wi_sched_id];
}

#ifdef __KERNEL__
static inline void
cfs_wi_sched_lock(cfs_wi_sched_t *sched)
{
        cfs_spin_lock(&sched->ws_lock);
}

static inline void
cfs_wi_sched_unlock(cfs_wi_sched_t *sched)
{
        cfs_spin_unlock(&sched->ws_lock);
}

static inline int
cfs_wi_sched_cansleep(cfs_wi_sched_t *sched)
{
        cfs_wi_sched_lock(sched);
        if (sched->ws_shuttingdown) {
                cfs_wi_sched_unlock(sched);
                return 0;
        }

        if (!cfs_list_empty(&sched->ws_runq)) {
                cfs_wi_sched_unlock(sched);
                return 0;
        }
        cfs_wi_sched_unlock(sched);
        return 1;
}

#else

static inline void
cfs_wi_sched_lock(cfs_wi_sched_t *sched)
{
        cfs_spin_lock(&cfs_wi_data.wi_glock);
}

static inline void
cfs_wi_sched_unlock(cfs_wi_sched_t *sched)
{
        cfs_spin_unlock(&cfs_wi_data.wi_glock);
}

#endif

/* XXX:
 * 0. it only works when called from wi->wi_action.
 * 1. when it returns no one shall try to schedule the workitem.
 */
void
cfs_wi_exit(cfs_workitem_t *wi)
{
        cfs_wi_sched_t *sched = cfs_wi_to_sched(wi);

        LASSERT (!cfs_in_interrupt()); /* because we use plain spinlock */
        LASSERT (!sched->ws_shuttingdown);

        cfs_wi_sched_lock(sched);

#ifdef __KERNEL__
        LASSERT (wi->wi_running);
#endif
        if (wi->wi_scheduled) { /* cancel pending schedules */
                LASSERT (!cfs_list_empty(&wi->wi_list));
                cfs_list_del_init(&wi->wi_list);
        }

        LASSERT (cfs_list_empty(&wi->wi_list));
        wi->wi_scheduled = 1; /* LBUG future schedule attempts */

        cfs_wi_sched_unlock(sched);
        return;
}
CFS_EXPORT_SYMBOL(cfs_wi_exit);

/**
 * cancel a workitem:
 */
int
cfs_wi_cancel (cfs_workitem_t *wi)
{
        cfs_wi_sched_t *sched = cfs_wi_to_sched(wi);
        int             rc;

        LASSERT (!cfs_in_interrupt()); /* because we use plain spinlock */
        LASSERT (!sched->ws_shuttingdown);

        cfs_wi_sched_lock(sched);
        /*
         * return 0 if it's running already, otherwise return 1, which
         * means the workitem will not be scheduled and will not have
         * any race with wi_action.
         */
        rc = !(wi->wi_running);

        if (wi->wi_scheduled) { /* cancel pending schedules */
                LASSERT (!cfs_list_empty(&wi->wi_list));
                cfs_list_del_init(&wi->wi_list);
                wi->wi_scheduled = 0;
        }

        LASSERT (cfs_list_empty(&wi->wi_list));

        cfs_wi_sched_unlock(sched);
        return rc;
}

CFS_EXPORT_SYMBOL(cfs_wi_cancel);

/*
 * Workitem scheduled with (serial == 1) is strictly serialised not only with
 * itself, but also with others scheduled this way.
 *
 * Now there's only one static serialised queue, but in the future more might
 * be added, and even dynamic creation of serialised queues might be supported.
 */
void
cfs_wi_schedule(cfs_workitem_t *wi)
{
        cfs_wi_sched_t *sched = cfs_wi_to_sched(wi);

        LASSERT (!cfs_in_interrupt()); /* because we use plain spinlock */
        LASSERT (!sched->ws_shuttingdown);

        cfs_wi_sched_lock(sched);

        if (!wi->wi_scheduled) {
                LASSERT (cfs_list_empty(&wi->wi_list));

                wi->wi_scheduled = 1;
                if (!wi->wi_running) {
                        cfs_list_add_tail(&wi->wi_list, &sched->ws_runq);
#ifdef __KERNEL__
                        cfs_waitq_signal(&sched->ws_waitq);
#endif
                } else {
                        cfs_list_add(&wi->wi_list, &sched->ws_rerunq);
                }
        }

        LASSERT (!cfs_list_empty(&wi->wi_list));
        cfs_wi_sched_unlock(sched);
        return;
}

CFS_EXPORT_SYMBOL(cfs_wi_schedule);

#ifdef __KERNEL__

static int
cfs_wi_scheduler (void *arg)
{
        int             id     = (int)(long_ptr_t) arg;
        int             serial = (id == -1);
        char            name[24];
        cfs_wi_sched_t *sched;

        if (serial) {
                sched = &cfs_wi_data.wi_scheds[cfs_wi_data.wi_nsched - 1];
                cfs_daemonize("wi_serial_sd");
        } else {
                /* will be sched = &cfs_wi_data.wi_scheds[id] in the future */
                sched = &cfs_wi_data.wi_scheds[0];
                snprintf(name, sizeof(name), "cfs_wi_sd%03d", id);
                cfs_daemonize(name);
        }

        cfs_block_allsigs();

        cfs_wi_sched_lock(sched);

        while (!sched->ws_shuttingdown) {
                int             nloops = 0;
                int             rc;
                cfs_workitem_t *wi;

                while (!cfs_list_empty(&sched->ws_runq) &&
                       nloops < CFS_WI_RESCHED) {
                        wi = cfs_list_entry(sched->ws_runq.next,
                                            cfs_workitem_t, wi_list);
                        LASSERT (wi->wi_scheduled && !wi->wi_running);

                        cfs_list_del_init(&wi->wi_list);

                        wi->wi_running   = 1;
                        wi->wi_scheduled = 0;
                        cfs_wi_sched_unlock(sched);
                        nloops++;

                        rc = (*wi->wi_action) (wi);

                        cfs_wi_sched_lock(sched);
                        if (rc != 0) /* WI should be dead, even be freed! */
                                continue;

                        wi->wi_running = 0;
                        if (cfs_list_empty(&wi->wi_list))
                                continue;

                        LASSERT (wi->wi_scheduled);
                        /* wi is rescheduled, should be on rerunq now, we
                         * move it to runq so it can run action now */
                        cfs_list_move_tail(&wi->wi_list, &sched->ws_runq);
                }

                if (!cfs_list_empty(&sched->ws_runq)) {
                        cfs_wi_sched_unlock(sched);
                        /* don't sleep because some workitems still
                         * expect me to come back soon */
                        cfs_cond_resched();
                        cfs_wi_sched_lock(sched);
                        continue;
                }

                cfs_wi_sched_unlock(sched);
                cfs_wait_event_interruptible_exclusive(sched->ws_waitq,
                                !cfs_wi_sched_cansleep(sched), rc);
                cfs_wi_sched_lock(sched);
        }

        cfs_wi_sched_unlock(sched);

        cfs_spin_lock(&cfs_wi_data.wi_glock);
        cfs_wi_data.wi_nthreads--;
        cfs_spin_unlock(&cfs_wi_data.wi_glock);
        return 0;
}

static int
cfs_wi_start_thread (int (*func) (void*), void *arg)
{
        long pid;

        pid = cfs_create_thread(func, arg, 0);
        if (pid < 0)
                return (int)pid;

        cfs_spin_lock(&cfs_wi_data.wi_glock);
        cfs_wi_data.wi_nthreads++;
        cfs_spin_unlock(&cfs_wi_data.wi_glock);
        return 0;
}

#else /* __KERNEL__ */

int
cfs_wi_check_events (void)
{
        int               n = 0;
        cfs_workitem_t   *wi;
        cfs_list_t       *q;

        cfs_spin_lock(&cfs_wi_data.wi_glock);

        for (;;) {
                /** rerunq is always empty for userspace */
                if (!cfs_list_empty(&cfs_wi_data.wi_scheds[1].ws_runq))
                        q = &cfs_wi_data.wi_scheds[1].ws_runq;
                else if (!cfs_list_empty(&cfs_wi_data.wi_scheds[0].ws_runq))
                        q = &cfs_wi_data.wi_scheds[0].ws_runq;
                else
                        break;

                wi = cfs_list_entry(q->next, cfs_workitem_t, wi_list);
                cfs_list_del_init(&wi->wi_list);

                LASSERT (wi->wi_scheduled);
                wi->wi_scheduled = 0;
                cfs_spin_unlock(&cfs_wi_data.wi_glock);

                n++;
                (*wi->wi_action) (wi);

                cfs_spin_lock(&cfs_wi_data.wi_glock);
        }

        cfs_spin_unlock(&cfs_wi_data.wi_glock);
        return n;
}

#endif

static void
cfs_wi_sched_init(cfs_wi_sched_t *sched)
{
        sched->ws_shuttingdown = 0;
#ifdef __KERNEL__
        cfs_spin_lock_init(&sched->ws_lock);
        cfs_waitq_init(&sched->ws_waitq);
#endif
        CFS_INIT_LIST_HEAD(&sched->ws_runq);
        CFS_INIT_LIST_HEAD(&sched->ws_rerunq);
}

static void
cfs_wi_sched_shutdown(cfs_wi_sched_t *sched)
{
        cfs_wi_sched_lock(sched);

        LASSERT(cfs_list_empty(&sched->ws_runq));
        LASSERT(cfs_list_empty(&sched->ws_rerunq));

        sched->ws_shuttingdown = 1;

#ifdef __KERNEL__
        cfs_waitq_broadcast(&sched->ws_waitq);
#endif
        cfs_wi_sched_unlock(sched);
}


int
cfs_wi_startup (void)
{
        int i;
        int n;
        int rc;

        cfs_wi_data.wi_nthreads = 0;
        cfs_wi_data.wi_nsched   = CFS_WI_NSCHED;
        LIBCFS_ALLOC(cfs_wi_data.wi_scheds,
                     cfs_wi_data.wi_nsched * sizeof(cfs_wi_sched_t));
        if (cfs_wi_data.wi_scheds == NULL)
                return -ENOMEM;

        cfs_spin_lock_init(&cfs_wi_data.wi_glock);
        for (i = 0; i < cfs_wi_data.wi_nsched; i++)
                cfs_wi_sched_init(&cfs_wi_data.wi_scheds[i]);

#ifdef __KERNEL__
        n = cfs_num_online_cpus();
        for (i = 0; i <= n; i++) {
                rc = cfs_wi_start_thread(cfs_wi_scheduler,
                                         (void *)(long_ptr_t)(i == n ? -1 : i));
                if (rc != 0) {
                        CERROR ("Can't spawn workitem scheduler: %d\n", rc);
                        cfs_wi_shutdown();
                        return rc;
                }
        }
#else
        n = rc = 0;
#endif

        return 0;
}

void
cfs_wi_shutdown (void)
{
        int i;

        if (cfs_wi_data.wi_scheds == NULL)
                return;

        for (i = 0; i < cfs_wi_data.wi_nsched; i++)
                cfs_wi_sched_shutdown(&cfs_wi_data.wi_scheds[i]);

#ifdef __KERNEL__
        cfs_spin_lock(&cfs_wi_data.wi_glock);
        i = 2;
        while (cfs_wi_data.wi_nthreads != 0) {
                CDEBUG(IS_PO2(++i) ? D_WARNING : D_NET,
                       "waiting for %d threads to terminate\n",
                       cfs_wi_data.wi_nthreads);
                cfs_spin_unlock(&cfs_wi_data.wi_glock);

                cfs_pause(cfs_time_seconds(1));

                cfs_spin_lock(&cfs_wi_data.wi_glock);
        }
        cfs_spin_unlock(&cfs_wi_data.wi_glock);
#endif
        LIBCFS_FREE(cfs_wi_data.wi_scheds,
                    cfs_wi_data.wi_nsched * sizeof(cfs_wi_sched_t));
        return;
}
