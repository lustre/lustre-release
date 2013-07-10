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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
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

#define CFS_WS_NAME_LEN         16

typedef struct cfs_wi_sched {
	cfs_list_t		ws_list;	/* chain on global list */
#ifdef __KERNEL__
	/** serialised workitems */
	spinlock_t		ws_lock;
	/** where schedulers sleep */
	cfs_waitq_t		ws_waitq;
#endif
	/** concurrent workitems */
	cfs_list_t		ws_runq;
	/** rescheduled running-workitems, a workitem can be rescheduled
	 * while running in wi_action(), but we don't to execute it again
	 * unless it returns from wi_action(), so we put it on ws_rerunq
	 * while rescheduling, and move it to runq after it returns
	 * from wi_action() */
	cfs_list_t		ws_rerunq;
	/** CPT-table for this scheduler */
	struct cfs_cpt_table	*ws_cptab;
	/** CPT id for affinity */
	int			ws_cpt;
	/** number of scheduled workitems */
	int			ws_nscheduled;
	/** started scheduler thread, protected by cfs_wi_data::wi_glock */
	unsigned int		ws_nthreads:30;
	/** shutting down, protected by cfs_wi_data::wi_glock */
	unsigned int		ws_stopping:1;
	/** serialize starting thread, protected by cfs_wi_data::wi_glock */
	unsigned int		ws_starting:1;
	/** scheduler name */
	char			ws_name[CFS_WS_NAME_LEN];
} cfs_wi_sched_t;

struct cfs_workitem_data {
	/** serialize */
	spinlock_t		wi_glock;
	/** list of all schedulers */
	cfs_list_t		wi_scheds;
	/** WI module is initialized */
	int			wi_init;
	/** shutting down the whole WI module */
	int			wi_stopping;
} cfs_wi_data;

#ifdef __KERNEL__
static inline void
cfs_wi_sched_lock(cfs_wi_sched_t *sched)
{
	spin_lock(&sched->ws_lock);
}

static inline void
cfs_wi_sched_unlock(cfs_wi_sched_t *sched)
{
	spin_unlock(&sched->ws_lock);
}

static inline int
cfs_wi_sched_cansleep(cfs_wi_sched_t *sched)
{
	cfs_wi_sched_lock(sched);
	if (sched->ws_stopping) {
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

#else /* !__KERNEL__ */

static inline void
cfs_wi_sched_lock(cfs_wi_sched_t *sched)
{
	spin_lock(&cfs_wi_data.wi_glock);
}

static inline void
cfs_wi_sched_unlock(cfs_wi_sched_t *sched)
{
	spin_unlock(&cfs_wi_data.wi_glock);
}

#endif /* __KERNEL__ */

/* XXX:
 * 0. it only works when called from wi->wi_action.
 * 1. when it returns no one shall try to schedule the workitem.
 */
void
cfs_wi_exit(struct cfs_wi_sched *sched, cfs_workitem_t *wi)
{
	LASSERT(!cfs_in_interrupt()); /* because we use plain spinlock */
	LASSERT(!sched->ws_stopping);

	cfs_wi_sched_lock(sched);

#ifdef __KERNEL__
	LASSERT(wi->wi_running);
#endif
	if (wi->wi_scheduled) { /* cancel pending schedules */
		LASSERT(!cfs_list_empty(&wi->wi_list));
		cfs_list_del_init(&wi->wi_list);

		LASSERT(sched->ws_nscheduled > 0);
		sched->ws_nscheduled--;
	}

	LASSERT(cfs_list_empty(&wi->wi_list));

	wi->wi_scheduled = 1; /* LBUG future schedule attempts */
	cfs_wi_sched_unlock(sched);

	return;
}
EXPORT_SYMBOL(cfs_wi_exit);

/**
 * cancel schedule request of workitem \a wi
 */
int
cfs_wi_deschedule(struct cfs_wi_sched *sched, cfs_workitem_t *wi)
{
	int	rc;

	LASSERT(!cfs_in_interrupt()); /* because we use plain spinlock */
	LASSERT(!sched->ws_stopping);

        /*
         * return 0 if it's running already, otherwise return 1, which
         * means the workitem will not be scheduled and will not have
         * any race with wi_action.
         */
	cfs_wi_sched_lock(sched);

	rc = !(wi->wi_running);

	if (wi->wi_scheduled) { /* cancel pending schedules */
		LASSERT(!cfs_list_empty(&wi->wi_list));
		cfs_list_del_init(&wi->wi_list);

		LASSERT(sched->ws_nscheduled > 0);
		sched->ws_nscheduled--;

                wi->wi_scheduled = 0;
        }

        LASSERT (cfs_list_empty(&wi->wi_list));

        cfs_wi_sched_unlock(sched);
        return rc;
}
EXPORT_SYMBOL(cfs_wi_deschedule);

/*
 * Workitem scheduled with (serial == 1) is strictly serialised not only with
 * itself, but also with others scheduled this way.
 *
 * Now there's only one static serialised queue, but in the future more might
 * be added, and even dynamic creation of serialised queues might be supported.
 */
void
cfs_wi_schedule(struct cfs_wi_sched *sched, cfs_workitem_t *wi)
{
	LASSERT(!cfs_in_interrupt()); /* because we use plain spinlock */
	LASSERT(!sched->ws_stopping);

        cfs_wi_sched_lock(sched);

        if (!wi->wi_scheduled) {
                LASSERT (cfs_list_empty(&wi->wi_list));

                wi->wi_scheduled = 1;
		sched->ws_nscheduled++;
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
EXPORT_SYMBOL(cfs_wi_schedule);

#ifdef __KERNEL__

static int
cfs_wi_scheduler (void *arg)
{
	struct cfs_wi_sched	*sched = (cfs_wi_sched_t *)arg;

	cfs_block_allsigs();

	/* CPT affinity scheduler? */
	if (sched->ws_cptab != NULL)
		cfs_cpt_bind(sched->ws_cptab, sched->ws_cpt);

	spin_lock(&cfs_wi_data.wi_glock);

	LASSERT(sched->ws_starting == 1);
	sched->ws_starting--;
	sched->ws_nthreads++;

	spin_unlock(&cfs_wi_data.wi_glock);

	cfs_wi_sched_lock(sched);

	while (!sched->ws_stopping) {
                int             nloops = 0;
                int             rc;
                cfs_workitem_t *wi;

                while (!cfs_list_empty(&sched->ws_runq) &&
                       nloops < CFS_WI_RESCHED) {
                        wi = cfs_list_entry(sched->ws_runq.next,
                                            cfs_workitem_t, wi_list);
			LASSERT(wi->wi_scheduled && !wi->wi_running);

			cfs_list_del_init(&wi->wi_list);

			LASSERT(sched->ws_nscheduled > 0);
			sched->ws_nscheduled--;

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

			LASSERT(wi->wi_scheduled);
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

	spin_lock(&cfs_wi_data.wi_glock);
	sched->ws_nthreads--;
	spin_unlock(&cfs_wi_data.wi_glock);

	return 0;
}

#else /* __KERNEL__ */

int
cfs_wi_check_events (void)
{
	int               n = 0;
	cfs_workitem_t   *wi;

	spin_lock(&cfs_wi_data.wi_glock);

	for (;;) {
		struct cfs_wi_sched	*sched = NULL;
		struct cfs_wi_sched	*tmp;

                /** rerunq is always empty for userspace */
		cfs_list_for_each_entry(tmp,
					&cfs_wi_data.wi_scheds, ws_list) {
			if (!cfs_list_empty(&tmp->ws_runq)) {
				sched = tmp;
				break;
			}
		}

		if (sched == NULL)
			break;

		wi = cfs_list_entry(sched->ws_runq.next,
				    cfs_workitem_t, wi_list);
		cfs_list_del_init(&wi->wi_list);

		LASSERT(sched->ws_nscheduled > 0);
		sched->ws_nscheduled--;

		LASSERT(wi->wi_scheduled);
		wi->wi_scheduled = 0;
		spin_unlock(&cfs_wi_data.wi_glock);

		n++;
		(*wi->wi_action) (wi);

		spin_lock(&cfs_wi_data.wi_glock);
	}

	spin_unlock(&cfs_wi_data.wi_glock);
	return n;
}

#endif

void
cfs_wi_sched_destroy(struct cfs_wi_sched *sched)
{
	int	i;

	LASSERT(cfs_wi_data.wi_init);
	LASSERT(!cfs_wi_data.wi_stopping);

	spin_lock(&cfs_wi_data.wi_glock);
	if (sched->ws_stopping) {
		CDEBUG(D_INFO, "%s is in progress of stopping\n",
		       sched->ws_name);
		spin_unlock(&cfs_wi_data.wi_glock);
		return;
	}

	LASSERT(!cfs_list_empty(&sched->ws_list));
	sched->ws_stopping = 1;

	spin_unlock(&cfs_wi_data.wi_glock);

	i = 2;
#ifdef __KERNEL__
	cfs_waitq_broadcast(&sched->ws_waitq);

	spin_lock(&cfs_wi_data.wi_glock);
	while (sched->ws_nthreads > 0) {
		CDEBUG(IS_PO2(++i) ? D_WARNING : D_NET,
		       "waiting for %d threads of WI sched[%s] to terminate\n",
		       sched->ws_nthreads, sched->ws_name);

		spin_unlock(&cfs_wi_data.wi_glock);
		cfs_pause(cfs_time_seconds(1) / 20);
		spin_lock(&cfs_wi_data.wi_glock);
	}

	cfs_list_del(&sched->ws_list);

	spin_unlock(&cfs_wi_data.wi_glock);
#else
	SET_BUT_UNUSED(i);
#endif
	LASSERT(sched->ws_nscheduled == 0);

	LIBCFS_FREE(sched, sizeof(*sched));
}
EXPORT_SYMBOL(cfs_wi_sched_destroy);

int
cfs_wi_sched_create(char *name, struct cfs_cpt_table *cptab,
		    int cpt, int nthrs, struct cfs_wi_sched **sched_pp)
{
	struct cfs_wi_sched	*sched;
	int			rc;

	LASSERT(cfs_wi_data.wi_init);
	LASSERT(!cfs_wi_data.wi_stopping);
	LASSERT(cptab == NULL || cpt == CFS_CPT_ANY ||
		(cpt >= 0 && cpt < cfs_cpt_number(cptab)));

	LIBCFS_ALLOC(sched, sizeof(*sched));
	if (sched == NULL)
		return -ENOMEM;

	strncpy(sched->ws_name, name, CFS_WS_NAME_LEN);
	sched->ws_cptab = cptab;
	sched->ws_cpt = cpt;

#ifdef __KERNEL__
	spin_lock_init(&sched->ws_lock);
	cfs_waitq_init(&sched->ws_waitq);
#endif
	CFS_INIT_LIST_HEAD(&sched->ws_runq);
	CFS_INIT_LIST_HEAD(&sched->ws_rerunq);
	CFS_INIT_LIST_HEAD(&sched->ws_list);

	rc = 0;
#ifdef __KERNEL__
	while (nthrs > 0)  {
		char	name[16];
		cfs_task_t	*task;
		spin_lock(&cfs_wi_data.wi_glock);
		while (sched->ws_starting > 0) {
			spin_unlock(&cfs_wi_data.wi_glock);
			cfs_schedule();
			spin_lock(&cfs_wi_data.wi_glock);
		}

		sched->ws_starting++;
		spin_unlock(&cfs_wi_data.wi_glock);

		if (sched->ws_cptab != NULL && sched->ws_cpt >= 0) {
			snprintf(name, sizeof(name), "%s_%02d_%02d",
				 sched->ws_name, sched->ws_cpt,
				 sched->ws_nthreads);
		} else {
			snprintf(name, sizeof(name), "%s_%02d",
				 sched->ws_name, sched->ws_nthreads);
		}

		task = kthread_run(cfs_wi_scheduler, sched, name);
		if (!IS_ERR(task)) {
			nthrs--;
			continue;
		}
		rc = PTR_ERR(task);

		CERROR("Failed to create thread for WI scheduler %s: %d\n",
		       name, rc);

		spin_lock(&cfs_wi_data.wi_glock);

		/* make up for cfs_wi_sched_destroy */
		cfs_list_add(&sched->ws_list, &cfs_wi_data.wi_scheds);
		sched->ws_starting--;

		spin_unlock(&cfs_wi_data.wi_glock);

		cfs_wi_sched_destroy(sched);
		return rc;
	}
#else
	SET_BUT_UNUSED(rc);
#endif
	spin_lock(&cfs_wi_data.wi_glock);
	cfs_list_add(&sched->ws_list, &cfs_wi_data.wi_scheds);
	spin_unlock(&cfs_wi_data.wi_glock);

	*sched_pp = sched;
	return 0;
}
EXPORT_SYMBOL(cfs_wi_sched_create);

int
cfs_wi_startup(void)
{
	memset(&cfs_wi_data, 0, sizeof(cfs_wi_data));

	spin_lock_init(&cfs_wi_data.wi_glock);
	CFS_INIT_LIST_HEAD(&cfs_wi_data.wi_scheds);
	cfs_wi_data.wi_init = 1;

	return 0;
}

void
cfs_wi_shutdown (void)
{
	struct cfs_wi_sched	*sched;

	spin_lock(&cfs_wi_data.wi_glock);
	cfs_wi_data.wi_stopping = 1;
	spin_unlock(&cfs_wi_data.wi_glock);

#ifdef __KERNEL__
	/* nobody should contend on this list */
	cfs_list_for_each_entry(sched, &cfs_wi_data.wi_scheds, ws_list) {
		sched->ws_stopping = 1;
		cfs_waitq_broadcast(&sched->ws_waitq);
	}

	cfs_list_for_each_entry(sched, &cfs_wi_data.wi_scheds, ws_list) {
		spin_lock(&cfs_wi_data.wi_glock);

		while (sched->ws_nthreads != 0) {
			spin_unlock(&cfs_wi_data.wi_glock);
			cfs_pause(cfs_time_seconds(1) / 20);
			spin_lock(&cfs_wi_data.wi_glock);
		}
		spin_unlock(&cfs_wi_data.wi_glock);
	}
#endif
	while (!cfs_list_empty(&cfs_wi_data.wi_scheds)) {
		sched = cfs_list_entry(cfs_wi_data.wi_scheds.next,
				       struct cfs_wi_sched, ws_list);
		cfs_list_del(&sched->ws_list);
		LIBCFS_FREE(sched, sizeof(*sched));
	}

	cfs_wi_data.wi_stopping = 0;
	cfs_wi_data.wi_init = 0;
}
