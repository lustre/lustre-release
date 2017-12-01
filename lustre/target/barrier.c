/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation.
 *
 * lustre/target/barrier.c
 *
 * Currently, the Lustre barrier is implemented as write barrier on all MDTs.
 * For each MDT in the system, when it starts, it registers a barrier instance
 * that will be used in handling subsequent barrier requests.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_SNAPSHOT

#include <linux/percpu_counter.h>

#include <dt_object.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_barrier.h>
#include <uapi/linux/lustre/lustre_barrier_user.h>

static LIST_HEAD(barrier_instance_list);
static DEFINE_SPINLOCK(barrier_instance_lock);

struct barrier_instance {
	struct list_head	 bi_link;
	struct dt_device	*bi_bottom;
	struct dt_device	*bi_next;
	wait_queue_head_t	 bi_waitq;
	rwlock_t		 bi_rwlock;
	struct percpu_counter	 bi_writers;
	atomic_t		 bi_ref;
	time64_t		 bi_deadline;
	__u32			 bi_status;
};

static inline char *barrier_barrier2name(struct barrier_instance *barrier)
{
	return barrier->bi_bottom->dd_lu_dev.ld_obd->obd_name;
}

static inline __u32 barrier_dev_idx(struct barrier_instance *barrier)
{
	return lu_site2seq(barrier->bi_bottom->dd_lu_dev.ld_site)->ss_node_id;
}

static void barrier_instance_cleanup(struct barrier_instance *barrier)
{
	LASSERT(list_empty(&barrier->bi_link));

	percpu_counter_destroy(&barrier->bi_writers);
	OBD_FREE_PTR(barrier);
}

static inline void barrier_instance_put(struct barrier_instance *barrier)
{
	if (atomic_dec_and_test(&barrier->bi_ref))
		barrier_instance_cleanup(barrier);
}

static struct barrier_instance *
barrier_instance_find_locked(struct dt_device *key)
{
	struct barrier_instance *barrier;

	list_for_each_entry(barrier, &barrier_instance_list, bi_link) {
		if (barrier->bi_bottom == key)
			return barrier;
	}

	return NULL;
}

static void barrier_instance_add(struct barrier_instance *barrier)
{
	struct barrier_instance *tmp;

	spin_lock(&barrier_instance_lock);
	tmp = barrier_instance_find_locked(barrier->bi_bottom);
	LASSERT(!tmp);

	list_add_tail(&barrier->bi_link, &barrier_instance_list);
	spin_unlock(&barrier_instance_lock);
}

static struct barrier_instance *barrier_instance_find(struct dt_device *key)
{
	struct barrier_instance *barrier;

	spin_lock(&barrier_instance_lock);
	barrier = barrier_instance_find_locked(key);
	if (barrier)
		atomic_inc(&barrier->bi_ref);
	spin_unlock(&barrier_instance_lock);

	return barrier;
}

static void barrier_set(struct barrier_instance *barrier, __u32 status)
{
	if (barrier->bi_status != status) {
		CDEBUG(D_SNAPSHOT, "%s: change barrier status from %u to %u\n",
		       barrier_barrier2name(barrier),
		       barrier->bi_status, status);

		barrier->bi_status = status;
	}
}

/**
 * Create the barrier for the given instance.
 *
 * We use two-phases barrier to guarantee that after the barrier setup:
 * 1) All the MDT side pending async modification have been flushed.
 * 2) Any subsequent modification will be blocked.
 * 3) All async transactions on the MDTs have been committed.
 *
 * For phase1, we do the following:
 *
 * Firstly, it sets barrier flag on the instance that will block subsequent
 * modifications from clients. (Note: server sponsored modification will be
 * allowed for flush pending modifications)
 *
 * Secondly, it will flush all pending modification via dt_sync(), such as
 * async OST-object destroy, async OST-object owner changes, and so on.
 *
 * If there are some on-handling clients sponsored modifications during the
 * barrier freezing, then related modifications may cause pending requests
 * after the first dt_sync(), so call dt_sync() again after all on-handling
 * modifications done.
 *
 * With the phase1 barrier set, all pending cross-servers modification have
 * been flushed to remote servers, and any new modification will be blocked.
 * But it does not guarantees that all the updates have been committed to
 * storage on remote servers. So when all the instances have done phase1
 * barrier successfully, the MGS will notify all instances to do the phase2
 * barrier as following:
 *
 * Every barrier instance will call dt_sync() to make all async transactions
 * to be committed locally.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] barrier	pointer to the barrier instance
 * \param[in] phase1	indicate whether it is phase1 barrier or not
 *
 * \retval		positive number for timeout
 * \retval		0 for success
 * \retval		negative error number on failure
 */
static int barrier_freeze(const struct lu_env *env,
			  struct barrier_instance *barrier, bool phase1)
{
	time64_t left;
	int rc = 0;
	__s64 inflight = 0;
	ENTRY;

	write_lock(&barrier->bi_rwlock);
	barrier_set(barrier, phase1 ? BS_FREEZING_P1 : BS_FREEZING_P2);

	/* Avoid out-of-order execution the barrier_set()
	 * and the check of inflight modifications count. */
	smp_mb();

	if (phase1)
		inflight = percpu_counter_sum(&barrier->bi_writers);
	write_unlock(&barrier->bi_rwlock);

	rc = dt_sync(env, barrier->bi_next);
	if (rc)
		RETURN(rc);

	LASSERT(barrier->bi_deadline != 0);

	left = barrier->bi_deadline - ktime_get_real_seconds();
	if (left <= 0)
		RETURN(1);

	if (phase1 && inflight != 0) {
		struct l_wait_info lwi = LWI_TIMEOUT(cfs_time_seconds(left),
						     NULL, NULL);

		rc = l_wait_event(barrier->bi_waitq,
				  percpu_counter_sum(&barrier->bi_writers) == 0,
				  &lwi);
		if (rc)
			RETURN(1);

		/* sync again after all inflight modifications done. */
		rc = dt_sync(env, barrier->bi_next);
		if (rc)
			RETURN(rc);

		if (ktime_get_real_seconds() > barrier->bi_deadline)
			RETURN(1);
	}

	CDEBUG(D_SNAPSHOT, "%s: barrier freezing %s done.\n",
	       barrier_barrier2name(barrier), phase1 ? "phase1" : "phase2");

	if (!phase1)
		barrier_set(barrier, BS_FROZEN);

	RETURN(0);
}

void barrier_init(void)
{
}

void barrier_fini(void)
{
	LASSERT(list_empty(&barrier_instance_list));
}

bool barrier_entry(struct dt_device *key)
{
	struct barrier_instance *barrier;
	bool entered = false;
	ENTRY;

	barrier = barrier_instance_find(key);
	if (unlikely(!barrier))
		/* Fail open */
		RETURN(true);

	read_lock(&barrier->bi_rwlock);
	if (likely(barrier->bi_status != BS_FREEZING_P1 &&
		   barrier->bi_status != BS_FREEZING_P2 &&
		   barrier->bi_status != BS_FROZEN) ||
	    ktime_get_real_seconds() > barrier->bi_deadline) {
		percpu_counter_inc(&barrier->bi_writers);
		entered = true;
	}
	read_unlock(&barrier->bi_rwlock);

	barrier_instance_put(barrier);
	return entered;
}
EXPORT_SYMBOL(barrier_entry);

void barrier_exit(struct dt_device *key)
{
	struct barrier_instance *barrier;

	barrier = barrier_instance_find(key);
	if (likely(barrier)) {
		percpu_counter_dec(&barrier->bi_writers);

		/* Avoid out-of-order execution the decreasing inflight
		 * modifications count and the check of barrier status. */
		smp_mb();

		if (unlikely(barrier->bi_status == BS_FREEZING_P1))
			wake_up_all(&barrier->bi_waitq);
		barrier_instance_put(barrier);
	}
}
EXPORT_SYMBOL(barrier_exit);

int barrier_handler(struct dt_device *key, struct ptlrpc_request *req)
{
	struct ldlm_gl_barrier_desc *desc;
	struct barrier_instance *barrier;
	struct barrier_lvb *lvb;
	struct lu_env env;
	int rc = 0;
	ENTRY;

	/* glimpse on barrier locks always packs a glimpse descriptor */
	req_capsule_extend(&req->rq_pill, &RQF_LDLM_GL_CALLBACK_DESC);
	desc = req_capsule_client_get(&req->rq_pill, &RMF_DLM_GL_DESC);
	if (!desc)
		GOTO(out, rc = -EPROTO);

	req_capsule_set_size(&req->rq_pill, &RMF_DLM_LVB, RCL_SERVER,
			      sizeof(struct barrier_lvb));
	rc = req_capsule_server_pack(&req->rq_pill);
	if (rc)
		GOTO(out, rc);

	lvb = req_capsule_server_get(&req->rq_pill, &RMF_DLM_LVB);
	barrier = barrier_instance_find(key);
	if (!barrier)
		GOTO(out, rc = -ENODEV);

	rc = lu_env_init(&env, LCT_MD_THREAD | LCT_DT_THREAD);
	if (rc)
		GOTO(out_barrier, rc);

	CDEBUG(D_SNAPSHOT,
	       "%s: handling barrier request: status %u, timeout %u\n",
	       barrier_barrier2name(barrier),
	       desc->lgbd_status, desc->lgbd_timeout);

	switch (desc->lgbd_status) {
	case BS_RESCAN:
		barrier_set(barrier, BS_INIT);
		break;
	case BS_FREEZING_P1:
	case BS_FREEZING_P2:
		if (OBD_FAIL_CHECK(OBD_FAIL_BARRIER_FAILURE))
			GOTO(fini, rc = -EINVAL);

		barrier->bi_deadline = ktime_get_real_seconds() +
				       desc->lgbd_timeout;
		rc = barrier_freeze(&env, barrier,
				    desc->lgbd_status == BS_FREEZING_P1);
		break;
	case BS_THAWING:
	case BS_FAILED:
	case BS_EXPIRED:
		barrier_set(barrier, BS_THAWED);
		break;
	default:
		CWARN("%s: unexpected barrier status %u\n",
		      barrier_barrier2name(barrier), desc->lgbd_status);
		rc = -EINVAL;
		break;
	}

	GOTO(fini, rc);

fini:
	lu_env_fini(&env);

out_barrier:
	if (rc < 0)
		barrier_set(barrier, BS_FAILED);
	else if (rc > 0)
		barrier_set(barrier, BS_EXPIRED);

	lvb->lvb_status = barrier->bi_status;
	lvb->lvb_index = barrier_dev_idx(barrier);

	CDEBUG(D_SNAPSHOT, "%s: handled barrier request: status %u, "
	       "deadline %lld: rc = %d\n", barrier_barrier2name(barrier),
	       lvb->lvb_status, barrier->bi_deadline, rc);

	barrier_instance_put(barrier);
	rc = 0;

out:
	req->rq_status = rc;
	return rc;
}
EXPORT_SYMBOL(barrier_handler);

int barrier_register(struct dt_device *key, struct dt_device *next)
{
	struct barrier_instance	*barrier;
	int rc;
	ENTRY;

	OBD_ALLOC_PTR(barrier);
	if (!barrier)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&barrier->bi_link);
	barrier->bi_bottom = key;
	barrier->bi_next = next;
	init_waitqueue_head(&barrier->bi_waitq);
	rwlock_init(&barrier->bi_rwlock);
	atomic_set(&barrier->bi_ref, 1);
#ifdef HAVE_PERCPU_COUNTER_INIT_GFP_FLAG
	rc = percpu_counter_init(&barrier->bi_writers, 0, GFP_KERNEL);
#else
	rc = percpu_counter_init(&barrier->bi_writers, 0);
#endif
	if (rc)
		barrier_instance_cleanup(barrier);
	else
		barrier_instance_add(barrier);

	RETURN(rc);
}
EXPORT_SYMBOL(barrier_register);

void barrier_deregister(struct dt_device *key)
{
	struct barrier_instance *barrier;

	spin_lock(&barrier_instance_lock);
	barrier = barrier_instance_find_locked(key);
	if (barrier)
		list_del_init(&barrier->bi_link);
	spin_unlock(&barrier_instance_lock);

	if (barrier)
		barrier_instance_put(barrier);
}
EXPORT_SYMBOL(barrier_deregister);
