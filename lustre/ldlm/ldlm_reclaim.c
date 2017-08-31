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
 * Copyright (c) 2015, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Niu    Yawei    <yawei.niu@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/kthread.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include "ldlm_internal.h"

/*
 * To avoid ldlm lock exhausting server memory, two global parameters:
 * ldlm_reclaim_threshold & ldlm_lock_limit are used for reclaiming
 * granted locks and rejecting incoming enqueue requests defensively.
 *
 * ldlm_reclaim_threshold: When the amount of granted locks reaching this
 * threshold, server start to revoke locks gradually.
 *
 * ldlm_lock_limit: When the amount of granted locks reaching this
 * threshold, server will return -EINPROGRESS to any incoming enqueue
 * request until the lock count is shrunk below the threshold again.
 *
 * ldlm_reclaim_threshold & ldlm_lock_limit is set to 20% & 30% of the
 * total memory by default. It is tunable via proc entry, when it's set
 * to 0, the feature is disabled.
 */

#ifdef HAVE_SERVER_SUPPORT

/* Lock count is stored in ldlm_reclaim_threshold & ldlm_lock_limit */
__u64 ldlm_reclaim_threshold;
__u64 ldlm_lock_limit;

/* Represents ldlm_reclaim_threshold & ldlm_lock_limit in MB, used for
 * proc interface. */
__u64 ldlm_reclaim_threshold_mb;
__u64 ldlm_lock_limit_mb;

struct percpu_counter		ldlm_granted_total;
static atomic_t			ldlm_nr_reclaimer;
static s64			ldlm_last_reclaim_age_ns;
static ktime_t			ldlm_last_reclaim_time;

struct ldlm_reclaim_cb_data {
	struct list_head	 rcd_rpc_list;
	int			 rcd_added;
	int			 rcd_total;
	int			 rcd_cursor;
	int			 rcd_start;
	bool			 rcd_skip;
	s64			 rcd_age_ns;
	struct cfs_hash_bd	*rcd_prev_bd;
};

static inline bool ldlm_lock_reclaimable(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	/* FLOCK & PLAIN lock are not reclaimable. FLOCK is
	 * explicitly controlled by application, PLAIN lock
	 * is used by quota global lock and config lock.
	 */
	if (ns->ns_client == LDLM_NAMESPACE_SERVER &&
	    (lock->l_resource->lr_type == LDLM_IBITS ||
	     lock->l_resource->lr_type == LDLM_EXTENT))
		return true;
	return false;
}

/**
 * Callback function for revoking locks from certain resource.
 *
 * \param [in] hs	ns_rs_hash
 * \param [in] bd	current bucket of ns_rsh_hash
 * \param [in] hnode	hnode of the resource
 * \param [in] arg	opaque data
 *
 * \retval 0		continue the scan
 * \retval 1		stop the iteration
 */
static int ldlm_reclaim_lock_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				struct hlist_node *hnode, void *arg)

{
	struct ldlm_resource		*res;
	struct ldlm_reclaim_cb_data	*data;
	struct ldlm_lock		*lock;
	struct ldlm_ns_bucket		*nsb;
	int				 rc = 0;

	data = (struct ldlm_reclaim_cb_data *)arg;

	LASSERTF(data->rcd_added < data->rcd_total, "added:%d >= total:%d\n",
		 data->rcd_added, data->rcd_total);

	nsb = cfs_hash_bd_extra_get(hs, bd);
	res = cfs_hash_object(hs, hnode);

	if (data->rcd_prev_bd != bd) {
		if (data->rcd_prev_bd != NULL)
			ldlm_res_to_ns(res)->ns_reclaim_start++;
		data->rcd_prev_bd = bd;
		data->rcd_cursor = 0;
		data->rcd_start = nsb->nsb_reclaim_start %
				  cfs_hash_bd_count_get(bd);
	}

	if (data->rcd_skip && data->rcd_cursor < data->rcd_start) {
		data->rcd_cursor++;
		return 0;
	}

	nsb->nsb_reclaim_start++;

	lock_res(res);
	list_for_each_entry(lock, &res->lr_granted, l_res_link) {
		if (!ldlm_lock_reclaimable(lock))
			continue;

		if (!OBD_FAIL_CHECK(OBD_FAIL_LDLM_WATERMARK_LOW) &&
		    ktime_before(ktime_get(),
				 ktime_add_ns(lock->l_last_used,
					      data->rcd_age_ns)))
			continue;

		if (!ldlm_is_ast_sent(lock)) {
			ldlm_set_ast_sent(lock);
			LASSERT(list_empty(&lock->l_rk_ast));
			list_add(&lock->l_rk_ast, &data->rcd_rpc_list);
			LDLM_LOCK_GET(lock);
			if (++data->rcd_added == data->rcd_total) {
				rc = 1; /* stop the iteration */
				break;
			}
		}
	}
	unlock_res(res);

	return rc;
}

/**
 * Revoke locks from the resources of a namespace in a roundrobin
 * manner.
 *
 * \param[in] ns	namespace to do the lock revoke on
 * \param[in] count	count of lock to be revoked
 * \param[in] age	only revoke locks older than the 'age'
 * \param[in] skip	scan from the first lock on resource if the
 *			'skip' is false, otherwise, continue scan
 *			from the last scanned position
 * \param[out] count	count of lock still to be revoked
 */
static void ldlm_reclaim_res(struct ldlm_namespace *ns, int *count,
			     s64 age_ns, bool skip)
{
	struct ldlm_reclaim_cb_data	data;
	int				idx, type, start;
	ENTRY;

	LASSERT(*count != 0);

	if (ns->ns_obd) {
		type = server_name2index(ns->ns_obd->obd_name, &idx, NULL);
		if (type != LDD_F_SV_TYPE_MDT && type != LDD_F_SV_TYPE_OST) {
			EXIT;
			return;
		}
	}

	if (atomic_read(&ns->ns_bref) == 0) {
		EXIT;
		return;
	}

	INIT_LIST_HEAD(&data.rcd_rpc_list);
	data.rcd_added = 0;
	data.rcd_total = *count;
	data.rcd_age_ns = age_ns;
	data.rcd_skip = skip;
	data.rcd_prev_bd = NULL;
	start = ns->ns_reclaim_start % CFS_HASH_NBKT(ns->ns_rs_hash);

	cfs_hash_for_each_nolock(ns->ns_rs_hash, ldlm_reclaim_lock_cb, &data,
				 start);

	CDEBUG(D_DLMTRACE, "NS(%s): %d locks to be reclaimed, found %d/%d "
	       "locks.\n", ldlm_ns_name(ns), *count, data.rcd_added,
	       data.rcd_total);

	LASSERTF(*count >= data.rcd_added, "count:%d, added:%d\n", *count,
		 data.rcd_added);

	ldlm_run_ast_work(ns, &data.rcd_rpc_list, LDLM_WORK_REVOKE_AST);
	*count -= data.rcd_added;
	EXIT;
}

#define LDLM_RECLAIM_BATCH	512
#define LDLM_RECLAIM_AGE_MIN	(300 * NSEC_PER_SEC)
#define LDLM_RECLAIM_AGE_MAX	(LDLM_DEFAULT_MAX_ALIVE * NSEC_PER_SEC * 3 / 4)

static inline s64 ldlm_reclaim_age(void)
{
	s64 age_ns = ldlm_last_reclaim_age_ns;
	ktime_t now = ktime_get();
	ktime_t diff;

	diff = ktime_sub(now, ldlm_last_reclaim_time);
	age_ns += ktime_to_ns(diff);
	if (age_ns > LDLM_RECLAIM_AGE_MAX)
		age_ns = LDLM_RECLAIM_AGE_MAX;
	else if (age_ns < (LDLM_RECLAIM_AGE_MIN * 2))
		age_ns = LDLM_RECLAIM_AGE_MIN;
	return age_ns;
}

/**
 * Revoke certain amount of locks from all the server namespaces
 * in a roundrobin manner. Lock age is used to avoid reclaim on
 * the non-aged locks.
 */
static void ldlm_reclaim_ns(void)
{
	struct ldlm_namespace	*ns;
	int			 count = LDLM_RECLAIM_BATCH;
	int			 ns_nr, nr_processed;
	enum ldlm_side		 ns_cli = LDLM_NAMESPACE_SERVER;
	s64 age_ns;
	bool			 skip = true;
	ENTRY;

	if (!atomic_add_unless(&ldlm_nr_reclaimer, 1, 1)) {
		EXIT;
		return;
	}

	age_ns = ldlm_reclaim_age();
again:
	nr_processed = 0;
	ns_nr = ldlm_namespace_nr_read(ns_cli);
	while (count > 0 && nr_processed < ns_nr) {
		mutex_lock(ldlm_namespace_lock(ns_cli));

		if (list_empty(ldlm_namespace_list(ns_cli))) {
			mutex_unlock(ldlm_namespace_lock(ns_cli));
			goto out;
		}

		ns = ldlm_namespace_first_locked(ns_cli);
		ldlm_namespace_move_to_active_locked(ns, ns_cli);
		mutex_unlock(ldlm_namespace_lock(ns_cli));

		ldlm_reclaim_res(ns, &count, age_ns, skip);
		ldlm_namespace_put(ns);
		nr_processed++;
	}

	if (count > 0 && age_ns > LDLM_RECLAIM_AGE_MIN) {
		age_ns >>= 1;
		if (age_ns < (LDLM_RECLAIM_AGE_MIN * 2))
			age_ns = LDLM_RECLAIM_AGE_MIN;
		skip = false;
		goto again;
	}

	ldlm_last_reclaim_age_ns = age_ns;
	ldlm_last_reclaim_time = ktime_get();
out:
	atomic_add_unless(&ldlm_nr_reclaimer, -1, 0);
	EXIT;
}

void ldlm_reclaim_add(struct ldlm_lock *lock)
{
	if (!ldlm_lock_reclaimable(lock))
		return;
	percpu_counter_add(&ldlm_granted_total, 1);
	lock->l_last_used = ktime_get();
}

void ldlm_reclaim_del(struct ldlm_lock *lock)
{
	if (!ldlm_lock_reclaimable(lock))
		return;
	percpu_counter_sub(&ldlm_granted_total, 1);
}

/**
 * Check on the total granted locks: return true if it reaches the
 * high watermark (ldlm_lock_limit), otherwise return false; It also
 * triggers lock reclaim if the low watermark (ldlm_reclaim_threshold)
 * is reached.
 *
 * \retval true		high watermark reached.
 * \retval false	high watermark not reached.
 */
bool ldlm_reclaim_full(void)
{
	__u64 high = ldlm_lock_limit;
	__u64 low = ldlm_reclaim_threshold;

	if (low != 0 && OBD_FAIL_CHECK(OBD_FAIL_LDLM_WATERMARK_LOW))
		low = cfs_fail_val;

	if (low != 0 &&
	    percpu_counter_sum_positive(&ldlm_granted_total) > low)
		ldlm_reclaim_ns();

	if (high != 0 && OBD_FAIL_CHECK(OBD_FAIL_LDLM_WATERMARK_HIGH))
		high = cfs_fail_val;

	if (high != 0 &&
	    percpu_counter_sum_positive(&ldlm_granted_total) > high)
		return true;

	return false;
}

static inline __u64 ldlm_ratio2locknr(int ratio)
{
	__u64 locknr;

	locknr = ((__u64)NUM_CACHEPAGES << PAGE_SHIFT) * ratio;
	do_div(locknr, 100 * sizeof(struct ldlm_lock));

	return locknr;
}

static inline __u64 ldlm_locknr2mb(__u64 locknr)
{
	return (locknr * sizeof(struct ldlm_lock) + 512 * 1024) >> 20;
}

#define LDLM_WM_RATIO_LOW_DEFAULT	20
#define LDLM_WM_RATIO_HIGH_DEFAULT	30

int ldlm_reclaim_setup(void)
{
	atomic_set(&ldlm_nr_reclaimer, 0);

	ldlm_reclaim_threshold = ldlm_ratio2locknr(LDLM_WM_RATIO_LOW_DEFAULT);
	ldlm_reclaim_threshold_mb = ldlm_locknr2mb(ldlm_reclaim_threshold);
	ldlm_lock_limit = ldlm_ratio2locknr(LDLM_WM_RATIO_HIGH_DEFAULT);
	ldlm_lock_limit_mb = ldlm_locknr2mb(ldlm_lock_limit);

	ldlm_last_reclaim_age_ns = LDLM_RECLAIM_AGE_MAX;
	ldlm_last_reclaim_time = ktime_get();

#ifdef HAVE_PERCPU_COUNTER_INIT_GFP_FLAG
	return percpu_counter_init(&ldlm_granted_total, 0, GFP_KERNEL);
#else
	return percpu_counter_init(&ldlm_granted_total, 0);
#endif
}

void ldlm_reclaim_cleanup(void)
{
	percpu_counter_destroy(&ldlm_granted_total);
}

#else /* HAVE_SERVER_SUPPORT */

bool ldlm_reclaim_full(void)
{
	return false;
}

void ldlm_reclaim_add(struct ldlm_lock *lock)
{
}

void ldlm_reclaim_del(struct ldlm_lock *lock)
{
}

int ldlm_reclaim_setup(void)
{
	return 0;
}

void ldlm_reclaim_cleanup(void)
{
}

#endif /* HAVE_SERVER_SUPPORT */
