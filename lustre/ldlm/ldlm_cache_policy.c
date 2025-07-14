// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 *
 * Author: Keguang Xu <squalfof@gmail.com>
 */

 /*
  * This file implements client lock cache policies for LDLM.
  * Currently supported policies:
  * - LRU (Least Recently Used)
  * - LFRU (Least Frequently and Recently Used)
  */

 #define DEBUG_SUBSYSTEM S_LDLM

 #include <lustre_swab.h>
 #include <obd_class.h>

 #include "ldlm_internal.h"

/* ==================== Basic LRU Implementation ==================== */
static void ldlm_lru_add_lock(struct ldlm_namespace *ns,
			      struct ldlm_lock *lock)
{
	ns->ns_nr_unused++;
	list_add_tail(&lock->l_lru, &ns->ns_unused_normal_list);
	lock->l_lru_type = LRU_NORMAL_LIST;
}

static int ldlm_lru_remove_lock(struct ldlm_namespace *ns,
				struct ldlm_lock *lock)
{
	int rc = 0;

	if (!list_empty(&lock->l_lru)) {
		LASSERT(lock->l_resource->lr_type != LDLM_FLOCK);
		if (ns->ns_last_pos == &lock->l_lru)
			ns->ns_last_pos = lock->l_lru.prev;
		list_del_init(&lock->l_lru);
		LASSERT(ns->ns_nr_unused > 0);
		ns->ns_nr_unused--;
		rc = 1;
	}
	return rc;
}

struct ldlm_lock_cache_ops ldlm_lru_cache_ops = {
	.llco_add_lock = ldlm_lru_add_lock,
	.llco_remove_lock = ldlm_lru_remove_lock,
};

/* ==================== LFRU Implementation ==================== */

/*
 * The privileged threshold is updated under two conditions:
 * - A lock with a strictly higher score is encountered.
 * - The access count reaches the window size, using the maximum
 *   frequency (max_freq) within the window as a basis.
 *
 * About `max_freq`:
 * - It is used to gradually decrement the `priv_score` to adapting changing
 *   workflows. A large `priv_score` should not persist for too long, as this
 *   could prevent new valuable locks from being promoted.
 * - To pick the appropriate score, one reasonable choice is to collect the
 *   recent (within the time window) lock access counts, pick the largest
 *   value, take that as the `priv_score's next value.
 * Why largest? Too small threshold would incorrectly lead to less valuable
 * locks to be promoted.
 */
static void ldlm_check_and_adjust_lfru_thresh(struct ldlm_namespace *ns,
					      __u8 score)
{
	if (score > ns->ns_lfru_priv_score_threshold ||
	    score == LDLM_LFRU_PRIV_THRESH_CAP) {
		ns->ns_lfru_priv_score_threshold = score;
		ns->ns_lfru_max_freq = LDLM_LFRU_MIN_PRIV_THRESH;
		ns->ns_lfru_access_window_cnt = 0;
		return;
	}

	if (score > ns->ns_lfru_max_freq)
		ns->ns_lfru_max_freq = score;
	ns->ns_lfru_access_window_cnt++;
	/* Update priv thres based on max_freq */
	if (ns->ns_lfru_access_window_cnt == ns->ns_lfru_check_window_size) {
		ns->ns_lfru_priv_score_threshold = ns->ns_lfru_max_freq;
		ns->ns_lfru_max_freq = LDLM_LFRU_MIN_PRIV_THRESH;
		ns->ns_lfru_access_window_cnt = 0;
	} else if (ns->ns_lfru_access_window_cnt ==
		   ns->ns_lfru_check_window_size / 2) {
		/*
		 * Decay scores by a factor of 0.75 (arbitrary chosen) after
		 * a half-window to reduce the influence of older access
		 * patterns when calculating the new threshold.
		 */
		ns->ns_lfru_max_freq = ns->ns_lfru_max_freq * 3 / 4;
	}
}

static void ldlm_lfru_add_lock(struct ldlm_namespace *ns,
			       struct ldlm_lock *lock)
{
	bool was_priv = lock->l_lru_type == LRU_PRIV;
	bool new_priv = false;

	/* save the lock in privilege or normal list */
	ns->ns_nr_unused++;
	lock->l_lru_score = min_t(int, lock->l_lru_score + 1,
				  LDLM_LFRU_PRIV_THRESH_CAP);
	new_priv = !was_priv &&
		   (lock->l_lru_score > ns->ns_lfru_priv_score_threshold ||
		    lock->l_lru_score == LDLM_LFRU_PRIV_THRESH_CAP);
	/*
	 * Once a lock is promoted to privilege list, it should reside there
	 * until it's evicted by the LRU policy.
	 */
	if (was_priv || new_priv) {
		list_add_tail(&lock->l_lru, &ns->ns_unused_priv_list);
		ns->ns_nr_priv++;
		lock->l_lru_type = LRU_PRIV;
	} else {
		list_add_tail(&lock->l_lru, &ns->ns_unused_normal_list);
		lock->l_lru_type = LRU_NORMAL_LIST;
	}
	if (!was_priv)
		ldlm_check_and_adjust_lfru_thresh(ns, lock->l_lru_score);
}

static int ldlm_lfru_remove_lock(struct ldlm_namespace *ns,
				 struct ldlm_lock *lock)
{
	int rc = 0;

	rc = ldlm_lru_remove_lock(ns, lock);
	if (rc && lock->l_lru_type == LRU_PRIV) {
		LASSERT(ns->ns_nr_priv > 0);
		ns->ns_nr_priv--;
	}
	return rc;
}

static void ldlm_lfru_demote_lock(struct ldlm_namespace *ns,
				  struct ldlm_lock *lock)
{
	if ((lock->l_flags & LDLM_FL_NS_SRV)) {
		LASSERT(list_empty(&lock->l_lru));
		return;
	}
	/* remove from priv list first */
	LASSERT(lock->l_lru_type == LRU_PRIV);
	ldlm_lfru_remove_lock(ns, lock);
	/* add to normal list */
	ns->ns_nr_unused++;
	list_add_tail(&lock->l_lru, &ns->ns_unused_normal_list);
	lock->l_lru_type = LRU_NORMAL_LIST;
	lock->l_lru_score >>= 2;
}

/**
 * ldlm_lfru_priv_too_many: determine if priv lock count is too large
 *
 * TOO MANY criteria:
 * - priv count exceeds 1/8 of the default LRU size, and
 * - priv count exceeds 1/3 of the current cache size
 */
static inline bool ldlm_lfru_priv_too_many(struct ldlm_namespace *ns)
{
	return (ns->ns_nr_priv >= (LDLM_DEFAULT_LRU_SIZE >> 3)) &&
	       (ns->ns_nr_priv >=
		ns->ns_nr_unused * ns->ns_lfru_priv_ratio_limit_256 >> 8);
}

static int ldlm_lfru_try_batch_demote_locks(struct ldlm_namespace *ns,
					    int batch_size)
{
	struct ldlm_lock *lock, *temp;
	int target_evicts = batch_size;
	int evicts = 0;

	if (unlikely(list_empty(&ns->ns_unused_priv_list)))
		return 0;

	/* priv list has exceeded capacity threshold or not */
	if (target_evicts == LDLM_LFRU_PRIV_PER_ROUND_LIMIT &&
	    !ldlm_lfru_priv_too_many(ns))
		return 0;

	list_for_each_entry_safe(lock, temp, &ns->ns_unused_priv_list, l_lru) {
		if (evicts < target_evicts) {
			ldlm_lfru_demote_lock(ns, lock);
			evicts++;
		} else {
			break;
		}
	}

	return evicts;
}

struct ldlm_lock_cache_ops ldlm_lfru_cache_ops = {
	.llco_add_lock = ldlm_lfru_add_lock,
	.llco_remove_lock = ldlm_lfru_remove_lock,
	.llco_demote_lock = ldlm_lfru_demote_lock,
	.llco_try_batch_demote_locks = ldlm_lfru_try_batch_demote_locks,
};
