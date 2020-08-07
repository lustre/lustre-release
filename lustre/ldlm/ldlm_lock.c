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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2010, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_lock.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LDLM

#include <libcfs/libcfs.h>

#include <lustre_swab.h>
#include <obd_class.h>

#include "ldlm_internal.h"

struct kmem_cache *ldlm_glimpse_work_kmem;
EXPORT_SYMBOL(ldlm_glimpse_work_kmem);

/* lock types */
char *ldlm_lockname[] = {
	[0] = "--",
	[LCK_EX] = "EX",
	[LCK_PW] = "PW",
	[LCK_PR] = "PR",
	[LCK_CW] = "CW",
	[LCK_CR] = "CR",
	[LCK_NL] = "NL",
	[LCK_GROUP] = "GROUP",
	[LCK_COS] = "COS"
};
EXPORT_SYMBOL(ldlm_lockname);

char *ldlm_typename[] = {
	[LDLM_PLAIN] = "PLN",
	[LDLM_EXTENT] = "EXT",
	[LDLM_FLOCK] = "FLK",
	[LDLM_IBITS] = "IBT",
};

static ldlm_policy_wire_to_local_t ldlm_policy_wire_to_local[] = {
	[LDLM_PLAIN - LDLM_MIN_TYPE]  = ldlm_plain_policy_wire_to_local,
	[LDLM_EXTENT - LDLM_MIN_TYPE] = ldlm_extent_policy_wire_to_local,
	[LDLM_FLOCK - LDLM_MIN_TYPE]  = ldlm_flock_policy_wire_to_local,
	[LDLM_IBITS - LDLM_MIN_TYPE]  = ldlm_ibits_policy_wire_to_local,
};

static ldlm_policy_local_to_wire_t ldlm_policy_local_to_wire[] = {
	[LDLM_PLAIN - LDLM_MIN_TYPE]  = ldlm_plain_policy_local_to_wire,
	[LDLM_EXTENT - LDLM_MIN_TYPE] = ldlm_extent_policy_local_to_wire,
	[LDLM_FLOCK - LDLM_MIN_TYPE]  = ldlm_flock_policy_local_to_wire,
	[LDLM_IBITS - LDLM_MIN_TYPE]  = ldlm_ibits_policy_local_to_wire,
};

/**
 * Converts lock policy from local format to on the wire lock_desc format
 */
void ldlm_convert_policy_to_wire(enum ldlm_type type,
				 const union ldlm_policy_data *lpolicy,
				 union ldlm_wire_policy_data *wpolicy)
{
	ldlm_policy_local_to_wire_t convert;

	convert = ldlm_policy_local_to_wire[type - LDLM_MIN_TYPE];

	convert(lpolicy, wpolicy);
}

/**
 * Converts lock policy from on the wire lock_desc format to local format
 */
void ldlm_convert_policy_to_local(struct obd_export *exp, enum ldlm_type type,
				  const union ldlm_wire_policy_data *wpolicy,
				  union ldlm_policy_data *lpolicy)
{
	ldlm_policy_wire_to_local_t convert;

	convert = ldlm_policy_wire_to_local[type - LDLM_MIN_TYPE];

	convert(wpolicy, lpolicy);
}

const char *ldlm_it2str(enum ldlm_intent_flags it)
{
	switch (it) {
	case IT_OPEN:
		return "open";
	case IT_CREAT:
		return "creat";
	case (IT_OPEN | IT_CREAT):
		return "open|creat";
	case IT_READDIR:
		return "readdir";
	case IT_GETATTR:
		return "getattr";
	case IT_LOOKUP:
		return "lookup";
	case IT_GETXATTR:
		return "getxattr";
	case IT_LAYOUT:
		return "layout";
	default:
		CERROR("Unknown intent 0x%08x\n", it);
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL(ldlm_it2str);

extern struct kmem_cache *ldlm_lock_slab;

#ifdef HAVE_SERVER_SUPPORT
static ldlm_processing_policy ldlm_processing_policy_table[] = {
	[LDLM_PLAIN]	= ldlm_process_plain_lock,
	[LDLM_EXTENT]	= ldlm_process_extent_lock,
	[LDLM_FLOCK]	= ldlm_process_flock_lock,
	[LDLM_IBITS]	= ldlm_process_inodebits_lock,
};

ldlm_processing_policy ldlm_get_processing_policy(struct ldlm_resource *res)
{
        return ldlm_processing_policy_table[res->lr_type];
}
EXPORT_SYMBOL(ldlm_get_processing_policy);

static ldlm_reprocessing_policy ldlm_reprocessing_policy_table[] = {
	[LDLM_PLAIN]	= ldlm_reprocess_queue,
	[LDLM_EXTENT]	= ldlm_reprocess_queue,
	[LDLM_FLOCK]	= ldlm_reprocess_queue,
	[LDLM_IBITS]	= ldlm_reprocess_inodebits_queue,
};

ldlm_reprocessing_policy ldlm_get_reprocessing_policy(struct ldlm_resource *res)
{
	return ldlm_reprocessing_policy_table[res->lr_type];
}

#endif /* HAVE_SERVER_SUPPORT */

void ldlm_register_intent(struct ldlm_namespace *ns, ldlm_res_policy arg)
{
        ns->ns_policy = arg;
}
EXPORT_SYMBOL(ldlm_register_intent);

/*
 * REFCOUNTED LOCK OBJECTS
 */


/**
 * Get a reference on a lock.
 *
 * Lock refcounts, during creation:
 *   - one special one for allocation, dec'd only once in destroy
 *   - one for being a lock that's in-use
 *   - one for the addref associated with a new lock
 */
struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock)
{
	atomic_inc(&lock->l_refc);
        return lock;
}
EXPORT_SYMBOL(ldlm_lock_get);

/**
 * Release lock reference.
 *
 * Also frees the lock if it was last reference.
 */
void ldlm_lock_put(struct ldlm_lock *lock)
{
        ENTRY;

        LASSERT(lock->l_resource != LP_POISON);
	LASSERT(atomic_read(&lock->l_refc) > 0);
	if (atomic_dec_and_test(&lock->l_refc)) {
                struct ldlm_resource *res;

                LDLM_DEBUG(lock,
                           "final lock_put on destroyed lock, freeing it.");

                res = lock->l_resource;
		LASSERT(ldlm_is_destroyed(lock));
		LASSERT(list_empty(&lock->l_exp_list));
		LASSERT(list_empty(&lock->l_res_link));
		LASSERT(list_empty(&lock->l_pending_chain));

                lprocfs_counter_decr(ldlm_res_to_ns(res)->ns_stats,
                                     LDLM_NSS_LOCKS);
                lu_ref_del(&res->lr_reference, "lock", lock);
                if (lock->l_export) {
                        class_export_lock_put(lock->l_export, lock);
                        lock->l_export = NULL;
                }

                if (lock->l_lvb_data != NULL)
                        OBD_FREE_LARGE(lock->l_lvb_data, lock->l_lvb_len);

		if (res->lr_type == LDLM_EXTENT) {
			ldlm_interval_free(ldlm_interval_detach(lock));
		} else if (res->lr_type == LDLM_IBITS) {
			if (lock->l_ibits_node != NULL)
				OBD_SLAB_FREE_PTR(lock->l_ibits_node,
						  ldlm_inodebits_slab);
		}
		ldlm_resource_putref(res);
		lock->l_resource = NULL;
                lu_ref_fini(&lock->l_reference);
		OBD_FREE_RCU(lock, sizeof(*lock), &lock->l_handle);
        }

        EXIT;
}
EXPORT_SYMBOL(ldlm_lock_put);

/**
 * Removes LDLM lock \a lock from LRU. Assumes LRU is already locked.
 */
int ldlm_lock_remove_from_lru_nolock(struct ldlm_lock *lock)
{
	int rc = 0;
	if (!list_empty(&lock->l_lru)) {
		struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

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

/**
 * Removes LDLM lock \a lock from LRU. Obtains the LRU lock first.
 *
 * If \a last_use is non-zero, it will remove the lock from LRU only if
 * it matches lock's l_last_used.
 *
 * \retval 0 if \a last_use is set, the lock is not in LRU list or \a last_use
 *           doesn't match lock's l_last_used;
 *           otherwise, the lock hasn't been in the LRU list.
 * \retval 1 the lock was in LRU list and removed.
 */
int ldlm_lock_remove_from_lru_check(struct ldlm_lock *lock, ktime_t last_use)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);
	int rc = 0;

	ENTRY;
	if (ldlm_is_ns_srv(lock)) {
		LASSERT(list_empty(&lock->l_lru));
		RETURN(0);
	}

	spin_lock(&ns->ns_lock);
	if (!ktime_compare(last_use, ktime_set(0, 0)) ||
	    !ktime_compare(last_use, lock->l_last_used))
		rc = ldlm_lock_remove_from_lru_nolock(lock);
	spin_unlock(&ns->ns_lock);

	RETURN(rc);
}

/**
 * Adds LDLM lock \a lock to namespace LRU. Assumes LRU is already locked.
 */
void ldlm_lock_add_to_lru_nolock(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	lock->l_last_used = ktime_get();
	LASSERT(list_empty(&lock->l_lru));
	LASSERT(lock->l_resource->lr_type != LDLM_FLOCK);
	list_add_tail(&lock->l_lru, &ns->ns_unused_list);
	LASSERT(ns->ns_nr_unused >= 0);
	ns->ns_nr_unused++;
}

/**
 * Adds LDLM lock \a lock to namespace LRU. Obtains necessary LRU locks
 * first.
 */
void ldlm_lock_add_to_lru(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	ENTRY;
	spin_lock(&ns->ns_lock);
	ldlm_lock_add_to_lru_nolock(lock);
	spin_unlock(&ns->ns_lock);
	EXIT;
}

/**
 * Moves LDLM lock \a lock that is already in namespace LRU to the tail of
 * the LRU. Performs necessary LRU locking
 */
void ldlm_lock_touch_in_lru(struct ldlm_lock *lock)
{
	struct ldlm_namespace *ns = ldlm_lock_to_ns(lock);

	ENTRY;
	if (ldlm_is_ns_srv(lock)) {
		LASSERT(list_empty(&lock->l_lru));
		EXIT;
		return;
	}

	spin_lock(&ns->ns_lock);
	if (!list_empty(&lock->l_lru)) {
		ldlm_lock_remove_from_lru_nolock(lock);
		ldlm_lock_add_to_lru_nolock(lock);
	}
	spin_unlock(&ns->ns_lock);
	EXIT;
}

/**
 * Helper to destroy a locked lock.
 *
 * Used by ldlm_lock_destroy and ldlm_lock_destroy_nolock
 * Must be called with l_lock and lr_lock held.
 *
 * Does not actually free the lock data, but rather marks the lock as
 * destroyed by setting l_destroyed field in the lock to 1.  Destroys a
 * handle->lock association too, so that the lock can no longer be found
 * and removes the lock from LRU list.  Actual lock freeing occurs when
 * last lock reference goes away.
 *
 * Original comment (of some historical value):
 * This used to have a 'strict' flag, which recovery would use to mark an
 * in-use lock as needing-to-die.  Lest I am ever tempted to put it back, I
 * shall explain why it's gone: with the new hash table scheme, once you call
 * ldlm_lock_destroy, you can never drop your final references on this lock.
 * Because it's not in the hash table anymore.  -phil
 */
static int ldlm_lock_destroy_internal(struct ldlm_lock *lock)
{
        ENTRY;

        if (lock->l_readers || lock->l_writers) {
                LDLM_ERROR(lock, "lock still has references");
                LBUG();
        }

	if (!list_empty(&lock->l_res_link)) {
                LDLM_ERROR(lock, "lock still on resource");
                LBUG();
        }

	if (ldlm_is_destroyed(lock)) {
		LASSERT(list_empty(&lock->l_lru));
		EXIT;
		return 0;
	}
	ldlm_set_destroyed(lock);

	if (lock->l_export && lock->l_export->exp_lock_hash) {
		/* NB: it's safe to call cfs_hash_del() even lock isn't
		 * in exp_lock_hash. */
		/* In the function below, .hs_keycmp resolves to
		 * ldlm_export_lock_keycmp() */
		/* coverity[overrun-buffer-val] */
		cfs_hash_del(lock->l_export->exp_lock_hash,
			     &lock->l_remote_handle, &lock->l_exp_hash);
	}

        ldlm_lock_remove_from_lru(lock);
        class_handle_unhash(&lock->l_handle);

        EXIT;
        return 1;
}

/**
 * Destroys a LDLM lock \a lock. Performs necessary locking first.
 */
void ldlm_lock_destroy(struct ldlm_lock *lock)
{
        int first;
        ENTRY;
        lock_res_and_lock(lock);
        first = ldlm_lock_destroy_internal(lock);
        unlock_res_and_lock(lock);

        /* drop reference from hashtable only for first destroy */
        if (first) {
                lu_ref_del(&lock->l_reference, "hash", lock);
                LDLM_LOCK_RELEASE(lock);
        }
        EXIT;
}

/**
 * Destroys a LDLM lock \a lock that is already locked.
 */
void ldlm_lock_destroy_nolock(struct ldlm_lock *lock)
{
        int first;
        ENTRY;
        first = ldlm_lock_destroy_internal(lock);
        /* drop reference from hashtable only for first destroy */
        if (first) {
                lu_ref_del(&lock->l_reference, "hash", lock);
                LDLM_LOCK_RELEASE(lock);
        }
        EXIT;
}

/* this is called by portals_handle2object with the handle lock taken */
static void lock_handle_addref(void *lock)
{
        LDLM_LOCK_GET((struct ldlm_lock *)lock);
}

static void lock_handle_free(void *lock, int size)
{
	LASSERT(size == sizeof(struct ldlm_lock));
	OBD_SLAB_FREE(lock, ldlm_lock_slab, size);
}

static struct portals_handle_ops lock_handle_ops = {
	.hop_addref = lock_handle_addref,
	.hop_free   = lock_handle_free,
};

/**
 *
 * Allocate and initialize new lock structure.
 *
 * usage: pass in a resource on which you have done ldlm_resource_get
 *        new lock will take over the refcount.
 * returns: lock with refcount 2 - one for current caller and one for remote
 */
static struct ldlm_lock *ldlm_lock_new(struct ldlm_resource *resource)
{
	struct ldlm_lock *lock;
	ENTRY;

	if (resource == NULL)
		LBUG();

	OBD_SLAB_ALLOC_PTR_GFP(lock, ldlm_lock_slab, GFP_NOFS);
	if (lock == NULL)
		RETURN(NULL);

	spin_lock_init(&lock->l_lock);
	lock->l_resource = resource;
	lu_ref_add(&resource->lr_reference, "lock", lock);

	atomic_set(&lock->l_refc, 2);
	INIT_LIST_HEAD(&lock->l_res_link);
	INIT_LIST_HEAD(&lock->l_lru);
	INIT_LIST_HEAD(&lock->l_pending_chain);
	INIT_LIST_HEAD(&lock->l_bl_ast);
	INIT_LIST_HEAD(&lock->l_cp_ast);
	INIT_LIST_HEAD(&lock->l_rk_ast);
	init_waitqueue_head(&lock->l_waitq);
	lock->l_blocking_lock = NULL;
	INIT_LIST_HEAD(&lock->l_sl_mode);
	INIT_LIST_HEAD(&lock->l_sl_policy);
	INIT_HLIST_NODE(&lock->l_exp_hash);
	INIT_HLIST_NODE(&lock->l_exp_flock_hash);

        lprocfs_counter_incr(ldlm_res_to_ns(resource)->ns_stats,
                             LDLM_NSS_LOCKS);
	INIT_LIST_HEAD_RCU(&lock->l_handle.h_link);
	class_handle_hash(&lock->l_handle, &lock_handle_ops);

        lu_ref_init(&lock->l_reference);
        lu_ref_add(&lock->l_reference, "hash", lock);
        lock->l_callback_timeout = 0;
	lock->l_activity = 0;

#if LUSTRE_TRACKS_LOCK_EXP_REFS
	INIT_LIST_HEAD(&lock->l_exp_refs_link);
        lock->l_exp_refs_nr = 0;
        lock->l_exp_refs_target = NULL;
#endif
	INIT_LIST_HEAD(&lock->l_exp_list);

        RETURN(lock);
}

/**
 * Moves LDLM lock \a lock to another resource.
 * This is used on client when server returns some other lock than requested
 * (typically as a result of intent operation)
 */
int ldlm_lock_change_resource(struct ldlm_namespace *ns, struct ldlm_lock *lock,
                              const struct ldlm_res_id *new_resid)
{
        struct ldlm_resource *oldres = lock->l_resource;
        struct ldlm_resource *newres;
        int type;
        ENTRY;

        LASSERT(ns_is_client(ns));

        lock_res_and_lock(lock);
        if (memcmp(new_resid, &lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) == 0) {
                /* Nothing to do */
                unlock_res_and_lock(lock);
                RETURN(0);
        }

        LASSERT(new_resid->name[0] != 0);

        /* This function assumes that the lock isn't on any lists */
	LASSERT(list_empty(&lock->l_res_link));

        type = oldres->lr_type;
        unlock_res_and_lock(lock);

	newres = ldlm_resource_get(ns, NULL, new_resid, type, 1);
	if (IS_ERR(newres))
		RETURN(PTR_ERR(newres));

        lu_ref_add(&newres->lr_reference, "lock", lock);
        /*
         * To flip the lock from the old to the new resource, lock, oldres and
         * newres have to be locked. Resource spin-locks are nested within
         * lock->l_lock, and are taken in the memory address order to avoid
         * dead-locks.
         */
	spin_lock(&lock->l_lock);
        oldres = lock->l_resource;
        if (oldres < newres) {
                lock_res(oldres);
                lock_res_nested(newres, LRT_NEW);
        } else {
                lock_res(newres);
                lock_res_nested(oldres, LRT_NEW);
        }
        LASSERT(memcmp(new_resid, &oldres->lr_name,
                       sizeof oldres->lr_name) != 0);
        lock->l_resource = newres;
        unlock_res(oldres);
        unlock_res_and_lock(lock);

        /* ...and the flowers are still standing! */
        lu_ref_del(&oldres->lr_reference, "lock", lock);
        ldlm_resource_putref(oldres);

        RETURN(0);
}

/** \defgroup ldlm_handles LDLM HANDLES
 * Ways to get hold of locks without any addresses.
 * @{
 */

/**
 * Fills in handle for LDLM lock \a lock into supplied \a lockh
 * Does not take any references.
 */
void ldlm_lock2handle(const struct ldlm_lock *lock, struct lustre_handle *lockh)
{
	lockh->cookie = lock->l_handle.h_cookie;
}
EXPORT_SYMBOL(ldlm_lock2handle);

/**
 * Obtain a lock reference by handle.
 *
 * if \a flags: atomically get the lock and set the flags.
 *              Return NULL if flag already set
 */
struct ldlm_lock *__ldlm_handle2lock(const struct lustre_handle *handle,
				     __u64 flags)
{
	struct ldlm_lock *lock;
	ENTRY;

	LASSERT(handle);

	lock = class_handle2object(handle->cookie, NULL);
	if (lock == NULL)
		RETURN(NULL);

	if (lock->l_export != NULL && lock->l_export->exp_failed) {
		CDEBUG(D_INFO, "lock export failed: lock %p, exp %p\n",
		       lock, lock->l_export);
		LDLM_LOCK_PUT(lock);
		RETURN(NULL);
	}

	/* It's unlikely but possible that someone marked the lock as
	 * destroyed after we did handle2object on it */
	if ((flags == 0) && !ldlm_is_destroyed(lock)) {
		lu_ref_add(&lock->l_reference, "handle", current);
		RETURN(lock);
	}

	lock_res_and_lock(lock);

	LASSERT(lock->l_resource != NULL);

	lu_ref_add_atomic(&lock->l_reference, "handle", current);
	if (unlikely(ldlm_is_destroyed(lock))) {
		unlock_res_and_lock(lock);
		CDEBUG(D_INFO, "lock already destroyed: lock %p\n", lock);
		LDLM_LOCK_PUT(lock);
		RETURN(NULL);
	}

	/* If we're setting flags, make sure none of them are already set. */
	if (flags != 0) {
		if ((lock->l_flags & flags) != 0) {
			unlock_res_and_lock(lock);
			LDLM_LOCK_PUT(lock);
			RETURN(NULL);
		}

		lock->l_flags |= flags;
	}

	unlock_res_and_lock(lock);
	RETURN(lock);
}
EXPORT_SYMBOL(__ldlm_handle2lock);
/** @} ldlm_handles */

/**
 * Fill in "on the wire" representation for given LDLM lock into supplied
 * lock descriptor \a desc structure.
 */
void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
	ldlm_res2desc(lock->l_resource, &desc->l_resource);
	desc->l_req_mode = lock->l_req_mode;
	desc->l_granted_mode = lock->l_granted_mode;
	ldlm_convert_policy_to_wire(lock->l_resource->lr_type,
				    &lock->l_policy_data,
				    &desc->l_policy_data);
}

/**
 * Add a lock to list of conflicting locks to send AST to.
 *
 * Only add if we have not sent a blocking AST to the lock yet.
 */
static void ldlm_add_bl_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
				  struct list_head *work_list)
{
	if (!ldlm_is_ast_sent(lock)) {
		LDLM_DEBUG(lock, "lock incompatible; sending blocking AST.");
		ldlm_set_ast_sent(lock);
		/* If the enqueuing client said so, tell the AST recipient to
		 * discard dirty data, rather than writing back. */
		if (ldlm_is_ast_discard_data(new))
			ldlm_set_discard_data(lock);

		/* Lock can be converted from a blocking state back to granted
		 * after lock convert or COS downgrade but still be in an
		 * older bl_list because it is controlled only by
		 * ldlm_work_bl_ast_lock(), let it be processed there.
		 */
		if (list_empty(&lock->l_bl_ast)) {
			list_add(&lock->l_bl_ast, work_list);
			LDLM_LOCK_GET(lock);
		}
		LASSERT(lock->l_blocking_lock == NULL);
		lock->l_blocking_lock = LDLM_LOCK_GET(new);
	}
}

/**
 * Add a lock to list of just granted locks to send completion AST to.
 */
static void ldlm_add_cp_work_item(struct ldlm_lock *lock,
				  struct list_head *work_list)
{
	if (!ldlm_is_cp_reqd(lock)) {
		ldlm_set_cp_reqd(lock);
                LDLM_DEBUG(lock, "lock granted; sending completion AST.");
		LASSERT(list_empty(&lock->l_cp_ast));
		list_add(&lock->l_cp_ast, work_list);
                LDLM_LOCK_GET(lock);
        }
}

/**
 * Aggregator function to add AST work items into a list. Determines
 * what sort of an AST work needs to be done and calls the proper
 * adding function.
 * Must be called with lr_lock held.
 */
void ldlm_add_ast_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
			    struct list_head *work_list)
{
        ENTRY;
        check_res_locked(lock->l_resource);
        if (new)
                ldlm_add_bl_work_item(lock, new, work_list);
        else
                ldlm_add_cp_work_item(lock, work_list);
        EXIT;
}

/**
 * Add specified reader/writer reference to LDLM lock with handle \a lockh.
 * r/w reference type is determined by \a mode
 * Calls ldlm_lock_addref_internal.
 */
void ldlm_lock_addref(const struct lustre_handle *lockh, enum ldlm_mode mode)
{
	struct ldlm_lock *lock;

	lock = ldlm_handle2lock(lockh);
	LASSERTF(lock != NULL, "Non-existing lock: %#llx\n", lockh->cookie);
	ldlm_lock_addref_internal(lock, mode);
	LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_addref);

/**
 * Helper function.
 * Add specified reader/writer reference to LDLM lock \a lock.
 * r/w reference type is determined by \a mode
 * Removes lock from LRU if it is there.
 * Assumes the LDLM lock is already locked.
 */
void ldlm_lock_addref_internal_nolock(struct ldlm_lock *lock,
				      enum ldlm_mode mode)
{
        ldlm_lock_remove_from_lru(lock);
        if (mode & (LCK_NL | LCK_CR | LCK_PR)) {
                lock->l_readers++;
                lu_ref_add_atomic(&lock->l_reference, "reader", lock);
        }
        if (mode & (LCK_EX | LCK_CW | LCK_PW | LCK_GROUP | LCK_COS)) {
                lock->l_writers++;
                lu_ref_add_atomic(&lock->l_reference, "writer", lock);
        }
        LDLM_LOCK_GET(lock);
        lu_ref_add_atomic(&lock->l_reference, "user", lock);
        LDLM_DEBUG(lock, "ldlm_lock_addref(%s)", ldlm_lockname[mode]);
}

/**
 * Attempts to add reader/writer reference to a lock with handle \a lockh, and
 * fails if lock is already LDLM_FL_CBPENDING or destroyed.
 *
 * \retval 0 success, lock was addref-ed
 *
 * \retval -EAGAIN lock is being canceled.
 */
int ldlm_lock_addref_try(const struct lustre_handle *lockh, enum ldlm_mode mode)
{
        struct ldlm_lock *lock;
        int               result;

        result = -EAGAIN;
        lock = ldlm_handle2lock(lockh);
        if (lock != NULL) {
                lock_res_and_lock(lock);
                if (lock->l_readers != 0 || lock->l_writers != 0 ||
		    !ldlm_is_cbpending(lock)) {
                        ldlm_lock_addref_internal_nolock(lock, mode);
                        result = 0;
                }
                unlock_res_and_lock(lock);
                LDLM_LOCK_PUT(lock);
        }
        return result;
}
EXPORT_SYMBOL(ldlm_lock_addref_try);

/**
 * Add specified reader/writer reference to LDLM lock \a lock.
 * Locks LDLM lock and calls ldlm_lock_addref_internal_nolock to do the work.
 * Only called for local locks.
 */
void ldlm_lock_addref_internal(struct ldlm_lock *lock, enum ldlm_mode mode)
{
	lock_res_and_lock(lock);
	ldlm_lock_addref_internal_nolock(lock, mode);
	unlock_res_and_lock(lock);
}

/**
 * Removes reader/writer reference for LDLM lock \a lock.
 * Assumes LDLM lock is already locked.
 * only called in ldlm_flock_destroy and for local locks.
 * Does NOT add lock to LRU if no r/w references left to accomodate flock locks
 * that cannot be placed in LRU.
 */
void ldlm_lock_decref_internal_nolock(struct ldlm_lock *lock,
				      enum ldlm_mode mode)
{
        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        if (mode & (LCK_NL | LCK_CR | LCK_PR)) {
                LASSERT(lock->l_readers > 0);
                lu_ref_del(&lock->l_reference, "reader", lock);
                lock->l_readers--;
        }
        if (mode & (LCK_EX | LCK_CW | LCK_PW | LCK_GROUP | LCK_COS)) {
                LASSERT(lock->l_writers > 0);
                lu_ref_del(&lock->l_reference, "writer", lock);
                lock->l_writers--;
        }

        lu_ref_del(&lock->l_reference, "user", lock);
        LDLM_LOCK_RELEASE(lock);    /* matches the LDLM_LOCK_GET() in addref */
}

/**
 * Removes reader/writer reference for LDLM lock \a lock.
 * Locks LDLM lock first.
 * If the lock is determined to be client lock on a client and r/w refcount
 * drops to zero and the lock is not blocked, the lock is added to LRU lock
 * on the namespace.
 * For blocked LDLM locks if r/w count drops to zero, blocking_ast is called.
 */
void ldlm_lock_decref_internal(struct ldlm_lock *lock, enum ldlm_mode mode)
{
        struct ldlm_namespace *ns;
        ENTRY;

        lock_res_and_lock(lock);

        ns = ldlm_lock_to_ns(lock);

        ldlm_lock_decref_internal_nolock(lock, mode);

	if ((ldlm_is_local(lock) || lock->l_req_mode == LCK_GROUP) &&
	    !lock->l_readers && !lock->l_writers) {
		/* If this is a local lock on a server namespace and this was
		 * the last reference, cancel the lock.
		 *
		 * Group locks are special:
		 * They must not go in LRU, but they are not called back
		 * like non-group locks, instead they are manually released.
		 * They have an l_writers reference which they keep until
		 * they are manually released, so we remove them when they have
		 * no more reader or writer references. - LU-6368 */
		ldlm_set_cbpending(lock);
	}

	if (!lock->l_readers && !lock->l_writers && ldlm_is_cbpending(lock)) {
		/* If we received a blocked AST and this was the last reference,
		 * run the callback. */
		if (ldlm_is_ns_srv(lock) && lock->l_export)
                        CERROR("FL_CBPENDING set on non-local lock--just a "
                               "warning\n");

                LDLM_DEBUG(lock, "final decref done on cbpending lock");

                LDLM_LOCK_GET(lock); /* dropped by bl thread */
                ldlm_lock_remove_from_lru(lock);
                unlock_res_and_lock(lock);

		if (ldlm_is_fail_loc(lock))
                        OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

		if (ldlm_is_atomic_cb(lock) ||
                    ldlm_bl_to_thread_lock(ns, NULL, lock) != 0)
                        ldlm_handle_bl_callback(ns, NULL, lock);
        } else if (ns_is_client(ns) &&
                   !lock->l_readers && !lock->l_writers &&
		   !ldlm_is_no_lru(lock) &&
		   !ldlm_is_bl_ast(lock) &&
		   !ldlm_is_converting(lock)) {

                LDLM_DEBUG(lock, "add lock into lru list");

                /* If this is a client-side namespace and this was the last
                 * reference, put it on the LRU. */
                ldlm_lock_add_to_lru(lock);
                unlock_res_and_lock(lock);

		if (ldlm_is_fail_loc(lock))
                        OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

                /* Call ldlm_cancel_lru() only if EARLY_CANCEL and LRU RESIZE
                 * are not supported by the server, otherwise, it is done on
                 * enqueue. */
                if (!exp_connect_cancelset(lock->l_conn_export) &&
                    !ns_connect_lru_resize(ns))
			ldlm_cancel_lru(ns, 0, LCF_ASYNC, 0);
        } else {
                LDLM_DEBUG(lock, "do not add lock into lru list");
                unlock_res_and_lock(lock);
        }

        EXIT;
}

/**
 * Decrease reader/writer refcount for LDLM lock with handle \a lockh
 */
void ldlm_lock_decref(const struct lustre_handle *lockh, enum ldlm_mode mode)
{
        struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);
	LASSERTF(lock != NULL, "Non-existing lock: %#llx\n", lockh->cookie);
        ldlm_lock_decref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_decref);

/**
 * Decrease reader/writer refcount for LDLM lock with handle
 * \a lockh and mark it for subsequent cancellation once r/w refcount
 * drops to zero instead of putting into LRU.
 *
 */
void ldlm_lock_decref_and_cancel(const struct lustre_handle *lockh,
				 enum ldlm_mode mode)
{
        struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);
        ENTRY;

        LASSERT(lock != NULL);

        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        lock_res_and_lock(lock);
	ldlm_set_cbpending(lock);
        unlock_res_and_lock(lock);
        ldlm_lock_decref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_decref_and_cancel);

struct sl_insert_point {
	struct list_head *res_link;
	struct list_head *mode_link;
	struct list_head *policy_link;
};

/**
 * Finds a position to insert the new lock into granted lock list.
 *
 * Used for locks eligible for skiplist optimization.
 *
 * Parameters:
 *      queue [input]:  the granted list where search acts on;
 *      req [input]:    the lock whose position to be located;
 *      prev [output]:  positions within 3 lists to insert @req to
 * Return Value:
 *      filled @prev
 * NOTE: called by
 *  - ldlm_grant_lock_with_skiplist
 */
static void search_granted_lock(struct list_head *queue,
                                struct ldlm_lock *req,
                                struct sl_insert_point *prev)
{
	struct list_head *tmp;
        struct ldlm_lock *lock, *mode_end, *policy_end;
        ENTRY;

	list_for_each(tmp, queue) {
		lock = list_entry(tmp, struct ldlm_lock, l_res_link);

		mode_end = list_entry(lock->l_sl_mode.prev,
                                          struct ldlm_lock, l_sl_mode);

                if (lock->l_req_mode != req->l_req_mode) {
                        /* jump to last lock of mode group */
                        tmp = &mode_end->l_res_link;
                        continue;
                }

                /* suitable mode group is found */
                if (lock->l_resource->lr_type == LDLM_PLAIN) {
                        /* insert point is last lock of the mode group */
                        prev->res_link = &mode_end->l_res_link;
                        prev->mode_link = &mode_end->l_sl_mode;
                        prev->policy_link = &req->l_sl_policy;
                        EXIT;
                        return;
                } else if (lock->l_resource->lr_type == LDLM_IBITS) {
                        for (;;) {
                                policy_end =
					list_entry(lock->l_sl_policy.prev,
                                                       struct ldlm_lock,
                                                       l_sl_policy);

                                if (lock->l_policy_data.l_inodebits.bits ==
                                    req->l_policy_data.l_inodebits.bits) {
                                        /* insert point is last lock of
                                         * the policy group */
                                        prev->res_link =
                                                &policy_end->l_res_link;
                                        prev->mode_link =
                                                &policy_end->l_sl_mode;
                                        prev->policy_link =
                                                &policy_end->l_sl_policy;
                                        EXIT;
                                        return;
                                }

                                if (policy_end == mode_end)
                                        /* done with mode group */
                                        break;

                                /* go to next policy group within mode group */
                                tmp = policy_end->l_res_link.next;
				lock = list_entry(tmp, struct ldlm_lock,
                                                      l_res_link);
                        }  /* loop over policy groups within the mode group */

                        /* insert point is last lock of the mode group,
                         * new policy group is started */
                        prev->res_link = &mode_end->l_res_link;
                        prev->mode_link = &mode_end->l_sl_mode;
                        prev->policy_link = &req->l_sl_policy;
                        EXIT;
                        return;
                } else {
                        LDLM_ERROR(lock,"is not LDLM_PLAIN or LDLM_IBITS lock");
                        LBUG();
                }
        }

        /* insert point is last lock on the queue,
         * new mode group and new policy group are started */
        prev->res_link = queue->prev;
        prev->mode_link = &req->l_sl_mode;
        prev->policy_link = &req->l_sl_policy;
        EXIT;
        return;
}

/**
 * Add a lock into resource granted list after a position described by
 * \a prev.
 */
static void ldlm_granted_list_add_lock(struct ldlm_lock *lock,
                                       struct sl_insert_point *prev)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        check_res_locked(res);

        ldlm_resource_dump(D_INFO, res);
        LDLM_DEBUG(lock, "About to add lock:");

	if (ldlm_is_destroyed(lock)) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                return;
        }

	LASSERT(list_empty(&lock->l_res_link));
	LASSERT(list_empty(&lock->l_sl_mode));
	LASSERT(list_empty(&lock->l_sl_policy));

	/*
	 * lock->link == prev->link means lock is first starting the group.
	 * Don't re-add to itself to suppress kernel warnings.
	 */
	if (&lock->l_res_link != prev->res_link)
		list_add(&lock->l_res_link, prev->res_link);
	if (&lock->l_sl_mode != prev->mode_link)
		list_add(&lock->l_sl_mode, prev->mode_link);
	if (&lock->l_sl_policy != prev->policy_link)
		list_add(&lock->l_sl_policy, prev->policy_link);

        EXIT;
}

/**
 * Add a lock to granted list on a resource maintaining skiplist
 * correctness.
 */
void ldlm_grant_lock_with_skiplist(struct ldlm_lock *lock)
{
	struct sl_insert_point prev;

	LASSERT(ldlm_is_granted(lock));

	search_granted_lock(&lock->l_resource->lr_granted, lock, &prev);
	ldlm_granted_list_add_lock(lock, &prev);
}

/**
 * Perform lock granting bookkeeping.
 *
 * Includes putting the lock into granted list and updating lock mode.
 * NOTE: called by
 *  - ldlm_lock_enqueue
 *  - ldlm_reprocess_queue
 *
 * must be called with lr_lock held
 */
void ldlm_grant_lock(struct ldlm_lock *lock, struct list_head *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        check_res_locked(res);

        lock->l_granted_mode = lock->l_req_mode;

	if (work_list && lock->l_completion_ast != NULL)
		ldlm_add_ast_work_item(lock, NULL, work_list);

        if (res->lr_type == LDLM_PLAIN || res->lr_type == LDLM_IBITS)
                ldlm_grant_lock_with_skiplist(lock);
        else if (res->lr_type == LDLM_EXTENT)
                ldlm_extent_add_lock(res, lock);
	else if (res->lr_type == LDLM_FLOCK) {
		/* We should not add locks to granted list in the following
		 * cases:
		 * - this is an UNLOCK but not a real lock;
		 * - this is a TEST lock;
		 * - this is a F_CANCELLK lock (async flock has req_mode == 0)
		 * - this is a deadlock (flock cannot be granted) */
		if (lock->l_req_mode == 0 ||
		    lock->l_req_mode == LCK_NL ||
		    ldlm_is_test_lock(lock) ||
		    ldlm_is_flock_deadlock(lock))
			RETURN_EXIT;
		ldlm_resource_add_lock(res, &res->lr_granted, lock);
	} else {
		LBUG();
	}

        ldlm_pool_add(&ldlm_res_to_ns(res)->ns_pool, lock);
        EXIT;
}

/**
 * Check if the given @lock meets the criteria for a match.
 * A reference on the lock is taken if matched.
 *
 * \param lock     test-against this lock
 * \param data	   parameters
 */
static int lock_matches(struct ldlm_lock *lock, struct ldlm_match_data *data)
{
	union ldlm_policy_data *lpol = &lock->l_policy_data;
	enum ldlm_mode match = LCK_MINMODE;

	if (lock == data->lmd_old)
		return INTERVAL_ITER_STOP;

	/* Check if this lock can be matched.
	 * Used by LU-2919(exclusive open) for open lease lock */
	if (ldlm_is_excl(lock))
		return INTERVAL_ITER_CONT;

	/* llite sometimes wants to match locks that will be
	 * canceled when their users drop, but we allow it to match
	 * if it passes in CBPENDING and the lock still has users.
	 * this is generally only going to be used by children
	 * whose parents already hold a lock so forward progress
	 * can still happen. */
	if (ldlm_is_cbpending(lock) &&
	    !(data->lmd_flags & LDLM_FL_CBPENDING))
		return INTERVAL_ITER_CONT;
	if (!data->lmd_unref && ldlm_is_cbpending(lock) &&
	    lock->l_readers == 0 && lock->l_writers == 0)
		return INTERVAL_ITER_CONT;

	if (!(lock->l_req_mode & *data->lmd_mode))
		return INTERVAL_ITER_CONT;

	/* When we search for ast_data, we are not doing a traditional match,
	 * so we don't worry about IBITS or extent matching.
	 */
	if (data->lmd_has_ast_data) {
		if (!lock->l_ast_data)
			return INTERVAL_ITER_CONT;

		goto matched;
	}

	match = lock->l_req_mode;

	switch (lock->l_resource->lr_type) {
	case LDLM_EXTENT:
		if (lpol->l_extent.start > data->lmd_policy->l_extent.start ||
		    lpol->l_extent.end < data->lmd_policy->l_extent.end)
			return INTERVAL_ITER_CONT;

		if (unlikely(match == LCK_GROUP) &&
		    data->lmd_policy->l_extent.gid != LDLM_GID_ANY &&
		    lpol->l_extent.gid != data->lmd_policy->l_extent.gid)
			return INTERVAL_ITER_CONT;
		break;
	case LDLM_IBITS:
		/* We match if we have existing lock with same or wider set
		   of bits. */
		if ((lpol->l_inodebits.bits &
		     data->lmd_policy->l_inodebits.bits) !=
		    data->lmd_policy->l_inodebits.bits)
			return INTERVAL_ITER_CONT;
		break;
	default:
		;
	}

	/* We match if we have existing lock with same or wider set
	   of bits. */
	if (!data->lmd_unref && LDLM_HAVE_MASK(lock, GONE))
		return INTERVAL_ITER_CONT;

	if (!equi(data->lmd_flags & LDLM_FL_LOCAL_ONLY, ldlm_is_local(lock)))
		return INTERVAL_ITER_CONT;

	/* Filter locks by skipping flags */
	if (data->lmd_skip_flags & lock->l_flags)
		return INTERVAL_ITER_CONT;

matched:
	if (data->lmd_flags & LDLM_FL_TEST_LOCK) {
		LDLM_LOCK_GET(lock);
		ldlm_lock_touch_in_lru(lock);
	} else {
		ldlm_lock_addref_internal_nolock(lock, match);
	}

	*data->lmd_mode = match;
	data->lmd_lock = lock;

	return INTERVAL_ITER_STOP;
}

static unsigned int itree_overlap_cb(struct interval_node *in, void *args)
{
	struct ldlm_interval *node = to_ldlm_interval(in);
	struct ldlm_match_data *data = args;
	struct ldlm_lock *lock;
	int rc;

	list_for_each_entry(lock, &node->li_group, l_sl_policy) {
		rc = lock_matches(lock, data);
		if (rc == INTERVAL_ITER_STOP)
			return INTERVAL_ITER_STOP;
	}
	return INTERVAL_ITER_CONT;
}

/**
 * Search for a lock with given parameters in interval trees.
 *
 * \param res      search for a lock in this resource
 * \param data	   parameters
 *
 * \retval a referenced lock or NULL.
 */
struct ldlm_lock *search_itree(struct ldlm_resource *res,
			       struct ldlm_match_data *data)
{
	struct interval_node_extent ext = {
		.start     = data->lmd_policy->l_extent.start,
		.end       = data->lmd_policy->l_extent.end
	};
	int idx;

	data->lmd_lock = NULL;

	for (idx = 0; idx < LCK_MODE_NUM; idx++) {
		struct ldlm_interval_tree *tree = &res->lr_itree[idx];

		if (tree->lit_root == NULL)
			continue;

		if (!(tree->lit_mode & *data->lmd_mode))
			continue;

		interval_search(tree->lit_root, &ext,
				itree_overlap_cb, data);
		if (data->lmd_lock)
			return data->lmd_lock;
	}

	return NULL;
}
EXPORT_SYMBOL(search_itree);


/**
 * Search for a lock with given properties in a queue.
 *
 * \param queue    search for a lock in this queue
 * \param data	   parameters
 *
 * \retval a referenced lock or NULL.
 */
static struct ldlm_lock *search_queue(struct list_head *queue,
				      struct ldlm_match_data *data)
{
	struct ldlm_lock *lock;
	int rc;

	data->lmd_lock = NULL;

	list_for_each_entry(lock, queue, l_res_link) {
		rc = lock_matches(lock, data);
		if (rc == INTERVAL_ITER_STOP)
			return data->lmd_lock;
	}

	return NULL;
}

void ldlm_lock_fail_match_locked(struct ldlm_lock *lock)
{
	if ((lock->l_flags & LDLM_FL_FAIL_NOTIFIED) == 0) {
		lock->l_flags |= LDLM_FL_FAIL_NOTIFIED;
		wake_up_all(&lock->l_waitq);
	}
}
EXPORT_SYMBOL(ldlm_lock_fail_match_locked);

void ldlm_lock_fail_match(struct ldlm_lock *lock)
{
        lock_res_and_lock(lock);
        ldlm_lock_fail_match_locked(lock);
        unlock_res_and_lock(lock);
}

/**
 * Mark lock as "matchable" by OST.
 *
 * Used to prevent certain races in LOV/OSC where the lock is granted, but LVB
 * is not yet valid.
 * Assumes LDLM lock is already locked.
 */
void ldlm_lock_allow_match_locked(struct ldlm_lock *lock)
{
	ldlm_set_lvb_ready(lock);
	wake_up_all(&lock->l_waitq);
}
EXPORT_SYMBOL(ldlm_lock_allow_match_locked);

/**
 * Mark lock as "matchable" by OST.
 * Locks the lock and then \see ldlm_lock_allow_match_locked
 */
void ldlm_lock_allow_match(struct ldlm_lock *lock)
{
        lock_res_and_lock(lock);
        ldlm_lock_allow_match_locked(lock);
        unlock_res_and_lock(lock);
}
EXPORT_SYMBOL(ldlm_lock_allow_match);

/**
 * Attempt to find a lock with specified properties.
 *
 * Typically returns a reference to matched lock unless LDLM_FL_TEST_LOCK is
 * set in \a flags
 *
 * Can be called in two ways:
 *
 * If 'ns' is NULL, then lockh describes an existing lock that we want to look
 * for a duplicate of.
 *
 * Otherwise, all of the fields must be filled in, to match against.
 *
 * If 'flags' contains LDLM_FL_LOCAL_ONLY, then only match local locks on the
 *     server (ie, connh is NULL)
 * If 'flags' contains LDLM_FL_BLOCK_GRANTED, then only locks on the granted
 *     list will be considered
 * If 'flags' contains LDLM_FL_CBPENDING, then locks that have been marked
 *     to be canceled can still be matched as long as they still have reader
 *     or writer refernces
 * If 'flags' contains LDLM_FL_TEST_LOCK, then don't actually reference a lock,
 *     just tell us if we would have matched.
 *
 * \retval 1 if it finds an already-existing lock that is compatible; in this
 * case, lockh is filled in with a addref()ed lock
 *
 * We also check security context, and if that fails we simply return 0 (to
 * keep caller code unchanged), the context failure will be discovered by
 * caller sometime later.
 */
enum ldlm_mode ldlm_lock_match_with_skip(struct ldlm_namespace *ns,
					 __u64 flags, __u64 skip_flags,
					 const struct ldlm_res_id *res_id,
					 enum ldlm_type type,
					 union ldlm_policy_data *policy,
					 enum ldlm_mode mode,
					 struct lustre_handle *lockh, int unref)
{
	struct ldlm_match_data data = {
		.lmd_old = NULL,
		.lmd_lock = NULL,
		.lmd_mode = &mode,
		.lmd_policy = policy,
		.lmd_flags = flags,
		.lmd_skip_flags = skip_flags,
		.lmd_unref = unref,
		.lmd_has_ast_data = false,
	};
	struct ldlm_resource *res;
	struct ldlm_lock *lock;
	int matched;

	ENTRY;

	if (ns == NULL) {
		data.lmd_old = ldlm_handle2lock(lockh);
		LASSERT(data.lmd_old != NULL);

		ns = ldlm_lock_to_ns(data.lmd_old);
		res_id = &data.lmd_old->l_resource->lr_name;
		type = data.lmd_old->l_resource->lr_type;
		*data.lmd_mode = data.lmd_old->l_req_mode;
	}

	res = ldlm_resource_get(ns, NULL, res_id, type, 0);
	if (IS_ERR(res)) {
		LASSERT(data.lmd_old == NULL);
		RETURN(0);
	}

	LDLM_RESOURCE_ADDREF(res);
	lock_res(res);
	if (res->lr_type == LDLM_EXTENT)
		lock = search_itree(res, &data);
	else
		lock = search_queue(&res->lr_granted, &data);
	if (!lock && !(flags & LDLM_FL_BLOCK_GRANTED))
		lock = search_queue(&res->lr_waiting, &data);
	matched = lock ? mode : 0;
	unlock_res(res);
	LDLM_RESOURCE_DELREF(res);
	ldlm_resource_putref(res);

	if (lock) {
		ldlm_lock2handle(lock, lockh);
		if ((flags & LDLM_FL_LVB_READY) &&
		    (!ldlm_is_lvb_ready(lock))) {
			__u64 wait_flags = LDLM_FL_LVB_READY |
				LDLM_FL_DESTROYED | LDLM_FL_FAIL_NOTIFIED;
			struct l_wait_info lwi;

			if (lock->l_completion_ast) {
				int err = lock->l_completion_ast(lock,
							LDLM_FL_WAIT_NOREPROC,
							NULL);
				if (err)
					GOTO(out_fail_match, matched = 0);
			}

			lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(obd_timeout),
					       NULL, LWI_ON_SIGNAL_NOOP, NULL);

			/* XXX FIXME see comment on CAN_MATCH in lustre_dlm.h */
			l_wait_event(lock->l_waitq, lock->l_flags & wait_flags,
				     &lwi);
			if (!ldlm_is_lvb_ready(lock))
				GOTO(out_fail_match, matched = 0);
		}

		/* check user's security context */
		if (lock->l_conn_export &&
		    sptlrpc_import_check_ctx(
				class_exp2cliimp(lock->l_conn_export)))
			GOTO(out_fail_match, matched = 0);

		LDLM_DEBUG(lock, "matched (%llu %llu)",
			   (type == LDLM_PLAIN || type == LDLM_IBITS) ?
			   res_id->name[2] : policy->l_extent.start,
			   (type == LDLM_PLAIN || type == LDLM_IBITS) ?
			   res_id->name[3] : policy->l_extent.end);

out_fail_match:
		if (flags & LDLM_FL_TEST_LOCK)
			LDLM_LOCK_RELEASE(lock);
		else if (!matched)
			ldlm_lock_decref_internal(lock, mode);
	}

	/* less verbose for test-only */
	if (!matched && !(flags & LDLM_FL_TEST_LOCK)) {
		LDLM_DEBUG_NOLOCK("not matched ns %p type %u mode %u res "
				  "%llu/%llu (%llu %llu)", ns,
				  type, mode, res_id->name[0], res_id->name[1],
				  (type == LDLM_PLAIN || type == LDLM_IBITS) ?
				  res_id->name[2] : policy->l_extent.start,
				  (type == LDLM_PLAIN || type == LDLM_IBITS) ?
				  res_id->name[3] : policy->l_extent.end);
	}
	if (data.lmd_old != NULL)
		LDLM_LOCK_PUT(data.lmd_old);

	return matched;
}
EXPORT_SYMBOL(ldlm_lock_match_with_skip);

enum ldlm_mode ldlm_revalidate_lock_handle(const struct lustre_handle *lockh,
					   __u64 *bits)
{
	struct ldlm_lock *lock;
	enum ldlm_mode mode = 0;
	ENTRY;

	lock = ldlm_handle2lock(lockh);
	if (lock != NULL) {
		lock_res_and_lock(lock);
		if (LDLM_HAVE_MASK(lock, GONE))
			GOTO(out, mode);

		if (ldlm_is_cbpending(lock) &&
                    lock->l_readers == 0 && lock->l_writers == 0)
                        GOTO(out, mode);

                if (bits)
                        *bits = lock->l_policy_data.l_inodebits.bits;
                mode = lock->l_granted_mode;
                ldlm_lock_addref_internal_nolock(lock, mode);
        }

        EXIT;

out:
        if (lock != NULL) {
                unlock_res_and_lock(lock);
                LDLM_LOCK_PUT(lock);
        }
        return mode;
}
EXPORT_SYMBOL(ldlm_revalidate_lock_handle);

/** The caller must guarantee that the buffer is large enough. */
int ldlm_fill_lvb(struct ldlm_lock *lock, struct req_capsule *pill,
		  enum req_location loc, void *data, int size)
{
	void *lvb;
	ENTRY;

	LASSERT(data != NULL);
	LASSERT(size >= 0);

	switch (lock->l_lvb_type) {
	case LVB_T_OST:
		if (size == sizeof(struct ost_lvb)) {
			if (loc == RCL_CLIENT)
				lvb = req_capsule_client_swab_get(pill,
						&RMF_DLM_LVB,
						lustre_swab_ost_lvb);
			else
				lvb = req_capsule_server_swab_get(pill,
						&RMF_DLM_LVB,
						lustre_swab_ost_lvb);
			if (unlikely(lvb == NULL)) {
				LDLM_ERROR(lock, "no LVB");
				RETURN(-EPROTO);
			}

			memcpy(data, lvb, size);
		} else if (size == sizeof(struct ost_lvb_v1)) {
			struct ost_lvb *olvb = data;

			if (loc == RCL_CLIENT)
				lvb = req_capsule_client_swab_get(pill,
						&RMF_DLM_LVB,
						lustre_swab_ost_lvb_v1);
			else
				lvb = req_capsule_server_sized_swab_get(pill,
						&RMF_DLM_LVB, size,
						lustre_swab_ost_lvb_v1);
			if (unlikely(lvb == NULL)) {
				LDLM_ERROR(lock, "no LVB");
				RETURN(-EPROTO);
			}

			memcpy(data, lvb, size);
			olvb->lvb_mtime_ns = 0;
			olvb->lvb_atime_ns = 0;
			olvb->lvb_ctime_ns = 0;
		} else {
			LDLM_ERROR(lock, "Replied unexpected ost LVB size %d",
				   size);
			RETURN(-EINVAL);
		}
		break;
	case LVB_T_LQUOTA:
		if (size == sizeof(struct lquota_lvb)) {
			if (loc == RCL_CLIENT)
				lvb = req_capsule_client_swab_get(pill,
						&RMF_DLM_LVB,
						lustre_swab_lquota_lvb);
			else
				lvb = req_capsule_server_swab_get(pill,
						&RMF_DLM_LVB,
						lustre_swab_lquota_lvb);
			if (unlikely(lvb == NULL)) {
				LDLM_ERROR(lock, "no LVB");
				RETURN(-EPROTO);
			}

			memcpy(data, lvb, size);
		} else {
			LDLM_ERROR(lock, "Replied unexpected lquota LVB size %d",
				   size);
			RETURN(-EINVAL);
		}
		break;
	case LVB_T_LAYOUT:
		if (size == 0)
			break;

		if (loc == RCL_CLIENT)
			lvb = req_capsule_client_get(pill, &RMF_DLM_LVB);
		else
			lvb = req_capsule_server_get(pill, &RMF_DLM_LVB);
		if (unlikely(lvb == NULL)) {
			LDLM_ERROR(lock, "no LVB");
			RETURN(-EPROTO);
		}

		memcpy(data, lvb, size);
		break;
	default:
		LDLM_ERROR(lock, "Unknown LVB type: %d", lock->l_lvb_type);
		libcfs_debug_dumpstack(NULL);
		RETURN(-EINVAL);
	}

	RETURN(0);
}

/**
 * Create and fill in new LDLM lock with specified properties.
 * Returns a referenced lock
 */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
				   const struct ldlm_res_id *res_id,
				   enum ldlm_type type,
				   enum ldlm_mode mode,
				   const struct ldlm_callback_suite *cbs,
				   void *data, __u32 lvb_len,
				   enum lvb_type lvb_type)
{
	struct ldlm_lock	*lock;
	struct ldlm_resource	*res;
	int			rc;
	ENTRY;

	res = ldlm_resource_get(ns, NULL, res_id, type, 1);
	if (IS_ERR(res))
		RETURN(ERR_CAST(res));

	lock = ldlm_lock_new(res);
	if (lock == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	lock->l_req_mode = mode;
	lock->l_ast_data = data;
	lock->l_pid = current_pid();
	if (ns_is_server(ns))
		ldlm_set_ns_srv(lock);
	if (cbs) {
		lock->l_blocking_ast = cbs->lcs_blocking;
		lock->l_completion_ast = cbs->lcs_completion;
		lock->l_glimpse_ast = cbs->lcs_glimpse;
	}

	switch (type) {
	case LDLM_EXTENT:
		rc = ldlm_extent_alloc_lock(lock);
		break;
	case LDLM_IBITS:
		rc = ldlm_inodebits_alloc_lock(lock);
		break;
	default:
		rc = 0;
	}
	if (rc)
		GOTO(out, rc);

	if (lvb_len) {
		lock->l_lvb_len = lvb_len;
		OBD_ALLOC_LARGE(lock->l_lvb_data, lvb_len);
		if (lock->l_lvb_data == NULL)
			GOTO(out, rc = -ENOMEM);
	}

	lock->l_lvb_type = lvb_type;
	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_NEW_LOCK))
		GOTO(out, rc = -ENOENT);

	RETURN(lock);

out:
	ldlm_lock_destroy(lock);
	LDLM_LOCK_RELEASE(lock);
	RETURN(ERR_PTR(rc));
}

#ifdef HAVE_SERVER_SUPPORT
static enum ldlm_error ldlm_lock_enqueue_helper(struct ldlm_lock *lock,
					     __u64 *flags)
{
	struct ldlm_resource *res = lock->l_resource;
	enum ldlm_error rc = ELDLM_OK;
	struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
	ldlm_processing_policy policy;

	ENTRY;

	policy = ldlm_get_processing_policy(res);
	policy(lock, flags, LDLM_PROCESS_ENQUEUE, &rc, &rpc_list);
	if (rc == ELDLM_OK && lock->l_granted_mode != lock->l_req_mode &&
	    res->lr_type != LDLM_FLOCK)
		rc = ldlm_handle_conflict_lock(lock, flags, &rpc_list);

	if (!list_empty(&rpc_list))
		ldlm_discard_bl_list(&rpc_list);

	RETURN(rc);
}
#endif

/**
 * Enqueue (request) a lock.
 *
 * Does not block. As a result of enqueue the lock would be put
 * into granted or waiting list.
 *
 * If namespace has intent policy sent and the lock has LDLM_FL_HAS_INTENT flag
 * set, skip all the enqueueing and delegate lock processing to intent policy
 * function.
 */
enum ldlm_error ldlm_lock_enqueue(const struct lu_env *env,
				  struct ldlm_namespace *ns,
				  struct ldlm_lock **lockp,
				  void *cookie, __u64 *flags)
{
	struct ldlm_lock *lock = *lockp;
	struct ldlm_resource *res = lock->l_resource;
	int local = ns_is_client(ldlm_res_to_ns(res));
	enum ldlm_error rc = ELDLM_OK;
	struct ldlm_interval *node = NULL;
	ENTRY;

        /* policies are not executed on the client or during replay */
        if ((*flags & (LDLM_FL_HAS_INTENT|LDLM_FL_REPLAY)) == LDLM_FL_HAS_INTENT
            && !local && ns->ns_policy) {
		rc = ns->ns_policy(env, ns, lockp, cookie, lock->l_req_mode,
				   *flags, NULL);
                if (rc == ELDLM_LOCK_REPLACED) {
                        /* The lock that was returned has already been granted,
                         * and placed into lockp.  If it's not the same as the
                         * one we passed in, then destroy the old one and our
                         * work here is done. */
                        if (lock != *lockp) {
                                ldlm_lock_destroy(lock);
                                LDLM_LOCK_RELEASE(lock);
                        }
                        *flags |= LDLM_FL_LOCK_CHANGED;
                        RETURN(0);
		} else if (rc != ELDLM_OK &&
			   ldlm_is_granted(lock)) {
			LASSERT(*flags & LDLM_FL_RESENT);
			/* It may happen that ns_policy returns an error in
			 * resend case, object may be unlinked or just some
			 * error occurs. It is unclear if lock reached the
			 * client in the original reply, just leave the lock on
			 * server, not returning it again to client. Due to
			 * LU-6529, the server will not OOM. */
			RETURN(rc);
                } else if (rc != ELDLM_OK ||
                           (rc == ELDLM_OK && (*flags & LDLM_FL_INTENT_ONLY))) {
                        ldlm_lock_destroy(lock);
                        RETURN(rc);
                }
        }

	if (*flags & LDLM_FL_RESENT) {
		/* Reconstruct LDLM_FL_SRV_ENQ_MASK @flags for reply.
		 * Set LOCK_CHANGED always.
		 * Check if the lock is granted for BLOCK_GRANTED.
		 * Take NO_TIMEOUT from the lock as it is inherited through
		 * LDLM_FL_INHERIT_MASK */
		*flags |= LDLM_FL_LOCK_CHANGED;
		if (!ldlm_is_granted(lock))
			*flags |= LDLM_FL_BLOCK_GRANTED;
		*flags |= lock->l_flags & LDLM_FL_NO_TIMEOUT;
		RETURN(ELDLM_OK);
	}

	/* For a replaying lock, it might be already in granted list. So
	 * unlinking the lock will cause the interval node to be freed, we
	 * have to allocate the interval node early otherwise we can't regrant
	 * this lock in the future. - jay */
	if (!local && (*flags & LDLM_FL_REPLAY) && res->lr_type == LDLM_EXTENT)
		OBD_SLAB_ALLOC_PTR_GFP(node, ldlm_interval_slab, GFP_NOFS);

	lock_res_and_lock(lock);
	if (local && ldlm_is_granted(lock)) {
                /* The server returned a blocked lock, but it was granted
                 * before we got a chance to actually enqueue it.  We don't
                 * need to do anything else. */
                *flags &= ~LDLM_FL_BLOCKED_MASK;
		GOTO(out, rc = ELDLM_OK);
        }

        ldlm_resource_unlink_lock(lock);
        if (res->lr_type == LDLM_EXTENT && lock->l_tree_node == NULL) {
                if (node == NULL) {
                        ldlm_lock_destroy_nolock(lock);
                        GOTO(out, rc = -ENOMEM);
                }

		INIT_LIST_HEAD(&node->li_group);
                ldlm_interval_attach(node, lock);
                node = NULL;
        }

	/* Some flags from the enqueue want to make it into the AST, via the
	 * lock's l_flags. */
	if (*flags & LDLM_FL_AST_DISCARD_DATA)
		ldlm_set_ast_discard_data(lock);
	if (*flags & LDLM_FL_TEST_LOCK)
		ldlm_set_test_lock(lock);
	if (*flags & LDLM_FL_COS_INCOMPAT)
		ldlm_set_cos_incompat(lock);
	if (*flags & LDLM_FL_COS_ENABLED)
		ldlm_set_cos_enabled(lock);

	/* This distinction between local lock trees is very important; a client
	 * namespace only has information about locks taken by that client, and
	 * thus doesn't have enough information to decide for itself if it can
	 * be granted (below).  In this case, we do exactly what the server
	 * tells us to do, as dictated by the 'flags'.
	 *
	 * We do exactly the same thing during recovery, when the server is
	 * more or less trusting the clients not to lie.
	 *
	 * FIXME (bug 268): Detect obvious lies by checking compatibility in
	 * granted queue. */
        if (local) {
		if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
			ldlm_resource_add_lock(res, &res->lr_waiting, lock);
		else
			ldlm_grant_lock(lock, NULL);
		GOTO(out, rc = ELDLM_OK);
#ifdef HAVE_SERVER_SUPPORT
	} else if (*flags & LDLM_FL_REPLAY) {
		if (*flags & LDLM_FL_BLOCK_WAIT) {
			ldlm_resource_add_lock(res, &res->lr_waiting, lock);
			GOTO(out, rc = ELDLM_OK);
		} else if (*flags & LDLM_FL_BLOCK_GRANTED) {
			ldlm_grant_lock(lock, NULL);
			GOTO(out, rc = ELDLM_OK);
		}
		/* If no flags, fall through to normal enqueue path. */
	}

	rc = ldlm_lock_enqueue_helper(lock, flags);
	GOTO(out, rc);
#else
        } else {
                CERROR("This is client-side-only module, cannot handle "
                       "LDLM_NAMESPACE_SERVER resource type lock.\n");
                LBUG();
        }
#endif

out:
        unlock_res_and_lock(lock);
        if (node)
                OBD_SLAB_FREE(node, ldlm_interval_slab, sizeof(*node));
        return rc;
}

#ifdef HAVE_SERVER_SUPPORT
/**
 * Iterate through all waiting locks on a given resource queue and attempt to
 * grant them.
 *
 * Must be called with resource lock held.
 */
int ldlm_reprocess_queue(struct ldlm_resource *res, struct list_head *queue,
			 struct list_head *work_list,
			 enum ldlm_process_intention intention,
			 struct ldlm_lock *hint)
{
	struct list_head *tmp, *pos;
	ldlm_processing_policy policy;
	__u64 flags;
	int rc = LDLM_ITER_CONTINUE;
	enum ldlm_error err;
	struct list_head bl_ast_list = LIST_HEAD_INIT(bl_ast_list);

	ENTRY;

	check_res_locked(res);

	policy = ldlm_get_processing_policy(res);
	LASSERT(policy);
	LASSERT(intention == LDLM_PROCESS_RESCAN ||
		intention == LDLM_PROCESS_RECOVERY);

restart:
	list_for_each_safe(tmp, pos, queue) {
		struct ldlm_lock *pending;
		struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);

		pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                CDEBUG(D_INFO, "Reprocessing lock %p\n", pending);

                flags = 0;
		rc = policy(pending, &flags, intention, &err, &rpc_list);
		if (pending->l_granted_mode == pending->l_req_mode ||
		    res->lr_type == LDLM_FLOCK) {
			list_splice(&rpc_list, work_list);
		} else {
			list_splice(&rpc_list, &bl_ast_list);
		}
		/*
		 * When this is called from recovery done, we always want
		 * to scan the whole list no matter what 'rc' is returned.
		 */
		if (rc != LDLM_ITER_CONTINUE &&
		    intention == LDLM_PROCESS_RESCAN)
			break;
        }

	if (!list_empty(&bl_ast_list)) {
		unlock_res(res);

		rc = ldlm_run_ast_work(ldlm_res_to_ns(res), &bl_ast_list,
				       LDLM_WORK_BL_AST);

		lock_res(res);
		if (rc == -ERESTART)
			GOTO(restart, rc);
	}

	if (!list_empty(&bl_ast_list))
		ldlm_discard_bl_list(&bl_ast_list);

        RETURN(intention == LDLM_PROCESS_RESCAN ? rc : LDLM_ITER_CONTINUE);
}

/**
 * Conflicting locks are detected for a lock to be enqueued, add the lock
 * into waiting list and send blocking ASTs to the conflicting locks.
 *
 * \param[in] lock		The lock to be enqueued.
 * \param[out] flags		Lock flags for the lock to be enqueued.
 * \param[in] rpc_list		Conflicting locks list.
 *
 * \retval -ERESTART:	Some lock was instantly canceled while sending
 * 			blocking ASTs, caller needs to re-check conflicting
 * 			locks.
 * \retval -EAGAIN:	Lock was destroyed, caller should return error.
 * \reval 0:		Lock is successfully added in waiting list.
 */
int ldlm_handle_conflict_lock(struct ldlm_lock *lock, __u64 *flags,
			      struct list_head *rpc_list)
{
	struct ldlm_resource *res = lock->l_resource;
	int rc;
	ENTRY;

	check_res_locked(res);

	/* If either of the compat_queue()s returned failure, then we
	 * have ASTs to send and must go onto the waiting list.
	 *
	 * bug 2322: we used to unlink and re-add here, which was a
	 * terrible folly -- if we goto restart, we could get
	 * re-ordered!  Causes deadlock, because ASTs aren't sent! */
	if (list_empty(&lock->l_res_link))
		ldlm_resource_add_lock(res, &res->lr_waiting, lock);
	unlock_res(res);

	rc = ldlm_run_ast_work(ldlm_res_to_ns(res), rpc_list,
			       LDLM_WORK_BL_AST);

	if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_OST_FAIL_RACE) &&
	    !ns_is_client(ldlm_res_to_ns(res)))
		class_fail_export(lock->l_export);

	if (rc == -ERESTART)
		ldlm_reprocess_all(res, NULL);

	lock_res(res);
	if (rc == -ERESTART) {
		/* 15715: The lock was granted and destroyed after
		 * resource lock was dropped. Interval node was freed
		 * in ldlm_lock_destroy. Anyway, this always happens
		 * when a client is being evicted. So it would be
		 * ok to return an error. -jay */
		if (ldlm_is_destroyed(lock))
			RETURN(-EAGAIN);

		/* lock was granted while resource was unlocked. */
		if (ldlm_is_granted(lock)) {
			/* bug 11300: if the lock has been granted,
			 * break earlier because otherwise, we will go
			 * to restart and ldlm_resource_unlink will be
			 * called and it causes the interval node to be
			 * freed. Then we will fail at
			 * ldlm_extent_add_lock() */
			*flags &= ~LDLM_FL_BLOCKED_MASK;
		}

	}
	*flags |= LDLM_FL_BLOCK_GRANTED;

	RETURN(0);
}

/**
 * Discard all AST work items from list.
 *
 * If for whatever reason we do not want to send ASTs to conflicting locks
 * anymore, disassemble the list with this function.
 */
void ldlm_discard_bl_list(struct list_head *bl_list)
{
	struct ldlm_lock *lock, *tmp;

	ENTRY;

	list_for_each_entry_safe(lock, tmp, bl_list, l_bl_ast) {
		LASSERT(!list_empty(&lock->l_bl_ast));
		list_del_init(&lock->l_bl_ast);
		ldlm_clear_ast_sent(lock);
		LASSERT(lock->l_bl_ast_run == 0);
		ldlm_clear_blocking_lock(lock);
		LDLM_LOCK_RELEASE(lock);
	}
	EXIT;
}

/**
 * Process a call to blocking AST callback for a lock in ast_work list
 */
static int
ldlm_work_bl_ast_lock(struct ptlrpc_request_set *rqset, void *opaq)
{
	struct ldlm_cb_set_arg *arg = opaq;
	struct ldlm_lock *lock;
	struct ldlm_lock_desc d;
	struct ldlm_bl_desc bld;
	int rc;

	ENTRY;

	if (list_empty(arg->list))
		RETURN(-ENOENT);

	lock = list_entry(arg->list->next, struct ldlm_lock, l_bl_ast);

	/* nobody should touch l_bl_ast but some locks in the list may become
	 * granted after lock convert or COS downgrade, these locks should be
	 * just skipped here and removed from the list.
	 */
	lock_res_and_lock(lock);
	list_del_init(&lock->l_bl_ast);

	/* lock is not blocking lock anymore, but was kept in the list because
	 * it can managed only here.
	 */
	if (!ldlm_is_ast_sent(lock)) {
		unlock_res_and_lock(lock);
		LDLM_LOCK_RELEASE(lock);
		RETURN(0);
	}

	LASSERT(lock->l_blocking_lock);
	ldlm_lock2desc(lock->l_blocking_lock, &d);
	/* copy blocking lock ibits in cancel_bits as well,
	 * new client may use them for lock convert and it is
	 * important to use new field to convert locks from
	 * new servers only
	 */
	d.l_policy_data.l_inodebits.cancel_bits =
		lock->l_blocking_lock->l_policy_data.l_inodebits.bits;

	/* Blocking lock is being destroyed here but some information about it
	 * may be needed inside l_blocking_ast() function below,
	 * e.g. in mdt_blocking_ast(). So save needed data in bl_desc.
	 */
	bld.bl_same_client = lock->l_client_cookie ==
			     lock->l_blocking_lock->l_client_cookie;
	bld.bl_cos_incompat = ldlm_is_cos_incompat(lock->l_blocking_lock);
	arg->bl_desc = &bld;

	LASSERT(ldlm_is_ast_sent(lock));
	LASSERT(lock->l_bl_ast_run == 0);
	lock->l_bl_ast_run++;
	ldlm_clear_blocking_lock(lock);
	unlock_res_and_lock(lock);

	rc = lock->l_blocking_ast(lock, &d, (void *)arg, LDLM_CB_BLOCKING);

	LDLM_LOCK_RELEASE(lock);

	RETURN(rc);
}

/**
 * Process a call to revocation AST callback for a lock in ast_work list
 */
static int
ldlm_work_revoke_ast_lock(struct ptlrpc_request_set *rqset, void *opaq)
{
	struct ldlm_cb_set_arg *arg = opaq;
	struct ldlm_lock_desc   desc;
	int                     rc;
	struct ldlm_lock       *lock;
	ENTRY;

	if (list_empty(arg->list))
		RETURN(-ENOENT);

	lock = list_entry(arg->list->next, struct ldlm_lock, l_rk_ast);
	list_del_init(&lock->l_rk_ast);

	/* the desc just pretend to exclusive */
	ldlm_lock2desc(lock, &desc);
	desc.l_req_mode = LCK_EX;
	desc.l_granted_mode = 0;

	rc = lock->l_blocking_ast(lock, &desc, (void*)arg, LDLM_CB_BLOCKING);
	LDLM_LOCK_RELEASE(lock);

	RETURN(rc);
}

/**
 * Process a call to glimpse AST callback for a lock in ast_work list
 */
int ldlm_work_gl_ast_lock(struct ptlrpc_request_set *rqset, void *opaq)
{
	struct ldlm_cb_set_arg		*arg = opaq;
	struct ldlm_glimpse_work	*gl_work;
	struct ldlm_lock		*lock;
	int				 rc = 0;
	ENTRY;

	if (list_empty(arg->list))
		RETURN(-ENOENT);

	gl_work = list_entry(arg->list->next, struct ldlm_glimpse_work,
				 gl_list);
	list_del_init(&gl_work->gl_list);

	lock = gl_work->gl_lock;

	/* transfer the glimpse descriptor to ldlm_cb_set_arg */
	arg->gl_desc = gl_work->gl_desc;
	arg->gl_interpret_reply = gl_work->gl_interpret_reply;
	arg->gl_interpret_data = gl_work->gl_interpret_data;

	/* invoke the actual glimpse callback */
	if (lock->l_glimpse_ast(lock, (void*)arg) == 0)
		rc = 1;

	LDLM_LOCK_RELEASE(lock);
	if (gl_work->gl_flags & LDLM_GL_WORK_SLAB_ALLOCATED)
		OBD_SLAB_FREE_PTR(gl_work, ldlm_glimpse_work_kmem);
	else
		OBD_FREE_PTR(gl_work);

	RETURN(rc);
}
#endif

/**
 * Process a call to completion AST callback for a lock in ast_work list
 */
static int
ldlm_work_cp_ast_lock(struct ptlrpc_request_set *rqset, void *opaq)
{
	struct ldlm_cb_set_arg *arg = opaq;
	struct ldlm_lock *lock;
	ldlm_completion_callback completion_callback;
	int rc = 0;

	ENTRY;

	if (list_empty(arg->list))
		RETURN(-ENOENT);

	lock = list_entry(arg->list->next, struct ldlm_lock, l_cp_ast);

	/* It's possible to receive a completion AST before we've set
	 * the l_completion_ast pointer: either because the AST arrived
	 * before the reply, or simply because there's a small race
	 * window between receiving the reply and finishing the local
	 * enqueue. (bug 842)
	 *
	 * This can't happen with the blocking_ast, however, because we
	 * will never call the local blocking_ast until we drop our
	 * reader/writer reference, which we won't do until we get the
	 * reply and finish enqueueing. */

	/* nobody should touch l_cp_ast */
	lock_res_and_lock(lock);
	list_del_init(&lock->l_cp_ast);
	LASSERT(ldlm_is_cp_reqd(lock));
	/* save l_completion_ast since it can be changed by
	 * mds_intent_policy(), see bug 14225 */
	completion_callback = lock->l_completion_ast;
	ldlm_clear_cp_reqd(lock);
	unlock_res_and_lock(lock);

	if (completion_callback != NULL)
		rc = completion_callback(lock, 0, (void *)arg);
	LDLM_LOCK_RELEASE(lock);

	RETURN(rc);
}

/**
 * Process list of locks in need of ASTs being sent.
 *
 * Used on server to send multiple ASTs together instead of sending one by
 * one.
 */
int ldlm_run_ast_work(struct ldlm_namespace *ns, struct list_head *rpc_list,
		      ldlm_desc_ast_t ast_type)
{
	struct ldlm_cb_set_arg *arg;
	set_producer_func work_ast_lock;
	int rc;

	if (list_empty(rpc_list))
		RETURN(0);

	OBD_ALLOC_PTR(arg);
	if (arg == NULL)
		RETURN(-ENOMEM);

	atomic_set(&arg->restart, 0);
	arg->list = rpc_list;

	switch (ast_type) {
	case LDLM_WORK_CP_AST:
		arg->type = LDLM_CP_CALLBACK;
		work_ast_lock = ldlm_work_cp_ast_lock;
		break;
#ifdef HAVE_SERVER_SUPPORT
	case LDLM_WORK_BL_AST:
		arg->type = LDLM_BL_CALLBACK;
		work_ast_lock = ldlm_work_bl_ast_lock;
		break;
	case LDLM_WORK_REVOKE_AST:
		arg->type = LDLM_BL_CALLBACK;
		work_ast_lock = ldlm_work_revoke_ast_lock;
		break;
	case LDLM_WORK_GL_AST:
		arg->type = LDLM_GL_CALLBACK;
		work_ast_lock = ldlm_work_gl_ast_lock;
		break;
#endif
	default:
		LBUG();
	}

	/* We create a ptlrpc request set with flow control extension.
	 * This request set will use the work_ast_lock function to produce new
	 * requests and will send a new request each time one completes in order
	 * to keep the number of requests in flight to ns_max_parallel_ast */
	arg->set = ptlrpc_prep_fcset(ns->ns_max_parallel_ast ? : UINT_MAX,
				     work_ast_lock, arg);
	if (arg->set == NULL)
		GOTO(out, rc = -ENOMEM);

	ptlrpc_set_wait(NULL, arg->set);
	ptlrpc_set_destroy(arg->set);

	rc = atomic_read(&arg->restart) ? -ERESTART : 0;
	GOTO(out, rc);
out:
	OBD_FREE_PTR(arg);
	return rc;
}

/**
 * Try to grant all waiting locks on a resource.
 *
 * Calls ldlm_reprocess_queue on waiting queue.
 *
 * Typically called after some resource locks are cancelled to see
 * if anything could be granted as a result of the cancellation.
 */
static void __ldlm_reprocess_all(struct ldlm_resource *res,
				 enum ldlm_process_intention intention,
				 struct ldlm_lock *hint)
{
	struct list_head rpc_list;
#ifdef HAVE_SERVER_SUPPORT
	ldlm_reprocessing_policy reprocess;
	struct obd_device *obd;
	int rc;

	ENTRY;

	INIT_LIST_HEAD(&rpc_list);
	/* Local lock trees don't get reprocessed. */
	if (ns_is_client(ldlm_res_to_ns(res))) {
		EXIT;
		return;
	}

	/* Disable reprocess during lock replay stage but allow during
	 * request replay stage.
	 */
	obd = ldlm_res_to_ns(res)->ns_obd;
	if (obd->obd_recovering &&
	    atomic_read(&obd->obd_req_replay_clients) == 0)
		RETURN_EXIT;
restart:
	lock_res(res);
	reprocess = ldlm_get_reprocessing_policy(res);
	reprocess(res, &res->lr_waiting, &rpc_list, intention, hint);
	unlock_res(res);

	rc = ldlm_run_ast_work(ldlm_res_to_ns(res), &rpc_list,
			       LDLM_WORK_CP_AST);
	if (rc == -ERESTART) {
		LASSERT(list_empty(&rpc_list));
		goto restart;
	}
#else
	ENTRY;

	INIT_LIST_HEAD(&rpc_list);
	if (!ns_is_client(ldlm_res_to_ns(res))) {
		CERROR("This is client-side-only module, cannot handle "
		       "LDLM_NAMESPACE_SERVER resource type lock.\n");
		LBUG();
	}
#endif
	EXIT;
}

void ldlm_reprocess_all(struct ldlm_resource *res, struct ldlm_lock *hint)
{
	__ldlm_reprocess_all(res, LDLM_PROCESS_RESCAN, hint);
}
EXPORT_SYMBOL(ldlm_reprocess_all);

static int ldlm_reprocess_res(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			      struct hlist_node *hnode, void *arg)
{
	struct ldlm_resource *res = cfs_hash_object(hs, hnode);

	/* This is only called once after recovery done. LU-8306. */
	__ldlm_reprocess_all(res, LDLM_PROCESS_RECOVERY, NULL);
	return 0;
}

/**
 * Iterate through all resources on a namespace attempting to grant waiting
 * locks.
 */
void ldlm_reprocess_recovery_done(struct ldlm_namespace *ns)
{
	ENTRY;

	if (ns != NULL) {
		cfs_hash_for_each_nolock(ns->ns_rs_hash,
					 ldlm_reprocess_res, NULL, 0);
	}
	EXIT;
}

/**
 * Helper function to call blocking AST for LDLM lock \a lock in a
 * "cancelling" mode.
 */
void ldlm_cancel_callback(struct ldlm_lock *lock)
{
	check_res_locked(lock->l_resource);
	if (!ldlm_is_cancel(lock)) {
		ldlm_set_cancel(lock);
		if (lock->l_blocking_ast) {
                        unlock_res_and_lock(lock);
                        lock->l_blocking_ast(lock, NULL, lock->l_ast_data,
                                             LDLM_CB_CANCELING);
                        lock_res_and_lock(lock);
                } else {
                        LDLM_DEBUG(lock, "no blocking ast");
                }

		/* only canceller can set bl_done bit */
		ldlm_set_bl_done(lock);
		wake_up_all(&lock->l_waitq);
	} else if (!ldlm_is_bl_done(lock)) {
		struct l_wait_info lwi = { 0 };

		/* The lock is guaranteed to have been canceled once
		 * returning from this function. */
		unlock_res_and_lock(lock);
		l_wait_event(lock->l_waitq, is_bl_done(lock), &lwi);
		lock_res_and_lock(lock);
	}
}

/**
 * Remove skiplist-enabled LDLM lock \a req from granted list
 */
void ldlm_unlink_lock_skiplist(struct ldlm_lock *req)
{
        if (req->l_resource->lr_type != LDLM_PLAIN &&
            req->l_resource->lr_type != LDLM_IBITS)
                return;

	list_del_init(&req->l_sl_policy);
	list_del_init(&req->l_sl_mode);
}

/**
 * Attempts to cancel LDLM lock \a lock that has no reader/writer references.
 */
void ldlm_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        ENTRY;

        lock_res_and_lock(lock);

        res = lock->l_resource;
        ns  = ldlm_res_to_ns(res);

        /* Please do not, no matter how tempting, remove this LBUG without
         * talking to me first. -phik */
        if (lock->l_readers || lock->l_writers) {
                LDLM_ERROR(lock, "lock still has references");
		unlock_res_and_lock(lock);
                LBUG();
        }

	if (ldlm_is_waited(lock))
		ldlm_del_waiting_lock(lock);

        /* Releases cancel callback. */
        ldlm_cancel_callback(lock);

	/* Yes, second time, just in case it was added again while we were
	 * running with no res lock in ldlm_cancel_callback */
	if (ldlm_is_waited(lock))
		ldlm_del_waiting_lock(lock);

        ldlm_resource_unlink_lock(lock);
        ldlm_lock_destroy_nolock(lock);

	if (ldlm_is_granted(lock))
		ldlm_pool_del(&ns->ns_pool, lock);

        /* Make sure we will not be called again for same lock what is possible
         * if not to zero out lock->l_granted_mode */
        lock->l_granted_mode = LCK_MINMODE;
        unlock_res_and_lock(lock);

        EXIT;
}
EXPORT_SYMBOL(ldlm_lock_cancel);

/**
 * Set opaque data into the lock that only makes sense to upper layer.
 */
int ldlm_lock_set_data(const struct lustre_handle *lockh, void *data)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        int rc = -EINVAL;
        ENTRY;

        if (lock) {
                if (lock->l_ast_data == NULL)
                        lock->l_ast_data = data;
                if (lock->l_ast_data == data)
                        rc = 0;
                LDLM_LOCK_PUT(lock);
        }
        RETURN(rc);
}
EXPORT_SYMBOL(ldlm_lock_set_data);

struct export_cl_data {
	const struct lu_env	*ecl_env;
	struct obd_export	*ecl_exp;
	int			ecl_loop;
};

static void ldlm_cancel_lock_for_export(struct obd_export *exp,
					struct ldlm_lock *lock,
					struct export_cl_data *ecl)
{
	struct ldlm_resource *res;

	res = ldlm_resource_getref(lock->l_resource);

	ldlm_lvbo_update(res, lock, NULL, 1);
	ldlm_lock_cancel(lock);
	if (!exp->exp_obd->obd_stopping)
		ldlm_reprocess_all(res, lock);
	ldlm_resource_putref(res);

	ecl->ecl_loop++;
	if ((ecl->ecl_loop & -ecl->ecl_loop) == ecl->ecl_loop) {
		CDEBUG(D_INFO, "Export %p, %d locks cancelled.\n",
		       exp, ecl->ecl_loop);
	}
}

/**
 * Iterator function for ldlm_export_cancel_locks.
 * Cancels passed locks.
 */
static int
ldlm_cancel_locks_for_export_cb(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				struct hlist_node *hnode, void *data)

{
	struct export_cl_data	*ecl = (struct export_cl_data *)data;
	struct obd_export	*exp  = ecl->ecl_exp;
	struct ldlm_lock	*lock = cfs_hash_object(hs, hnode);

	LDLM_LOCK_GET(lock);
	ldlm_cancel_lock_for_export(exp, lock, ecl);
	LDLM_LOCK_RELEASE(lock);

	return 0;
}

/**
 * Cancel all blocked locks for given export.
 *
 * Typically called on client disconnection/eviction
 */
int ldlm_export_cancel_blocked_locks(struct obd_export *exp)
{
	struct lu_env env;
	struct export_cl_data	ecl = {
		.ecl_exp	= exp,
		.ecl_loop	= 0,
	};
	int rc;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);
	ecl.ecl_env = &env;

	while (!list_empty(&exp->exp_bl_list)) {
		struct ldlm_lock *lock;

		spin_lock_bh(&exp->exp_bl_list_lock);
		if (!list_empty(&exp->exp_bl_list)) {
			lock = list_entry(exp->exp_bl_list.next,
					  struct ldlm_lock, l_exp_list);
			LDLM_LOCK_GET(lock);
			list_del_init(&lock->l_exp_list);
		} else {
			lock = NULL;
		}
		spin_unlock_bh(&exp->exp_bl_list_lock);

		if (lock == NULL)
			break;

		ldlm_cancel_lock_for_export(exp, lock, &ecl);
		LDLM_LOCK_RELEASE(lock);
	}

	lu_env_fini(&env);

	CDEBUG(D_DLMTRACE, "Export %p, canceled %d locks, "
	       "left on hash table %d.\n", exp, ecl.ecl_loop,
	       atomic_read(&exp->exp_lock_hash->hs_count));

	return ecl.ecl_loop;
}

/**
 * Cancel all locks for given export.
 *
 * Typically called after client disconnection/eviction
 */
int ldlm_export_cancel_locks(struct obd_export *exp)
{
	struct export_cl_data ecl;
	struct lu_env env;
	int rc;

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc)
		RETURN(rc);
	ecl.ecl_env = &env;
	ecl.ecl_exp = exp;
	ecl.ecl_loop = 0;

	cfs_hash_for_each_empty(exp->exp_lock_hash,
				ldlm_cancel_locks_for_export_cb, &ecl);

	CDEBUG(D_DLMTRACE, "Export %p, canceled %d locks, "
	       "left on hash table %d.\n", exp, ecl.ecl_loop,
	       atomic_read(&exp->exp_lock_hash->hs_count));

	if (ecl.ecl_loop > 0 &&
	    atomic_read(&exp->exp_lock_hash->hs_count) == 0 &&
	    exp->exp_obd->obd_stopping)
		ldlm_reprocess_recovery_done(exp->exp_obd->obd_namespace);

	lu_env_fini(&env);

	return ecl.ecl_loop;
}

/**
 * Downgrade an PW/EX lock to COS | CR mode.
 *
 * A lock mode convertion from PW/EX mode to less conflict mode. The
 * convertion may fail if lock was canceled before downgrade, but it doesn't
 * indicate any problem, because such lock has no reader or writer, and will
 * be released soon.
 *
 * Used by Commit on Sharing (COS) code to force object changes commit in case
 * of conflict. Converted lock is considered as new lock and all blocking AST
 * things are cleared, so any pending or new blocked lock on that lock will
 * cause new call to blocking_ast and force resource object commit.
 *
 * Also used by layout_change to replace EX lock to CR lock.
 *
 * \param lock A lock to convert
 * \param new_mode new lock mode
 */
void ldlm_lock_mode_downgrade(struct ldlm_lock *lock, enum ldlm_mode new_mode)
{
#ifdef HAVE_SERVER_SUPPORT
	ENTRY;

	LASSERT(new_mode == LCK_COS || new_mode == LCK_CR);

	lock_res_and_lock(lock);

	if (!(lock->l_granted_mode & (LCK_PW | LCK_EX))) {
		unlock_res_and_lock(lock);

		LASSERT(lock->l_granted_mode == LCK_MINMODE);
		LDLM_DEBUG(lock, "lock was canceled before downgrade");
		RETURN_EXIT;
	}

	ldlm_resource_unlink_lock(lock);
	/*
	 * Remove the lock from pool as it will be added again in
	 * ldlm_grant_lock() called below.
	 */
	ldlm_pool_del(&ldlm_lock_to_ns(lock)->ns_pool, lock);

	/* Consider downgraded lock as a new lock and clear all states
	 * related to a previous blocking AST processing.
	 */
	ldlm_clear_blocking_data(lock);

	lock->l_req_mode = new_mode;
	ldlm_grant_lock(lock, NULL);
	unlock_res_and_lock(lock);

	ldlm_reprocess_all(lock->l_resource, lock);

	EXIT;
#endif
}
EXPORT_SYMBOL(ldlm_lock_mode_downgrade);

/**
 * Print lock with lock handle \a lockh description into debug log.
 *
 * Used when printing all locks on a resource for debug purposes.
 */
void ldlm_lock_dump_handle(int level, const struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;

        if (!((libcfs_debug | D_ERROR) & level))
                return;

        lock = ldlm_handle2lock(lockh);
        if (lock == NULL)
                return;

        LDLM_DEBUG_LIMIT(level, lock, "###");

        LDLM_LOCK_PUT(lock);
}
EXPORT_SYMBOL(ldlm_lock_dump_handle);

/**
 * Print lock information with custom message into debug log.
 * Helper function.
 */
void _ldlm_lock_debug(struct ldlm_lock *lock,
                      struct libcfs_debug_msg_data *msgdata,
                      const char *fmt, ...)
{
        va_list args;
        struct obd_export *exp = lock->l_export;
	struct ldlm_resource *resource = NULL;
        char *nid = "local";

	/* on server-side resource of lock doesn't change */
	if ((lock->l_flags & LDLM_FL_NS_SRV) != 0) {
		if (lock->l_resource != NULL)
			resource = ldlm_resource_getref(lock->l_resource);
	} else if (spin_trylock(&lock->l_lock)) {
		if (lock->l_resource != NULL)
			resource = ldlm_resource_getref(lock->l_resource);
		spin_unlock(&lock->l_lock);
	}

        va_start(args, fmt);

        if (exp && exp->exp_connection) {
		nid = obd_export_nid2str(exp);
        } else if (exp && exp->exp_obd != NULL) {
                struct obd_import *imp = exp->exp_obd->u.cli.cl_import;
		nid = obd_import_nid2str(imp);
        }

        if (resource == NULL) {
                libcfs_debug_vmsg2(msgdata, fmt, args,
		       " ns: \?\? lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s "
		       "res: \?\? rrc=\?\? type: \?\?\? flags: %#llx nid: %s "
		       "remote: %#llx expref: %d pid: %u timeout: %lld "
		       "lvb_type: %d\n",
                       lock,
		       lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
                       lock->l_readers, lock->l_writers,
                       ldlm_lockname[lock->l_granted_mode],
                       ldlm_lockname[lock->l_req_mode],
                       lock->l_flags, nid, lock->l_remote_handle.cookie,
		       exp ? atomic_read(&exp->exp_refcount) : -99,
                       lock->l_pid, lock->l_callback_timeout, lock->l_lvb_type);
                va_end(args);
                return;
        }

	switch (resource->lr_type) {
	case LDLM_EXTENT:
		libcfs_debug_vmsg2(msgdata, fmt, args,
			" ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s "
			"res: "DLDLMRES" rrc: %d type: %s [%llu->%llu] "
			"(req %llu->%llu) flags: %#llx nid: %s remote: "
			"%#llx expref: %d pid: %u timeout: %lld lvb_type: %d\n",
			ldlm_lock_to_ns_name(lock), lock,
			lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
			lock->l_readers, lock->l_writers,
			ldlm_lockname[lock->l_granted_mode],
			ldlm_lockname[lock->l_req_mode],
			PLDLMRES(resource),
			atomic_read(&resource->lr_refcount),
			ldlm_typename[resource->lr_type],
			lock->l_policy_data.l_extent.start,
			lock->l_policy_data.l_extent.end,
			lock->l_req_extent.start, lock->l_req_extent.end,
			lock->l_flags, nid, lock->l_remote_handle.cookie,
			exp ? atomic_read(&exp->exp_refcount) : -99,
			lock->l_pid, lock->l_callback_timeout,
			lock->l_lvb_type);
		break;

	case LDLM_FLOCK:
		libcfs_debug_vmsg2(msgdata, fmt, args,
			" ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s "
			"res: "DLDLMRES" rrc: %d type: %s pid: %d "
			"[%llu->%llu] flags: %#llx nid: %s "
			"remote: %#llx expref: %d pid: %u timeout: %lld\n",
			ldlm_lock_to_ns_name(lock), lock,
			lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
			lock->l_readers, lock->l_writers,
			ldlm_lockname[lock->l_granted_mode],
			ldlm_lockname[lock->l_req_mode],
			PLDLMRES(resource),
			atomic_read(&resource->lr_refcount),
			ldlm_typename[resource->lr_type],
			lock->l_policy_data.l_flock.pid,
			lock->l_policy_data.l_flock.start,
			lock->l_policy_data.l_flock.end,
			lock->l_flags, nid, lock->l_remote_handle.cookie,
			exp ? atomic_read(&exp->exp_refcount) : -99,
			lock->l_pid, lock->l_callback_timeout);
		break;

	case LDLM_IBITS:
		libcfs_debug_vmsg2(msgdata, fmt, args,
			" ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s "
			"res: "DLDLMRES" bits %#llx/%#llx rrc: %d type: %s "
			"flags: %#llx nid: %s remote: %#llx expref: %d "
			"pid: %u timeout: %lld lvb_type: %d\n",
			ldlm_lock_to_ns_name(lock),
			lock, lock->l_handle.h_cookie,
			atomic_read(&lock->l_refc),
			lock->l_readers, lock->l_writers,
			ldlm_lockname[lock->l_granted_mode],
			ldlm_lockname[lock->l_req_mode],
			PLDLMRES(resource),
			lock->l_policy_data.l_inodebits.bits,
			lock->l_policy_data.l_inodebits.try_bits,
			atomic_read(&resource->lr_refcount),
			ldlm_typename[resource->lr_type],
			lock->l_flags, nid, lock->l_remote_handle.cookie,
			exp ? atomic_read(&exp->exp_refcount) : -99,
			lock->l_pid, lock->l_callback_timeout,
			lock->l_lvb_type);
		break;

	default:
		libcfs_debug_vmsg2(msgdata, fmt, args,
			" ns: %s lock: %p/%#llx lrc: %d/%d,%d mode: %s/%s "
			"res: "DLDLMRES" rrc: %d type: %s flags: %#llx "
			"nid: %s remote: %#llx expref: %d pid: %u "
			"timeout: %lld lvb_type: %d\n",
			ldlm_lock_to_ns_name(lock),
			lock, lock->l_handle.h_cookie,
			atomic_read(&lock->l_refc),
			lock->l_readers, lock->l_writers,
			ldlm_lockname[lock->l_granted_mode],
			ldlm_lockname[lock->l_req_mode],
			PLDLMRES(resource),
			atomic_read(&resource->lr_refcount),
			ldlm_typename[resource->lr_type],
			lock->l_flags, nid, lock->l_remote_handle.cookie,
			exp ? atomic_read(&exp->exp_refcount) : -99,
			lock->l_pid, lock->l_callback_timeout,
			lock->l_lvb_type);
		break;
	}
	va_end(args);
	ldlm_resource_putref(resource);
}
EXPORT_SYMBOL(_ldlm_lock_debug);
