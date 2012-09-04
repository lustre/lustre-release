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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
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

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
# include <linux/lustre_intent.h>
#else
# include <liblustre.h>
# include <libcfs/kp30.h>
#endif

#include <obd_class.h>
#include "ldlm_internal.h"

//struct lustre_lock ldlm_everything_lock;

/* lock types */
char *ldlm_lockname[] = {
        [0] "--",
        [LCK_EX] "EX",
        [LCK_PW] "PW",
        [LCK_PR] "PR",
        [LCK_CW] "CW",
        [LCK_CR] "CR",
        [LCK_NL] "NL",
        [LCK_GROUP] "GROUP"
};

char *ldlm_typename[] = {
        [LDLM_PLAIN] "PLN",
        [LDLM_EXTENT] "EXT",
        [LDLM_FLOCK] "FLK",
        [LDLM_IBITS] "IBT",
};

char *ldlm_it2str(int it)
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
        case IT_UNLINK:
                return "unlink";
        case IT_GETXATTR:
                return "getxattr";
        default:
                CERROR("Unknown intent %d\n", it);
                return "UNKNOWN";
        }
}

extern cfs_mem_cache_t *ldlm_lock_slab;

static ldlm_processing_policy ldlm_processing_policy_table[] = {
        [LDLM_PLAIN] ldlm_process_plain_lock,
        [LDLM_EXTENT] ldlm_process_extent_lock,
#ifdef __KERNEL__
        [LDLM_FLOCK] ldlm_process_flock_lock,
#endif
        [LDLM_IBITS] ldlm_process_inodebits_lock,
};

ldlm_processing_policy ldlm_get_processing_policy(struct ldlm_resource *res)
{
        return ldlm_processing_policy_table[res->lr_type];
}

void ldlm_register_intent(struct ldlm_namespace *ns, ldlm_res_policy arg)
{
        ns->ns_policy = arg;
}

/*
 * REFCOUNTED LOCK OBJECTS
 */


/*
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

static void ldlm_lock_free(struct ldlm_lock *lock, size_t size)
{
        LASSERT(size == sizeof(*lock));
        OBD_SLAB_FREE(lock, ldlm_lock_slab, sizeof(*lock));
}

void ldlm_lock_put(struct ldlm_lock *lock)
{
        ENTRY;

        LASSERT(lock->l_resource != LP_POISON);
        LASSERT(atomic_read(&lock->l_refc) > 0);
        if (atomic_dec_and_test(&lock->l_refc)) {
                struct ldlm_resource *res;

                LDLM_DEBUG(lock, "final lock_put on destroyed lock, freeing it.");

                res = lock->l_resource;
                LASSERT(lock->l_destroyed);
                LASSERT(list_empty(&lock->l_res_link));
                LASSERT(list_empty(&lock->l_pending_chain));

                atomic_dec(&res->lr_namespace->ns_locks);
                ldlm_resource_putref(res);
                lock->l_resource = NULL;
                if (lock->l_export) {
                        class_export_put(lock->l_export);
                        lock->l_export = NULL;
                }

                if (lock->l_lvb_data != NULL)
                        OBD_FREE(lock->l_lvb_data, lock->l_lvb_len);

                ldlm_interval_free(ldlm_interval_detach(lock));
                OBD_FREE_RCU_CB(lock, sizeof(*lock), &lock->l_handle,
                                ldlm_lock_free);
        }

        EXIT;
}

int ldlm_lock_remove_from_lru_nolock(struct ldlm_lock *lock)
{
        int rc = 0;
        if (!list_empty(&lock->l_lru)) {
                struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
                LASSERT(lock->l_resource->lr_type != LDLM_FLOCK);
                list_del_init(&lock->l_lru);
                if (lock->l_flags & LDLM_FL_SKIPPED)
                        lock->l_flags &= ~LDLM_FL_SKIPPED;
                LASSERT(ns->ns_nr_unused > 0);
                ns->ns_nr_unused--;
                atomic_dec(&ldlm_cli_all_ns_unused);
                rc = 1;
        }
        return rc;
}

int ldlm_lock_remove_from_lru(struct ldlm_lock *lock)
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        int rc;
        ENTRY;
        spin_lock(&ns->ns_unused_lock);
        rc = ldlm_lock_remove_from_lru_nolock(lock);
        spin_unlock(&ns->ns_unused_lock);
        EXIT;
        return rc;
}

void ldlm_lock_add_to_lru_nolock(struct ldlm_lock *lock)
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        lock->l_last_used = cfs_time_current();
        LASSERT(list_empty(&lock->l_lru));
        LASSERT(lock->l_resource->lr_type != LDLM_FLOCK);
        list_add_tail(&lock->l_lru, &ns->ns_unused_list);
        LASSERT(ns->ns_nr_unused >= 0);
        ns->ns_nr_unused++;
        atomic_inc(&ldlm_cli_all_ns_unused);
}

void ldlm_lock_add_to_lru(struct ldlm_lock *lock)
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        ENTRY;
        spin_lock(&ns->ns_unused_lock);
        ldlm_lock_add_to_lru_nolock(lock);
        spin_unlock(&ns->ns_unused_lock);
        EXIT;
}

void ldlm_lock_touch_in_lru(struct ldlm_lock *lock)
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        ENTRY;
        spin_lock(&ns->ns_unused_lock);
        if (!list_empty(&lock->l_lru)) {
                ldlm_lock_remove_from_lru_nolock(lock);
                ldlm_lock_add_to_lru_nolock(lock);
        }
        spin_unlock(&ns->ns_unused_lock);
        EXIT;
}

/* This used to have a 'strict' flag, which recovery would use to mark an
 * in-use lock as needing-to-die.  Lest I am ever tempted to put it back, I
 * shall explain why it's gone: with the new hash table scheme, once you call
 * ldlm_lock_destroy, you can never drop your final references on this lock.
 * Because it's not in the hash table anymore.  -phil */
int ldlm_lock_destroy_internal(struct ldlm_lock *lock)
{
        ENTRY;

        if (lock->l_readers || lock->l_writers) {
                LDLM_ERROR(lock, "lock still has references");
                ldlm_lock_dump(D_ERROR, lock, 0);
                LBUG();
        }

        if (!list_empty(&lock->l_res_link)) {
                LDLM_ERROR(lock, "lock still on resource");
                ldlm_lock_dump(D_ERROR, lock, 0);
                LBUG();
        }

        if (lock->l_destroyed) {
                LASSERT(list_empty(&lock->l_lru));
                EXIT;
                return 0;
        }
        lock->l_destroyed = 1;

        if (lock->l_export && lock->l_export->exp_lock_hash)
                lustre_hash_del(lock->l_export->exp_lock_hash,
                                &lock->l_remote_handle, &lock->l_exp_hash);

        ldlm_lock_remove_from_lru(lock);
        class_handle_unhash(&lock->l_handle);

#if 0
        /* Wake anyone waiting for this lock */
        /* FIXME: I should probably add yet another flag, instead of using
         * l_export to only call this on clients */
        if (lock->l_export)
                class_export_put(lock->l_export);
        lock->l_export = NULL;
        if (lock->l_export && lock->l_completion_ast)
                lock->l_completion_ast(lock, 0);
#endif
        EXIT;
        return 1;
}

void ldlm_lock_destroy(struct ldlm_lock *lock)
{
        int first;
        ENTRY;
        lock_res_and_lock(lock);
        first = ldlm_lock_destroy_internal(lock);
        unlock_res_and_lock(lock);

        /* drop reference from hashtable only for first destroy */
        if (first)
                LDLM_LOCK_PUT(lock);
        EXIT;
}

void ldlm_lock_destroy_nolock(struct ldlm_lock *lock)
{
        int first;
        ENTRY;
        first = ldlm_lock_destroy_internal(lock);
        /* drop reference from hashtable only for first destroy */
        if (first)
                LDLM_LOCK_PUT(lock);
        EXIT;
}

/* this is called by portals_handle2object with the handle lock taken */
static void lock_handle_addref(void *lock)
{
        LDLM_LOCK_GET((struct ldlm_lock *)lock);
}

/*
 * usage: pass in a resource on which you have done ldlm_resource_get
 *        pass in a parent lock on which you have done a ldlm_lock_get
 *        after return, ldlm_*_put the resource and parent
 * returns: lock with refcount 2 - one for current caller and one for remote
 */
static struct ldlm_lock *ldlm_lock_new(struct ldlm_resource *resource)
{
        struct ldlm_lock *lock;
        ENTRY;

        if (resource == NULL)
                LBUG();

        OBD_SLAB_ALLOC(lock, ldlm_lock_slab, CFS_ALLOC_IO, sizeof(*lock));
        if (lock == NULL)
                RETURN(NULL);

        spin_lock_init(&lock->l_lock);
        lock->l_resource = ldlm_resource_getref(resource);

        atomic_set(&lock->l_refc, 2);
        CFS_INIT_LIST_HEAD(&lock->l_res_link);
        CFS_INIT_LIST_HEAD(&lock->l_lru);
        CFS_INIT_LIST_HEAD(&lock->l_pending_chain);
        CFS_INIT_LIST_HEAD(&lock->l_bl_ast);
        CFS_INIT_LIST_HEAD(&lock->l_cp_ast);
        cfs_waitq_init(&lock->l_waitq);
        lock->l_blocking_lock = NULL;
        CFS_INIT_LIST_HEAD(&lock->l_sl_mode);
        CFS_INIT_LIST_HEAD(&lock->l_sl_policy);
        CFS_INIT_HLIST_NODE(&lock->l_exp_hash);

        atomic_inc(&resource->lr_namespace->ns_locks);
        CFS_INIT_LIST_HEAD(&lock->l_handle.h_link);
        class_handle_hash(&lock->l_handle, lock_handle_addref);

        CFS_INIT_LIST_HEAD(&lock->l_extents_list);
        spin_lock_init(&lock->l_extents_list_lock);
        CFS_INIT_LIST_HEAD(&lock->l_cache_locks_list);
        lock->l_callback_timeout = 0;

        RETURN(lock);
}

int ldlm_lock_change_resource(struct ldlm_namespace *ns, struct ldlm_lock *lock,
                              struct ldlm_res_id new_resid)
{
        struct ldlm_resource *oldres = lock->l_resource;
        struct ldlm_resource *newres;
        int type;
        ENTRY;

        LASSERT(ns_is_client(ns));

        lock_res_and_lock(lock);
        if (memcmp(&new_resid, &lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) == 0) {
                /* Nothing to do */
                unlock_res_and_lock(lock);
                RETURN(0);
        }

        LASSERT(new_resid.name[0] != 0);

        /* This function assumes that the lock isn't on any lists */
        LASSERT(list_empty(&lock->l_res_link));

        type = oldres->lr_type;
        unlock_res_and_lock(lock);

        newres = ldlm_resource_get(ns, NULL, new_resid, type, 1);
        if (newres == NULL)
                RETURN(-ENOMEM);

        lock_res_and_lock(lock);
        LASSERT(memcmp(&new_resid, &lock->l_resource->lr_name,
                       sizeof(lock->l_resource->lr_name)) != 0);
        lock_res(newres);
        lock->l_resource = newres;
        unlock_res(oldres);
        unlock_res_and_lock(lock);

        /* ...and the flowers are still standing! */
        ldlm_resource_putref(oldres);

        RETURN(0);
}

/*
 *  HANDLES
 */

void ldlm_lock2handle(struct ldlm_lock *lock, struct lustre_handle *lockh)
{
        lockh->cookie = lock->l_handle.h_cookie;
}

/* if flags: atomically get the lock and set the flags.
 *           Return NULL if flag already set
 */

struct ldlm_lock *__ldlm_handle2lock(struct lustre_handle *handle, int flags)
{
        struct ldlm_namespace *ns;
        struct ldlm_lock *lock = NULL, *retval = NULL;
        ENTRY;

        LASSERT(handle);

        lock = class_handle2object(handle->cookie);
        if (lock == NULL)
                RETURN(NULL);

        LASSERT(lock->l_resource != NULL);
        ns = lock->l_resource->lr_namespace;
        LASSERT(ns != NULL);

        lock_res_and_lock(lock);

        /* It's unlikely but possible that someone marked the lock as
         * destroyed after we did handle2object on it */
        if (lock->l_destroyed) {
                unlock_res_and_lock(lock);
                CDEBUG(D_INFO, "lock already destroyed: lock %p\n", lock);
                LDLM_LOCK_PUT(lock);
                GOTO(out, retval);
        }

        if (flags && (lock->l_flags & flags)) {
                unlock_res_and_lock(lock);
                LDLM_LOCK_PUT(lock);
                GOTO(out, retval);
        }

        if (flags)
                lock->l_flags |= flags;

        unlock_res_and_lock(lock);
        retval = lock;
        EXIT;
 out:
        return retval;
}

struct ldlm_lock *ldlm_handle2lock_ns(struct ldlm_namespace *ns,
                                      struct lustre_handle *handle)
{
        struct ldlm_lock *retval = NULL;
        retval = __ldlm_handle2lock(handle, 0);
        return retval;
}

void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
        struct obd_export *exp = lock->l_export?:lock->l_conn_export;
        /* INODEBITS_INTEROP: If the other side does not support
         * inodebits, reply with a plain lock descriptor.
         */
        if ((lock->l_resource->lr_type == LDLM_IBITS) &&
            (exp && !(exp->exp_connect_flags & OBD_CONNECT_IBITS))) {

                /* Make sure all the right bits are set in this lock we
                   are going to pass to client */
                LASSERTF(lock->l_policy_data.l_inodebits.bits ==
                         (MDS_INODELOCK_LOOKUP|MDS_INODELOCK_UPDATE),
                         "Inappropriate inode lock bits during "
                         "conversion " LPU64 "\n",
                         lock->l_policy_data.l_inodebits.bits);
                ldlm_res2desc(lock->l_resource, &desc->l_resource);
                desc->l_resource.lr_type = LDLM_PLAIN;
                /* Convert "new" lock mode to something old client can
                   understand */
                if ((lock->l_req_mode == LCK_CR) ||
                    (lock->l_req_mode == LCK_CW))
                        desc->l_req_mode = LCK_PR;
                else
                        desc->l_req_mode = lock->l_req_mode;
                if ((lock->l_granted_mode == LCK_CR) ||
                    (lock->l_granted_mode == LCK_CW)) {
                        desc->l_granted_mode = LCK_PR;
                } else {
                        /* We never grant PW/EX locks to clients */
                        LASSERT((lock->l_granted_mode != LCK_PW) &&
                                (lock->l_granted_mode != LCK_EX));
                        desc->l_granted_mode = lock->l_granted_mode;
                }

                /* We do not copy policy here, because there is no
                   policy for plain locks */
        } else {
                ldlm_res2desc(lock->l_resource, &desc->l_resource);
                desc->l_req_mode = lock->l_req_mode;
                desc->l_granted_mode = lock->l_granted_mode;
                desc->l_policy_data = lock->l_policy_data;
        }
}

void ldlm_add_bl_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
                           struct list_head *work_list)
{
        if ((lock->l_flags & LDLM_FL_AST_SENT) == 0) {
                LDLM_DEBUG(lock, "lock incompatible; sending blocking AST.");
                lock->l_flags |= LDLM_FL_AST_SENT;
                /* If the enqueuing client said so, tell the AST recipient to
                 * discard dirty data, rather than writing back. */
                if (new->l_flags & LDLM_AST_DISCARD_DATA)
                        lock->l_flags |= LDLM_FL_DISCARD_DATA;
                LASSERT(list_empty(&lock->l_bl_ast));
                list_add(&lock->l_bl_ast, work_list);
                LDLM_LOCK_GET(lock);
                LASSERT(lock->l_blocking_lock == NULL);
                lock->l_blocking_lock = LDLM_LOCK_GET(new);
        }
}

void ldlm_add_cp_work_item(struct ldlm_lock *lock, struct list_head *work_list)
{
        if ((lock->l_flags & LDLM_FL_CP_REQD) == 0) {
                lock->l_flags |= LDLM_FL_CP_REQD;
                LDLM_DEBUG(lock, "lock granted; sending completion AST.");
                LASSERT(list_empty(&lock->l_cp_ast));
                list_add(&lock->l_cp_ast, work_list);
                LDLM_LOCK_GET(lock);
        }
}

/* must be called with lr_lock held */
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

void ldlm_lock_addref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock;

        lock = ldlm_handle2lock(lockh);
        LASSERT(lock != NULL);
        ldlm_lock_addref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}

void ldlm_lock_addref_internal_nolock(struct ldlm_lock *lock, __u32 mode)
{
        ldlm_lock_remove_from_lru(lock);
        if (mode & (LCK_NL | LCK_CR | LCK_PR))
                lock->l_readers++;
        if (mode & (LCK_EX | LCK_CW | LCK_PW | LCK_GROUP))
                lock->l_writers++;
        LDLM_LOCK_GET(lock);
        LDLM_DEBUG(lock, "ldlm_lock_addref(%s)", ldlm_lockname[mode]);
}

/* only called for local locks */
void ldlm_lock_addref_internal(struct ldlm_lock *lock, __u32 mode)
{
        lock_res_and_lock(lock);
        ldlm_lock_addref_internal_nolock(lock, mode);
        unlock_res_and_lock(lock);
}

/* only called in ldlm_flock_destroy and for local locks.
 * for LDLM_FLOCK type locks, l_blocking_ast is null, and
 * ldlm_lock_remove_from_lru() does nothing, it is safe
 * for ldlm_flock_destroy usage by dropping some code */
void ldlm_lock_decref_internal_nolock(struct ldlm_lock *lock, __u32 mode)
{
        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        if (mode & (LCK_NL | LCK_CR | LCK_PR)) {
                LASSERT(lock->l_readers > 0);
                lock->l_readers--;
        }
        if (mode & (LCK_EX | LCK_CW | LCK_PW | LCK_GROUP)) {
                LASSERT(lock->l_writers > 0);
                lock->l_writers--;
        }

        LDLM_LOCK_PUT(lock);    /* matches the ldlm_lock_get in addref */
}

void ldlm_lock_decref_internal(struct ldlm_lock *lock, __u32 mode)
{
        struct ldlm_namespace *ns;
        ENTRY;

        lock_res_and_lock(lock);

        ns = lock->l_resource->lr_namespace;

        ldlm_lock_decref_internal_nolock(lock, mode);

        if (lock->l_flags & LDLM_FL_LOCAL &&
            !lock->l_readers && !lock->l_writers) {
                /* If this is a local lock on a server namespace and this was
                 * the last reference, cancel the lock. */
                CDEBUG(D_INFO, "forcing cancel of local lock\n");
                lock->l_flags |= LDLM_FL_CBPENDING;
        }

        if (!lock->l_readers && !lock->l_writers &&
            (lock->l_flags & LDLM_FL_CBPENDING)) {
                /* If we received a blocked AST and this was the last reference,
                 * run the callback. */
                if (ns_is_server(ns) && lock->l_export)
                        CERROR("FL_CBPENDING set on non-local lock--just a "
                               "warning\n");

                LDLM_DEBUG(lock, "final decref done on cbpending lock");

                LDLM_LOCK_GET(lock); /* dropped by bl thread */
                ldlm_lock_remove_from_lru(lock);
                unlock_res_and_lock(lock);

                if (lock->l_flags & LDLM_FL_FAIL_LOC)
                        OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

                if ((lock->l_flags & LDLM_FL_ATOMIC_CB) ||
                    ldlm_bl_to_thread_lock(ns, NULL, lock) != 0)
                        ldlm_handle_bl_callback(ns, NULL, lock);
        } else if (ns_is_client(ns) &&
                   !lock->l_readers && !lock->l_writers &&
                   !(lock->l_flags & LDLM_FL_NO_LRU) &&
                   !(lock->l_flags & LDLM_FL_BL_AST)) {
                /* If this is a client-side namespace and this was the last
                 * reference, put it on the LRU. */
                ldlm_lock_add_to_lru(lock);
                unlock_res_and_lock(lock);

                if (lock->l_flags & LDLM_FL_FAIL_LOC)
                        OBD_RACE(OBD_FAIL_LDLM_CP_BL_RACE);

                /* Call ldlm_cancel_lru() only if EARLY_CANCEL and LRU RESIZE
                 * are not supported by the server, otherwise, it is done on
                 * enqueue. */
                if (!exp_connect_cancelset(lock->l_conn_export) &&
                    !ns_connect_lru_resize(ns))
                        ldlm_cancel_lru(ns, 0, LDLM_ASYNC, 0);
        } else {
                unlock_res_and_lock(lock);
        }

        EXIT;
}

void ldlm_lock_decref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);
        LASSERTF(lock != NULL, "Non-existing lock: "LPX64"\n", lockh->cookie);
        ldlm_lock_decref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}

/* This will drop a lock reference and mark it for destruction, but will not
 * necessarily cancel the lock before returning. */
void ldlm_lock_decref_and_cancel(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);
        ENTRY;

        LASSERT(lock != NULL);

        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        lock_res_and_lock(lock);
        lock->l_flags |= LDLM_FL_CBPENDING;
        unlock_res_and_lock(lock);
        ldlm_lock_decref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}

struct sl_insert_point {
        struct list_head *res_link;
        struct list_head *mode_link;
        struct list_head *policy_link;
};

/*
 * search_granted_lock
 *
 * Description:
 *      Finds a position to insert the new lock.
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

                mode_end = list_entry(lock->l_sl_mode.prev, struct ldlm_lock,
                                      l_sl_mode);

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
                                policy_end = list_entry(lock->l_sl_policy.prev,
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

                                /* jump to next policy group within the mode group */
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
                        LDLM_ERROR(lock, "is not LDLM_PLAIN or LDLM_IBITS lock");
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

static void ldlm_granted_list_add_lock(struct ldlm_lock *lock,
                                       struct sl_insert_point *prev)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        check_res_locked(res);

        ldlm_resource_dump(D_INFO, res);
        CDEBUG(D_OTHER, "About to add this lock:\n");
        ldlm_lock_dump(D_OTHER, lock, 0);

        if (lock->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                return;
        }

        LASSERT(list_empty(&lock->l_res_link));
        LASSERT(list_empty(&lock->l_sl_mode));
        LASSERT(list_empty(&lock->l_sl_policy));

        list_add(&lock->l_res_link, prev->res_link);
        list_add(&lock->l_sl_mode, prev->mode_link);
        list_add(&lock->l_sl_policy, prev->policy_link);

        EXIT;
}

static void ldlm_grant_lock_with_skiplist(struct ldlm_lock *lock)
{
        struct sl_insert_point prev;
        ENTRY;

        LASSERT(lock->l_req_mode == lock->l_granted_mode);

        search_granted_lock(&lock->l_resource->lr_granted, lock, &prev);
        ldlm_granted_list_add_lock(lock, &prev);
        EXIT;
}

/* NOTE: called by
 *  - ldlm_lock_enqueue
 *  - ldlm_reprocess_queue
 *  - ldlm_lock_convert
 *
 * must be called with lr_lock held
 */
void ldlm_grant_lock(struct ldlm_lock *lock, struct list_head *work_list)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        check_res_locked(res);

        lock->l_granted_mode = lock->l_req_mode;
        if (res->lr_type == LDLM_PLAIN || res->lr_type == LDLM_IBITS)
                ldlm_grant_lock_with_skiplist(lock);
        else if (res->lr_type == LDLM_EXTENT)
                ldlm_extent_add_lock(res, lock);
        else
                ldlm_resource_add_lock(res, &res->lr_granted, lock);

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (work_list && lock->l_completion_ast != NULL)
                ldlm_add_ast_work_item(lock, NULL, work_list);

        ldlm_pool_add(&res->lr_namespace->ns_pool, lock);
        EXIT;
}

/* returns a referenced lock or NULL.  See the flag descriptions below, in the
 * comment above ldlm_lock_match */
static struct ldlm_lock *search_queue(struct list_head *queue,
                                      ldlm_mode_t *mode,
                                      ldlm_policy_data_t *policy,
                                      struct ldlm_lock *old_lock, int flags)
{
        struct ldlm_lock *lock;
        struct list_head *tmp;

        list_for_each(tmp, queue) {
                ldlm_mode_t match;

                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock == old_lock)
                        break;

                /* llite sometimes wants to match locks that will be
                 * canceled when their users drop, but we allow it to match
                 * if it passes in CBPENDING and the lock still has users.
                 * this is generally only going to be used by children
                 * whose parents already hold a lock so forward progress
                 * can still happen. */
                if (lock->l_flags & LDLM_FL_CBPENDING &&
                    !(flags & LDLM_FL_CBPENDING))
                        continue;
                if (lock->l_flags & LDLM_FL_CBPENDING &&
                    lock->l_readers == 0 && lock->l_writers == 0)
                        continue;

                if (!(lock->l_req_mode & *mode))
                        continue;

                match = lock->l_req_mode;
                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    (lock->l_policy_data.l_extent.start >
                     policy->l_extent.start ||
                     lock->l_policy_data.l_extent.end < policy->l_extent.end))
                        continue;

                if (unlikely(match == LCK_GROUP) &&
                    lock->l_resource->lr_type == LDLM_EXTENT &&
                    lock->l_policy_data.l_extent.gid != policy->l_extent.gid)
                        continue;

                /* We match if we have existing lock with same or wider set
                   of bits. */
                if (lock->l_resource->lr_type == LDLM_IBITS &&
                     ((lock->l_policy_data.l_inodebits.bits &
                      policy->l_inodebits.bits) !=
                      policy->l_inodebits.bits))
                        continue;

                if (lock->l_destroyed || (lock->l_flags & LDLM_FL_FAILED))
                        continue;

                if ((flags & LDLM_FL_LOCAL_ONLY) &&
                    !(lock->l_flags & LDLM_FL_LOCAL))
                        continue;

                if (flags & LDLM_FL_TEST_LOCK) {
                        LDLM_LOCK_GET(lock);
                        ldlm_lock_touch_in_lru(lock);
                } else {
                        ldlm_lock_addref_internal_nolock(lock, match);
                }
                *mode = match;
                return lock;
        }

        return NULL;
}

void ldlm_lock_allow_match(struct ldlm_lock *lock)
{
        lock_res_and_lock(lock);
        lock->l_flags |= LDLM_FL_LVB_READY;
        cfs_waitq_signal(&lock->l_waitq);
        unlock_res_and_lock(lock);
}

int ldlm_lock_fast_match(struct ldlm_lock *lock, int rw,
                         obd_off start, obd_off end,
                         struct lustre_handle *lockh)
{
        LASSERT(rw == OBD_BRW_READ || rw == OBD_BRW_WRITE);
        LASSERT(lockh != NULL);

        if (!lock)
                return 0;

        lock_res_and_lock(lock);
        /* check if granted mode is compatible */
        if (rw == OBD_BRW_WRITE &&
            !(lock->l_granted_mode & (LCK_PW|LCK_GROUP)))
                goto no_match;

        /* does the lock cover the region we would like to access? */
        if ((lock->l_policy_data.l_extent.start > start) ||
            (lock->l_policy_data.l_extent.end < end))
                goto no_match;

        /* if we received a blocking callback and the lock is no longer
         * referenced, don't use it */
        if ((lock->l_flags & LDLM_FL_CBPENDING) &&
            !lock->l_writers && !lock->l_readers)
                goto no_match;

        ldlm_lock_addref_internal_nolock(lock,
                                         rw == OBD_BRW_WRITE ? LCK_PW : LCK_PR);
        unlock_res_and_lock(lock);
        ldlm_lock2handle(lock, lockh);
        return 1; /* avoid using rc for stack relief */

no_match:
        unlock_res_and_lock(lock);
        return 0;
}

/* Can be called in two ways:
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
 * Returns 1 if it finds an already-existing lock that is compatible; in this
 * case, lockh is filled in with a addref()ed lock
 */
ldlm_mode_t ldlm_lock_match(struct ldlm_namespace *ns, int flags,
                            struct ldlm_res_id *res_id, ldlm_type_t type,
                            ldlm_policy_data_t *policy, ldlm_mode_t mode,
                            struct lustre_handle *lockh)
{
        struct ldlm_resource *res;
        struct ldlm_lock *lock, *old_lock = NULL;
        int rc = 0;
        ENTRY;

        if (ns == NULL) {
                old_lock = ldlm_handle2lock(lockh);
                LASSERT(old_lock);

                ns = old_lock->l_resource->lr_namespace;
                res_id = &old_lock->l_resource->lr_name;
                type = old_lock->l_resource->lr_type;
                mode = old_lock->l_req_mode;
        }

        res = ldlm_resource_get(ns, NULL, *res_id, type, 0);
        if (res == NULL) {
                LASSERT(old_lock == NULL);
                RETURN(0);
        }

        lock_res(res);

        lock = search_queue(&res->lr_granted, &mode, policy, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);
        if (flags & LDLM_FL_BLOCK_GRANTED)
                GOTO(out, rc = 0);
        lock = search_queue(&res->lr_converting, &mode, policy, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);
        lock = search_queue(&res->lr_waiting, &mode, policy, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);

        EXIT;
 out:
        unlock_res(res);
        ldlm_resource_putref(res);

        if (lock) {
                ldlm_lock2handle(lock, lockh);
                if ((flags & LDLM_FL_LVB_READY) && (!(lock->l_flags & LDLM_FL_LVB_READY))) {
                        struct l_wait_info lwi;
                        if (lock->l_completion_ast) {
                                int err = lock->l_completion_ast(lock,
                                                          LDLM_FL_WAIT_NOREPROC,
                                                                 NULL);
                                if (err) {
                                        if (flags & LDLM_FL_TEST_LOCK)
                                                LDLM_LOCK_PUT(lock);
                                        else
                                                ldlm_lock_decref_internal(lock, mode);
                                        rc = 0;
                                        goto out2;
                                }
                        }

                        lwi = LWI_TIMEOUT_INTR(cfs_time_seconds(obd_timeout), NULL,
                                               LWI_ON_SIGNAL_NOOP, NULL);

                        /* XXX FIXME see comment on CAN_MATCH in lustre_dlm.h */
                        l_wait_event(lock->l_waitq,
                                     (lock->l_flags & LDLM_FL_LVB_READY), &lwi);
                }
        }
 out2:
        if (rc) {
                LDLM_DEBUG(lock, "matched ("LPU64" "LPU64")",
                           (type == LDLM_PLAIN || type == LDLM_IBITS) ?
                                res_id->name[2] : policy->l_extent.start,
                           (type == LDLM_PLAIN || type == LDLM_IBITS) ?
                                res_id->name[3] : policy->l_extent.end);
        } else if (!(flags & LDLM_FL_TEST_LOCK)) {/*less verbose for test-only*/
                LDLM_DEBUG_NOLOCK("not matched ns %p type %u mode %u res "
                                  LPU64"/"LPU64" ("LPU64" "LPU64")", ns,
                                  type, mode, res_id->name[0], res_id->name[1],
                                  (type == LDLM_PLAIN || type == LDLM_IBITS) ?
                                        res_id->name[2] :policy->l_extent.start,
                                (type == LDLM_PLAIN || type == LDLM_IBITS) ?
                                        res_id->name[3] : policy->l_extent.end);
        }
        if (old_lock)
                LDLM_LOCK_PUT(old_lock);
        if (flags & LDLM_FL_TEST_LOCK && rc)
                LDLM_LOCK_PUT(lock);

        return rc ? mode : 0;
}

/* Returns a referenced lock */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
                                   struct ldlm_res_id res_id, ldlm_type_t type,
                                   ldlm_mode_t mode,
                                   ldlm_blocking_callback blocking,
                                   ldlm_completion_callback completion,
                                   ldlm_glimpse_callback glimpse,
                                   void *data, __u32 lvb_len)
{
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        ENTRY;

        res = ldlm_resource_get(ns, NULL, res_id, type, 1);
        if (res == NULL)
                RETURN(NULL);

        lock = ldlm_lock_new(res);
        ldlm_resource_putref(res);

        if (lock == NULL)
                RETURN(NULL);

        lock->l_req_mode = mode;
        lock->l_ast_data = data;
        lock->l_blocking_ast = blocking;
        lock->l_completion_ast = completion;
        lock->l_glimpse_ast = glimpse;
        lock->l_pid = cfs_curproc_pid();

        lock->l_tree_node = NULL;
        /* if this is the extent lock, allocate the interval tree node */
        if (type == LDLM_EXTENT) {
                if (ldlm_interval_alloc(lock) == NULL)
                        GOTO(out, 0);
        }

        if (lvb_len) {
                lock->l_lvb_len = lvb_len;
                OBD_ALLOC(lock->l_lvb_data, lvb_len);
                if (lock->l_lvb_data == NULL)
                        GOTO(out, 0);
        }

        RETURN(lock);

out:
        if (lock->l_lvb_data)
                OBD_FREE(lock->l_lvb_data, lvb_len);
        ldlm_interval_free(ldlm_interval_detach(lock));
        OBD_SLAB_FREE(lock, ldlm_lock_slab, sizeof(*lock));
        return NULL;
}

ldlm_error_t ldlm_lock_enqueue(struct ldlm_namespace *ns,
                               struct ldlm_lock **lockp,
                               void *cookie, int *flags)
{
        struct ldlm_lock *lock = *lockp;
        struct ldlm_resource *res = lock->l_resource;
        int local = ns_is_client(res->lr_namespace);
        ldlm_processing_policy policy;
        ldlm_error_t rc = ELDLM_OK;
        struct ldlm_interval *node = NULL;
        ENTRY;

        lock->l_last_activity = cfs_time_current_sec();
        /* policies are not executed on the client or during replay */
        if ((*flags & (LDLM_FL_HAS_INTENT|LDLM_FL_REPLAY)) == LDLM_FL_HAS_INTENT
            && !local && ns->ns_policy) {
                rc = ns->ns_policy(ns, lockp, cookie, lock->l_req_mode, *flags,
                                   NULL);
                if (rc == ELDLM_LOCK_REPLACED) {
                        /* The lock that was returned has already been granted,
                         * and placed into lockp.  If it's not the same as the
                         * one we passed in, then destroy the old one and our
                         * work here is done. */
                        if (lock != *lockp) {
                                ldlm_lock_destroy(lock);
                                LDLM_LOCK_PUT(lock);
                        }
                        *flags |= LDLM_FL_LOCK_CHANGED;
                        RETURN(0);
                } else if (rc != ELDLM_OK ||
                           (rc == ELDLM_OK && (*flags & LDLM_FL_INTENT_ONLY))) {
                        ldlm_lock_destroy(lock);
                        RETURN(rc);
                }
        }

        /* For a replaying lock, it might be already in granted list. So
         * unlinking the lock will cause the interval node to be freed, we
         * have to allocate the interval node early otherwise we can't regrant
         * this lock in the future. - jay */
        if (!local && (*flags & LDLM_FL_REPLAY) && res->lr_type == LDLM_EXTENT)
                OBD_SLAB_ALLOC(node, ldlm_interval_slab, CFS_ALLOC_IO,
                               sizeof(*node));
        if(res->lr_type == LDLM_EXTENT)
                OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_ENQUEUE_LOCAL, 30);

        lock_res_and_lock(lock);
        if (lock->l_destroyed)
                GOTO(out, rc = -EAGAIN);

        if (local && lock->l_req_mode == lock->l_granted_mode) {
                /* The server returned a blocked lock, but it was granted
                 * before we got a chance to actually enqueue it.  We don't
                 * need to do anything else. */
                *flags &= ~(LDLM_FL_BLOCK_GRANTED |
                            LDLM_FL_BLOCK_CONV | LDLM_FL_BLOCK_WAIT);
                GOTO(out, ELDLM_OK);
        }

        ldlm_resource_unlink_lock(lock);
        if (res->lr_type == LDLM_EXTENT && lock->l_tree_node == NULL) {
                LASSERT(!local && (*flags & LDLM_FL_REPLAY));
                if (node == NULL) {
                        ldlm_lock_destroy_nolock(lock);
                        GOTO(out, rc = -ENOMEM);
                }

                CFS_INIT_LIST_HEAD(&node->li_group);
                ldlm_interval_attach(node, lock);
                node = NULL;
        }

        /* Some flags from the enqueue want to make it into the AST, via the
         * lock's l_flags. */
        lock->l_flags |= *flags & LDLM_AST_DISCARD_DATA;

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
         * granted/converting queues. */
        if (local) {
                if (*flags & LDLM_FL_BLOCK_CONV)
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                else if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                else
                        ldlm_grant_lock(lock, NULL);
                GOTO(out, ELDLM_OK);
        } else if (*flags & LDLM_FL_REPLAY) {
                if (*flags & LDLM_FL_BLOCK_CONV) {
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                        GOTO(out, ELDLM_OK);
                } else if (*flags & LDLM_FL_BLOCK_WAIT) {
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                        GOTO(out, ELDLM_OK);
                } else if (*flags & LDLM_FL_BLOCK_GRANTED) {
                        ldlm_grant_lock(lock, NULL);
                        GOTO(out, ELDLM_OK);
                }
                /* If no flags, fall through to normal enqueue path. */
        }

        policy = ldlm_processing_policy_table[res->lr_type];
        policy(lock, flags, 1, &rc, NULL);
        GOTO(out, rc);
out:
        unlock_res_and_lock(lock);
        if (node)
                OBD_SLAB_FREE(node, ldlm_interval_slab, sizeof(*node));
        return rc;
}

/* Must be called with namespace taken: queue is waiting or converting. */
int ldlm_reprocess_queue(struct ldlm_resource *res, struct list_head *queue,
                         struct list_head *work_list)
{
        struct list_head *tmp, *pos;
        ldlm_processing_policy policy;
        int flags;
        int rc = LDLM_ITER_CONTINUE;
        ldlm_error_t err;
        ENTRY;

        check_res_locked(res);

        policy = ldlm_processing_policy_table[res->lr_type];
        LASSERT(policy);

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *pending;
                pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                CDEBUG(D_INFO, "Reprocessing lock %p\n", pending);

                flags = 0;
                rc = policy(pending, &flags, 0, &err, work_list);
                if (rc != LDLM_ITER_CONTINUE)
                        break;
        }

        RETURN(rc);
}

/* Helper function for pair ldlm_run_{bl,cp}_ast_work().
 *
 * Send an existing rpc set specified by @arg->set and then
 * destroy it. Create new one if @do_create flag is set. */
static void
ldlm_send_and_maybe_create_set(struct ldlm_cb_set_arg *arg, int do_create)
{
        int rc;

        rc = ptlrpc_set_wait(arg->set);
        if (arg->type == LDLM_BL_CALLBACK)
                OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_GLIMPSE, 2);
        ptlrpc_set_destroy(arg->set);

        if (do_create)
                arg->set = ptlrpc_prep_set();
}

int ldlm_run_bl_ast_work(struct list_head *rpc_list)
{
        struct ldlm_cb_set_arg arg;
        struct list_head *tmp, *pos;
        struct ldlm_lock_desc d;
        int ast_count;
        int rc = 0;
        ENTRY;

        if (list_empty(rpc_list))
                RETURN(0);

        arg.set = ptlrpc_prep_set();
        if (NULL == arg.set)
                RETURN(-ERESTART);
        atomic_set(&arg.restart, 0);
        arg.type = LDLM_BL_CALLBACK;

        ast_count = 0;
        list_for_each_safe(tmp, pos, rpc_list) {
                struct ldlm_lock *lock =
                        list_entry(tmp, struct ldlm_lock, l_bl_ast);

                /* nobody should touch l_bl_ast */
                lock_res_and_lock(lock);
                list_del_init(&lock->l_bl_ast);

                LASSERT(lock->l_flags & LDLM_FL_AST_SENT);
                LASSERT(lock->l_bl_ast_run == 0);
                LASSERT(lock->l_blocking_lock);
                lock->l_bl_ast_run++;
                unlock_res_and_lock(lock);

                ldlm_lock2desc(lock->l_blocking_lock, &d);

                LDLM_LOCK_PUT(lock->l_blocking_lock);
                lock->l_blocking_lock = NULL;
                rc = lock->l_blocking_ast(lock, &d, (void *)&arg,
                                          LDLM_CB_BLOCKING);
                LDLM_LOCK_PUT(lock);
                ast_count++;

                /* Send the request set if it exceeds the PARALLEL_AST_LIMIT,
                 * and create a new set for requests that remained in
                 * @rpc_list */
                if (unlikely(ast_count == PARALLEL_AST_LIMIT)) {
                        ldlm_send_and_maybe_create_set(&arg, 1);
                        ast_count = 0;
                }
        }

        if (ast_count > 0)
                ldlm_send_and_maybe_create_set(&arg, 0);
        else
                /* In case when number of ASTs is multiply of
                 * PARALLEL_AST_LIMIT or @rpc_list was initially empty,
                 * @arg.set must be destroyed here, otherwise we get
                 * write memory leaking. */
                ptlrpc_set_destroy(arg.set);

        RETURN(atomic_read(&arg.restart) ? -ERESTART : 0);
}

int ldlm_run_cp_ast_work(struct list_head *rpc_list)
{
        struct ldlm_cb_set_arg arg;
        struct list_head *tmp, *pos;
        int ast_count;
        int rc = 0;
        ENTRY;

        if (list_empty(rpc_list))
                RETURN(0);

        arg.set = ptlrpc_prep_set();
        if (NULL == arg.set)
                RETURN(-ERESTART);
        atomic_set(&arg.restart, 0);
        arg.type = LDLM_CP_CALLBACK;

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

        ast_count = 0;
        list_for_each_safe(tmp, pos, rpc_list) {
                struct ldlm_lock *lock =
                        list_entry(tmp, struct ldlm_lock, l_cp_ast);
                ldlm_completion_callback completion_callback;

                /* nobody should touch l_cp_ast */
                lock_res_and_lock(lock);
                list_del_init(&lock->l_cp_ast);
                LASSERT(lock->l_flags & LDLM_FL_CP_REQD);
                /* save l_completion_ast since it can be changed by
                 * mds_intent_policy(), see bug 14225 */
                completion_callback = lock->l_completion_ast;
                lock->l_flags &= ~LDLM_FL_CP_REQD;
                unlock_res_and_lock(lock);

                if (completion_callback != NULL) {
                        rc = completion_callback(lock, 0, (void *)&arg);
                        ast_count++;
                }
                LDLM_LOCK_PUT(lock);

                /* Send the request set if it exceeds the PARALLEL_AST_LIMIT,
                 * and create a new set for requests that remained in
                 * @rpc_list */
                if (unlikely(ast_count == PARALLEL_AST_LIMIT)) {
                        ldlm_send_and_maybe_create_set(&arg, 1);
                        ast_count = 0;
                }
        }

        if (ast_count > 0)
                ldlm_send_and_maybe_create_set(&arg, 0);
        else
                /* In case when number of ASTs is multiply of
                 * PARALLEL_AST_LIMIT or @rpc_list was initially empty,
                 * @arg.set must be destroyed here, otherwise we get
                 * write memory leaking. */
                ptlrpc_set_destroy(arg.set);

        RETURN(atomic_read(&arg.restart) ? -ERESTART : 0);
}

static int reprocess_one_queue(struct ldlm_resource *res, void *closure)
{
        ldlm_reprocess_all(res);
        return LDLM_ITER_CONTINUE;
}

void ldlm_reprocess_all_ns(struct ldlm_namespace *ns)
{
        struct list_head *tmp;
        int i, rc;

        ENTRY;
        spin_lock(&ns->ns_hash_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                tmp = ns->ns_hash[i].next;
                while (tmp != &(ns->ns_hash[i])) {
                        struct ldlm_resource *res =
                                list_entry(tmp, struct ldlm_resource, lr_hash);

                        ldlm_resource_getref(res);
                        spin_unlock(&ns->ns_hash_lock);

                        rc = reprocess_one_queue(res, NULL);

                        spin_lock(&ns->ns_hash_lock);
                        tmp = tmp->next;
                        ldlm_resource_putref_locked(res);

                        if (rc == LDLM_ITER_STOP)
                                GOTO(out, rc);
                }
        }
 out:
        spin_unlock(&ns->ns_hash_lock);
        EXIT;
}

void ldlm_reprocess_all(struct ldlm_resource *res)
{
        CFS_LIST_HEAD(rpc_list);
        int rc;
        ENTRY;

        /* Local lock trees don't get reprocessed. */
        if (ns_is_client(res->lr_namespace)) {
                EXIT;
                return;
        }

 restart:
        lock_res(res);
        rc = ldlm_reprocess_queue(res, &res->lr_converting, &rpc_list);
        if (rc == LDLM_ITER_CONTINUE)
                ldlm_reprocess_queue(res, &res->lr_waiting, &rpc_list);
        unlock_res(res);

        rc = ldlm_run_cp_ast_work(&rpc_list);
        if (rc == -ERESTART) {
                LASSERT(list_empty(&rpc_list));
                goto restart;
        }
        EXIT;
}

void ldlm_cancel_callback(struct ldlm_lock *lock)
{
        check_res_locked(lock->l_resource);
        if (!(lock->l_flags & LDLM_FL_CANCEL)) {
                lock->l_flags |= LDLM_FL_CANCEL;
                if (lock->l_blocking_ast) {
                        // l_check_no_ns_lock(ns);
                        unlock_res_and_lock(lock);
                        lock->l_blocking_ast(lock, NULL, lock->l_ast_data,
                                             LDLM_CB_CANCELING);
                        lock_res_and_lock(lock);
                } else {
                        LDLM_DEBUG(lock, "no blocking ast");
                }
        }
        lock->l_flags |= LDLM_FL_BL_DONE;
}

void ldlm_unlink_lock_skiplist(struct ldlm_lock *req)
{
        if (req->l_resource->lr_type != LDLM_PLAIN &&
            req->l_resource->lr_type != LDLM_IBITS)
                return;

        list_del_init(&req->l_sl_policy);
        list_del_init(&req->l_sl_mode);
}

void ldlm_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        ENTRY;

        lock_res_and_lock(lock);

        res = lock->l_resource;
        ns = res->lr_namespace;

        /* Please do not, no matter how tempting, remove this LBUG without
         * talking to me first. -phik */
        if (lock->l_readers || lock->l_writers) {
                LDLM_ERROR(lock, "lock still has references");
                LBUG();
        }

        ldlm_del_waiting_lock(lock);
        /* Releases res lock */
        ldlm_cancel_callback(lock);

        /* Yes, second time, just in case it was added again while we were
           running with no res lock in ldlm_cancel_callback */
        ldlm_del_waiting_lock(lock);

        ldlm_resource_unlink_lock(lock);
        ldlm_lock_destroy_nolock(lock);

        if (lock->l_granted_mode == lock->l_req_mode)
                ldlm_pool_del(&ns->ns_pool, lock);

        /* Make sure we will not be called again for same lock what is possible
         * if not to zero out lock->l_granted_mode */
        lock->l_granted_mode = 0;
        unlock_res_and_lock(lock);

        EXIT;
}

int ldlm_lock_set_data(struct lustre_handle *lockh, void *data)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        if (lock == NULL)
                RETURN(-EINVAL);

        lock->l_ast_data = data;
        LDLM_LOCK_PUT(lock);
        RETURN(0);
}

void ldlm_cancel_locks_for_export_cb(void *obj, void *data)
{
        struct obd_export     *exp = data;
        struct ldlm_lock      *lock = obj;
        struct ldlm_resource  *res;

        res = ldlm_resource_getref(lock->l_resource);
        LDLM_LOCK_GET(lock);

        LDLM_DEBUG(lock, "export %p", exp);
        ldlm_res_lvbo_update(res, NULL, 0, 1);

        ldlm_lock_cancel(lock);
        ldlm_reprocess_all(res);

        ldlm_resource_putref(res);
        LDLM_LOCK_PUT(lock);
}

void ldlm_cancel_locks_for_export(struct obd_export *exp)
{
        lustre_hash_for_each_empty(exp->exp_lock_hash,
                                   ldlm_cancel_locks_for_export_cb, exp);
}

struct ldlm_resource *ldlm_lock_convert(struct ldlm_lock *lock, int new_mode,
                                        __u32 *flags)
{
        CFS_LIST_HEAD(rpc_list);
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        int granted = 0;
        int old_mode, rc;
        struct sl_insert_point prev;
        ldlm_error_t err;
        struct ldlm_interval *node;
        ENTRY;

        if (new_mode == lock->l_granted_mode) { // No changes? Just return.
                *flags |= LDLM_FL_BLOCK_GRANTED;
                RETURN(lock->l_resource);
        }

        /* I can't check the type of lock here because the bitlock of lock
         * is not held here, so do the allocation blindly. -jay */
        OBD_SLAB_ALLOC(node, ldlm_interval_slab, CFS_ALLOC_IO, sizeof(*node));
        if (node == NULL)  /* Actually, this causes EDEADLOCK to be returned */
                RETURN(NULL);

        LASSERTF(new_mode == LCK_PW && lock->l_granted_mode == LCK_PR,
                 "new_mode %u, granted %u\n", new_mode, lock->l_granted_mode);

        lock_res_and_lock(lock);
        if (unlikely(lock->l_destroyed != 0)) {
                unlock_res_and_lock(lock);
                RETURN(NULL);
        }

        res = lock->l_resource;
        ns = res->lr_namespace;

        old_mode = lock->l_req_mode;
        lock->l_req_mode = new_mode;
        if (res->lr_type == LDLM_PLAIN || res->lr_type == LDLM_IBITS) {
                /* remember the lock position where the lock might be
                 * added back to the granted list later and also
                 * remember the join mode for skiplist fixing. */
                prev.res_link = lock->l_res_link.prev;
                prev.mode_link = lock->l_sl_mode.prev;
                prev.policy_link = lock->l_sl_policy.prev;
                ldlm_resource_unlink_lock(lock);
        } else {
                ldlm_resource_unlink_lock(lock);
                if (res->lr_type == LDLM_EXTENT) {
                        /* FIXME: ugly code, I have to attach the lock to a
                         * interval node again since perhaps it will be granted
                         * soon */
                        CFS_INIT_LIST_HEAD(&node->li_group);
                        ldlm_interval_attach(node, lock);
                        node = NULL;
                }
        }

        /* If this is a local resource, put it on the appropriate list. */
        if (ns_is_client(res->lr_namespace)) {
                if (*flags & (LDLM_FL_BLOCK_CONV | LDLM_FL_BLOCK_GRANTED)) {
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                } else {
                        /* This should never happen, because of the way the
                         * server handles conversions. */
                        LDLM_ERROR(lock, "Erroneous flags %d on local lock\n",
                                   *flags);
                        LBUG();

                        ldlm_grant_lock(lock, &rpc_list);
                        granted = 1;
                        /* FIXME: completion handling not with ns_lock held ! */
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock, 0, NULL);
                }
        } else {
                int pflags = 0;
                ldlm_processing_policy policy;
                policy = ldlm_processing_policy_table[res->lr_type];
                rc = policy(lock, &pflags, 0, &err, &rpc_list);
                if (rc == LDLM_ITER_STOP) {
                        lock->l_req_mode = old_mode;
                        if (res->lr_type == LDLM_EXTENT)
                                ldlm_extent_add_lock(res, lock);
                        else
                                ldlm_granted_list_add_lock(lock, &prev);

                        res = NULL;
                } else {
                        *flags |= LDLM_FL_BLOCK_GRANTED;
                        granted = 1;
                }
        }
        unlock_res_and_lock(lock);

        if (granted)
                ldlm_run_cp_ast_work(&rpc_list);
        if (node)
                OBD_SLAB_FREE(node, ldlm_interval_slab, sizeof(*node));
        RETURN(res);
}

void ldlm_lock_dump(int level, struct ldlm_lock *lock, int pos)
{
        struct obd_device *obd = NULL;

        if (!((libcfs_debug | D_ERROR) & level))
                return;

        if (!lock) {
                CDEBUG(level, "  NULL LDLM lock\n");
                return;
        }

        CDEBUG(level," -- Lock dump: %p/"LPX64" (rc: %d) (pos: %d) (pid: %d)\n",
               lock, lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
               pos, lock->l_pid);
        if (lock->l_conn_export != NULL)
                obd = lock->l_conn_export->exp_obd;
        if (lock->l_export && lock->l_export->exp_connection) {
                CDEBUG(level, "  Node: NID %s (rhandle: "LPX64")\n",
                     libcfs_nid2str(lock->l_export->exp_connection->c_peer.nid),
                     lock->l_remote_handle.cookie);
        } else if (obd == NULL) {
                CDEBUG(level, "  Node: local\n");
        } else {
                struct obd_import *imp = obd->u.cli.cl_import;
                CDEBUG(level, "  Node: NID %s (rhandle: "LPX64")\n",
                       libcfs_nid2str(imp->imp_connection->c_peer.nid),
                       lock->l_remote_handle.cookie);
        }
        CDEBUG(level, "  Resource: %p ("LPU64"/"LPU64")\n", lock->l_resource,
               lock->l_resource->lr_name.name[0],
               lock->l_resource->lr_name.name[1]);
        CDEBUG(level, "  Req mode: %s, grant mode: %s, rc: %u, read: %d, "
               "write: %d flags: "LPX64"\n", ldlm_lockname[lock->l_req_mode],
               ldlm_lockname[lock->l_granted_mode],
               atomic_read(&lock->l_refc), lock->l_readers, lock->l_writers,
               lock->l_flags);
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                CDEBUG(level, "  Extent: "LPU64" -> "LPU64
                       " (req "LPU64"-"LPU64")\n",
                       lock->l_policy_data.l_extent.start,
                       lock->l_policy_data.l_extent.end,
                       lock->l_req_extent.start, lock->l_req_extent.end);
        else if (lock->l_resource->lr_type == LDLM_FLOCK)
                CDEBUG(level, "  Pid: %d Extent: "LPU64" -> "LPU64"\n",
                       lock->l_policy_data.l_flock.pid,
                       lock->l_policy_data.l_flock.start,
                       lock->l_policy_data.l_flock.end);
       else if (lock->l_resource->lr_type == LDLM_IBITS)
                CDEBUG(level, "  Bits: "LPX64"\n",
                       lock->l_policy_data.l_inodebits.bits);
}

void ldlm_lock_dump_handle(int level, struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;

        if (!((libcfs_debug | D_ERROR) & level))
                return;

        lock = ldlm_handle2lock(lockh);
        if (lock == NULL)
                return;

        ldlm_lock_dump(D_OTHER, lock, 0);

        LDLM_LOCK_PUT(lock);
}

void _ldlm_lock_debug(struct ldlm_lock *lock, __u32 level,
                      struct libcfs_debug_msg_data *data, const char *fmt,
                      ...)
{
        va_list args;
        cfs_debug_limit_state_t *cdls = data->msg_cdls;

        va_start(args, fmt);
        if (lock->l_resource == NULL) {
                libcfs_debug_vmsg2(cdls, data->msg_subsys, level, data->msg_file,
                                   data->msg_fn, data->msg_line, fmt, args,
                                   " ns: \?\? lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "
                                   "res: \?\? rrc=\?\? type: \?\?\? flags: "LPX64" remote: "
                                   LPX64" expref: %d pid: %u timeout: %lu\n", lock,
                                   lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
                                   lock->l_readers, lock->l_writers,
                                   ldlm_lockname[lock->l_granted_mode],
                                   ldlm_lockname[lock->l_req_mode],
                                   lock->l_flags, lock->l_remote_handle.cookie,
                                   lock->l_export ?
                                        atomic_read(&lock->l_export->exp_refcount) : -99,
                                   lock->l_pid, lock->l_callback_timeout);
                va_end(args);
                return;
        }

        switch (lock->l_resource->lr_type) {
        case LDLM_EXTENT:
                libcfs_debug_vmsg2(cdls, data->msg_subsys, level, data->msg_file,
                                   data->msg_fn, data->msg_line, fmt, args,
                                   " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "
                                   "res: "LPU64"/"LPU64" rrc: %d type: %s ["LPU64"->"LPU64
                                   "] (req "LPU64"->"LPU64") flags: "LPX64" remote: "LPX64
                                    " expref: %d pid: %u timeout %lu\n",
                                    lock->l_resource->lr_namespace->ns_name, lock,
                                    lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
                                    lock->l_readers, lock->l_writers,
                                    ldlm_lockname[lock->l_granted_mode],
                                    ldlm_lockname[lock->l_req_mode],
                                    lock->l_resource->lr_name.name[0],
                                    lock->l_resource->lr_name.name[1],
                                    atomic_read(&lock->l_resource->lr_refcount),
                                    ldlm_typename[lock->l_resource->lr_type],
                                    lock->l_policy_data.l_extent.start,
                                    lock->l_policy_data.l_extent.end,
                                    lock->l_req_extent.start, lock->l_req_extent.end,
                                    lock->l_flags, lock->l_remote_handle.cookie,
                                    lock->l_export ?
                                        atomic_read(&lock->l_export->exp_refcount) : -99,
                                    lock->l_pid, lock->l_callback_timeout);
                break;
        case LDLM_FLOCK:
                libcfs_debug_vmsg2(cdls, data->msg_subsys, level, data->msg_file,
                                   data->msg_fn, data->msg_line, fmt, args,
                                   " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "
                                   "res: "LPU64"/"LPU64" rrc: %d type: %s pid: %d "
                                   "["LPU64"->"LPU64"] flags: "LPX64" remote: "LPX64
                                   " expref: %d pid: %u timeout: %lu\n",
                                   lock->l_resource->lr_namespace->ns_name, lock,
                                   lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
                                   lock->l_readers, lock->l_writers,
                                   ldlm_lockname[lock->l_granted_mode],
                                   ldlm_lockname[lock->l_req_mode],
                                   lock->l_resource->lr_name.name[0],
                                   lock->l_resource->lr_name.name[1],
                                   atomic_read(&lock->l_resource->lr_refcount),
                                   ldlm_typename[lock->l_resource->lr_type],
                                   lock->l_policy_data.l_flock.pid,
                                   lock->l_policy_data.l_flock.start,
                                   lock->l_policy_data.l_flock.end,
                                   lock->l_flags, lock->l_remote_handle.cookie,
                                   lock->l_export ?
                                        atomic_read(&lock->l_export->exp_refcount) : -99,
                                   lock->l_pid, lock->l_callback_timeout);
                break;
        case LDLM_IBITS:
                libcfs_debug_vmsg2(cdls, data->msg_subsys, level, data->msg_file,
                                   data->msg_fn, data->msg_line, fmt, args,
                                   " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "
                                   "res: "LPU64"/"LPU64" bits "LPX64" rrc: %d type: %s "
                                   "flags: "LPX64" remote: "LPX64" expref: %d "
                                   "pid: %u timeout: %lu\n",
                                   lock->l_resource->lr_namespace->ns_name,
                                   lock, lock->l_handle.h_cookie,
                                   atomic_read (&lock->l_refc),
                                   lock->l_readers, lock->l_writers,
                                   ldlm_lockname[lock->l_granted_mode],
                                   ldlm_lockname[lock->l_req_mode],
                                   lock->l_resource->lr_name.name[0],
                                   lock->l_resource->lr_name.name[1],
                                   lock->l_policy_data.l_inodebits.bits,
                                   atomic_read(&lock->l_resource->lr_refcount),
                                   ldlm_typename[lock->l_resource->lr_type],
                                   lock->l_flags, lock->l_remote_handle.cookie,
                                   lock->l_export ?
                                        atomic_read(&lock->l_export->exp_refcount) : -99,
                                   lock->l_pid, lock->l_callback_timeout);
                break;
        default:
                libcfs_debug_vmsg2(cdls, data->msg_subsys, level, data->msg_file,
                                   data->msg_fn, data->msg_line, fmt, args,
                                   " ns: %s lock: %p/"LPX64" lrc: %d/%d,%d mode: %s/%s "
                                   "res: "LPU64"/"LPU64" rrc: %d type: %s flags: "LPX64" "
                                   "remote: "LPX64" expref: %d pid: %u timeout %lu\n",
                                   lock->l_resource->lr_namespace->ns_name,
                                   lock, lock->l_handle.h_cookie,
                                   atomic_read (&lock->l_refc),
                                   lock->l_readers, lock->l_writers,
                                   ldlm_lockname[lock->l_granted_mode],
                                   ldlm_lockname[lock->l_req_mode],
                                   lock->l_resource->lr_name.name[0],
                                   lock->l_resource->lr_name.name[1],
                                   atomic_read(&lock->l_resource->lr_refcount),
                                   ldlm_typename[lock->l_resource->lr_type],
                                   lock->l_flags, lock->l_remote_handle.cookie,
                                   lock->l_export ?
                                         atomic_read(&lock->l_export->exp_refcount) : -99,
                                   lock->l_pid, lock->l_callback_timeout);
                break;
        }
        va_end(args);
}
EXPORT_SYMBOL(_ldlm_lock_debug);
