/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_LDLM

#ifdef __KERNEL__
# include <linux/slab.h>
# include <linux/module.h>
# include <linux/lustre_dlm.h>
#else
# include <liblustre.h>
# include <linux/kp30.h>
#endif

#include <linux/obd_class.h>
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
        [LCK_NL] "NL"
};
char *ldlm_typename[] = {
        [LDLM_PLAIN] "PLN",
        [LDLM_EXTENT] "EXT",
        [LDLM_FLOCK] "FLK",
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

extern kmem_cache_t *ldlm_lock_slab;
struct lustre_lock ldlm_handle_lock;

static ldlm_processing_policy ldlm_processing_policy_table[] = {
        [LDLM_PLAIN] ldlm_process_plain_lock,
        [LDLM_EXTENT] ldlm_process_extent_lock,
#ifdef __KERNEL__
        [LDLM_FLOCK] ldlm_process_flock_lock,
#endif
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

void ldlm_lock_put(struct ldlm_lock *lock)
{
        ENTRY;

        if (atomic_dec_and_test(&lock->l_refc)) {
                struct ldlm_namespace *ns = lock->l_resource->lr_namespace;

                l_lock(&ns->ns_lock);
                LDLM_DEBUG(lock, "final lock_put on destroyed lock, freeing");
                LASSERT(lock->l_destroyed);
                LASSERT(list_empty(&lock->l_res_link));

                spin_lock(&ns->ns_counter_lock);
                ns->ns_locks--;
                spin_unlock(&ns->ns_counter_lock);

                ldlm_resource_putref(lock->l_resource);
                lock->l_resource = NULL;
                if (lock->l_export)
                        class_export_put(lock->l_export);

                if (lock->l_parent)
                        LDLM_LOCK_PUT(lock->l_parent);

                if (lock->l_lvb_data != NULL)
                        OBD_FREE(lock->l_lvb_data, lock->l_lvb_len);

                OBD_SLAB_FREE(lock, ldlm_lock_slab, sizeof(*lock));
                l_unlock(&ns->ns_lock);
        }

        EXIT;
}

void ldlm_lock_remove_from_lru(struct ldlm_lock *lock)
{
        ENTRY;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (!list_empty(&lock->l_lru)) {
                list_del_init(&lock->l_lru);
                lock->l_resource->lr_namespace->ns_nr_unused--;
                LASSERT(lock->l_resource->lr_namespace->ns_nr_unused >= 0);
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        EXIT;
}

/* This used to have a 'strict' flact, which recovery would use to mark an
 * in-use lock as needing-to-die.  Lest I am ever tempted to put it back, I
 * shall explain why it's gone: with the new hash table scheme, once you call
 * ldlm_lock_destroy, you can never drop your final references on this lock.
 * Because it's not in the hash table anymore.  -phil */
void ldlm_lock_destroy(struct ldlm_lock *lock)
{
        ENTRY;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        if (!list_empty(&lock->l_children)) {
                LDLM_ERROR(lock, "still has children (%p)!",
                           lock->l_children.next);
                ldlm_lock_dump(D_ERROR, lock, 0);
                LBUG();
        }
        if (lock->l_readers || lock->l_writers) {
                LDLM_ERROR(lock, "lock still has references");
                ldlm_lock_dump(D_ERROR, lock, 0);
                LBUG();
        }

        if (!list_empty(&lock->l_res_link)) {
                ldlm_lock_dump(D_ERROR, lock, 0);
                LBUG();
        }

        if (lock->l_destroyed) {
                LASSERT(list_empty(&lock->l_lru));
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                EXIT;
                return;
        }
        lock->l_destroyed = 1;

        list_del_init(&lock->l_export_chain);
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

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
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
 * returns: lock with refcount 1
 */
static struct ldlm_lock *ldlm_lock_new(struct ldlm_lock *parent,
                                       struct ldlm_resource *resource)
{
        struct ldlm_lock *lock;
        ENTRY;

        if (resource == NULL)
                LBUG();

        OBD_SLAB_ALLOC(lock, ldlm_lock_slab, SLAB_NOFS, sizeof(*lock));
        if (lock == NULL)
                RETURN(NULL);

        lock->l_resource = ldlm_resource_getref(resource);

        atomic_set(&lock->l_refc, 2);
        INIT_LIST_HEAD(&lock->l_children);
        INIT_LIST_HEAD(&lock->l_res_link);
        INIT_LIST_HEAD(&lock->l_lru);
        INIT_LIST_HEAD(&lock->l_export_chain);
        INIT_LIST_HEAD(&lock->l_pending_chain);
        init_waitqueue_head(&lock->l_waitq);

        spin_lock(&resource->lr_namespace->ns_counter_lock);
        resource->lr_namespace->ns_locks++;
        spin_unlock(&resource->lr_namespace->ns_counter_lock);

        if (parent != NULL) {
                l_lock(&parent->l_resource->lr_namespace->ns_lock);
                lock->l_parent = LDLM_LOCK_GET(parent);
                list_add(&lock->l_childof, &parent->l_children);
                l_unlock(&parent->l_resource->lr_namespace->ns_lock);
        }

        INIT_LIST_HEAD(&lock->l_handle.h_link);
        class_handle_hash(&lock->l_handle, lock_handle_addref);

        RETURN(lock);
}

int ldlm_lock_change_resource(struct ldlm_namespace *ns, struct ldlm_lock *lock,
                              struct ldlm_res_id new_resid)
{
        struct ldlm_resource *oldres = lock->l_resource;
        ENTRY;

        l_lock(&ns->ns_lock);
        if (memcmp(&new_resid, &lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) == 0) {
                /* Nothing to do */
                l_unlock(&ns->ns_lock);
                RETURN(0);
        }

        LASSERT(new_resid.name[0] != 0);

        /* This function assumes that the lock isn't on any lists */
        LASSERT(list_empty(&lock->l_res_link));

        lock->l_resource = ldlm_resource_get(ns, NULL, new_resid,
                                             lock->l_resource->lr_type, 1);
        if (lock->l_resource == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        /* ...and the flowers are still standing! */
        ldlm_resource_putref(oldres);

        l_unlock(&ns->ns_lock);
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

        l_lock(&ns->ns_lock);

        /* It's unlikely but possible that someone marked the lock as
         * destroyed after we did handle2object on it */
        if (lock->l_destroyed) {
                CDEBUG(D_INFO, "lock already destroyed: lock %p\n", lock);
                LDLM_LOCK_PUT(lock);
                GOTO(out, retval);
        }

        if (flags && (lock->l_flags & flags)) {
                LDLM_LOCK_PUT(lock);
                GOTO(out, retval);
        }

        if (flags)
                lock->l_flags |= flags;

        retval = lock;
        EXIT;
 out:
        l_unlock(&ns->ns_lock);
        return retval;
}

struct ldlm_lock *ldlm_handle2lock_ns(struct ldlm_namespace *ns,
                                      struct lustre_handle *handle)
{
        struct ldlm_lock *retval = NULL;

        l_lock(&ns->ns_lock);
        retval = __ldlm_handle2lock(handle, 0);
        l_unlock(&ns->ns_lock);

        return retval;
}

void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
        ldlm_res2desc(lock->l_resource, &desc->l_resource);
        desc->l_req_mode = lock->l_req_mode;
        desc->l_granted_mode = lock->l_granted_mode;
        memcpy(&desc->l_policy_data, &lock->l_policy_data,
               sizeof(desc->l_policy_data));
}

void ldlm_add_ast_work_item(struct ldlm_lock *lock, struct ldlm_lock *new,
                            void *data, int datalen)
{
        struct ldlm_ast_work *w;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (new && (lock->l_flags & LDLM_FL_AST_SENT))
                GOTO(out, 0);

        CDEBUG(D_OTHER, "lock %p incompatible; sending blocking AST.\n", lock);

        OBD_ALLOC(w, sizeof(*w));
        if (!w) {
                LBUG();
                GOTO(out, 0);
        }

        w->w_data = data;
        w->w_datalen = datalen;
        if (new) {
                LDLM_DEBUG(lock, "lock incompatible; sending blocking AST.");
                lock->l_flags |= LDLM_FL_AST_SENT;
                /* If the enqueuing client said so, tell the AST recipient to
                 * discard dirty data, rather than writing back. */
                if (new->l_flags & LDLM_AST_DISCARD_DATA)
                        lock->l_flags |= LDLM_FL_DISCARD_DATA;
                w->w_blocking = 1;
                ldlm_lock2desc(new, &w->w_desc);
        }

        w->w_lock = LDLM_LOCK_GET(lock);
        list_add(&w->w_list, lock->l_resource->lr_tmp);
        EXIT;
 out:
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
}

void ldlm_lock_addref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock;

        lock = ldlm_handle2lock(lockh);
        ldlm_lock_addref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}

/* only called for local locks */
void ldlm_lock_addref_internal(struct ldlm_lock *lock, __u32 mode)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_lock_remove_from_lru(lock);
        if (mode & (LCK_NL | LCK_CR | LCK_PR))
                lock->l_readers++;
        if (mode & (LCK_EX | LCK_CW | LCK_PW))
                lock->l_writers++;
        lock->l_last_used = jiffies;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_GET(lock);
        LDLM_DEBUG(lock, "ldlm_lock_addref(%s)", ldlm_lockname[mode]);
}

void ldlm_lock_decref_internal(struct ldlm_lock *lock, __u32 mode)
{
        struct ldlm_namespace *ns;
        ENTRY;

        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        ns = lock->l_resource->lr_namespace;
        l_lock(&ns->ns_lock);
        if (mode & (LCK_NL | LCK_CR | LCK_PR)) {
                LASSERT(lock->l_readers > 0);
                lock->l_readers--;
        }
        if (mode & (LCK_EX | LCK_CW | LCK_PW)) {
                LASSERT(lock->l_writers > 0);
                lock->l_writers--;
        }

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
                if (ns->ns_client == LDLM_NAMESPACE_SERVER && lock->l_export)
                        CERROR("FL_CBPENDING set on non-local lock--just a "
                               "warning\n");

                LDLM_DEBUG(lock, "final decref done on cbpending lock");

                LDLM_LOCK_GET(lock); /* dropped by bl thread */
                ldlm_lock_remove_from_lru(lock);
#ifdef __KERNEL__
                ldlm_bl_to_thread(ns, NULL, lock);
                l_unlock(&ns->ns_lock);
#else
                l_unlock(&ns->ns_lock);
                liblustre_ldlm_handle_bl_callback(ns, NULL, lock);
#endif
        } else if (ns->ns_client == LDLM_NAMESPACE_CLIENT &&
                   !lock->l_readers && !lock->l_writers) {
                /* If this is a client-side namespace and this was the last
                 * reference, put it on the LRU. */
                LASSERT(list_empty(&lock->l_lru));
                LASSERT(ns->ns_nr_unused >= 0);
                list_add_tail(&lock->l_lru, &ns->ns_unused_list);
                ns->ns_nr_unused++;
                l_unlock(&ns->ns_lock);
                ldlm_cancel_lru(ns);
        } else {
                l_unlock(&ns->ns_lock);
        }

        LDLM_LOCK_PUT(lock);    /* matches the ldlm_lock_get in addref */

        EXIT;
}

void ldlm_lock_decref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0);
        LASSERT(lock != NULL);
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
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_flags |= LDLM_FL_CBPENDING;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_lock_decref_internal(lock, mode);
        LDLM_LOCK_PUT(lock);
}

/* NOTE: called by
 *  - ldlm_lock_enqueue
 *  - ldlm_reprocess_queue
 *  - ldlm_lock_convert
 */
void ldlm_grant_lock(struct ldlm_lock *lock, void *data, int datalen,
                     int run_ast)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_granted_mode = lock->l_req_mode;
        ldlm_resource_add_lock(res, &res->lr_granted, lock);

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (run_ast && lock->l_completion_ast != NULL)
                ldlm_add_ast_work_item(lock, NULL, data, datalen);

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        EXIT;
}

/* returns a referenced lock or NULL.  See the flag descriptions below, in the
 * comment above ldlm_lock_match */
static struct ldlm_lock *search_queue(struct list_head *queue, ldlm_mode_t mode,
                                      ldlm_policy_data_t *policy,
                                      struct ldlm_lock *old_lock, int flags)
{
        struct ldlm_lock *lock;
        struct list_head *tmp;

        list_for_each(tmp, queue) {
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

                if (!(lock->l_req_mode & mode))
                        continue;

                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    (lock->l_policy_data.l_extent.start >
                     policy->l_extent.start ||
                     lock->l_policy_data.l_extent.end < policy->l_extent.end))
                        continue;

                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    mode == LCK_CW &&
                    lock->l_policy_data.l_extent.gid != policy->l_extent.gid)
                        continue;

                if (lock->l_destroyed)
                        continue;

                if ((flags & LDLM_FL_LOCAL_ONLY) &&
                    !(lock->l_flags & LDLM_FL_LOCAL))
                        continue;

                if (flags & LDLM_FL_TEST_LOCK)
                        LDLM_LOCK_GET(lock);
                else
                        ldlm_lock_addref_internal(lock, mode);
                return lock;
        }

        return NULL;
}

void ldlm_lock_allow_match(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_flags |= LDLM_FL_CAN_MATCH;
        wake_up(&lock->l_waitq);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
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
int ldlm_lock_match(struct ldlm_namespace *ns, int flags,
                    struct ldlm_res_id *res_id, __u32 type,
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

        l_lock(&ns->ns_lock);

        lock = search_queue(&res->lr_granted, mode, policy, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);
        if (flags & LDLM_FL_BLOCK_GRANTED)
                GOTO(out, rc = 0);
        lock = search_queue(&res->lr_converting, mode, policy, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);
        lock = search_queue(&res->lr_waiting, mode, policy, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);

        EXIT;
 out:
        ldlm_resource_putref(res);
        l_unlock(&ns->ns_lock);

        if (lock) {
                ldlm_lock2handle(lock, lockh);
                if (!(lock->l_flags & LDLM_FL_CAN_MATCH)) {
                        struct l_wait_info lwi;
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock,
                                                       LDLM_FL_WAIT_NOREPROC,
                                                       NULL);

                        lwi = LWI_TIMEOUT_INTR(obd_timeout*HZ, NULL,NULL,NULL);

                        /* XXX FIXME see comment on CAN_MATCH in lustre_dlm.h */
                        l_wait_event(lock->l_waitq,
                                     (lock->l_flags & LDLM_FL_CAN_MATCH), &lwi);
                }
        }
        if (rc)
                LDLM_DEBUG(lock, "matched ("LPU64" "LPU64")",
                           type == LDLM_PLAIN ? res_id->name[2] :
                                policy->l_extent.start,
                           type == LDLM_PLAIN ? res_id->name[3] :
                                policy->l_extent.end);
        else if (!(flags & LDLM_FL_TEST_LOCK)) /* less verbose for test-only */
                LDLM_DEBUG_NOLOCK("not matched ns %p type %u mode %u res "
                                  LPU64"/"LPU64" ("LPU64" "LPU64")", ns,
                                  type, mode, res_id->name[0], res_id->name[1],
                                  type == LDLM_PLAIN ? res_id->name[2] :
                                        policy->l_extent.start,
                                  type == LDLM_PLAIN ? res_id->name[3] :
                                        policy->l_extent.end);

        if (old_lock)
                LDLM_LOCK_PUT(old_lock);
        if (flags & LDLM_FL_TEST_LOCK && rc)
                LDLM_LOCK_PUT(lock);

        return rc;
}

/* Returns a referenced lock */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
                                   struct lustre_handle *parent_lock_handle,
                                   struct ldlm_res_id res_id, __u32 type,
                                   ldlm_mode_t mode,
                                   ldlm_blocking_callback blocking,
                                   ldlm_completion_callback completion,
                                   ldlm_glimpse_callback glimpse,
                                   void *data, __u32 lvb_len)
{
        struct ldlm_resource *res, *parent_res = NULL;
        struct ldlm_lock *lock, *parent_lock = NULL;
        ENTRY;

        if (parent_lock_handle) {
                parent_lock = ldlm_handle2lock(parent_lock_handle);
                if (parent_lock)
                        parent_res = parent_lock->l_resource;
        }

        res = ldlm_resource_get(ns, parent_res, res_id, type, 1);
        if (res == NULL)
                RETURN(NULL);

        lock = ldlm_lock_new(parent_lock, res);
        ldlm_resource_putref(res);
        if (parent_lock != NULL)
                LDLM_LOCK_PUT(parent_lock);

        if (lock == NULL)
                RETURN(NULL);

        lock->l_req_mode = mode;
        lock->l_ast_data = data;
        lock->l_blocking_ast = blocking;
        lock->l_completion_ast = completion;
        lock->l_glimpse_ast = glimpse;

        if (lvb_len) {
                lock->l_lvb_len = lvb_len;
                OBD_ALLOC(lock->l_lvb_data, lvb_len);
                if (lock->l_lvb_data == NULL) {
                        OBD_SLAB_FREE(lock, ldlm_lock_slab, sizeof(*lock));
                        RETURN(NULL);
                }
        }

        RETURN(lock);
}

ldlm_error_t ldlm_lock_enqueue(struct ldlm_namespace *ns,
                               struct ldlm_lock **lockp,
                               void *cookie, int *flags)
{
        struct ldlm_lock *lock = *lockp;
        struct ldlm_resource *res = lock->l_resource;
        int local = res->lr_namespace->ns_client;
        ldlm_processing_policy policy;
        ldlm_error_t rc = ELDLM_OK;
        ENTRY;

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
                } else if (rc == ELDLM_LOCK_ABORTED ||
                           (rc == 0 && (*flags & LDLM_FL_INTENT_ONLY))) {
                        ldlm_lock_destroy(lock);
                        RETURN(rc);
                }
                LASSERT(rc == ELDLM_OK);
        }

        l_lock(&ns->ns_lock);
        if (local && lock->l_req_mode == lock->l_granted_mode) {
                /* The server returned a blocked lock, but it was granted before
                 * we got a chance to actually enqueue it.  We don't need to do
                 * anything else. */
                *flags &= ~(LDLM_FL_BLOCK_GRANTED |
                            LDLM_FL_BLOCK_CONV | LDLM_FL_BLOCK_WAIT);
                GOTO(out, ELDLM_OK);
        }

        /* Some flags from the enqueue want to make it into the AST, via the
         * lock's l_flags. */
        lock->l_flags |= (*flags & LDLM_AST_DISCARD_DATA);

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
        ldlm_resource_unlink_lock(lock);
        if (local) {
                if (*flags & LDLM_FL_BLOCK_CONV)
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                else if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                else
                        ldlm_grant_lock(lock, NULL, 0, 0);
                GOTO(out, ELDLM_OK);
        } else if (*flags & LDLM_FL_REPLAY) {
                if (*flags & LDLM_FL_BLOCK_CONV) {
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                        GOTO(out, ELDLM_OK);
                } else if (*flags & LDLM_FL_BLOCK_WAIT) {
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                        GOTO(out, ELDLM_OK);
                } else if (*flags & LDLM_FL_BLOCK_GRANTED) {
                        ldlm_grant_lock(lock, NULL, 0, 0);
                        GOTO(out, ELDLM_OK);
                }
                /* If no flags, fall through to normal enqueue path. */
        }

        policy = ldlm_processing_policy_table[res->lr_type];
        policy(lock, flags, 1, &rc);
        EXIT;
out:
        l_unlock(&ns->ns_lock);
        return rc;
}

/* Must be called with namespace taken: queue is waiting or converting. */
int ldlm_reprocess_queue(struct ldlm_resource *res, struct list_head *queue)
{
        struct list_head *tmp, *pos;
        ldlm_processing_policy policy;
        int flags;
        int rc = LDLM_ITER_CONTINUE;
        ldlm_error_t err;
        ENTRY;

        policy = ldlm_processing_policy_table[res->lr_type];
        LASSERT(policy);

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *pending;
                pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                CDEBUG(D_INFO, "Reprocessing lock %p\n", pending);

                flags = 0;
                rc = policy(pending, &flags, 0, &err);
                if (rc != LDLM_ITER_CONTINUE)
                        break;
        }

        RETURN(rc);
}

int ldlm_run_ast_work(struct ldlm_namespace *ns, struct list_head *rpc_list)
{
        struct list_head *tmp, *pos;
        int rc, retval = 0;
        ENTRY;

        l_check_no_ns_lock(ns);

        list_for_each_safe(tmp, pos, rpc_list) {
                struct ldlm_ast_work *w =
                        list_entry(tmp, struct ldlm_ast_work, w_list);

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
                LASSERT(w->w_lock != NULL);
                if (w->w_blocking) {
                        LASSERT(w->w_lock->l_blocking_ast != NULL);
                        rc = w->w_lock->l_blocking_ast
                                (w->w_lock, &w->w_desc, w->w_data,
                                 LDLM_CB_BLOCKING);
                } else if (w->w_lock->l_completion_ast != NULL) {
                        LASSERT(w->w_lock->l_completion_ast != NULL);
                        rc = w->w_lock->l_completion_ast(w->w_lock, w->w_flags,
                                                         w->w_data);
                } else {
                        rc = 0;
                }
                if (rc == -ERESTART)
                        retval = rc;
                else if (rc)
                        CDEBUG(D_DLMTRACE, "Failed AST - should clean & "
                               "disconnect client\n");
                LDLM_LOCK_PUT(w->w_lock);
                list_del(&w->w_list);
                OBD_FREE(w, sizeof(*w));
        }
        RETURN(retval);
}

static int reprocess_one_queue(struct ldlm_resource *res, void *closure)
{
        ldlm_reprocess_all(res);
        return LDLM_ITER_CONTINUE;
}

void ldlm_reprocess_all_ns(struct ldlm_namespace *ns)
{
        int i, rc;

        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *next;
                list_for_each_safe(tmp, next, &(ns->ns_hash[i])) {
                        struct ldlm_resource *res =
                                list_entry(tmp, struct ldlm_resource, lr_hash);

                        ldlm_resource_getref(res);
                        l_unlock(&ns->ns_lock);
                        rc = reprocess_one_queue(res, NULL);
                        l_lock(&ns->ns_lock);
                        next = tmp->next;
                        ldlm_resource_putref(res);
                        if (rc == LDLM_ITER_STOP)
                                GOTO(out, rc);
                }
        }
 out:
        l_unlock(&ns->ns_lock);
        EXIT;
}

void ldlm_reprocess_all(struct ldlm_resource *res)
{
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        int rc;
        ENTRY;

        /* Local lock trees don't get reprocessed. */
        if (res->lr_namespace->ns_client) {
                EXIT;
                return;
        }

 restart:
        l_lock(&res->lr_namespace->ns_lock);
        res->lr_tmp = &rpc_list;

        rc = ldlm_reprocess_queue(res, &res->lr_converting);
        if (rc == LDLM_ITER_CONTINUE)
                ldlm_reprocess_queue(res, &res->lr_waiting);

        res->lr_tmp = NULL;
        l_unlock(&res->lr_namespace->ns_lock);

        rc = ldlm_run_ast_work(res->lr_namespace, &rpc_list);
        if (rc == -ERESTART) {
                LASSERT(list_empty(&rpc_list));
                goto restart;
        }
        EXIT;
}

void ldlm_cancel_callback(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (!(lock->l_flags & LDLM_FL_CANCEL)) {
                lock->l_flags |= LDLM_FL_CANCEL;
                if (lock->l_blocking_ast) {
                        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                        // l_check_no_ns_lock(lock->l_resource->lr_namespace);
                        lock->l_blocking_ast(lock, NULL, lock->l_ast_data,
                                             LDLM_CB_CANCELING);
                        return;
                } else {
                        LDLM_DEBUG(lock, "no blocking ast");
                }
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
}

void ldlm_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        ENTRY;

        /* There's no race between calling this and taking the ns lock below;
         * a lock can only be put on the waiting list once, because it can only
         * issue a blocking AST once. */
        ldlm_del_waiting_lock(lock);

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);
        /* Please do not, no matter how tempting, remove this LBUG without
         * talking to me first. -phik */
        if (lock->l_readers || lock->l_writers) {
                LDLM_DEBUG(lock, "lock still has references");
                ldlm_lock_dump(D_OTHER, lock, 0);
                LBUG();
        }

        ldlm_cancel_callback(lock);

        ldlm_resource_unlink_lock(lock);
        ldlm_lock_destroy(lock);
        l_unlock(&ns->ns_lock);
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

void ldlm_cancel_locks_for_export(struct obd_export *exp)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct ldlm_lock *lock;
        struct ldlm_resource *res;

        l_lock(&ns->ns_lock);
        while(!list_empty(&exp->exp_ldlm_data.led_held_locks)) { 
                lock = list_entry(exp->exp_ldlm_data.led_held_locks.next,
                                  struct ldlm_lock, l_export_chain);
                res = ldlm_resource_getref(lock->l_resource);
                LDLM_DEBUG(lock, "export %p", exp);
                ldlm_lock_cancel(lock);
                l_unlock(&ns->ns_lock);
                ldlm_reprocess_all(res);
                ldlm_resource_putref(res);
                l_lock(&ns->ns_lock);
        }
        l_unlock(&ns->ns_lock);
}

struct ldlm_resource *ldlm_lock_convert(struct ldlm_lock *lock, int new_mode,
                                        int *flags)
{
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        int granted = 0;
        ENTRY;

        LBUG();

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);

        lock->l_req_mode = new_mode;
        ldlm_resource_unlink_lock(lock);

        /* If this is a local resource, put it on the appropriate list. */
        if (res->lr_namespace->ns_client) {
                if (*flags & (LDLM_FL_BLOCK_CONV | LDLM_FL_BLOCK_GRANTED)) {
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                } else {
                        /* This should never happen, because of the way the
                         * server handles conversions. */
                        LBUG();

                        res->lr_tmp = &rpc_list;
                        ldlm_grant_lock(lock, NULL, 0, 0);
                        res->lr_tmp = NULL;
                        granted = 1;
                        /* FIXME: completion handling not with ns_lock held ! */
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock, 0, NULL);
                }
        } else {
                /* FIXME: We should try the conversion right away and possibly
                 * return success without the need for an extra AST */
                ldlm_resource_add_lock(res, &res->lr_converting, lock);
                *flags |= LDLM_FL_BLOCK_CONV;
        }

        l_unlock(&ns->ns_lock);

        if (granted)
                ldlm_run_ast_work(ns, &rpc_list);
        RETURN(res);
}

void ldlm_lock_dump(int level, struct ldlm_lock *lock, int pos)
{
        char str[PTL_NALFMT_SIZE];
        struct obd_device *obd = NULL;

        if (!((portal_debug | D_ERROR) & level))
                return;

        if (!lock) {
                CDEBUG(level, "  NULL LDLM lock\n");
                return;
        }

        CDEBUG(level, "  -- Lock dump: %p/"LPX64" (rc: %d) (pos: %d)\n",
               lock, lock->l_handle.h_cookie, atomic_read(&lock->l_refc),
               pos);
        if (lock->l_conn_export != NULL)
                obd = lock->l_conn_export->exp_obd;
        if (lock->l_export && lock->l_export->exp_connection) {
                CDEBUG(level, "  Node: NID "LPX64" (%s) on %s (rhandle: "LPX64")\n",
                       lock->l_export->exp_connection->c_peer.peer_nid,
                       portals_nid2str(lock->l_export->exp_connection->c_peer.peer_ni->pni_number,
                                       lock->l_export->exp_connection->c_peer.peer_nid, str),
                       lock->l_export->exp_connection->c_peer.peer_ni->pni_name,
                       lock->l_remote_handle.cookie);
        } else if (obd == NULL) {
                CDEBUG(level, "  Node: local\n");
        } else {
                struct obd_import *imp = obd->u.cli.cl_import;
                CDEBUG(level, "  Node: NID "LPX64" (%s) on %s (rhandle: "LPX64")\n",
                       imp->imp_connection->c_peer.peer_nid,
                       portals_nid2str(imp->imp_connection->c_peer.peer_ni->pni_number,
                                       imp->imp_connection->c_peer.peer_nid, str),
                       imp->imp_connection->c_peer.peer_ni->pni_name,
                       lock->l_remote_handle.cookie);
        }
        CDEBUG(level, "  Resource: %p ("LPU64"/"LPU64")\n", lock->l_resource,
               lock->l_resource->lr_name.name[0],
               lock->l_resource->lr_name.name[1]);
        CDEBUG(level, "  Req mode: %d, grant mode: %d, rc: %u, read: %d, "
               "write: %d\n", (int)lock->l_req_mode, (int)lock->l_granted_mode,
               atomic_read(&lock->l_refc), lock->l_readers, lock->l_writers);
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                CDEBUG(level, "  Extent: "LPU64" -> "LPU64
                       " (req "LPU64"-"LPU64")\n",
                       lock->l_policy_data.l_extent.start,
                       lock->l_policy_data.l_extent.end,
                       lock->l_req_extent.start, lock->l_req_extent.end);
        else if (lock->l_resource->lr_type == LDLM_FLOCK)
                CDEBUG(level, "  Pid: "LPU64" Extent: "LPU64" -> "LPU64"\n",
                       lock->l_policy_data.l_flock.pid,
                       lock->l_policy_data.l_flock.start,
                       lock->l_policy_data.l_flock.end);
}

void ldlm_lock_dump_handle(int level, struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;

        lock = ldlm_handle2lock(lockh);
        if (lock == NULL)
                return;

        ldlm_lock_dump(D_OTHER, lock, 0);

        LDLM_LOCK_PUT(lock);
}
