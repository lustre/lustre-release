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

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>

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
        case IT_TRUNC:
                return "truncate";
        case IT_SETATTR:
                return "setattr";
        case IT_LOOKUP:
                return "lookup";
        case IT_UNLINK:
                return "unlink";
        default:
                CERROR("Unknown intent %d\n", it);
                return "UNKNOWN";
        }
}

extern kmem_cache_t *ldlm_lock_slab;
struct lustre_lock ldlm_handle_lock;

static int ldlm_plain_compat(struct ldlm_lock *a, struct ldlm_lock *b);

ldlm_res_compat ldlm_res_compat_table[] = {
        [LDLM_PLAIN] ldlm_plain_compat,
        [LDLM_EXTENT] ldlm_extent_compat,
};

static ldlm_res_policy ldlm_intent_policy_func;

static int ldlm_plain_policy(struct ldlm_namespace *ns, struct ldlm_lock **lock,
                             void *req_cookie, ldlm_mode_t mode, int flags,
                             void *data)
{
        if ((flags & LDLM_FL_HAS_INTENT) && ldlm_intent_policy_func) {
                return ldlm_intent_policy_func(ns, lock, req_cookie, mode,
                                               flags, data);
        }

        return ELDLM_OK;
}

ldlm_res_policy ldlm_res_policy_table[] = {
        [LDLM_PLAIN] ldlm_plain_policy,
        [LDLM_EXTENT] ldlm_extent_policy,
};

void ldlm_register_intent(ldlm_res_policy arg)
{
        ldlm_intent_policy_func = arg;
}

void ldlm_unregister_intent(void)
{
        ldlm_intent_policy_func = NULL;
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
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        ENTRY;

        if (atomic_dec_and_test(&lock->l_refc)) {
                l_lock(&ns->ns_lock);
                LDLM_DEBUG0(lock, "final lock_put on destroyed lock, freeing");
                LASSERT(lock->l_destroyed);
                LASSERT(list_empty(&lock->l_res_link));

                spin_lock(&ns->ns_counter_lock);
                ns->ns_locks--;
                spin_unlock(&ns->ns_counter_lock);

                ldlm_resource_putref(lock->l_resource);
                lock->l_resource = NULL;

                if (lock->l_parent)
                        LDLM_LOCK_PUT(lock->l_parent);

                PORTAL_SLAB_FREE(lock, ldlm_lock_slab, sizeof(*lock));
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
                ldlm_lock_dump(D_ERROR, lock);
                LBUG();
        }
        if (lock->l_readers || lock->l_writers) {
                LDLM_ERROR(lock, "lock still has references");
                ldlm_lock_dump(D_ERROR, lock);
                LBUG();
        }

        if (!list_empty(&lock->l_res_link)) {
                ldlm_lock_dump(D_ERROR, lock);
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
        portals_handle_unhash(&lock->l_handle);

#if 0
        /* Wake anyone waiting for this lock */
        /* FIXME: I should probably add yet another flag, instead of using
         * l_export to only call this on clients */
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

        PORTAL_SLAB_ALLOC(lock, ldlm_lock_slab, sizeof(*lock));
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
        portals_handle_hash(&lock->l_handle, lock_handle_addref);

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
        memset(&lockh->addr, 0x69, sizeof(lockh->addr));
        lockh->cookie = lock->l_handle.h_cookie;
}

/* if flags: atomically get the lock and set the flags.
 *           Return NULL if flag already set
 */

struct ldlm_lock *__ldlm_handle2lock(struct lustre_handle *handle, int flags)
{
        struct ldlm_lock *lock = NULL, *retval = NULL;
        ENTRY;

        LASSERT(handle);

        lock = portals_handle2object(handle->cookie);
        if (lock == NULL)
                RETURN(NULL);

        LASSERT(lock->l_resource != NULL);
        LASSERT(lock->l_resource->lr_namespace != NULL);

        l_lock(&lock->l_resource->lr_namespace->ns_lock);

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
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
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

static int ldlm_plain_compat(struct ldlm_lock *a, struct ldlm_lock *b)
{
        return lockmode_compat(a->l_req_mode, b->l_req_mode);
}

void ldlm_lock2desc(struct ldlm_lock *lock, struct ldlm_lock_desc *desc)
{
        ldlm_res2desc(lock->l_resource, &desc->l_resource);
        desc->l_req_mode = lock->l_req_mode;
        desc->l_granted_mode = lock->l_granted_mode;
        memcpy(&desc->l_extent, &lock->l_extent, sizeof(desc->l_extent));
        memcpy(desc->l_version, lock->l_version, sizeof(desc->l_version));
}

static void ldlm_add_ast_work_item(struct ldlm_lock *lock,
                                   struct ldlm_lock *new, 
                                   void *data, int datalen)
{
        struct ldlm_ast_work *w;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (new && (lock->l_flags & LDLM_FL_AST_SENT))
                GOTO(out, 0);

        OBD_ALLOC(w, sizeof(*w));
        if (!w) {
                LBUG();
                GOTO(out, 0);
        }

        w->w_data = data;
        w->w_datalen = datalen;
        if (new) {
                lock->l_flags |= LDLM_FL_AST_SENT;
                w->w_blocking = 1;
                ldlm_lock2desc(new, &w->w_desc);
        }

        w->w_lock = LDLM_LOCK_GET(lock);
        list_add(&w->w_list, lock->l_resource->lr_tmp);
        EXIT;
 out:
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return;
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
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR)
                lock->l_readers++;
        else
                lock->l_writers++;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_GET(lock);
        LDLM_DEBUG(lock, "ldlm_lock_addref(%s)", ldlm_lockname[mode]);
}

/* Args: unlocked lock */
int ldlm_cli_cancel_unused_resource(struct ldlm_namespace *ns,
                                    struct ldlm_res_id, int flags);

void ldlm_lock_decref_internal(struct ldlm_lock *lock, __u32 mode)
{
        struct ldlm_namespace *ns;
        ENTRY;

        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        ns = lock->l_resource->lr_namespace;
        l_lock(&ns->ns_lock);
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR) {
                LASSERT(lock->l_readers > 0);
                lock->l_readers--;
        } else {
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
                if (!ns->ns_client && lock->l_export)
                        CERROR("FL_CBPENDING set on non-local lock--just a "
                               "warning\n");

                LDLM_DEBUG0(lock, "final decref done on cbpending lock");
                l_unlock(&ns->ns_lock);

                /* FIXME: need a real 'desc' here */
                lock->l_blocking_ast(lock, NULL, lock->l_data,
                                     LDLM_CB_BLOCKING);
        } else if (ns->ns_client && !lock->l_readers && !lock->l_writers) {
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
        ldlm_lock_decref_internal(lock, mode);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_PUT(lock);
}

static int ldlm_lock_compat_list(struct ldlm_lock *lock, int send_cbs,
                                 struct list_head *queue)
{
        struct list_head *tmp, *pos;
        int rc = 1;

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *child;
                ldlm_res_compat compat;

                child = list_entry(tmp, struct ldlm_lock, l_res_link);
                if (lock == child)
                        continue;

                compat = ldlm_res_compat_table[child->l_resource->lr_type];
                if (compat && compat(child, lock)) {
                        CDEBUG(D_OTHER, "compat function succeded, next.\n");
                        continue;
                }
                if (lockmode_compat(child->l_granted_mode, lock->l_req_mode)) {
                        CDEBUG(D_OTHER, "lock modes are compatible, next.\n");
                        continue;
                }

                rc = 0;

                if (send_cbs && child->l_blocking_ast != NULL) {
                        CDEBUG(D_OTHER, "lock %p incompatible; sending "
                               "blocking AST.\n", child);
                        ldlm_add_ast_work_item(child, lock, NULL, 0);
                }
        }

        return rc;
}

static int ldlm_lock_compat(struct ldlm_lock *lock, int send_cbs)
{
        int rc;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        rc = ldlm_lock_compat_list(lock, send_cbs,
                                   &lock->l_resource->lr_granted);
        /* FIXME: should we be sending ASTs to converting? */
        if (rc)
                rc = ldlm_lock_compat_list
                        (lock, send_cbs, &lock->l_resource->lr_converting);

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        RETURN(rc);
}

/* NOTE: called by
 *  - ldlm_lock_enqueue
 *  - ldlm_reprocess_queue
 *  - ldlm_lock_convert
 */
void ldlm_grant_lock(struct ldlm_lock *lock, void *data, int datalen)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_resource_add_lock(res, &res->lr_granted, lock);
        lock->l_granted_mode = lock->l_req_mode;

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (lock->l_completion_ast != NULL)
                ldlm_add_ast_work_item(lock, NULL, data, datalen);

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        EXIT;
}

/* returns a referenced lock or NULL.  See the flag descriptions below, in the
 * comment above ldlm_lock_match */
static struct ldlm_lock *search_queue(struct list_head *queue, ldlm_mode_t mode,
                                      struct ldlm_extent *extent,
                                      struct ldlm_lock *old_lock, int flags)
{
        struct ldlm_lock *lock;
        struct list_head *tmp;

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock == old_lock)
                        break;

                if (lock->l_flags & LDLM_FL_CBPENDING)
                        continue;

                if (lock->l_req_mode != mode)
                        continue;

                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    (lock->l_extent.start > extent->start ||
                     lock->l_extent.end < extent->end))
                        continue;

                if (lock->l_destroyed)
                        continue;

                if ((flags & LDLM_FL_LOCAL_ONLY) &&
                    !(lock->l_flags & LDLM_FL_LOCAL))
                        continue;

                ldlm_lock_addref_internal(lock, mode);
                return lock;
        }

        return NULL;
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
 *
 * Returns 1 if it finds an already-existing lock that is compatible; in this
 * case, lockh is filled in with a addref()ed lock
 */
int ldlm_lock_match(struct ldlm_namespace *ns, int flags,
                    struct ldlm_res_id *res_id, __u32 type, void *cookie,
                    int cookielen, ldlm_mode_t mode,struct lustre_handle *lockh)
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

        lock = search_queue(&res->lr_granted, mode, cookie, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);
        if (flags & LDLM_FL_BLOCK_GRANTED)
                GOTO(out, rc = 0);
        lock = search_queue(&res->lr_converting, mode, cookie, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);
        lock = search_queue(&res->lr_waiting, mode, cookie, old_lock, flags);
        if (lock != NULL)
                GOTO(out, rc = 1);

        EXIT;
       out:
        ldlm_resource_putref(res);
        l_unlock(&ns->ns_lock);

        if (lock) {
                ldlm_lock2handle(lock, lockh);
                if (lock->l_completion_ast)
                        lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC, NULL);
        }
        if (rc)
                LDLM_DEBUG0(lock, "matched");
        else
                LDLM_DEBUG_NOLOCK("not matched");

        if (old_lock)
                LDLM_LOCK_PUT(old_lock);

        return rc;
}

/* Returns a referenced lock */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
                                   struct lustre_handle *parent_lock_handle,
                                   struct ldlm_res_id res_id, __u32 type,
                                   ldlm_mode_t mode, void *data, void *cp_data)
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
        lock->l_data = data;
        lock->l_cp_data = cp_data;

        RETURN(lock);
}

ldlm_error_t ldlm_lock_enqueue(struct ldlm_namespace *ns,
                               struct ldlm_lock **lockp,
                               void *cookie, int cookie_len,
                               int *flags,
                               ldlm_completion_callback completion,
                               ldlm_blocking_callback blocking)
{
        struct ldlm_resource *res;
        struct ldlm_lock *lock = *lockp;
        int local;
        ldlm_res_policy policy;
        ENTRY;

        res = lock->l_resource;
        lock->l_blocking_ast = blocking;

        if (res->lr_type == LDLM_EXTENT)
                memcpy(&lock->l_extent, cookie, sizeof(lock->l_extent));

        /* policies are not executed on the client or during replay */
        local = res->lr_namespace->ns_client;
        if (!local && !(*flags & LDLM_FL_REPLAY) &&
            (policy = ldlm_res_policy_table[res->lr_type])) {
                int rc;
                rc = policy(ns, lockp, cookie, lock->l_req_mode, *flags, NULL);
                if (rc == ELDLM_LOCK_CHANGED) {
                        res = lock->l_resource;
                        *flags |= LDLM_FL_LOCK_CHANGED;
                } else if (rc == ELDLM_LOCK_REPLACED) {
                        /* The lock that was returned has already been granted,
                         * and placed into lockp.  Destroy the old one and our
                         * work here is done. */
                        ldlm_lock_destroy(lock);
                        LDLM_LOCK_PUT(lock);
                        *flags |= LDLM_FL_LOCK_CHANGED;
                        RETURN(0);
                } else if (rc == ELDLM_LOCK_ABORTED) {
                        ldlm_lock_destroy(lock);
                        RETURN(rc);
                }
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
                        ldlm_grant_lock(lock, NULL, 0);
                GOTO(out, ELDLM_OK);
        } else if (*flags & LDLM_FL_REPLAY) {
                if (*flags & LDLM_FL_BLOCK_CONV) {
                        ldlm_resource_add_lock(res, &res->lr_converting, lock);
                        GOTO(out, ELDLM_OK);
                } else if (*flags & LDLM_FL_BLOCK_WAIT) {
                        ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                        GOTO(out, ELDLM_OK);
                } else if (*flags & LDLM_FL_BLOCK_GRANTED) {
                        ldlm_grant_lock(lock, NULL, 0);
                        GOTO(out, ELDLM_OK);
                }
                /* If no flags, fall through to normal enqueue path. */
        }

        /* FIXME: We may want to optimize by checking lr_most_restr */
        if (!list_empty(&res->lr_converting)) {
                ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                *flags |= LDLM_FL_BLOCK_CONV;
                GOTO(out, ELDLM_OK);
        }
        if (!list_empty(&res->lr_waiting)) {
                ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                *flags |= LDLM_FL_BLOCK_WAIT;
                GOTO(out, ELDLM_OK);
        }
        if (!ldlm_lock_compat(lock, 0)) {
                ldlm_resource_add_lock(res, &res->lr_waiting, lock);
                *flags |= LDLM_FL_BLOCK_GRANTED;
                GOTO(out, ELDLM_OK);
        }

        if (lock->l_granted_cb != NULL && lock->l_data != NULL) {
                /* We just -know- */
                struct ptlrpc_request *req = lock->l_data;
                lock->l_granted_cb(lock, req->rq_repmsg, 0);
        }
        ldlm_grant_lock(lock, NULL, 0);
        EXIT;
      out:
        l_unlock(&ns->ns_lock);
        /* Don't set 'completion_ast' until here so that if the lock is granted
         * immediately we don't do an unnecessary completion call. */
        lock->l_completion_ast = completion;
        return ELDLM_OK;
}

/* Must be called with namespace taken: queue is waiting or converting. */
static int ldlm_reprocess_queue(struct ldlm_resource *res,
                                struct list_head *queue)
{
        struct list_head *tmp, *pos;
        ENTRY;

        list_for_each_safe(tmp, pos, queue) {
                struct ldlm_lock *pending;
                pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                CDEBUG(D_INFO, "Reprocessing lock %p\n", pending);

                if (!ldlm_lock_compat(pending, 1))
                        RETURN(1);

                list_del_init(&pending->l_res_link);
                ldlm_grant_lock(pending, NULL, 0);
        }

        RETURN(0);
}

int ldlm_run_ast_work(struct list_head *rpc_list)
{
        struct list_head *tmp, *pos;
        int rc, retval = 0;
        ENTRY;

        list_for_each_safe(tmp, pos, rpc_list) {
                struct ldlm_ast_work *w =
                        list_entry(tmp, struct ldlm_ast_work, w_list);

                if (w->w_blocking)
                        rc = w->w_lock->l_blocking_ast
                                (w->w_lock, &w->w_desc, w->w_data,
                                 LDLM_CB_BLOCKING);
                else
                        rc = w->w_lock->l_completion_ast(w->w_lock, w->w_flags,
                                                         w->w_data);
                if (rc == -ERESTART)
                        retval = rc;
                else if (rc)
                        CERROR("Failed AST - should clean & disconnect "
                               "client\n");
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
        (void)ldlm_namespace_foreach_res(ns, reprocess_one_queue, NULL);
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

        ldlm_reprocess_queue(res, &res->lr_converting);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(res, &res->lr_waiting);

        res->lr_tmp = NULL;
        l_unlock(&res->lr_namespace->ns_lock);

        rc = ldlm_run_ast_work(&rpc_list);
        if (rc == -ERESTART)
                goto restart;
        EXIT;
}

void ldlm_cancel_callback(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (!(lock->l_flags & LDLM_FL_CANCEL)) {
                lock->l_flags |= LDLM_FL_CANCEL;
                if (lock->l_blocking_ast)
                        lock->l_blocking_ast(lock, NULL, lock->l_data,
                                             LDLM_CB_CANCELING);
                else
                        LDLM_DEBUG0(lock, "no blocking ast");
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
}

void ldlm_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        ENTRY;

        ldlm_del_waiting_lock(lock);

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);
        /* Please do not, no matter how tempting, remove this LBUG without
         * talking to me first. -phik */
        if (lock->l_readers || lock->l_writers) {
                LDLM_DEBUG0(lock, "lock still has references");
                ldlm_lock_dump(D_OTHER, lock);
                LBUG();
        }

        ldlm_cancel_callback(lock);

        ldlm_resource_unlink_lock(lock);
        ldlm_lock_destroy(lock);
        l_unlock(&ns->ns_lock);
        EXIT;
}

int ldlm_lock_set_data(struct lustre_handle *lockh, void *data, void *cp_data)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        if (lock == NULL)
                RETURN(-EINVAL);

        lock->l_data = data;
        lock->l_cp_data = cp_data;

        LDLM_LOCK_PUT(lock);

        RETURN(0);
}

/* This function is only called from one thread (per export); no locking around
 * the list ops needed */
void ldlm_cancel_locks_for_export(struct obd_export *exp)
{
        struct list_head *iter, *n;

        list_for_each_safe(iter, n, &exp->exp_ldlm_data.led_held_locks) {
                struct ldlm_lock *lock;
                struct ldlm_resource *res;
                lock = list_entry(iter, struct ldlm_lock, l_export_chain);
                res = ldlm_resource_getref(lock->l_resource);
                LDLM_DEBUG(lock, "export %p", exp);
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(res);
                ldlm_resource_putref(res);
        }
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
                        ldlm_grant_lock(lock, NULL, 0);
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
                ldlm_run_ast_work(&rpc_list);
        RETURN(res);
}

void ldlm_lock_dump(int level, struct ldlm_lock *lock)
{
        char ver[128];

        if (!((portal_debug | D_ERROR) & level))
                return;

        if (RES_VERSION_SIZE != 4)
                LBUG();

        if (!lock) {
                CDEBUG(level, "  NULL LDLM lock\n");
                return;
        }

        snprintf(ver, sizeof(ver), "%x %x %x %x",
                 lock->l_version[0], lock->l_version[1],
                 lock->l_version[2], lock->l_version[3]);

        CDEBUG(level, "  -- Lock dump: %p (%s) (rc: %d)\n", lock, ver,
               atomic_read(&lock->l_refc));
        if (lock->l_export && lock->l_export->exp_connection)
                CDEBUG(level, "  Node: NID %x (rhandle: "LPX64")\n",
                       lock->l_export->exp_connection->c_peer.peer_nid,
                       lock->l_remote_handle.cookie);
        else
                CDEBUG(level, "  Node: local\n");
        CDEBUG(level, "  Parent: %p\n", lock->l_parent);
        CDEBUG(level, "  Resource: %p ("LPD64")\n", lock->l_resource,
               lock->l_resource->lr_name.name[0]);
        CDEBUG(level, "  Requested mode: %d, granted mode: %d\n",
               (int)lock->l_req_mode, (int)lock->l_granted_mode);
        CDEBUG(level, "  Readers: %u ; Writers; %u\n",
               lock->l_readers, lock->l_writers);
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                CDEBUG(level, "  Extent: "LPU64" -> "LPU64"\n",
                       lock->l_extent.start, lock->l_extent.end);
}

void ldlm_lock_dump_handle(int level, struct lustre_handle *lockh)
{
        struct ldlm_lock *lock;

        lock = ldlm_handle2lock(lockh);
        if (lock == NULL)
                return;

        ldlm_lock_dump(D_OTHER, lock);

        LDLM_LOCK_PUT(lock);
}
