/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc.
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
#include <linux/random.h>
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
        case IT_MKDIR:
                return "mkdir";
        case IT_LINK:
                return "link";
        case IT_LINK2:
                return "link2";
        case IT_SYMLINK:
                return "symlink";
        case IT_UNLINK:
                return "unlink";
        case IT_RMDIR:
                return "rmdir";
        case IT_RENAME:
                return "rename";
        case IT_RENAME2:
                return "rename2";
        case IT_READDIR:
                return "readdir";
        case IT_GETATTR:
                return "getattr";
        case IT_SETATTR:
                return "setattr";
        case IT_READLINK:
                return "readlink";
        case IT_MKNOD:
                return "mknod";
        case IT_LOOKUP:
                return "lookup";
        default:
                CERROR("Unknown intent %d\n", it);
                return "UNKNOWN";
        }
}

extern kmem_cache_t *ldlm_lock_slab;

static int ldlm_plain_compat(struct ldlm_lock *a, struct ldlm_lock *b);

ldlm_res_compat ldlm_res_compat_table[] = {
        [LDLM_PLAIN] ldlm_plain_compat,
        [LDLM_EXTENT] ldlm_extent_compat,
};

static ldlm_res_policy ldlm_intent_policy_func;

static int ldlm_plain_policy(struct ldlm_lock *lock, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
        if ((flags & LDLM_FL_HAS_INTENT) && ldlm_intent_policy_func) {
                return ldlm_intent_policy_func(lock, req_cookie, mode, flags, 
                                               data);
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
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        lock->l_refc++;
        ldlm_resource_getref(lock->l_resource);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return lock;
}

void ldlm_lock_put(struct ldlm_lock *lock)
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        ENTRY;

        l_lock(&ns->ns_lock);
        lock->l_refc--;
        //LDLM_DEBUG(lock, "after refc--");
        if (lock->l_refc < 0)
                LBUG();

        if (ldlm_resource_put(lock->l_resource)) {
                LASSERT(lock->l_refc == 0);
                lock->l_resource = NULL;
        }
        if (lock->l_parent)
                LDLM_LOCK_PUT(lock->l_parent);

        if (lock->l_refc == 0 && (lock->l_flags & LDLM_FL_DESTROYED)) {
                l_unlock(&ns->ns_lock);
                LDLM_DEBUG(lock, "final lock_put on destroyed lock, freeing");

                //spin_lock(&ldlm_handle_lock);
                spin_lock(&ns->ns_counter_lock);
                ns->ns_locks--;
                spin_unlock(&ns->ns_counter_lock);

                lock->l_resource = NULL;
                lock->l_random = DEAD_HANDLE_MAGIC;
                if (lock->l_export && lock->l_export->exp_connection)
                        ptlrpc_put_connection(lock->l_export->exp_connection);
                kmem_cache_free(ldlm_lock_slab, lock);
                //spin_unlock(&ldlm_handle_lock);
                CDEBUG(D_MALLOC, "kfreed 'lock': %d at %p (tot 0).\n",
                       sizeof(*lock), lock);
        } else
                l_unlock(&ns->ns_lock);

        EXIT;
}

void ldlm_lock_destroy(struct ldlm_lock *lock)
{
        ENTRY;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        if (!list_empty(&lock->l_children)) {
                LDLM_DEBUG(lock, "still has children (%p)!",
                           lock->l_children.next);
                ldlm_lock_dump(lock);
                LBUG();
        }
        if (lock->l_readers || lock->l_writers) {
                LDLM_DEBUG(lock, "lock still has references");
                ldlm_lock_dump(lock);
        }

        if (!list_empty(&lock->l_res_link)) {
                ldlm_lock_dump(lock);
                LBUG();
        }

        if (lock->l_flags & LDLM_FL_DESTROYED) {
                LASSERT(list_empty(&lock->l_lru));
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                EXIT;
                return;
        }

        list_del_init(&lock->l_lru);
        list_del(&lock->l_export_chain);
        lock->l_export = NULL;
        lock->l_flags |= LDLM_FL_DESTROYED;

        /* Wake anyone waiting for this lock */
        /* FIXME: I should probably add yet another flag, instead of using
         * l_export to only call this on clients */
        if (lock->l_export && lock->l_completion_ast)
                lock->l_completion_ast(lock, 0);

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        LDLM_LOCK_PUT(lock);
        EXIT;
}

/*
   usage: pass in a resource on which you have done get
          pass in a parent lock on which you have done a get
          do not put the resource or the parent
   returns: lock with refcount 1
*/
static struct ldlm_lock *ldlm_lock_new(struct ldlm_lock *parent,
                                       struct ldlm_resource *resource)
{
        struct ldlm_lock *lock;
        ENTRY;

        if (resource == NULL)
                LBUG();

        lock = kmem_cache_alloc(ldlm_lock_slab, SLAB_KERNEL);
        if (lock == NULL)
                RETURN(NULL);

        memset(lock, 0, sizeof(*lock));
        get_random_bytes(&lock->l_random, sizeof(__u64));

        lock->l_resource = resource;
        /* this refcount matches the one of the resource passed
           in which is not being put away */
        lock->l_refc = 1;
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
                lock->l_parent = parent;
                list_add(&lock->l_childof, &parent->l_children);
                l_unlock(&parent->l_resource->lr_namespace->ns_lock);
        }

        CDEBUG(D_MALLOC, "kmalloced 'lock': %d at "
               "%p (tot %d).\n", sizeof(*lock), lock, 1);
        /* this is the extra refcount, to prevent the lock from evaporating */
        LDLM_LOCK_GET(lock);
        RETURN(lock);
}

int ldlm_lock_change_resource(struct ldlm_lock *lock, __u64 new_resid[3])
{
        struct ldlm_namespace *ns = lock->l_resource->lr_namespace;
        struct ldlm_resource *oldres = lock->l_resource;
        int i;
        ENTRY;

        l_lock(&ns->ns_lock);
        if (memcmp(new_resid, lock->l_resource->lr_name,
                   sizeof(lock->l_resource->lr_name)) == 0) {
                /* Nothing to do */
                l_unlock(&ns->ns_lock);
                RETURN(0);
        }

        LASSERT(new_resid[0] != 0);

        /* This function assumes that the lock isn't on any lists */
        LASSERT(list_empty(&lock->l_res_link));

        lock->l_resource = ldlm_resource_get(ns, NULL, new_resid,
                                             lock->l_resource->lr_type, 1);
        if (lock->l_resource == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }

        /* move references over */
        for (i = 0; i < lock->l_refc; i++) {
                int rc;
                ldlm_resource_getref(lock->l_resource);
                rc = ldlm_resource_put(oldres);
                if (rc == 1 && i != lock->l_refc - 1)
                        LBUG();
        }
        /* compensate for the initial get above.. */
        ldlm_resource_put(lock->l_resource);

        l_unlock(&ns->ns_lock);
        RETURN(0);
}

/*
 *  HANDLES
 */

void ldlm_lock2handle(struct ldlm_lock *lock, struct lustre_handle *lockh)
{
        lockh->addr = (__u64) (unsigned long)lock;
        lockh->cookie = lock->l_random;
}

/* 
 * if flags: atomically get the lock and set the flags. 
 * Return NULL if flag already set
 */

struct ldlm_lock *__ldlm_handle2lock(struct lustre_handle *handle,
                                     int strict, int flags)
{
        struct ldlm_lock *lock = NULL, *retval = NULL;
        ENTRY;

        if (!handle || !handle->addr)
                RETURN(NULL);

        //spin_lock(&ldlm_handle_lock);
        lock = (struct ldlm_lock *)(unsigned long)(handle->addr);
        if (!kmem_cache_validate(ldlm_lock_slab, (void *)lock)) {
                //CERROR("bogus lock %p\n", lock);
                GOTO(out2, retval);
        }

        if (lock->l_random != handle->cookie) {
                //CERROR("bogus cookie: lock %p has "LPX64" vs. handle "LPX64"\n",
                //       lock, lock->l_random, handle->cookie);
                GOTO(out2, NULL);
        }
        if (!lock->l_resource) {
                CERROR("trying to lock bogus resource: lock %p\n", lock);
                //LDLM_DEBUG(lock, "ldlm_handle2lock(%p)", lock);
                GOTO(out2, retval);
        }
        if (!lock->l_resource->lr_namespace) {
                CERROR("trying to lock bogus namespace: lock %p\n", lock);
                //LDLM_DEBUG(lock, "ldlm_handle2lock(%p)", lock);
                GOTO(out2, retval);
        }

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (strict && lock->l_flags & LDLM_FL_DESTROYED) {
                CERROR("lock already destroyed: lock %p\n", lock);
                //LDLM_DEBUG(lock, "ldlm_handle2lock(%p)", lock);
                GOTO(out, NULL);
        }

        if (flags && (lock->l_flags & flags)) 
                GOTO(out, NULL);

        if (flags)
                lock->l_flags |= flags;

        retval = LDLM_LOCK_GET(lock);
        if (!retval)
                CERROR("lock disappeared below us!!! %p\n", lock);
        EXIT;
 out:
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
 out2:
        //spin_unlock(&ldlm_handle_lock);
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
                                   struct ldlm_lock *new)
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

        if (new) {
                lock->l_flags |= LDLM_FL_AST_SENT;
                w->w_blocking = 1;
                ldlm_lock2desc(new, &w->w_desc);
        }

        w->w_lock = LDLM_LOCK_GET(lock);
        list_add(&w->w_list, lock->l_resource->lr_tmp);
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

        if (!list_empty(&lock->l_lru)) { 
                list_del_init(&lock->l_lru);
                lock->l_resource->lr_namespace->ns_nr_unused--;
                LASSERT(lock->l_resource->lr_namespace->ns_nr_unused >= 0);
        }

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
                                    __u64 *res_id, int flags);

void ldlm_lock_decref(struct lustre_handle *lockh, __u32 mode)
{
        struct ldlm_lock *lock = __ldlm_handle2lock(lockh, 0, 0);
        struct ldlm_namespace *ns;
        ENTRY;

        if (lock == NULL)
                LBUG();

        LDLM_DEBUG(lock, "ldlm_lock_decref(%s)", ldlm_lockname[mode]);
        ns = lock->l_resource->lr_namespace;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (mode == LCK_NL || mode == LCK_CR || mode == LCK_PR)
                lock->l_readers--;
        else
                lock->l_writers--;

        /* If we received a blocked AST and this was the last reference,
         * run the callback. */
        if (!lock->l_readers && !lock->l_writers &&
            (lock->l_flags & LDLM_FL_CBPENDING)) {
                if (!lock->l_resource->lr_namespace->ns_client &&
                    lock->l_export)
                        CERROR("FL_CBPENDING set on non-local lock--just a "
                               "warning\n");

                LDLM_DEBUG(lock, "final decref done on cbpending lock");
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

                /* FIXME: need a real 'desc' here */
                lock->l_blocking_ast(lock, NULL, lock->l_data,
                                     lock->l_data_len, LDLM_CB_BLOCKING);
        } else if (ns->ns_client && !lock->l_readers && !lock->l_writers) {
                LASSERT(list_empty(&lock->l_lru));
                LASSERT(ns->ns_nr_unused >= 0);
                list_add_tail(&lock->l_lru, &ns->ns_unused_list);
                ns->ns_nr_unused++;
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                ldlm_cancel_lru(ns);
        } else
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        LDLM_LOCK_PUT(lock);    /* matches the ldlm_lock_get in addref */
        LDLM_LOCK_PUT(lock);    /* matches the handle2lock above */

        EXIT;
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
                        ldlm_add_ast_work_item(child, lock);
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
   - ldlm_handle_enqueuque - resource
*/
void ldlm_grant_lock(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;
        ENTRY;

        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        ldlm_resource_add_lock(res, &res->lr_granted, lock);
        lock->l_granted_mode = lock->l_req_mode;

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (lock->l_completion_ast) {
                ldlm_add_ast_work_item(lock, NULL);
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        EXIT;
}

/* returns a referenced lock or NULL */
static struct ldlm_lock *search_queue(struct list_head *queue, ldlm_mode_t mode,
                                      struct ldlm_extent *extent,
                                      struct ldlm_lock *old_lock)
{
        struct ldlm_lock *lock;
        struct list_head *tmp;

        list_for_each(tmp, queue) {
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);

                if (lock == old_lock)
                        continue;

                if (lock->l_flags & (LDLM_FL_CBPENDING | LDLM_FL_DESTROYED))
                        continue;

                if (lock->l_req_mode != mode)
                        continue;

                if (lock->l_resource->lr_type == LDLM_EXTENT &&
                    (lock->l_extent.start > extent->start ||
                     lock->l_extent.end < extent->end))
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
 * Returns 1 if it finds an already-existing lock that is compatible; in this
 * case, lockh is filled in with a addref()ed lock
 */
int ldlm_lock_match(struct ldlm_namespace *ns, __u64 *res_id, __u32 type,
                    void *cookie, int cookielen, ldlm_mode_t mode,
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
                res_id = old_lock->l_resource->lr_name;
                type = old_lock->l_resource->lr_type;
                mode = old_lock->l_req_mode;
        }

        res = ldlm_resource_get(ns, NULL, res_id, type, 0);
        if (res == NULL) {
                LASSERT(old_lock == NULL);
                RETURN(0);
        }

        l_lock(&ns->ns_lock);

        if ((lock = search_queue(&res->lr_granted, mode, cookie, old_lock)))
                GOTO(out, rc = 1);
        if ((lock = search_queue(&res->lr_converting, mode, cookie, old_lock)))
                GOTO(out, rc = 1);
        if ((lock = search_queue(&res->lr_waiting, mode, cookie, old_lock)))
                GOTO(out, rc = 1);

        EXIT;
       out:
        ldlm_resource_put(res);
        l_unlock(&ns->ns_lock);

        if (lock) {
                ldlm_lock2handle(lock, lockh);
                if (lock->l_completion_ast)
                        lock->l_completion_ast(lock, LDLM_FL_WAIT_NOREPROC);
        }
        if (rc)
                LDLM_DEBUG(lock, "matched");
        else
                LDLM_DEBUG_NOLOCK("not matched");

        if (old_lock)
                LDLM_LOCK_PUT(old_lock);

        return rc;
}

/* Returns a referenced lock */
struct ldlm_lock *ldlm_lock_create(struct ldlm_namespace *ns,
                                   struct lustre_handle *parent_lock_handle,
                                   __u64 * res_id, __u32 type,
                                   ldlm_mode_t mode, void *data, __u32 data_len)
{
        struct ldlm_resource *res, *parent_res = NULL;
        struct ldlm_lock *lock, *parent_lock;

        parent_lock = ldlm_handle2lock(parent_lock_handle);
        if (parent_lock)
                parent_res = parent_lock->l_resource;

        res = ldlm_resource_get(ns, parent_res, res_id, type, 1);
        if (res == NULL)
                RETURN(NULL);

        lock = ldlm_lock_new(parent_lock, res);
        if (lock == NULL) {
                ldlm_resource_put(res);
                RETURN(NULL);
        }

        lock->l_req_mode = mode;
        lock->l_data = data;
        lock->l_data_len = data_len;

        return lock;
}

/* Must be called with lock->l_lock and lock->l_resource->lr_lock not held */
ldlm_error_t ldlm_lock_enqueue(struct ldlm_lock * lock,
                               void *cookie, int cookie_len,
                               int *flags,
                               ldlm_completion_callback completion,
                               ldlm_blocking_callback blocking)
{
        struct ldlm_resource *res;
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
                rc = policy(lock, cookie, lock->l_req_mode, *flags, NULL);

                if (rc == ELDLM_LOCK_CHANGED) {
                        res = lock->l_resource;
                        *flags |= LDLM_FL_LOCK_CHANGED;
                } else if (rc == ELDLM_LOCK_ABORTED) {
                        ldlm_lock_destroy(lock);
                        RETURN(rc);
                }
        }

        l_lock(&res->lr_namespace->ns_lock);
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
         * FIXME (bug 629283): Detect obvious lies by checking compatibility in
         * granted/converting queues. */
        ldlm_resource_unlink_lock(lock);
        if (local || (*flags & LDLM_FL_REPLAY)) {
                if (*flags & LDLM_FL_BLOCK_CONV)
                        ldlm_resource_add_lock(res, res->lr_converting.prev,
                                               lock);
                else if (*flags & (LDLM_FL_BLOCK_WAIT | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                else
                        ldlm_grant_lock(lock);
                GOTO(out, ELDLM_OK);
        }

        /* FIXME: We may want to optimize by checking lr_most_restr */
        if (!list_empty(&res->lr_converting)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_CONV;
                GOTO(out, ELDLM_OK);
        }
        if (!list_empty(&res->lr_waiting)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_WAIT;
                GOTO(out, ELDLM_OK);
        }
        if (!ldlm_lock_compat(lock, 0)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                *flags |= LDLM_FL_BLOCK_GRANTED;
                GOTO(out, ELDLM_OK);
        }

        ldlm_grant_lock(lock);
        EXIT;
      out:
        l_unlock(&res->lr_namespace->ns_lock);
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
                ldlm_grant_lock(pending);
        }

        RETURN(0);
}

void ldlm_run_ast_work(struct list_head *rpc_list)
{
        struct list_head *tmp, *pos;
        int rc;
        ENTRY;

        list_for_each_safe(tmp, pos, rpc_list) {
                struct ldlm_ast_work *w =
                        list_entry(tmp, struct ldlm_ast_work, w_list);

                if (w->w_blocking)
                        rc = w->w_lock->l_blocking_ast
                                (w->w_lock, &w->w_desc, w->w_data,
                                 w->w_datalen, LDLM_CB_BLOCKING);
                else
                        rc = w->w_lock->l_completion_ast(w->w_lock, w->w_flags);
                if (rc)
                        CERROR("Failed AST - should clean & disconnect "
                               "client\n");
                LDLM_LOCK_PUT(w->w_lock);
                list_del(&w->w_list);
                OBD_FREE(w, sizeof(*w));
        }
        EXIT;
}

/* Must be called with resource->lr_lock not taken. */
void ldlm_reprocess_all(struct ldlm_resource *res)
{
        struct list_head rpc_list = LIST_HEAD_INIT(rpc_list);
        ENTRY;

        /* Local lock trees don't get reprocessed. */
        if (res->lr_namespace->ns_client) {
                EXIT;
                return;
        }

        l_lock(&res->lr_namespace->ns_lock);
        res->lr_tmp = &rpc_list;

        ldlm_reprocess_queue(res, &res->lr_converting);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(res, &res->lr_waiting);

        res->lr_tmp = NULL;
        l_unlock(&res->lr_namespace->ns_lock);

        ldlm_run_ast_work(&rpc_list);
        EXIT;
}

void ldlm_cancel_callback(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (!(lock->l_flags & LDLM_FL_CANCEL)) {
                lock->l_flags |= LDLM_FL_CANCEL;
                if (lock->l_blocking_ast)
                        lock->l_blocking_ast(lock, NULL, lock->l_data,
                                             lock->l_data_len,
                                             LDLM_CB_CANCELING);
                else
                        LDLM_DEBUG(lock, "no blocking ast");
        }
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
}

void ldlm_lock_cancel(struct ldlm_lock *lock)
{
        struct ldlm_resource *res;
        struct ldlm_namespace *ns;
        ENTRY;

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);
        if (lock->l_readers || lock->l_writers)
                LDLM_DEBUG(lock, "lock still has references");

        ldlm_cancel_callback(lock);

        ldlm_del_waiting_lock(lock);
        ldlm_resource_unlink_lock(lock);
        ldlm_lock_destroy(lock);
        l_unlock(&ns->ns_lock);
        EXIT;
}

int ldlm_lock_set_data(struct lustre_handle *lockh, void *data, int datalen)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        if (lock == NULL)
                RETURN(-EINVAL);

        lock->l_data = data;
        lock->l_data_len = datalen;

        LDLM_LOCK_PUT(lock);

        RETURN(0);
}

void ldlm_cancel_locks_for_export(struct obd_export *exp)
{
        struct list_head *iter, *n; /* MUST BE CALLED "n"! */

        list_for_each_safe(iter, n, &exp->exp_ldlm_data.led_held_locks) {
                struct ldlm_lock *lock;
                struct ldlm_resource *res;
                lock = list_entry(iter, struct ldlm_lock, l_export_chain);
                res = ldlm_resource_getref(lock->l_resource);
                LDLM_DEBUG(lock, "export %p", exp);
                ldlm_lock_cancel(lock);
                ldlm_reprocess_all(res);
                ldlm_resource_put(res);
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

        res = lock->l_resource;
        ns = res->lr_namespace;

        l_lock(&ns->ns_lock);

        lock->l_req_mode = new_mode;
        ldlm_resource_unlink_lock(lock);

        /* If this is a local resource, put it on the appropriate list. */
        if (res->lr_namespace->ns_client) {
                if (*flags & (LDLM_FL_BLOCK_CONV | LDLM_FL_BLOCK_GRANTED))
                        ldlm_resource_add_lock(res, res->lr_converting.prev,
                                               lock);
                else {
                        /* This should never happen, because of the way the
                         * server handles conversions. */
                        LBUG();

                        res->lr_tmp = &rpc_list;
                        ldlm_grant_lock(lock);
                        res->lr_tmp = NULL;
                        granted = 1;
                        /* FIXME: completion handling not with ns_lock held ! */
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock, 0);
                }
        } else {
                /* FIXME: We should try the conversion right away and possibly
                 * return success without the need for an extra AST */
                ldlm_resource_add_lock(res, res->lr_converting.prev, lock);
                *flags |= LDLM_FL_BLOCK_CONV;
        }

        l_unlock(&ns->ns_lock);

        if (granted)
                ldlm_run_ast_work(&rpc_list);
        RETURN(res);
}

void ldlm_lock_dump(struct ldlm_lock *lock)
{
        char ver[128];

        if (!(portal_debug & D_OTHER))
                return;

        if (RES_VERSION_SIZE != 4)
                LBUG();

        if (!lock) {
                CDEBUG(D_OTHER, "  NULL LDLM lock\n");
                return;
        }

        snprintf(ver, sizeof(ver), "%x %x %x %x",
                 lock->l_version[0], lock->l_version[1],
                 lock->l_version[2], lock->l_version[3]);

        CDEBUG(D_OTHER, "  -- Lock dump: %p (%s)\n", lock, ver);
        if (lock->l_export && lock->l_export->exp_connection)
                CDEBUG(D_OTHER, "  Node: NID %x (rhandle: "LPX64")\n",
                       lock->l_export->exp_connection->c_peer.peer_nid,
                       lock->l_remote_handle.addr);
        else
                CDEBUG(D_OTHER, "  Node: local\n");
        CDEBUG(D_OTHER, "  Parent: %p\n", lock->l_parent);
        CDEBUG(D_OTHER, "  Resource: %p ("LPD64")\n", lock->l_resource,
               lock->l_resource->lr_name[0]);
        CDEBUG(D_OTHER, "  Requested mode: %d, granted mode: %d\n",
               (int)lock->l_req_mode, (int)lock->l_granted_mode);
        CDEBUG(D_OTHER, "  Readers: %u ; Writers; %u\n",
               lock->l_readers, lock->l_writers);
        if (lock->l_resource->lr_type == LDLM_EXTENT)
                CDEBUG(D_OTHER, "  Extent: %Lu -> %Lu\n",
                       (unsigned long long)lock->l_extent.start,
                       (unsigned long long)lock->l_extent.end);
}
