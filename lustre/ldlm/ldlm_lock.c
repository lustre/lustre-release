/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
 * authors, Peter Braam <braam@clusterfs.com> & 
 * Phil Schwan <phil@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/obd_support.h>
#include <linux/obd_class.h>

#include <linux/lustre_dlm.h>

extern kmem_cache_t *ldlm_lock_slab;

ldlm_res_compat ldlm_res_compat_table [] = {
        [LDLM_PLAIN] NULL,
        [LDLM_EXTENT] ldlm_extent_compat,
        [LDLM_MDSINTENT] NULL
};

ldlm_res_policy ldlm_res_policy_table [] = {
        [LDLM_PLAIN] NULL,
        [LDLM_EXTENT] ldlm_extent_policy,
        [LDLM_MDSINTENT] NULL
};

static struct ldlm_lock *ldlm_lock_new(struct ldlm_lock *parent,
                                       struct ldlm_resource *resource,
                                       ldlm_mode_t mode)
{
        struct ldlm_lock *lock;

        if (resource == NULL)
                LBUG();

        lock = kmem_cache_alloc(ldlm_lock_slab, SLAB_KERNEL);
        if (lock == NULL)
                return NULL;

        memset(lock, 0, sizeof(*lock));
        lock->l_resource = resource;
        lock->l_req_mode = mode;
        INIT_LIST_HEAD(&lock->l_children);

        if (parent != NULL) {
                lock->l_parent = parent;
                list_add(&lock->l_childof, &parent->l_children);
        }

        return lock;
}

static int ldlm_notify_incompatible(struct list_head *list,
                                    struct ldlm_lock *new)
{
        struct list_head *tmp;
        int rc = 0;

        list_for_each(tmp, list) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                if (lockmode_compat(lock->l_req_mode, new->l_req_mode))
                        continue;

                rc = 1;

                if (lock->l_blocking_ast != NULL)
                        lock->l_blocking_ast(lock, new, lock->l_data,
                                             lock->l_data_len);
        }

        return rc;
}

static int ldlm_lock_compat(struct ldlm_lock *lock)
{
        struct ldlm_resource *parent_res = lock->l_resource->lr_parent;
        ldlm_res_compat compat;

        if (parent_res &&
            (compat = ldlm_res_compat_table[parent_res->lr_type])) {
                struct list_head *tmp;
                int incompat = 0;
                list_for_each(tmp, &parent_res->lr_children) {
                        struct ldlm_resource *child;
                        child = list_entry(tmp, struct ldlm_resource,
                                           lr_childof);

                        /* compat will return 0 when child == l_resource
                         * hence notifications on the same resource are incl. */
                        if (compat(child, lock->l_resource))
                                continue;

                        incompat |= ldlm_notify_incompatible(&child->lr_granted,
                                                             lock);
                }

                return incompat;
        }

        return ldlm_notify_incompatible(&lock->l_resource->lr_granted, lock);
}

static void ldlm_grant_lock(struct ldlm_resource *res, struct ldlm_lock *lock)
{
        ldlm_resource_add_lock(res, &res->lr_granted, lock);
        lock->l_granted_mode = lock->l_req_mode;

        if (lock->l_granted_mode < res->lr_most_restr)
                res->lr_most_restr = lock->l_granted_mode;

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, NULL, NULL, 0);
}

static int ldlm_reprocess_queue(struct ldlm_lock *lock,
                                struct list_head *converting,
                                struct list_head *granted_list)
{
        struct list_head *tmp, *pos;
        int incompat = 0;

        list_for_each_safe(tmp, pos, converting) { 
                struct ldlm_lock *pending;
                pending = list_entry(tmp, struct ldlm_lock, l_res_link);

                incompat = ldlm_lock_compat(pending);
                if (incompat)
                        break;

                list_del(&pending->l_res_link); 
                ldlm_grant_lock(pending->l_resource, pending);
        }

        return incompat;
}

/* XXX: Revisit the error handling; we do not, for example, do
 * ldlm_resource_put()s in our error cases, and we probably leak an allocated
 * memory. */
ldlm_error_t ldlm_local_lock_enqueue(struct obd_device *obddev,
                                     __u32 ns_id,
                                     struct ldlm_handle *parent_lock_handle,
                                     __u64 *res_id,
                                     __u32 type,
                                     ldlm_mode_t mode,
                                     int *flags,
                                     ldlm_lock_callback completion,
                                     ldlm_lock_callback blocking,
                                     void *data,
                                     __u32 data_len,
                                     struct ldlm_handle *lockh)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res, *parent_res;
        struct ldlm_lock *lock, *parent_lock;
        int incompat = 0, rc;
        __u64 new_id[RES_NAME_SIZE];
        ldlm_res_policy policy;

        ENTRY;
        
        parent_lock = ldlm_handle2object(parent_lock_handle);
        if ( parent_lock ) 
                parent_res = parent_lock->l_resource;
        else 
                parent_res = NULL;

        ns = ldlm_namespace_find(obddev, ns_id);
        if (ns == NULL || ns->ns_hash == NULL) 
                RETURN(-ELDLM_BAD_NAMESPACE);

        if (parent_res &&
            (policy = ldlm_res_policy_table[parent_res->lr_type])) {
                rc = policy(parent_res, res_id, new_id, mode, NULL);
                if (rc == ELDLM_RES_CHANGED) {
                        *flags |= LDLM_FL_RES_CHANGED;
                        memcpy(res_id, new_id, sizeof(*new_id));
                }
        }

        res = ldlm_resource_get(ns, parent_res, res_id, type, 1);
        if (res == NULL)
                RETURN(-ENOMEM);

        lock = ldlm_lock_new(parent_lock, res, mode);
        if (lock == NULL)
                RETURN(-ENOMEM);

        lock->l_data = data;
        lock->l_data_len = data_len;
        if ((*flags) & LDLM_FL_COMPLETION_AST)
                lock->l_completion_ast = completion;
        if ((*flags) & LDLM_FL_BLOCKING_AST)
                lock->l_blocking_ast = blocking;
        ldlm_object2handle(lock, lockh);
        spin_lock(&res->lr_lock);

        /* FIXME: We may want to optimize by checking lr_most_restr */

        if (!list_empty(&res->lr_converting)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                GOTO(out, rc = -ELDLM_BLOCK_CONV);
        }
        if (!list_empty(&res->lr_waiting)) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                GOTO(out, rc = -ELDLM_BLOCK_WAIT);
        }

        incompat = ldlm_lock_compat(lock);
        if (incompat) {
                ldlm_resource_add_lock(res, res->lr_waiting.prev, lock);
                GOTO(out, rc = -ELDLM_BLOCK_GRANTED);
        }

        ldlm_grant_lock(res, lock);
        GOTO(out, rc = ELDLM_OK);

 out:
        spin_unlock(&res->lr_lock);
        return rc;
}

static void ldlm_reprocess_res_compat(struct ldlm_lock *lock)
{
        struct ldlm_resource *parent_res = lock->l_resource->lr_parent;
        struct list_head *tmp;
        int do_waiting;

        list_for_each(tmp, &parent_res->lr_children) {
                struct ldlm_resource *child;
                child = list_entry(tmp, struct ldlm_resource, lr_childof);

                ldlm_reprocess_queue(lock, &child->lr_converting,
                                     &child->lr_granted);
                if (!list_empty(&child->lr_converting))
                        do_waiting = 0;
        }

        if (!do_waiting)
                return;

        list_for_each(tmp, &parent_res->lr_children) {
                struct ldlm_resource *child;
                child = list_entry(tmp, struct ldlm_resource, lr_childof);

                ldlm_reprocess_queue(lock, &child->lr_waiting,
                                     &child->lr_granted);
        }
}

static void ldlm_reprocess_all(struct ldlm_lock *lock)
{
        struct ldlm_resource *res = lock->l_resource;
        struct ldlm_resource *parent_res = res->lr_parent;

        if (parent_res && ldlm_res_compat_table[parent_res->lr_type]) {
                ldlm_reprocess_res_compat(lock);
                return;
        }

        ldlm_reprocess_queue(lock, &res->lr_converting, &res->lr_granted);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(lock, &res->lr_waiting, &res->lr_granted);
}

ldlm_error_t ldlm_local_lock_cancel(struct obd_device *obddev,
                                    struct ldlm_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        ENTRY;

        lock = ldlm_handle2object(lockh);
        res = lock->l_resource;

        ldlm_resource_del_lock(lock);

        kmem_cache_free(ldlm_lock_slab, lock);
        if (ldlm_resource_put(res))
                RETURN(ELDLM_OK);
        ldlm_reprocess_all(lock);

        RETURN(ELDLM_OK);
}

ldlm_error_t ldlm_local_lock_convert(struct obd_device *obddev,
                                     struct ldlm_handle *lockh,
                                     int new_mode, int *flags)
{
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        ENTRY;

        lock = ldlm_handle2object(lockh);
        res = lock->l_resource;
        list_del(&lock->l_res_link);
        lock->l_req_mode = new_mode;

        list_add(&lock->l_res_link, res->lr_converting.prev);

        ldlm_reprocess_all(lock);

        RETURN(ELDLM_OK);
}

void ldlm_lock_dump(struct ldlm_lock *lock)
{
        char ver[128];

        if (RES_VERSION_SIZE != 4)
                LBUG();

        snprintf(ver, sizeof(ver), "%x %x %x %x",
                 lock->l_version[0], lock->l_version[1],
                 lock->l_version[2], lock->l_version[3]);

        CDEBUG(D_OTHER, "  -- Lock dump: %p (%s)\n", lock, ver);
        CDEBUG(D_OTHER, "  Parent: %p\n", lock->l_parent);
        CDEBUG(D_OTHER, "  Requested mode: %d, granted mode: %d\n",
               (int)lock->l_req_mode, (int)lock->l_granted_mode);
}
