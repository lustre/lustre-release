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

                if (lock->l_resource->lr_blocking != NULL)
                        lock->l_resource->lr_blocking(lock, new);
        }

        return rc;
}


static int ldlm_reprocess_queue(struct list_head *queue, 
                                struct list_head *granted_list)
{
        struct list_head *tmp1, *tmp2;
        struct ldlm_resource *res;
        int rc = 0;

        list_for_each(tmp1, queue) { 
                struct ldlm_lock *pending;
                rc = 0; 
                pending = list_entry(tmp1, struct ldlm_lock, l_res_link);

                /* check if pending can go in ... */ 
                list_for_each(tmp2, granted_list) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp2, struct ldlm_lock, l_res_link);
                        if (lockmode_compat(lock->l_granted_mode, 
                                            pending->l_req_mode))
                                continue;
                        else { 
                                /* no, we are done */
                                rc = 1;
                                break;
                        }
                }

                if (rc) { 
                        /* no - we are done */
                        break;
                }

                res = pending->l_resource;
                list_del(&pending->l_res_link); 
                list_add(&pending->l_res_link, &res->lr_granted);
                pending->l_granted_mode = pending->l_req_mode;

                if (pending->l_granted_mode < res->lr_most_restr)
                        res->lr_most_restr = pending->l_granted_mode;

                if (pending->l_completion_ast)
                        pending->l_completion_ast(pending, NULL, NULL);
                

        }

        return rc;
}

ldlm_error_t ldlm_local_lock_enqueue(struct obd_device *obddev,
                                     __u32 ns_id,
                                     struct ldlm_handle *parent_res_handle,
                                     struct ldlm_handle *parent_lock_handle,
                                     __u64 *res_id,
                                     ldlm_mode_t mode,
                                     int *flags,
                                     ldlm_lock_callback completion,
                                     ldlm_lock_callback blocking,
                                     __u32 data_len,
                                     void *data,
                                     struct ldlm_handle *lockh)
{
        struct ldlm_namespace *ns;
        struct ldlm_resource *res, *parent_res;
        struct ldlm_lock *lock, *parent_lock;
        int incompat = 0, rc;
        __u64 new_id[RES_NAME_SIZE];
        ldlm_res_compat compat;
        ldlm_res_policy policy;

        ENTRY;

        parent_res = ldlm_handle2object(parent_res_handle);
        parent_lock = ldlm_handle2object(parent_lock_handle);

        ns = ldlm_namespace_find(obddev, ns_id);
        if (ns == NULL || ns->ns_hash == NULL) 
                RETURN(-ELDLM_BAD_NAMESPACE);

        if (parent_res &&
            (policy = ldlm_res_policy_table[parent_res->lr_type])) {
                rc = policy(parent_res, res_id, new_id, mode, NULL);
                if (rc == ELDLM_RES_CHANGED) {
                        *flags |= LDLM_FL_RES_CHANGED;
                        memcpy(res_id, new_id, sizeof(__u64) * RES_NAME_SIZE);
                }
        }

        res = ldlm_resource_get(ns, parent_res, res_id, 1);
        if (res == NULL)
                RETURN(-ENOMEM);

        lock = ldlm_lock_new(parent_lock, res, mode);
        if (lock == NULL)
                RETURN(-ENOMEM);

        if ((*flags) & LDLM_FL_COMPLETION_AST)
                lock->l_completion_ast = completion;
        if ((*flags) & LDLM_FL_BLOCKING_AST)
                lock->l_blocking_ast = blocking;
        ldlm_object2handle(lock, lockh);
        spin_lock(&res->lr_lock);

        /* FIXME: We may want to optimize by checking lr_most_restr */

        if (!list_empty(&res->lr_converting)) {
                list_add(&lock->l_res_link, res->lr_waiting.prev);
                rc = -ELDLM_BLOCK_CONV;
                GOTO(out, rc);
        }
        if (!list_empty(&res->lr_waiting)) {
                list_add(&lock->l_res_link, res->lr_waiting.prev);
                rc = -ELDLM_BLOCK_WAIT;
                GOTO(out, rc);
        }

        if (parent_res &&
            (compat = ldlm_res_compat_table[parent_res->lr_type])) {
                struct list_head *tmp;
                list_for_each(tmp, &parent_res->lr_children) {
                        struct ldlm_resource *child;
                        child = list_entry(tmp, struct ldlm_resource,
                                           lr_childof);

                        if (compat(child, res))
                                continue;

                        incompat |= ldlm_notify_incompatible(&child->lr_granted,
                                                             lock);
                }
        } else
                incompat = ldlm_notify_incompatible(&res->lr_granted, lock);

        if (incompat) {
                list_add(&lock->l_res_link, res->lr_waiting.prev);
                rc = -ELDLM_BLOCK_GRANTED;
                GOTO(out, rc);
        }

        list_add(&lock->l_res_link, &res->lr_granted);
        lock->l_granted_mode = mode;
        if (mode < res->lr_most_restr)
                res->lr_most_restr = mode;

        if (lock->l_completion_ast)
                lock->l_completion_ast(lock, NULL, NULL);

        rc = ELDLM_OK;
        GOTO(out, rc);

 out:
        spin_unlock(&res->lr_lock);
        return rc;
}

ldlm_error_t ldlm_local_lock_cancel(struct obd_device *obddev,
                                    struct ldlm_handle *lockh)
{
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        ENTRY;

        lock = (struct ldlm_lock *)(unsigned long)lockh->addr;
        res = lock->l_resource;
        list_del(&lock->l_res_link);

        kmem_cache_free(ldlm_lock_slab, lock);
        if (ldlm_resource_put(res)) {
                EXIT;
                return 0;
        }

        ldlm_reprocess_queue(&res->lr_converting, &res->lr_granted);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(&res->lr_waiting, &res->lr_granted);

        return 0;
}

ldlm_error_t ldlm_local_lock_convert(struct obd_device *obddev,
                                     struct ldlm_handle *lockh,
                                     int new_mode, int flags)
{
        struct ldlm_lock *lock;
        struct ldlm_resource *res;
        ENTRY;

        lock = (struct ldlm_lock *)(unsigned long)lockh->addr;
        res = lock->l_resource;
        list_del(&lock->l_res_link);
        lock->l_req_mode = new_mode;

        list_add(&lock->l_res_link, &res->lr_converting);

        ldlm_reprocess_queue(&res->lr_converting, &res->lr_granted);
        if (list_empty(&res->lr_converting))
                ldlm_reprocess_queue(&res->lr_waiting, &res->lr_granted);

        return 0;
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
