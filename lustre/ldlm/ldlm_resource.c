/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Cluster File Systems, Inc.
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

kmem_cache_t *ldlm_resource_slab;
kmem_cache_t *ldlm_lock_slab;

struct ldlm_namespace *ldlm_namespace_find(struct obd_device *obddev, __u32 id)
{
        struct list_head *tmp;
        struct ldlm_namespace *res;

        ldlm_lock(obddev);

        res = NULL;
        list_for_each(tmp, &obddev->u.ldlm.ldlm_namespaces) { 
                struct ldlm_namespace *chk;
                chk = list_entry(tmp, struct ldlm_namespace, ns_link);
                
                if ( chk->ns_id == id ) {
                        res = chk;
                        break;
                }
        }

        ldlm_unlock(obddev);

        return res;
}

/* this must be called with ldlm_lock(obddev) held */
static void res_hash_init(struct ldlm_namespace *ns)
{
        struct list_head *res_hash;
        struct list_head *bucket;

        if (ns->ns_hash != NULL)
                return;

        OBD_ALLOC(res_hash, sizeof(struct list_head) * RES_HASH_SIZE);
        if (!res_hash)
                LBUG();

        for (bucket = res_hash + RES_HASH_SIZE-1 ; bucket >= res_hash ;
             bucket--) {
                INIT_LIST_HEAD(bucket);
        }

        ns->ns_hash = res_hash;
}

struct ldlm_namespace *ldlm_namespace_new(struct obd_device *obddev, __u32 id)
{
        struct ldlm_namespace *ns;

        ldlm_lock(obddev);

        if (ldlm_namespace_find(obddev, id))
                LBUG();

        OBD_ALLOC(ns, sizeof(*ns));
        if (!ns)
                LBUG();

        ns->ns_id = id;
        INIT_LIST_HEAD(&ns->ns_root_list);

        list_add(&ns->ns_link, &obddev->u.ldlm.ldlm_namespaces);

        res_hash_init(ns); 

        ldlm_unlock(obddev);

        return ns;
}

static __u32 ldlm_hash_fn(struct ldlm_resource *parent, __u64 *name)
{
        __u32 hash = 0;
        int i;

        for (i = 0; i < RES_NAME_SIZE; i++) {
                hash += name[i];
        }

        hash += (__u32)((unsigned long)parent >> 4);

        return (hash & RES_HASH_MASK);
}

static struct ldlm_resource *ldlm_resource_new(void)
{
        struct ldlm_resource *res;

        res = kmem_cache_alloc(ldlm_resource_slab, SLAB_KERNEL);
        if (res == NULL)
                LBUG();
        memset(res, 0, sizeof(*res));

        INIT_LIST_HEAD(&res->lr_children);
        INIT_LIST_HEAD(&res->lr_granted);
        INIT_LIST_HEAD(&res->lr_converting);
        INIT_LIST_HEAD(&res->lr_waiting);

        res->lr_lock = SPIN_LOCK_UNLOCKED;

        atomic_set(&res->lr_refcount, 1);

        return res;
}

/* ldlm_lock(obddev) must be taken before calling resource_add */
static struct ldlm_resource *ldlm_resource_add(struct ldlm_namespace *ns,
                                               struct ldlm_resource *parent,
                                               __u64 *name)
{
        struct list_head *bucket;
        struct ldlm_resource *res;

        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

        res = ldlm_resource_new();
        if (!res)
                LBUG();

        memcpy(res->lr_name, name, RES_NAME_SIZE * sizeof(__u32));
        res->lr_namespace = ns;
        list_add(&res->lr_hash, bucket);
        if (parent == NULL) {
                res->lr_parent = res;
                list_add(&res->lr_rootlink, &ns->ns_root_list);
        } else {
                res->lr_parent = parent;
                list_add(&res->lr_childof, &parent->lr_children);
        }

        return res;
}

struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        __u64 *name, int create)
{
        struct list_head *bucket;
        struct list_head *tmp = bucket;
        struct ldlm_resource *res;

        ENTRY;

        if (ns->ns_hash == NULL)
                RETURN(NULL);
        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

        ldlm_lock(ns->ns_obddev);

        res = NULL;
        list_for_each(tmp, bucket) {
                struct ldlm_resource *chk;
                chk = list_entry(tmp, struct ldlm_resource, lr_hash);

                if (memcmp(chk->lr_name, name,
                           RES_NAME_SIZE * sizeof(__u32)) == 0) {
                        res = chk;
                        atomic_inc(&res->lr_refcount);
                        break;
                }
        }

        if (res == NULL && create)
                res = ldlm_resource_add(ns, parent, name);

        ldlm_unlock(ns->ns_obddev);

        RETURN(res);
}

int ldlm_resource_put(struct ldlm_resource *res)
{
        int rc = 0; 
        ldlm_lock(res->lr_namespace->ns_obddev);

        if (atomic_dec_and_test(&res->lr_refcount)) {
                if (!list_empty(&res->lr_granted))
                        LBUG();

                if (!list_empty(&res->lr_converting))
                        LBUG();

                if (!list_empty(&res->lr_waiting))
                        LBUG();

                list_del(&res->lr_hash);
                list_del(&res->lr_rootlink);
                list_del(&res->lr_childof);

                kmem_cache_free(ldlm_resource_slab, res);
                rc = 1;
        }
        ldlm_unlock(res->lr_namespace->ns_obddev);
        return rc; 
}

int ldlm_get_resource_handle(struct ldlm_resource *res, struct ldlm_handle *h)
{
        LBUG();
        return 0;
}

void ldlm_resource_dump(struct ldlm_resource *res)
{
        struct list_head *tmp;
        char name[256];

        if (RES_NAME_SIZE != 3)
                LBUG();

        snprintf(name, sizeof(name), "%Lx %Lx %Lx",
                 res->lr_name[0], res->lr_name[1], res->lr_name[2]);

        CDEBUG(D_OTHER, "--- Resource: %p (%s)\n", res, name);
        CDEBUG(D_OTHER, "Namespace: %p (%u)\n", res->lr_namespace,
               res->lr_namespace->ns_id);
        CDEBUG(D_OTHER, "Parent: %p, root: %p\n", res->lr_parent, res->lr_root);

        CDEBUG(D_OTHER, "Granted locks:\n");
        list_for_each(tmp, &res->lr_granted) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_dump(lock);
        }

        CDEBUG(D_OTHER, "Converting locks:\n");
        list_for_each(tmp, &res->lr_converting) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_dump(lock);
        }

        CDEBUG(D_OTHER, "Waiting locks:\n");
        list_for_each(tmp, &res->lr_waiting) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_dump(lock);
        }
}

