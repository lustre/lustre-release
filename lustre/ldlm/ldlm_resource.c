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
#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/lustre_dlm.h>

kmem_cache_t *ldlm_resource_slab, *ldlm_lock_slab;

struct ldlm_namespace *ldlm_namespace_new(struct obd_device *obddev,
                                          __u32 local)
{
        struct ldlm_namespace *ns;
        struct list_head *bucket;

        OBD_ALLOC(ns, sizeof(*ns));
        if (!ns) {
                LBUG();
                RETURN(NULL);
        }
        OBD_ALLOC(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        if (!ns->ns_hash) {
                OBD_FREE(ns, sizeof(*ns));
                LBUG();
                RETURN(NULL);
        }

        ns->ns_obddev = obddev;
        INIT_LIST_HEAD(&ns->ns_root_list);
        ns->ns_lock = SPIN_LOCK_UNLOCKED;
        ns->ns_refcount = 0;
        ns->ns_local = local;

        for (bucket = ns->ns_hash + RES_HASH_SIZE - 1; bucket >= ns->ns_hash;
             bucket--)
                INIT_LIST_HEAD(bucket);

        return ns;
}

static int cleanup_resource(struct ldlm_resource *res, struct list_head *q)
{
        struct list_head *tmp, *pos;
        int rc = 0;

        list_for_each_safe(tmp, pos, q) {
                struct ldlm_lock *lock;

                if (rc) {
                        /* Res was already cleaned up. */
                        LBUG();
                }

                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                spin_lock(&lock->l_lock);
                ldlm_resource_del_lock(lock);
                ldlm_lock_free(lock);

                rc = ldlm_resource_put(res);
        }

        return rc;
}

int ldlm_namespace_free(struct ldlm_namespace *ns)
{
        struct list_head *tmp, *pos;
        int i, rc;

        /* We should probably take the ns_lock, but then ldlm_resource_put
         * couldn't take it.  Hmm. */
        for (i = 0; i < RES_HASH_SIZE; i++) {
                list_for_each_safe(tmp, pos, &(ns->ns_hash[i])) {
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);

                        spin_lock(&res->lr_lock);
                        rc = cleanup_resource(res, &res->lr_granted);
                        if (!rc)
                                rc = cleanup_resource(res, &res->lr_converting);
                        if (!rc)
                                rc = cleanup_resource(res, &res->lr_waiting);

                        if (rc == 0) {
                                CERROR("Resource refcount nonzero after lock "
                                       "cleanup; forcing cleanup.\n");
                                res->lr_refcount = 1;
                                rc = ldlm_resource_put(res);
                        }
                }
        }

        OBD_FREE(ns->ns_hash, sizeof(struct list_head) * RES_HASH_SIZE);
        OBD_FREE(ns, sizeof(*ns));

        return ELDLM_OK;
}

static __u32 ldlm_hash_fn(struct ldlm_resource *parent, __u64 *name)
{
        __u32 hash = 0;
        int i;

        for (i = 0; i < RES_NAME_SIZE; i++)
                hash += name[i];

        hash += (__u32)((unsigned long)parent >> 4);

        return (hash & RES_HASH_MASK);
}

static struct ldlm_resource *ldlm_resource_new(void)
{
        struct ldlm_resource *res;

        res = kmem_cache_alloc(ldlm_resource_slab, SLAB_KERNEL);
        if (res == NULL) {
                LBUG();
                return NULL;
        }
        memset(res, 0, sizeof(*res));

        INIT_LIST_HEAD(&res->lr_children);
        INIT_LIST_HEAD(&res->lr_childof);
        INIT_LIST_HEAD(&res->lr_granted);
        INIT_LIST_HEAD(&res->lr_converting);
        INIT_LIST_HEAD(&res->lr_waiting);

        res->lr_lock = SPIN_LOCK_UNLOCKED;
        res->lr_refcount = 1;

        return res;
}

/* Args: locked namespace
 * Returns: newly-allocated, referenced, unlocked resource */
static struct ldlm_resource *ldlm_resource_add(struct ldlm_namespace *ns,
                                               struct ldlm_resource *parent,
                                               __u64 *name, __u32 type)
{
        struct list_head *bucket;
        struct ldlm_resource *res;

        if (type < 0 || type > LDLM_MAX_TYPE) 
                LBUG();

        res = ldlm_resource_new();
        if (!res) {
                LBUG();
                return NULL;
        }

        memcpy(res->lr_name, name, sizeof(res->lr_name));
        res->lr_namespace = ns;
        ns->ns_refcount++;

        res->lr_type = type; 
        res->lr_most_restr = LCK_NL;

        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);
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

/* Args: unlocked namespace
 * Locks: takes and releases ns->ns_lock and res->lr_lock
 * Returns: referenced, unlocked ldlm_resource or NULL */
struct ldlm_resource *ldlm_resource_get(struct ldlm_namespace *ns,
                                        struct ldlm_resource *parent,
                                        __u64 *name, __u32 type, int create)
{
        struct list_head *bucket;
        struct list_head *tmp = bucket;
        struct ldlm_resource *res = NULL;

        ENTRY;

        if (ns->ns_hash == NULL)
                RETURN(NULL);

        spin_lock(&ns->ns_lock);
        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

        list_for_each(tmp, bucket) {
                struct ldlm_resource *chk;
                chk = list_entry(tmp, struct ldlm_resource, lr_hash);

                if (memcmp(chk->lr_name, name, sizeof(chk->lr_name)) == 0) {
                        res = chk;
                        spin_lock(&res->lr_lock);
                        res->lr_refcount++;
                        spin_unlock(&res->lr_lock);
                        break;
                }
        }

        if (res == NULL && create)
                res = ldlm_resource_add(ns, parent, name, type);
        spin_unlock(&ns->ns_lock);

        RETURN(res);
}

/* Args: locked resource
 * Locks: takes and releases res->lr_lock
 *        takes and releases ns->ns_lock iff res->lr_refcount falls to 0
 */
int ldlm_resource_put(struct ldlm_resource *res)
{
        int rc = 0; 

        res->lr_refcount--;
        if (res->lr_refcount < 0)
                LBUG();

        if (res->lr_refcount == 0) {
                struct ldlm_namespace *ns = res->lr_namespace;

                spin_lock(&ns->ns_lock);
                spin_lock(&res->lr_lock);
                if (res->lr_refcount != 0)
                        goto out;

                if (!list_empty(&res->lr_granted))
                        LBUG();

                if (!list_empty(&res->lr_converting))
                        LBUG();

                if (!list_empty(&res->lr_waiting))
                        LBUG();

                if (!list_empty(&res->lr_children))
                        LBUG();

                ns->ns_refcount--;
                list_del(&res->lr_hash);
                list_del(&res->lr_rootlink);
                list_del(&res->lr_childof);

                kmem_cache_free(ldlm_resource_slab, res);
                rc = 1;
        out:
                spin_unlock(&res->lr_lock);
                spin_unlock(&ns->ns_lock);
        }

        return rc; 
}

/* Must be called with resource->lr_lock taken */
void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock)
{
        list_add(&lock->l_res_link, head);
        res->lr_refcount++;
}

/* Must be called with resource->lr_lock taken */
void ldlm_resource_del_lock(struct ldlm_lock *lock)
{
        list_del(&lock->l_res_link);
        lock->l_resource->lr_refcount--;
}

int ldlm_get_resource_handle(struct ldlm_resource *res, struct ldlm_handle *h)
{
        LBUG();
        return 0;
}

void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc)
{
        desc->lr_type = res->lr_type;
        memcpy(desc->lr_name, res->lr_name, sizeof(desc->lr_name));
        memcpy(desc->lr_version, res->lr_version, sizeof(desc->lr_version));
}

void ldlm_resource_dump(struct ldlm_resource *res)
{
        struct list_head *tmp;
        char name[256];

        if (RES_NAME_SIZE != 3)
                LBUG();

        snprintf(name, sizeof(name), "%Lx %Lx %Lx",
                 (unsigned long long)res->lr_name[0],
                 (unsigned long long)res->lr_name[1],
                 (unsigned long long)res->lr_name[2]);

        CDEBUG(D_OTHER, "--- Resource: %p (%s)\n", res, name);
        CDEBUG(D_OTHER, "Namespace: %p\n", res->lr_namespace);
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
