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

#define DEBUG_SUBSYSTEM S_LDLM

#include <linux/lustre_dlm.h>

kmem_cache_t *ldlm_resource_slab, *ldlm_lock_slab;

struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 client)
{
        struct ldlm_namespace *ns = NULL;
        struct list_head *bucket;

        OBD_ALLOC(ns, sizeof(*ns));
        if (!ns) {
                LBUG();
                GOTO(out, NULL);
        }

        ns->ns_hash = vmalloc(sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        if (!ns->ns_hash) {
                LBUG();
                GOTO(out, ns);
        }

        OBD_ALLOC(ns->ns_name, strlen(name) + 1);
        if (!ns->ns_name) {
                LBUG();
                GOTO(out, ns);
        }
        strcpy(ns->ns_name, name);

        ptlrpc_init_client(NULL, NULL, LDLM_REQUEST_PORTAL, LDLM_REPLY_PORTAL,
                           &ns->ns_rpc_client);

        INIT_LIST_HEAD(&ns->ns_root_list);
        l_lock_init(&ns->ns_lock);
        ns->ns_refcount = 0;
        ns->ns_client = client;

        for (bucket = ns->ns_hash + RES_HASH_SIZE - 1; bucket >= ns->ns_hash;
             bucket--)
                INIT_LIST_HEAD(bucket);
        RETURN(ns);

 out:
        if (ns && ns->ns_hash)
                vfree(ns->ns_hash);
        if (ns && ns->ns_name)
                OBD_FREE(ns->ns_name, strlen(name) + 1);
        if (ns)
                OBD_FREE(ns, sizeof(*ns));
        return NULL;
}

extern struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);

static void cleanup_resource(struct ldlm_resource *res, struct list_head *q)
{
        struct list_head *tmp, *pos;
        int rc = 0, client = res->lr_namespace->ns_client;
        ENTRY;

        list_for_each_safe(tmp, pos, q) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_get(lock);

                if (client) {
                        struct lustre_handle lockh;
                        ldlm_lock2handle(lock, &lockh);
                        rc = ldlm_cli_cancel(&lockh);
                        if (rc < 0) {
                                CERROR("ldlm_cli_cancel: %d\n", rc);
                                LBUG();
                        }
                } else {
                        CERROR("Freeing a lock still held by a client node.\n");

                        ldlm_resource_unlink_lock(lock);
                        ldlm_lock_destroy(lock);
                }
                ldlm_lock_put(lock);
        }

        return; 
}

int ldlm_namespace_free(struct ldlm_namespace *ns)
{
        struct list_head *tmp, *pos;
        int i;

        if (!ns)
                RETURN(ELDLM_OK);

        l_lock(&ns->ns_lock);

        for (i = 0; i < RES_HASH_SIZE; i++) {
                list_for_each_safe(tmp, pos, &(ns->ns_hash[i])) {
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);

                        cleanup_resource(res, &res->lr_granted);
                        cleanup_resource(res, &res->lr_converting);
                        cleanup_resource(res, &res->lr_waiting);
                        
                        if (!ldlm_resource_put(res)) { 
                                CERROR("Resource refcount nonzero (%d) after "
                                       "lock cleanup; forcing cleanup.\n",
                                       atomic_read(&res->lr_refcount));
                                ldlm_resource_dump(res);
                                atomic_set(&res->lr_refcount, 1);
                                ldlm_resource_put(res);
                        }
                }
        }

        vfree(ns->ns_hash /* , sizeof(struct list_head) * RES_HASH_SIZE */);
        ptlrpc_cleanup_client(&ns->ns_rpc_client);
        OBD_FREE(ns->ns_name, strlen(ns->ns_name) + 1);
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

        atomic_set(&res->lr_refcount, 1);

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
        ENTRY;

        if (type < LDLM_MIN_TYPE || type > LDLM_MAX_TYPE) {
                LBUG();
                RETURN(NULL);
        }

        res = ldlm_resource_new();
        if (!res) {
                LBUG();
                RETURN(NULL);
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

        RETURN(res);
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

        if (ns == NULL || ns->ns_hash == NULL) {
                LBUG();
                RETURN(NULL);
        }

        l_lock(&ns->ns_lock);
        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

        list_for_each(tmp, bucket) {
                struct ldlm_resource *chk;
                chk = list_entry(tmp, struct ldlm_resource, lr_hash);

                if (memcmp(chk->lr_name, name, sizeof(chk->lr_name)) == 0) {
                        res = chk;
                        atomic_inc(&res->lr_refcount);
                        EXIT;
                        break;
                }
        }

        if (res == NULL && create)
                res = ldlm_resource_add(ns, parent, name, type);
        l_unlock(&ns->ns_lock);

        RETURN(res);
}

struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res)
{
        atomic_inc(&res->lr_refcount);
        return res;
}

/* Returns 1 if the resource was freed, 0 if it remains. */
int ldlm_resource_put(struct ldlm_resource *res)
{
        int rc = 0;

        if (atomic_dec_and_test(&res->lr_refcount)) {
                struct ldlm_namespace *ns = res->lr_namespace;
                ENTRY;

                l_lock(&ns->ns_lock);

                if (atomic_read(&res->lr_refcount) != 0) {
                        /* We lost the race. */
                        l_unlock(&ns->ns_lock);
                        goto out;
                }

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
                l_unlock(&ns->ns_lock);
                rc = 1;
        } else {
                ENTRY;
        out:
                if (atomic_read(&res->lr_refcount) < 0)
                        LBUG();
        }

        RETURN(rc);
}

void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock)
{
        l_lock(&res->lr_namespace->ns_lock);

        ldlm_resource_dump(res);
        ldlm_lock_dump(lock);

        if (!list_empty(&lock->l_res_link))
                LBUG();

        list_add(&lock->l_res_link, head);
        l_unlock(&res->lr_namespace->ns_lock);
}

void ldlm_resource_unlink_lock(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        list_del_init(&lock->l_res_link);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
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

        CDEBUG(D_OTHER, "--- Resource: %p (%s) (rc: %d)\n", res, name,
               atomic_read(&res->lr_refcount));
        CDEBUG(D_OTHER, "Namespace: %p (%s)\n", res->lr_namespace,
               res->lr_namespace->ns_name);
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
