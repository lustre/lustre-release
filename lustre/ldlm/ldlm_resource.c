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
#include <linux/obd_class.h>

kmem_cache_t *ldlm_resource_slab, *ldlm_lock_slab;

spinlock_t ldlm_namespace_lock = SPIN_LOCK_UNLOCKED;
struct list_head ldlm_namespace_list = LIST_HEAD_INIT(ldlm_namespace_list);
static struct proc_dir_entry *ldlm_ns_proc_dir = NULL;
extern struct proc_dir_entry proc_root;

int ldlm_proc_setup(struct obd_device *obd)
{
        ENTRY;

        LASSERT(ldlm_ns_proc_dir == NULL);

        ldlm_ns_proc_dir = proc_mkdir("ldlm", &proc_root);
        if (ldlm_ns_proc_dir == NULL) {
                CERROR("Couldn't create /proc/ldlm\n");
                RETURN(-EPERM);
        }
        RETURN(0);
}

void ldlm_proc_cleanup(struct obd_device *obd)
{
        remove_proc_entry("ldlm", &proc_root);
}

/* FIXME: This can go away when we start to really use lprocfs */
static int ldlm_proc_ll_rd(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{
        int len;
        __u64 *temp = (__u64 *)data;

        len = snprintf(page, count, "%Lu\n", *temp);

        return len;
}

struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 client)
{
        struct ldlm_namespace *ns = NULL;
        struct list_head *bucket;
        struct proc_dir_entry *proc_entry;

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
        obd_memory += sizeof(*ns->ns_hash) * RES_HASH_SIZE;

        OBD_ALLOC(ns->ns_name, strlen(name) + 1);
        if (!ns->ns_name) {
                LBUG();
                GOTO(out, ns);
        }
        strcpy(ns->ns_name, name);

        INIT_LIST_HEAD(&ns->ns_root_list);
        l_lock_init(&ns->ns_lock);
        ns->ns_refcount = 0;
        ns->ns_client = client;
        spin_lock_init(&ns->ns_counter_lock);
        ns->ns_locks = 0;
        ns->ns_resources = 0;

        for (bucket = ns->ns_hash + RES_HASH_SIZE - 1; bucket >= ns->ns_hash;
             bucket--)
                INIT_LIST_HEAD(bucket);

        spin_lock(&ldlm_namespace_lock);
        list_add(&ns->ns_list_chain, &ldlm_namespace_list);
        spin_unlock(&ldlm_namespace_lock);

        ns->ns_proc_dir = proc_mkdir(ns->ns_name, ldlm_ns_proc_dir);
        if (ns->ns_proc_dir == NULL)
                CERROR("Unable to create proc directory for namespace.\n");
        proc_entry = create_proc_entry("resource_count", 0444, ns->ns_proc_dir);
        proc_entry->read_proc = ldlm_proc_ll_rd;
        proc_entry->data = &ns->ns_resources;
        proc_entry = create_proc_entry("lock_count", 0444, ns->ns_proc_dir);
        proc_entry->read_proc = ldlm_proc_ll_rd;
        proc_entry->data = &ns->ns_locks;

        RETURN(ns);

 out:
        if (ns && ns->ns_hash) {
                vfree(ns->ns_hash);
                obd_memory -= sizeof(*ns->ns_hash) * RES_HASH_SIZE;
        }
        if (ns && ns->ns_name)
                OBD_FREE(ns->ns_name, strlen(name) + 1);
        if (ns)
                OBD_FREE(ns, sizeof(*ns));
        return NULL;
}

extern struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);

/* If 'local_only' is true, don't try to tell the server, just cleanup. */
static void cleanup_resource(struct ldlm_resource *res, struct list_head *q,
                             int local_only)
{
        struct list_head *tmp, *pos;
        int rc = 0, client = res->lr_namespace->ns_client;
        ENTRY;

        list_for_each_safe(tmp, pos, q) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                LDLM_LOCK_GET(lock);

                /* At shutdown time, don't call the cancellation callback */
                lock->l_flags |= LDLM_FL_CANCEL;

                if (client) {
                        struct lustre_handle lockh;
                        ldlm_lock2handle(lock, &lockh);
                        if (!local_only) {
                                rc = ldlm_cli_cancel(&lockh);
                                if (rc)
                                        CERROR("ldlm_cli_cancel: %d\n", rc);
                        }
                        /* Force local cleanup on errors, too. */
                        if (local_only || rc != ELDLM_OK)
                                ldlm_lock_cancel(lock);
                } else {
                        LDLM_DEBUG(lock, "Freeing a lock still held by a "
                                   "client node.\n");

                        ldlm_resource_unlink_lock(lock);
                        ldlm_lock_destroy(lock);
                }
                LDLM_LOCK_PUT(lock);
        }
}

int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int local_only)
{
        int i;

        l_lock(&ns->ns_lock);
        for (i = 0; i < RES_HASH_SIZE; i++) {
                struct list_head *tmp, *pos;
                list_for_each_safe(tmp, pos, &(ns->ns_hash[i])) {
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);

                        cleanup_resource(res, &res->lr_granted, local_only);
                        cleanup_resource(res, &res->lr_converting, local_only);
                        cleanup_resource(res, &res->lr_waiting, local_only);

                        /* XXX this is a bit counter-intuitive and should
                         * probably be cleaner: don't force cleanup if we're
                         * local_only (which is only used by recovery).  We
                         * probably still have outstanding lock refs which
                         * reference these resources. -phil */
                        if (!ldlm_resource_put(res) && !local_only) {
                                CERROR("Resource refcount nonzero (%d) after "
                                       "lock cleanup; forcing cleanup.\n",
                                       atomic_read(&res->lr_refcount));
                                ldlm_resource_dump(res);
                                atomic_set(&res->lr_refcount, 1);
                                ldlm_resource_put(res);
                        }
                }
        }
        l_unlock(&ns->ns_lock);

        return ELDLM_OK;
}

/* Cleanup, but also free, the namespace */
int ldlm_namespace_free(struct ldlm_namespace *ns)
{
        if (!ns)
                RETURN(ELDLM_OK);

        spin_lock(&ldlm_namespace_lock);
        list_del(&ns->ns_list_chain);
        remove_proc_entry("resource_count", ns->ns_proc_dir);
        remove_proc_entry("lock_count", ns->ns_proc_dir);
        remove_proc_entry(ns->ns_name, ldlm_ns_proc_dir);
        spin_unlock(&ldlm_namespace_lock);

        ldlm_namespace_cleanup(ns, 0);

        vfree(ns->ns_hash /* , sizeof(*ns->ns_hash) * RES_HASH_SIZE */);
        obd_memory -= sizeof(*ns->ns_hash) * RES_HASH_SIZE;
        OBD_FREE(ns->ns_name, strlen(ns->ns_name) + 1);
        OBD_FREE(ns, sizeof(*ns));

        return ELDLM_OK;
}

int ldlm_client_free(struct obd_export *exp)
{
        struct ldlm_export_data *led = &exp->exp_ldlm_data;
        ptlrpc_cleanup_client(&led->led_import);
        RETURN(0);
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

        spin_lock(&ns->ns_counter_lock);
        ns->ns_resources++;
        spin_unlock(&ns->ns_counter_lock);

        memcpy(res->lr_name, name, sizeof(res->lr_name));
        res->lr_namespace = ns;
        ns->ns_refcount++;

        res->lr_type = type;
        res->lr_most_restr = LCK_NL;

        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);
        list_add(&res->lr_hash, bucket);

        if (parent == NULL)
                list_add(&res->lr_childof, &ns->ns_root_list);
        else {
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
                list_del(&res->lr_childof);

                kmem_cache_free(ldlm_resource_slab, res);
                l_unlock(&ns->ns_lock);

                spin_lock(&ns->ns_counter_lock);
                ns->ns_resources--;
                spin_unlock(&ns->ns_counter_lock);

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

void ldlm_dump_all_namespaces(void)
{
        struct list_head *tmp;

        spin_lock(&ldlm_namespace_lock);

        list_for_each(tmp, &ldlm_namespace_list) {
                struct ldlm_namespace *ns;
                ns = list_entry(tmp, struct ldlm_namespace, ns_list_chain);
                ldlm_namespace_dump(ns);
        }

        spin_unlock(&ldlm_namespace_lock);
}

void ldlm_namespace_dump(struct ldlm_namespace *ns)
{
        struct list_head *tmp;

        l_lock(&ns->ns_lock);
        CDEBUG(D_OTHER, "--- Namespace: %s (rc: %d, client: %d)\n", ns->ns_name,
               ns->ns_refcount, ns->ns_client);

        list_for_each(tmp, &ns->ns_root_list) {
                struct ldlm_resource *res;
                res = list_entry(tmp, struct ldlm_resource, lr_childof);

                /* Once we have resources with children, this should really dump
                 * them recursively. */
                ldlm_resource_dump(res);
        }
        l_unlock(&ns->ns_lock);
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
