/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Peter Braam <braam@clusterfs.com>
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
#include <linux/lustre_dlm.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_class.h>

kmem_cache_t *ldlm_resource_slab, *ldlm_lock_slab;

spinlock_t ldlm_namespace_lock = SPIN_LOCK_UNLOCKED;
struct list_head ldlm_namespace_list = LIST_HEAD_INIT(ldlm_namespace_list);
static struct proc_dir_entry *ldlm_ns_proc_dir = NULL;

int ldlm_proc_setup(struct obd_device *obd)
{
        int rc;
        ENTRY;
        LASSERT(ldlm_ns_proc_dir == NULL);
        LASSERT(obd != NULL);
        rc = lprocfs_obd_attach(obd, 0);
        if (rc) {
                CERROR("LProcFS failed in ldlm-init\n");
                RETURN(rc);
        }
        ldlm_ns_proc_dir = obd->obd_proc_entry;
        RETURN(0);
}

void ldlm_proc_cleanup(struct obd_device *obd)
{
        if (ldlm_ns_proc_dir) {
                lprocfs_obd_detach(obd);
                ldlm_ns_proc_dir = NULL;
        }
}

#ifdef __KERNEL__
static int lprocfs_uint_rd(char *page, char **start, off_t off,
                           int count, int *eof, void *data)
{
        unsigned int *temp = (unsigned int *)data;
        return snprintf(page, count, "%u\n", *temp);
}


#define MAX_STRING_SIZE 128
void ldlm_proc_namespace(struct ldlm_namespace *ns)
{
        struct lprocfs_vars lock_vars[2];
        char lock_name[MAX_STRING_SIZE + 1];

        LASSERT(ns != NULL);
        LASSERT(ns->ns_name != NULL);

        lock_name[MAX_STRING_SIZE] = '\0';

        memset(lock_vars, 0, sizeof(lock_vars));
        lock_vars[0].read_fptr = lprocfs_rd_u64;

        lock_vars[0].name = lock_name;

        snprintf(lock_name, MAX_STRING_SIZE, "%s/resource_count", ns->ns_name);

        lock_vars[0].data = &ns->ns_resources;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_count", ns->ns_name);

        lock_vars[0].data = &ns->ns_locks;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_unused_count",
                 ns->ns_name);
        lock_vars[0].data = &ns->ns_nr_unused;
        lock_vars[0].read_fptr = lprocfs_uint_rd;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);
}
#endif
#undef MAX_STRING_SIZE

#define LDLM_MAX_UNUSED 20
struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 client)
{
        struct ldlm_namespace *ns = NULL;
        struct list_head *bucket;
        ENTRY;

        OBD_ALLOC(ns, sizeof(*ns));
        if (!ns)
                RETURN(NULL);

        ns->ns_hash = vmalloc(sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        if (!ns->ns_hash)
                GOTO(out_ns, NULL);

        atomic_add(sizeof(*ns->ns_hash) * RES_HASH_SIZE, &obd_memory);

        OBD_ALLOC(ns->ns_name, strlen(name) + 1);
        if (!ns->ns_name)
                GOTO(out_hash, NULL);

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

        INIT_LIST_HEAD(&ns->ns_unused_list);
        ns->ns_nr_unused = 0;
        ns->ns_max_unused = LDLM_MAX_UNUSED;

        spin_lock(&ldlm_namespace_lock);
        list_add(&ns->ns_list_chain, &ldlm_namespace_list);
        spin_unlock(&ldlm_namespace_lock);
#ifdef __KERNEL__
        ldlm_proc_namespace(ns);
#endif
        RETURN(ns);

out_hash:
        POISON(ns->ns_hash, 0x5a, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        vfree(ns->ns_hash);
        atomic_sub(sizeof(*ns->ns_hash) * RES_HASH_SIZE, &obd_memory);
out_ns:
        OBD_FREE(ns, sizeof(*ns));
        return NULL;
}

extern struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);

/* If 'local_only' is true, don't try to tell the server, just cleanup.
 * This is currently only used for recovery, and we make certain assumptions
 * as a result--notably, that we shouldn't cancel locks with refs. -phil
 *
 * Called with the ns_lock held. */
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

                if (local_only && (lock->l_readers || lock->l_writers)) {
                        /* This is a little bit gross, but much better than the
                         * alternative: pretend that we got a blocking AST from
                         * the server, so that when the lock is decref'd, it
                         * will go away ... */
                        lock->l_flags |= LDLM_FL_CBPENDING;
                        /* ... without sending a CANCEL message. */
                        lock->l_flags |= LDLM_FL_LOCAL_ONLY;
                        /* ... and without calling the cancellation callback */
                        lock->l_flags |= LDLM_FL_CANCEL;
                        LDLM_LOCK_PUT(lock);
                        continue;
                }

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
                                   "client node");

                        ldlm_resource_unlink_lock(lock);
                        ldlm_lock_destroy(lock);
                }
                LDLM_LOCK_PUT(lock);
        }
        EXIT;
}

int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int local_only)
{
        int i;

        if (ns == NULL) {
                CDEBUG(D_INFO, "NULL ns, skipping cleanup\n");
                return ELDLM_OK;
        }

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

                        /* XXX what a mess: don't force cleanup if we're
                         * local_only (which is only used by recovery).  In that
                         * case, we probably still have outstanding lock refs
                         * which reference these resources. -phil */
                        if (!ldlm_resource_putref(res) && !local_only) {
                                CERROR("Resource refcount nonzero (%d) after "
                                       "lock cleanup; forcing cleanup.\n",
                                       atomic_read(&res->lr_refcount));
                                ldlm_resource_dump(res);
                                atomic_set(&res->lr_refcount, 1);
                                ldlm_resource_putref(res);
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

        spin_unlock(&ldlm_namespace_lock);

        ldlm_namespace_cleanup(ns, 0);

        POISON(ns->ns_hash, 0x5a, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        vfree(ns->ns_hash /* , sizeof(*ns->ns_hash) * RES_HASH_SIZE */);
        atomic_sub(sizeof(*ns->ns_hash) * RES_HASH_SIZE, &obd_memory);
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

static __u32 ldlm_hash_fn(struct ldlm_resource *parent, struct ldlm_res_id name)
{
        __u32 hash = 0;
        int i;

        for (i = 0; i < RES_NAME_SIZE; i++)
                hash += name.name[i];

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
static struct ldlm_resource *
ldlm_resource_add(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, __u32 type)
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

        l_lock(&ns->ns_lock);
        memcpy(&res->lr_name, &name, sizeof(res->lr_name));
        res->lr_namespace = ns;
        ns->ns_refcount++;

        res->lr_type = type;
        res->lr_most_restr = LCK_NL;

        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);
        list_add(&res->lr_hash, bucket);

        if (parent == NULL) {
                list_add(&res->lr_childof, &ns->ns_root_list);
        } else {
                res->lr_parent = parent;
                list_add(&res->lr_childof, &parent->lr_children);
        }
        l_unlock(&ns->ns_lock);

        RETURN(res);
}

/* Args: unlocked namespace
 * Locks: takes and releases ns->ns_lock and res->lr_lock
 * Returns: referenced, unlocked ldlm_resource or NULL */
struct ldlm_resource *
ldlm_resource_get(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, __u32 type, int create)
{
        struct list_head *bucket, *tmp;
        struct ldlm_resource *res = NULL;
        ENTRY;

        LASSERT(ns != NULL);
        LASSERT(ns->ns_hash != NULL);

        l_lock(&ns->ns_lock);
        bucket = ns->ns_hash + ldlm_hash_fn(parent, name);

        list_for_each(tmp, bucket) {
                res = list_entry(tmp, struct ldlm_resource, lr_hash);

                if (memcmp(&res->lr_name, &name, sizeof(res->lr_name)) == 0) {
                        ldlm_resource_getref(res);
                        l_unlock(&ns->ns_lock);
                        RETURN(res);
                }
        }

        if (create)
                res = ldlm_resource_add(ns, parent, name, type);
        else
                res = NULL;

        l_unlock(&ns->ns_lock);

        RETURN(res);
}

struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res)
{
        atomic_inc(&res->lr_refcount);
        CDEBUG(D_INFO, "getref res: %p count: %d\n", res,
               atomic_read(&res->lr_refcount));
        return res;
}

/* Returns 1 if the resource was freed, 0 if it remains. */
int ldlm_resource_putref(struct ldlm_resource *res)
{
        int rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "putref res: %p count: %d\n", res,
               atomic_read(&res->lr_refcount) - 1);
        LASSERT(atomic_read(&res->lr_refcount) > 0);
        LASSERT(atomic_read(&res->lr_refcount) < 0x5a5a5a5a);

        if (atomic_dec_and_test(&res->lr_refcount)) {
                struct ldlm_namespace *ns = res->lr_namespace;
                ENTRY;

                l_lock(&ns->ns_lock);

                if (atomic_read(&res->lr_refcount) != 0) {
                        /* We lost the race. */
                        l_unlock(&ns->ns_lock);
                        RETURN(rc);
                }

                if (!list_empty(&res->lr_granted)) {
                        ldlm_resource_dump(res);
                        LBUG();
                }

                if (!list_empty(&res->lr_converting)) {
                        ldlm_resource_dump(res);
                        LBUG();
                }

                if (!list_empty(&res->lr_waiting)) {
                        ldlm_resource_dump(res);
                        LBUG();
                }

                if (!list_empty(&res->lr_children)) {
                        ldlm_resource_dump(res);
                        LBUG();
                }

                ns->ns_refcount--;
                list_del_init(&res->lr_hash);
                list_del_init(&res->lr_childof);

                POISON(res, 0x5a, sizeof(*res));
                kmem_cache_free(ldlm_resource_slab, res);
                l_unlock(&ns->ns_lock);

                spin_lock(&ns->ns_counter_lock);
                ns->ns_resources--;
                spin_unlock(&ns->ns_counter_lock);

                rc = 1;
                EXIT;
        }

        RETURN(rc);
}

void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock)
{
        l_lock(&res->lr_namespace->ns_lock);

        ldlm_resource_dump(res);
        CDEBUG(D_OTHER, "About to add this lock:\n");
        ldlm_lock_dump(D_OTHER, lock);

        if (lock->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                return;
        }

        LASSERT(list_empty(&lock->l_res_link));

        list_add_tail(&lock->l_res_link, head);
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
        memcpy(&desc->lr_name, &res->lr_name, sizeof(desc->lr_name));
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
                 (unsigned long long)res->lr_name.name[0],
                 (unsigned long long)res->lr_name.name[1],
                 (unsigned long long)res->lr_name.name[2]);

        CDEBUG(D_OTHER, "--- Resource: %p (%s) (rc: %d)\n", res, name,
               atomic_read(&res->lr_refcount));
        CDEBUG(D_OTHER, "Namespace: %p (%s)\n", res->lr_namespace,
               res->lr_namespace->ns_name);
        CDEBUG(D_OTHER, "Parent: %p, root: %p\n", res->lr_parent, res->lr_root);

        CDEBUG(D_OTHER, "Granted locks:\n");
        list_for_each(tmp, &res->lr_granted) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_dump(D_OTHER, lock);
        }

        CDEBUG(D_OTHER, "Converting locks:\n");
        list_for_each(tmp, &res->lr_converting) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_dump(D_OTHER, lock);
        }

        CDEBUG(D_OTHER, "Waiting locks:\n");
        list_for_each(tmp, &res->lr_waiting) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                ldlm_lock_dump(D_OTHER, lock);
        }
}
