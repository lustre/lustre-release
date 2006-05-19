/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Peter Braam <braam@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#define DEBUG_SUBSYSTEM S_LDLM
#ifdef __KERNEL__
# include <lustre_dlm.h>
#else
# include <liblustre.h>
#endif

#include <obd_class.h>
#include "ldlm_internal.h"

cfs_mem_cache_t *ldlm_resource_slab, *ldlm_lock_slab;

struct semaphore ldlm_namespace_lock;
struct list_head ldlm_namespace_list = CFS_LIST_HEAD_INIT(ldlm_namespace_list);
cfs_proc_dir_entry_t *ldlm_type_proc_dir = NULL;
cfs_proc_dir_entry_t *ldlm_ns_proc_dir = NULL;
cfs_proc_dir_entry_t *ldlm_svc_proc_dir = NULL;

#ifdef LPROCFS
static int ldlm_proc_dump_ns(struct file *file, const char *buffer,
                             unsigned long count, void *data)
{
        ldlm_dump_all_namespaces(D_DLMTRACE);
        RETURN(count);
}

int ldlm_proc_setup(void)
{
        int rc;
        struct lprocfs_vars list[] = {
                { "dump_namespaces", NULL, ldlm_proc_dump_ns, NULL },
                { NULL }};
        ENTRY;
        LASSERT(ldlm_ns_proc_dir == NULL);

        ldlm_type_proc_dir = lprocfs_register(OBD_LDLM_DEVICENAME,
                                              proc_lustre_root,
                                              NULL, NULL);
        if (IS_ERR(ldlm_type_proc_dir)) {
                CERROR("LProcFS failed in ldlm-init\n");
                rc = PTR_ERR(ldlm_type_proc_dir);
                GOTO(err, rc);
        }

        ldlm_ns_proc_dir = lprocfs_register("namespaces",
                                            ldlm_type_proc_dir,
                                            NULL, NULL);
        if (IS_ERR(ldlm_ns_proc_dir)) {
                CERROR("LProcFS failed in ldlm-init\n");
                rc = PTR_ERR(ldlm_ns_proc_dir);
                GOTO(err_type, rc);
        }

        ldlm_svc_proc_dir = lprocfs_register("services",
                                            ldlm_type_proc_dir,
                                            NULL, NULL);
        if (IS_ERR(ldlm_svc_proc_dir)) {
                CERROR("LProcFS failed in ldlm-init\n");
                rc = PTR_ERR(ldlm_svc_proc_dir);
                GOTO(err_ns, rc);
        }

        rc = lprocfs_add_vars(ldlm_type_proc_dir, list, NULL);

        RETURN(0);

err_ns:
        lprocfs_remove(ldlm_ns_proc_dir);
err_type:
        lprocfs_remove(ldlm_type_proc_dir);
err:
        ldlm_type_proc_dir = NULL;
        ldlm_ns_proc_dir = NULL;
        ldlm_svc_proc_dir = NULL;
        RETURN(rc);
}

void ldlm_proc_cleanup(void)
{
        if (ldlm_svc_proc_dir) {
                lprocfs_remove(ldlm_svc_proc_dir);
                ldlm_svc_proc_dir = NULL;
        }

        if (ldlm_ns_proc_dir) {
                lprocfs_remove(ldlm_ns_proc_dir);
                ldlm_ns_proc_dir = NULL;
        }

        if (ldlm_type_proc_dir) {
                lprocfs_remove(ldlm_type_proc_dir);
                ldlm_type_proc_dir = NULL;
        }
}

static int lprocfs_uint_rd(char *page, char **start, off_t off,
                           int count, int *eof, void *data)
{
        unsigned int *temp = (unsigned int *)data;
        return snprintf(page, count, "%u\n", *temp);
}

static int lprocfs_read_lru_size(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct ldlm_namespace *ns = data;
        return lprocfs_uint_rd(page, start, off, count, eof,
                               &ns->ns_max_unused);
}

#define MAX_STRING_SIZE 128
static int lprocfs_write_lru_size(struct file *file, const char *buffer,
                                  unsigned long count, void *data)
{
        struct ldlm_namespace *ns = data;
        char dummy[MAX_STRING_SIZE + 1], *end;
        unsigned long tmp;

        dummy[MAX_STRING_SIZE] = '\0';
        if (copy_from_user(dummy, buffer, MAX_STRING_SIZE))
                return -EFAULT;

        if (count == 6 && memcmp(dummy, "clear", 5) == 0) {
                CDEBUG(D_DLMTRACE,
                       "dropping all unused locks from namespace %s\n",
                       ns->ns_name);
                tmp = ns->ns_max_unused;
                ns->ns_max_unused = 0;
                ldlm_cancel_lru(ns, LDLM_SYNC);
                ns->ns_max_unused = tmp;
                return count;
        }

        tmp = simple_strtoul(dummy, &end, 0);
        if (tmp == 0 && *end) {
                CERROR("invalid value written\n");
                return -EINVAL;
        }

        CDEBUG(D_DLMTRACE, "changing namespace %s max_unused from %u to %u\n",
               ns->ns_name, ns->ns_max_unused, (unsigned int)tmp);
        ns->ns_max_unused = (unsigned int)tmp;

        ldlm_cancel_lru(ns, LDLM_ASYNC);

        return count;
}

void ldlm_proc_namespace(struct ldlm_namespace *ns)
{
        struct lprocfs_vars lock_vars[2];
        char lock_name[MAX_STRING_SIZE + 1];

        LASSERT(ns != NULL);
        LASSERT(ns->ns_name != NULL);

        lock_name[MAX_STRING_SIZE] = '\0';

        memset(lock_vars, 0, sizeof(lock_vars));
        lock_vars[0].name = lock_name;

        snprintf(lock_name, MAX_STRING_SIZE, "%s/resource_count", ns->ns_name);
        lock_vars[0].data = &ns->ns_refcount;
        lock_vars[0].read_fptr = lprocfs_rd_atomic;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_count", ns->ns_name);
        lock_vars[0].data = &ns->ns_locks;
        lock_vars[0].read_fptr = lprocfs_rd_u64;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        if (ns->ns_client) {
                snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_unused_count",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_nr_unused;
                lock_vars[0].read_fptr = lprocfs_uint_rd;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/lru_size",
                         ns->ns_name);
                lock_vars[0].data = ns;
                lock_vars[0].read_fptr = lprocfs_read_lru_size;
                lock_vars[0].write_fptr = lprocfs_write_lru_size;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);
        }
}
#undef MAX_STRING_SIZE
#else
#define ldlm_proc_namespace(ns) do {} while (0)
#endif /* LPROCFS */

struct ldlm_namespace *ldlm_namespace_new(char *name, __u32 client)
{
        struct ldlm_namespace *ns = NULL;
        struct list_head *bucket;
        int rc;
        ENTRY;

        rc = ldlm_get_ref();
        if (rc) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                RETURN(NULL);
        }

        OBD_ALLOC(ns, sizeof(*ns));
        if (!ns)
                GOTO(out_ref, NULL);

        OBD_VMALLOC(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        if (!ns->ns_hash)
                GOTO(out_ns, NULL);

        OBD_ALLOC(ns->ns_name, strlen(name) + 1);
        if (!ns->ns_name)
                GOTO(out_hash, NULL);

        strcpy(ns->ns_name, name);

        CFS_INIT_LIST_HEAD(&ns->ns_root_list);
        l_lock_init(&ns->ns_lock);
        cfs_waitq_init(&ns->ns_refcount_waitq);
        atomic_set(&ns->ns_refcount, 0);
        ns->ns_client = client;
        spin_lock_init(&ns->ns_counter_lock);
        ns->ns_locks = 0;

        for (bucket = ns->ns_hash + RES_HASH_SIZE - 1; bucket >= ns->ns_hash;
             bucket--)
                CFS_INIT_LIST_HEAD(bucket);

        CFS_INIT_LIST_HEAD(&ns->ns_unused_list);
        ns->ns_nr_unused = 0;
        ns->ns_max_unused = LDLM_DEFAULT_LRU_SIZE;

        mutex_down(&ldlm_namespace_lock);
        list_add(&ns->ns_list_chain, &ldlm_namespace_list);
        mutex_up(&ldlm_namespace_lock);
        ldlm_proc_namespace(ns);
        RETURN(ns);

out_hash:
        POISON(ns->ns_hash, 0x5a, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_VFREE(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
out_ns:
        OBD_FREE(ns, sizeof(*ns));
out_ref:
        ldlm_put_ref(0);
        RETURN(NULL);
}

extern struct ldlm_lock *ldlm_lock_get(struct ldlm_lock *lock);

/* If flags contains FL_LOCAL_ONLY, don't try to tell the server, just cleanup.
 * This is currently only used for recovery, and we make certain assumptions
 * as a result--notably, that we shouldn't cancel locks with refs. -phil
 *
 * Called with the ns_lock held. */
static void cleanup_resource(struct ldlm_resource *res, struct list_head *q,
                             int flags)
{
        struct list_head *tmp, *pos;
        int rc = 0, client = res->lr_namespace->ns_client;
        int local_only = (flags & LDLM_FL_LOCAL_ONLY);
        ENTRY;

        list_for_each_safe(tmp, pos, q) {
                struct ldlm_lock *lock;
                lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                LDLM_LOCK_GET(lock);

                /* Set CBPENDING so nothing in the cancellation path
                 * can match this lock */
                lock->l_flags |= LDLM_FL_CBPENDING;
                lock->l_flags |= LDLM_FL_FAILED;
                lock->l_flags |= flags;

                if (local_only && (lock->l_readers || lock->l_writers)) {
                        /* This is a little bit gross, but much better than the
                         * alternative: pretend that we got a blocking AST from
                         * the server, so that when the lock is decref'd, it
                         * will go away ... */
                        /* ... without sending a CANCEL message. */
                        lock->l_flags |= LDLM_FL_LOCAL_ONLY;
                        LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock, 0, NULL);
                        LDLM_LOCK_PUT(lock);
                        continue;
                }

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

int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int flags)
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

                        cleanup_resource(res, &res->lr_granted, flags);
                        cleanup_resource(res, &res->lr_converting, flags);
                        cleanup_resource(res, &res->lr_waiting, flags);

                        if (!ldlm_resource_putref(res)) {
                                CERROR("Namespace %s resource refcount %d "
                                       "after lock cleanup; forcing cleanup.\n",
                                       ns->ns_name,
                                       atomic_read(&res->lr_refcount));
                        }
                }
        }
        l_unlock(&ns->ns_lock);

        return ELDLM_OK;
}

/* Cleanup, but also free, the namespace */
int ldlm_namespace_free(struct ldlm_namespace *ns, int force)
{
        ENTRY;
        if (!ns)
                RETURN(ELDLM_OK);

        mutex_down(&ldlm_namespace_lock);
        list_del(&ns->ns_list_chain);
        mutex_up(&ldlm_namespace_lock);

        /* At shutdown time, don't call the cancellation callback */
        ldlm_namespace_cleanup(ns, 0);

#ifdef LPROCFS
        {
                struct proc_dir_entry *dir;
                dir = lprocfs_srch(ldlm_ns_proc_dir, ns->ns_name);
                if (dir == NULL) {
                        CERROR("dlm namespace %s has no procfs dir?\n",
                               ns->ns_name);
                } else {
                        lprocfs_remove(dir);
                }
        }
#endif

        if (atomic_read(&ns->ns_refcount) > 0) {
                struct l_wait_info lwi = LWI_INTR(NULL, NULL);
                int rc;
                CDEBUG(D_DLMTRACE,
                       "dlm namespace %s free waiting on refcount %d\n",
                       ns->ns_name, atomic_read(&ns->ns_refcount));
                rc = l_wait_event(ns->ns_refcount_waitq,
                                  atomic_read(&ns->ns_refcount) == 0, &lwi);
                if (atomic_read(&ns->ns_refcount)) {
                        LCONSOLE_ERROR("Lock manager: wait for %s namespace "
                                       "cleanup aborted with %d resources in "
                                       "use. (%d)\nI'm going to try to clean "
                                       "up anyway, but I might need a reboot "
                                       "of this node.\n", ns->ns_name,
                                       atomic_read(&ns->ns_refcount), rc);
                }
                CDEBUG(D_DLMTRACE,
                       "dlm namespace %s free done waiting\n", ns->ns_name);
        }

        POISON(ns->ns_hash, 0x5a, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_VFREE(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_FREE(ns->ns_name, strlen(ns->ns_name) + 1);
        OBD_FREE(ns, sizeof(*ns));

        ldlm_put_ref(force);

        return ELDLM_OK;
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

        OBD_SLAB_ALLOC(res, ldlm_resource_slab, CFS_ALLOC_IO, sizeof *res);
        if (res == NULL)
                return NULL;

        memset(res, 0, sizeof(*res));

        CFS_INIT_LIST_HEAD(&res->lr_children);
        CFS_INIT_LIST_HEAD(&res->lr_childof);
        CFS_INIT_LIST_HEAD(&res->lr_granted);
        CFS_INIT_LIST_HEAD(&res->lr_converting);
        CFS_INIT_LIST_HEAD(&res->lr_waiting);
        sema_init(&res->lr_lvb_sem, 1);
        atomic_set(&res->lr_refcount, 1);

        return res;
}

/* Args: locked namespace
 * Returns: newly-allocated, referenced, unlocked resource */
static struct ldlm_resource *
ldlm_resource_add(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, ldlm_type_t type)
{
        struct list_head *bucket;
        struct ldlm_resource *res;
        ENTRY;

        LASSERTF(type >= LDLM_MIN_TYPE && type < LDLM_MAX_TYPE,
                 "type: %d\n", type);

        res = ldlm_resource_new();
        if (!res)
                RETURN(NULL);

        l_lock(&ns->ns_lock);
        res->lr_name = name;
        res->lr_namespace = ns;
        atomic_inc(&ns->ns_refcount);

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
                  struct ldlm_res_id name, ldlm_type_t type, int create)
{
        struct list_head *bucket, *tmp;
        struct ldlm_resource *res = NULL;
        ENTRY;

        LASSERT(ns != NULL);
        LASSERT(ns->ns_hash != NULL);
        LASSERT(name.name[0] != 0);

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

        if (create) {
                res = ldlm_resource_add(ns, parent, name, type);
                if (res == NULL)
                        GOTO(out, NULL);
        } else {
                res = NULL;
        }

        if (create && ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                int rc;

                /* Although this is technically a lock inversion risk (lvb_sem
                 * should be taken before DLM lock), this resource was just
                 * created, so nobody else can take the lvb_sem yet. -p */
                mutex_down(&res->lr_lvb_sem);
                /* Drop the dlm lock, because lvbo_init can touch the disk */
                l_unlock(&ns->ns_lock);
                OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CREATE_RESOURCE, 2);
                rc = ns->ns_lvbo->lvbo_init(res);
                mutex_up(&res->lr_lvb_sem);
                if (rc)
                        CERROR("lvbo_init failed for resource "LPU64"/"LPU64
                               ": rc %d\n", name.name[0], name.name[1], rc);
        } else {
out:
                l_unlock(&ns->ns_lock);
        }

        RETURN(res);
}

struct ldlm_resource *ldlm_resource_getref(struct ldlm_resource *res)
{
        LASSERT(res != NULL);
        LASSERT(res != LP_POISON);
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
        LASSERT(atomic_read(&res->lr_refcount) < LI_POISON);

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
                        ldlm_resource_dump(D_ERROR, res);
                        LBUG();
                }

                if (!list_empty(&res->lr_converting)) {
                        ldlm_resource_dump(D_ERROR, res);
                        LBUG();
                }

                if (!list_empty(&res->lr_waiting)) {
                        ldlm_resource_dump(D_ERROR, res);
                        LBUG();
                }

                if (!list_empty(&res->lr_children)) {
                        ldlm_resource_dump(D_ERROR, res);
                        LBUG();
                }

                list_del_init(&res->lr_hash);
                list_del_init(&res->lr_childof);
                if (res->lr_lvb_data)
                        OBD_FREE(res->lr_lvb_data, res->lr_lvb_len);
                l_unlock(&ns->ns_lock);

                OBD_SLAB_FREE(res, ldlm_resource_slab, sizeof *res);

                if (atomic_dec_and_test(&ns->ns_refcount)) {
                        CDEBUG(D_DLMTRACE, "last ref on ns %s\n", ns->ns_name);
                        cfs_waitq_signal(&ns->ns_refcount_waitq);
                }

                rc = 1;
                EXIT;
        }

        RETURN(rc);
}

void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock)
{
        l_lock(&res->lr_namespace->ns_lock);

        ldlm_resource_dump(D_OTHER, res);
        CDEBUG(D_OTHER, "About to add this lock:\n");
        ldlm_lock_dump(D_OTHER, lock, 0);

        if (lock->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                goto out;
        }

        LASSERT(list_empty(&lock->l_res_link));

        list_add_tail(&lock->l_res_link, head);
 out:
        l_unlock(&res->lr_namespace->ns_lock);
}

void ldlm_resource_insert_lock_after(struct ldlm_lock *original,
                                     struct ldlm_lock *new)
{
        struct ldlm_resource *res = original->l_resource;

        l_lock(&res->lr_namespace->ns_lock);

        ldlm_resource_dump(D_OTHER, res);
        CDEBUG(D_OTHER, "About to insert this lock after %p:\n", original);
        ldlm_lock_dump(D_OTHER, new, 0);

        if (new->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                goto out;
        }

        LASSERT(list_empty(&new->l_res_link));

        list_add(&new->l_res_link, &original->l_res_link);
 out:
        l_unlock(&res->lr_namespace->ns_lock);
}

void ldlm_resource_unlink_lock(struct ldlm_lock *lock)
{
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        list_del_init(&lock->l_res_link);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
}
EXPORT_SYMBOL(ldlm_resource_unlink_lock);

void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc)
{
        desc->lr_type = res->lr_type;
        desc->lr_name = res->lr_name;
}

void ldlm_dump_all_namespaces(int level)
{
        struct list_head *tmp;

        mutex_down(&ldlm_namespace_lock);

        list_for_each(tmp, &ldlm_namespace_list) {
                struct ldlm_namespace *ns;
                ns = list_entry(tmp, struct ldlm_namespace, ns_list_chain);
                ldlm_namespace_dump(level, ns);
        }

        mutex_up(&ldlm_namespace_lock);
}

void ldlm_namespace_dump(int level, struct ldlm_namespace *ns)
{
        struct list_head *tmp;

        CDEBUG_EX(level, "--- Namespace: %s (rc: %d, client: %d)\n", ns->ns_name,
               atomic_read(&ns->ns_refcount), ns->ns_client);

        l_lock(&ns->ns_lock);
        if (cfs_time_after(cfs_time_current(), ns->ns_next_dump)) {
                list_for_each(tmp, &ns->ns_root_list) {
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_childof);

                        /* Once we have resources with children, this should
                         * really dump them recursively. */
                        ldlm_resource_dump(level, res);
                }
                ns->ns_next_dump = cfs_time_shift(10);
        }
        l_unlock(&ns->ns_lock);
}

void ldlm_resource_dump(int level, struct ldlm_resource *res)
{
        struct list_head *tmp;
        int pos;

        if (RES_NAME_SIZE != 4)
                LBUG();

        CDEBUG_EX(level, "--- Resource: %p ("LPU64"/"LPU64"/"LPU64"/"LPU64
               ") (rc: %d)\n", res, res->lr_name.name[0], res->lr_name.name[1],
               res->lr_name.name[2], res->lr_name.name[3],
               atomic_read(&res->lr_refcount));

        if (!list_empty(&res->lr_granted)) {
                pos = 0;
                CDEBUG_EX(level, "Granted locks:\n");
                list_for_each(tmp, &res->lr_granted) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
        if (!list_empty(&res->lr_converting)) {
                pos = 0;
                CDEBUG_EX(level, "Converting locks:\n");
                list_for_each(tmp, &res->lr_converting) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
        if (!list_empty(&res->lr_waiting)) {
                pos = 0;
                CDEBUG_EX(level, "Waiting locks:\n");
                list_for_each(tmp, &res->lr_waiting) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
}
