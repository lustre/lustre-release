/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ldlm/ldlm_resource.c
 *
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Peter Braam <braam@clusterfs.com>
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

atomic_t ldlm_srv_namespace_nr = ATOMIC_INIT(0);
atomic_t ldlm_cli_namespace_nr = ATOMIC_INIT(0);

struct semaphore ldlm_srv_namespace_lock;
struct list_head ldlm_srv_namespace_list =
        CFS_LIST_HEAD_INIT(ldlm_srv_namespace_list);

struct semaphore ldlm_cli_namespace_lock;
struct list_head ldlm_cli_namespace_list =
        CFS_LIST_HEAD_INIT(ldlm_cli_namespace_list);

cfs_proc_dir_entry_t *ldlm_type_proc_dir = NULL;
cfs_proc_dir_entry_t *ldlm_ns_proc_dir = NULL;
cfs_proc_dir_entry_t *ldlm_svc_proc_dir = NULL;

extern unsigned int ldlm_cancel_unused_locks_before_replay;

#ifdef LPROCFS
static int ldlm_proc_dump_ns(struct file *file, const char *buffer,
                             unsigned long count, void *data)
{
        ldlm_dump_all_namespaces(LDLM_NAMESPACE_SERVER, D_DLMTRACE);
        ldlm_dump_all_namespaces(LDLM_NAMESPACE_CLIENT, D_DLMTRACE);
        RETURN(count);
}

int ldlm_proc_setup(void)
{
        int rc;
        struct lprocfs_vars list[] = {
                { "dump_namespaces", NULL, ldlm_proc_dump_ns, NULL },
                { "cancel_unused_locks_before_replay", 
                  lprocfs_rd_uint, lprocfs_wr_uint, 
                  &ldlm_cancel_unused_locks_before_replay, NULL },
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
        lprocfs_remove(&ldlm_ns_proc_dir);
err_type:
        lprocfs_remove(&ldlm_type_proc_dir);
err:
        ldlm_svc_proc_dir = NULL;
        RETURN(rc);
}

void ldlm_proc_cleanup(void)
{
        if (ldlm_svc_proc_dir)
                lprocfs_remove(&ldlm_svc_proc_dir);

        if (ldlm_ns_proc_dir)
                lprocfs_remove(&ldlm_ns_proc_dir);

        if (ldlm_type_proc_dir)
                lprocfs_remove(&ldlm_type_proc_dir);
}

static int lprocfs_rd_lru_size(char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
        struct ldlm_namespace *ns = data;
        __u32 *nr = &ns->ns_max_unused;

        if (ns_connect_lru_resize(ns))
                nr = &ns->ns_nr_unused;
        return lprocfs_rd_uint(page, start, off, count, eof, nr);
}

static int lprocfs_wr_lru_size(struct file *file, const char *buffer,
                               unsigned long count, void *data)
{
        struct ldlm_namespace *ns = data;
        char dummy[MAX_STRING_SIZE + 1] = { '\0' }, *end;
        unsigned long tmp;
        int lru_resize;

        if (count >= sizeof(dummy) || count == 0)
                return -EINVAL;

        if (copy_from_user(dummy, buffer, count))
                return -EFAULT;

        if (strncmp(dummy, "clear", 5) == 0) {
                CDEBUG(D_DLMTRACE,
                       "dropping all unused locks from namespace %s\n",
                       ns->ns_name);
                if (ns_connect_lru_resize(ns)) {
                        int canceled, unused  = ns->ns_nr_unused;

                        /* Try to cancel all @ns_nr_unused locks. */
                        canceled = ldlm_cancel_lru(ns, unused, LDLM_SYNC,
                                                   LDLM_CANCEL_PASSED);
                        if (canceled < unused) {
                                CDEBUG(D_DLMTRACE,
                                       "not all requested locks are canceled, "
                                       "requested: %d, canceled: %d\n", unused,
                                       canceled);
                                return -EINVAL;
                        }
                } else {
                        tmp = ns->ns_max_unused;
                        ns->ns_max_unused = 0;
                        ldlm_cancel_lru(ns, 0, LDLM_SYNC, LDLM_CANCEL_PASSED);
                        ns->ns_max_unused = tmp;
                }
                return count;
        }

        tmp = simple_strtoul(dummy, &end, 0);
        if (dummy == end) {
                CERROR("invalid value written\n");
                return -EINVAL;
        }
        lru_resize = (tmp == 0);

        if (ns_connect_lru_resize(ns)) {
                if (!lru_resize)
                        ns->ns_max_unused = (unsigned int)tmp;

                if (tmp > ns->ns_nr_unused)
                        tmp = ns->ns_nr_unused;
                tmp = ns->ns_nr_unused - tmp;

                CDEBUG(D_DLMTRACE,
                       "changing namespace %s unused locks from %u to %u\n",
                       ns->ns_name, ns->ns_nr_unused, (unsigned int)tmp);
                ldlm_cancel_lru(ns, tmp, LDLM_ASYNC, LDLM_CANCEL_PASSED);

                if (!lru_resize) {
                        CDEBUG(D_DLMTRACE,
                               "disable lru_resize for namespace %s\n",
                               ns->ns_name);
                        ns->ns_connect_flags &= ~OBD_CONNECT_LRU_RESIZE;
                }
        } else {
                CDEBUG(D_DLMTRACE,
                       "changing namespace %s max_unused from %u to %u\n",
                       ns->ns_name, ns->ns_max_unused, (unsigned int)tmp);
                ns->ns_max_unused = (unsigned int)tmp;
                ldlm_cancel_lru(ns, 0, LDLM_ASYNC, LDLM_CANCEL_PASSED);

                /* Make sure that originally lru resize was supported before
                 * turning it on here. */
                if (lru_resize &&
                    (ns->ns_orig_connect_flags & OBD_CONNECT_LRU_RESIZE)) {
                        CDEBUG(D_DLMTRACE,
                               "enable lru_resize for namespace %s\n",
                               ns->ns_name);
                        ns->ns_connect_flags |= OBD_CONNECT_LRU_RESIZE;
                }
        }
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
        lock_vars[0].read_fptr = lprocfs_rd_atomic;
        lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

        if (ns_is_client(ns)) {
                snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_unused_count",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_nr_unused;
                lock_vars[0].read_fptr = lprocfs_rd_uint;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/lru_size",
                         ns->ns_name);
                lock_vars[0].data = ns;
                lock_vars[0].read_fptr = lprocfs_rd_lru_size;
                lock_vars[0].write_fptr = lprocfs_wr_lru_size;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/lru_max_age",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_max_age;
                lock_vars[0].read_fptr = lprocfs_rd_uint;
                lock_vars[0].write_fptr = lprocfs_wr_uint;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);
        } else {
                snprintf(lock_name, MAX_STRING_SIZE, "%s/lock_timeouts",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_timeouts;
                lock_vars[0].read_fptr = lprocfs_rd_uint;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/max_nolock_bytes",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_max_nolock_size;
                lock_vars[0].read_fptr = lprocfs_rd_uint;
                lock_vars[0].write_fptr = lprocfs_wr_uint;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/contention_seconds",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_contention_time;
                lock_vars[0].read_fptr = lprocfs_rd_uint;
                lock_vars[0].write_fptr = lprocfs_wr_uint;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);

                snprintf(lock_name, MAX_STRING_SIZE, "%s/contended_locks",
                         ns->ns_name);
                lock_vars[0].data = &ns->ns_contended_locks;
                lock_vars[0].read_fptr = lprocfs_rd_uint;
                lock_vars[0].write_fptr = lprocfs_wr_uint;
                lprocfs_add_vars(ldlm_ns_proc_dir, lock_vars, 0);
        }
}
#undef MAX_STRING_SIZE
#else
#define ldlm_proc_namespace(ns) do {} while (0)
#endif /* LPROCFS */

struct ldlm_namespace *
ldlm_namespace_new(struct obd_device *obd, char *name,
                   ldlm_side_t client, ldlm_appetite_t apt)
{
        struct ldlm_namespace *ns = NULL;
        struct list_head *bucket;
        int rc, idx, namelen;
        ENTRY;

        rc = ldlm_get_ref();
        if (rc) {
                CERROR("ldlm_get_ref failed: %d\n", rc);
                RETURN(NULL);
        }

        OBD_ALLOC_PTR(ns);
        if (!ns)
                GOTO(out_ref, NULL);

        OBD_VMALLOC(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        if (!ns->ns_hash)
                GOTO(out_ns, NULL);

        namelen = strlen(name);
        OBD_ALLOC(ns->ns_name, namelen + 1);
        if (!ns->ns_name)
                GOTO(out_hash, NULL);

        ns->ns_appetite = apt;

        LASSERT(obd != NULL);
        ns->ns_obd = obd;

        strcpy(ns->ns_name, name);

        CFS_INIT_LIST_HEAD(&ns->ns_root_list);
        CFS_INIT_LIST_HEAD(&ns->ns_list_chain);
        ns->ns_refcount = 0;
        ns->ns_client = client;
        spin_lock_init(&ns->ns_hash_lock);
        atomic_set(&ns->ns_locks, 0);
        ns->ns_resources = 0;
        cfs_waitq_init(&ns->ns_waitq);
        ns->ns_max_nolock_size = NS_DEFAULT_MAX_NOLOCK_BYTES;
        ns->ns_contention_time = NS_DEFAULT_CONTENTION_SECONDS;
        ns->ns_contended_locks = NS_DEFAULT_CONTENDED_LOCKS;

        for (bucket = ns->ns_hash + RES_HASH_SIZE - 1; bucket >= ns->ns_hash;
             bucket--)
                CFS_INIT_LIST_HEAD(bucket);

        CFS_INIT_LIST_HEAD(&ns->ns_unused_list);
        CFS_INIT_LIST_HEAD(&ns->ns_list_chain);
        ns->ns_nr_unused = 0;
        ns->ns_max_unused = LDLM_DEFAULT_LRU_SIZE;
        ns->ns_max_age = LDLM_DEFAULT_MAX_ALIVE;
        ns->ns_timeouts = 0;
        spin_lock_init(&ns->ns_unused_lock);
        ns->ns_orig_connect_flags = 0;
        ns->ns_connect_flags = 0;

        ldlm_proc_namespace(ns);

        idx = atomic_read(ldlm_namespace_nr(client));

        rc = ldlm_pool_init(&ns->ns_pool, ns, idx, client);
        if (rc) {
                CERROR("Can't initialize lock pool, rc %d\n", rc);
                GOTO(out_proc, rc);
        }

        at_init(&ns->ns_at_estimate, ldlm_enqueue_min, 0);
        ldlm_namespace_register(ns, client);
        RETURN(ns);
out_proc:
        ldlm_namespace_cleanup(ns, 0);
        OBD_FREE(ns->ns_name, namelen + 1);
out_hash:
        OBD_VFREE(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
out_ns:
        OBD_FREE_PTR(ns);
out_ref:
        ldlm_put_ref();
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
        struct list_head *tmp;
        int rc = 0, client = ns_is_client(res->lr_namespace);
        int local_only = (flags & LDLM_FL_LOCAL_ONLY);
        ENTRY;

        do {
                struct ldlm_lock *lock = NULL;

                /* first, we look for non-cleaned-yet lock
                 * all cleaned locks are marked by CLEANED flag */
                lock_res(res);
                list_for_each(tmp, q) {
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        if (lock->l_flags & LDLM_FL_CLEANED) {
                                lock = NULL;
                                continue;
                        }
                        LDLM_LOCK_GET(lock);
                        lock->l_flags |= LDLM_FL_CLEANED;
                        break;
                }

                if (lock == NULL) {
                        unlock_res(res);
                        break;
                }

                /* Set CBPENDING so nothing in the cancellation path
                 * can match this lock */
                lock->l_flags |= LDLM_FL_CBPENDING;
                lock->l_flags |= LDLM_FL_FAILED;
                lock->l_flags |= flags;

                /* ... without sending a CANCEL message for local_only. */
                if (local_only)
                        lock->l_flags |= LDLM_FL_LOCAL_ONLY;

                if (local_only && (lock->l_readers || lock->l_writers)) {
                        /* This is a little bit gross, but much better than the
                         * alternative: pretend that we got a blocking AST from
                         * the server, so that when the lock is decref'd, it
                         * will go away ... */
                        unlock_res(res);
                        LDLM_DEBUG(lock, "setting FL_LOCAL_ONLY");
                        if (lock->l_completion_ast)
                                lock->l_completion_ast(lock, 0, NULL);
                        LDLM_LOCK_PUT(lock);
                        continue;
                }

                if (client) {
                        struct lustre_handle lockh;

                        unlock_res(res);
                        ldlm_lock2handle(lock, &lockh);
                        rc = ldlm_cli_cancel(&lockh);
                        if (rc)
                                CERROR("ldlm_cli_cancel: %d\n", rc);
                } else {
                        ldlm_resource_unlink_lock(lock);
                        unlock_res(res);
                        LDLM_DEBUG(lock, "Freeing a lock still held by a "
                                   "client node");
                        ldlm_lock_destroy(lock);
                }
                LDLM_LOCK_PUT(lock);
        } while (1);

        EXIT;
}

int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int flags)
{
        struct list_head *tmp;
        int i;

        if (ns == NULL) {
                CDEBUG(D_INFO, "NULL ns, skipping cleanup\n");
                return ELDLM_OK;
        }

        for (i = 0; i < RES_HASH_SIZE; i++) {
                spin_lock(&ns->ns_hash_lock);
                tmp = ns->ns_hash[i].next;
                while (tmp != &(ns->ns_hash[i])) {
                        struct ldlm_resource *res;
                        res = list_entry(tmp, struct ldlm_resource, lr_hash);
                        ldlm_resource_getref(res);
                        spin_unlock(&ns->ns_hash_lock);

                        cleanup_resource(res, &res->lr_granted, flags);
                        cleanup_resource(res, &res->lr_converting, flags);
                        cleanup_resource(res, &res->lr_waiting, flags);

                        spin_lock(&ns->ns_hash_lock);
                        tmp = tmp->next;

                        /* XXX: former stuff caused issues in case of race
                         * between ldlm_namespace_cleanup() and lockd() when
                         * client gets blocking ast when lock gets distracted by
                         * server. This is 1_4 branch solution, let's see how
                         * will it behave. */
                        if (!ldlm_resource_putref_locked(res)) {
                                CERROR("Namespace %s resource refcount nonzero "
                                       "(%d) after lock cleanup; forcing cleanup.\n",
                                       ns->ns_name, atomic_read(&res->lr_refcount));
                                CERROR("Resource: %p ("LPU64"/"LPU64"/"LPU64"/"
                                       LPU64") (rc: %d)\n", res,
                                       res->lr_name.name[0], res->lr_name.name[1],
                                       res->lr_name.name[2], res->lr_name.name[3],
                                       atomic_read(&res->lr_refcount));
                        }
                }
                spin_unlock(&ns->ns_hash_lock);
        }

        return ELDLM_OK;
}

static int __ldlm_namespace_free(struct ldlm_namespace *ns, int force)
{
        ENTRY;
        /* At shutdown time, don't call the cancellation callback */
        ldlm_namespace_cleanup(ns, force ? LDLM_FL_LOCAL_ONLY : 0);

        if (ns->ns_refcount > 0) {
                struct l_wait_info lwi = LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);
                int rc;
                CDEBUG(D_DLMTRACE,
                       "dlm namespace %s free waiting on refcount %d\n",
                       ns->ns_name, ns->ns_refcount);
force_wait:
                if (force)
                        lwi = LWI_TIMEOUT(obd_timeout * HZ / 4, NULL, NULL);

                rc = l_wait_event(ns->ns_waitq,
                                  ns->ns_refcount == 0, &lwi);

                /* Forced cleanups should be able to reclaim all references,
                 * so it's safe to wait forever... we can't leak locks... */
                if (force && rc == -ETIMEDOUT) {
                        LCONSOLE_ERROR("Forced cleanup waiting for %s "
                                       "namespace with %d resources in use, "
                                       "(rc=%d)\n", ns->ns_name,
                                       ns->ns_refcount, rc);
                        GOTO(force_wait, rc);
                }

                if (ns->ns_refcount) {
                        LCONSOLE_ERROR("Cleanup waiting for %s namespace "
                                       "with %d resources in use, (rc=%d)\n",
                                       ns->ns_name,
                                       ns->ns_refcount, rc);
                        RETURN(ELDLM_NAMESPACE_EXISTS);
                }
                CDEBUG(D_DLMTRACE,
                       "dlm namespace %s free done waiting\n", ns->ns_name);
        }

        RETURN(ELDLM_OK);
}

void ldlm_namespace_free_prior(struct ldlm_namespace *ns,
                               struct obd_import *imp,
                               int force)
{
        int rc;
        ENTRY;
        if (!ns) {
                EXIT;
                return;
        }


        /* Can fail with -EINTR when force == 0 in which case try harder */
        rc = __ldlm_namespace_free(ns, force);
        if (rc != ELDLM_OK) {
                if (imp) {
                        ptlrpc_disconnect_import(imp, 0);
                        ptlrpc_invalidate_import(imp);
                }

                /* With all requests dropped and the import inactive
                 * we are gaurenteed all reference will be dropped. */
                rc = __ldlm_namespace_free(ns, 1);
                LASSERT(rc == 0);
        }
        EXIT;
}

void ldlm_namespace_free_post(struct ldlm_namespace *ns)
{
        ENTRY;
        if (!ns) {
                EXIT;
                return;
        }

        /* Make sure that nobody can find this ns in its list. */
        ldlm_namespace_unregister(ns, ns->ns_client);

        /* Fini pool _before_ parent proc dir is removed. This is important
         * as ldlm_pool_fini() removes own proc dir which is child to @dir.
         * Removing it after @dir may cause oops. */
        ldlm_pool_fini(&ns->ns_pool);

#ifdef LPROCFS
        {
                struct proc_dir_entry *dir;
                dir = lprocfs_srch(ldlm_ns_proc_dir, ns->ns_name);
                if (dir == NULL) {
                        CERROR("dlm namespace %s has no procfs dir?\n",
                               ns->ns_name);
                } else {
                        lprocfs_remove(&dir);
                }
        }
#endif
        OBD_VFREE(ns->ns_hash, sizeof(*ns->ns_hash) * RES_HASH_SIZE);
        OBD_FREE(ns->ns_name, strlen(ns->ns_name) + 1);

        /* @ns should be not on list in this time, otherwise this will cause
         * issues realted to using freed @ns in pools thread. */
        LASSERT(list_empty(&ns->ns_list_chain));
        OBD_FREE_PTR(ns);
        ldlm_put_ref();
        EXIT;
}

/* Cleanup the resource, and free namespace.
 * bug 12864:
 * Deadlock issue:
 * proc1: destroy import
 *        class_disconnect_export(grab cl_sem) ->
 *              -> ldlm_namespace_free ->
 *              -> lprocfs_remove(grab _lprocfs_lock).
 * proc2: read proc info
 *        lprocfs_fops_read(grab _lprocfs_lock) ->
 *              -> osc_rd_active, etc(grab cl_sem).
 *
 * So that I have to split the ldlm_namespace_free into two parts - the first
 * part ldlm_namespace_free_prior is used to cleanup the resource which is
 * being used; the 2nd part ldlm_namespace_free_post is used to unregister the
 * lprocfs entries, and then free memory. It will be called w/o cli->cl_sem
 * held.
 */
void ldlm_namespace_free(struct ldlm_namespace *ns,
                         struct obd_import *imp,
                         int force)
{
        ldlm_namespace_free_prior(ns, imp, force);
        ldlm_namespace_free_post(ns);
}

void ldlm_namespace_get_locked(struct ldlm_namespace *ns)
{
        ns->ns_refcount++;
}

void ldlm_namespace_get(struct ldlm_namespace *ns)
{
        spin_lock(&ns->ns_hash_lock);
        ldlm_namespace_get_locked(ns);
        spin_unlock(&ns->ns_hash_lock);
}

void ldlm_namespace_put_locked(struct ldlm_namespace *ns, int wakeup)
{
        LASSERT(ns->ns_refcount > 0);
        ns->ns_refcount--;
        if (ns->ns_refcount == 0 && wakeup)
                wake_up(&ns->ns_waitq);
}

void ldlm_namespace_put(struct ldlm_namespace *ns, int wakeup)
{
        spin_lock(&ns->ns_hash_lock);
        ldlm_namespace_put_locked(ns, wakeup);
        spin_unlock(&ns->ns_hash_lock);
}

/* Register @ns in the list of namespaces */
void ldlm_namespace_register(struct ldlm_namespace *ns, ldlm_side_t client)
{
        mutex_down(ldlm_namespace_lock(client));
        LASSERT(list_empty(&ns->ns_list_chain));
        list_add(&ns->ns_list_chain, ldlm_namespace_list(client));
        atomic_inc(ldlm_namespace_nr(client));
        mutex_up(ldlm_namespace_lock(client));
}

/* Unregister @ns from the list of namespaces */
void ldlm_namespace_unregister(struct ldlm_namespace *ns, ldlm_side_t client)
{
        mutex_down(ldlm_namespace_lock(client));
        LASSERT(!list_empty(&ns->ns_list_chain));
        /*
         * Some asserts and possibly other parts of code still using
         * list_empty(&ns->ns_list_chain). This is why it is important
         * to use list_del_init() here.
         */
        list_del_init(&ns->ns_list_chain);
        atomic_dec(ldlm_namespace_nr(client));
        mutex_up(ldlm_namespace_lock(client));
}

/* Should be called under ldlm_namespace_lock(client) taken */
void ldlm_namespace_move_locked(struct ldlm_namespace *ns, ldlm_side_t client)
{
        LASSERT(!list_empty(&ns->ns_list_chain));
        LASSERT_SEM_LOCKED(ldlm_namespace_lock(client));
        list_move_tail(&ns->ns_list_chain, ldlm_namespace_list(client));
}

/* Should be called under ldlm_namespace_lock(client) taken */
struct ldlm_namespace *ldlm_namespace_first_locked(ldlm_side_t client)
{
        LASSERT_SEM_LOCKED(ldlm_namespace_lock(client));
        LASSERT(!list_empty(ldlm_namespace_list(client)));
        return container_of(ldlm_namespace_list(client)->next,
                struct ldlm_namespace, ns_list_chain);
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
        int idx;

        OBD_SLAB_ALLOC(res, ldlm_resource_slab, CFS_ALLOC_IO, sizeof *res);
        if (res == NULL)
                return NULL;

        memset(res, 0, sizeof(*res));

        CFS_INIT_LIST_HEAD(&res->lr_children);
        CFS_INIT_LIST_HEAD(&res->lr_childof);
        CFS_INIT_LIST_HEAD(&res->lr_granted);
        CFS_INIT_LIST_HEAD(&res->lr_converting);
        CFS_INIT_LIST_HEAD(&res->lr_waiting);

        /* initialize interval trees for each lock mode*/
        for (idx = 0; idx < LCK_MODE_NUM; idx++) {
                res->lr_itree[idx].lit_size = 0;
                res->lr_itree[idx].lit_mode = 1 << idx;
                res->lr_itree[idx].lit_root = NULL;
        }

        atomic_set(&res->lr_refcount, 1);
        spin_lock_init(&res->lr_lock);

        /* one who creates the resource must unlock
         * the semaphore after lvb initialization */
        init_MUTEX_LOCKED(&res->lr_lvb_sem);

        return res;
}

/* must be called with hash lock held */
static struct ldlm_resource *
ldlm_resource_find(struct ldlm_namespace *ns, struct ldlm_res_id name, __u32 hash)
{
        struct list_head *bucket, *tmp;
        struct ldlm_resource *res;

        LASSERT_SPIN_LOCKED(&ns->ns_hash_lock);
        bucket = ns->ns_hash + hash;

        list_for_each(tmp, bucket) {
                res = list_entry(tmp, struct ldlm_resource, lr_hash);
                if (memcmp(&res->lr_name, &name, sizeof(res->lr_name)) == 0)
                        return res;
        }

        return NULL;
}

/* Args: locked namespace
 * Returns: newly-allocated, referenced, unlocked resource */
static struct ldlm_resource *
ldlm_resource_add(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, __u32 hash, ldlm_type_t type)
{
        struct list_head *bucket;
        struct ldlm_resource *res, *old_res;
        ENTRY;

        LASSERTF(type >= LDLM_MIN_TYPE && type < LDLM_MAX_TYPE,
                 "type: %d\n", type);

        res = ldlm_resource_new();
        if (!res)
                RETURN(NULL);

        res->lr_name = name;
        res->lr_namespace = ns;
        res->lr_type = type;
        res->lr_most_restr = LCK_NL;

        spin_lock(&ns->ns_hash_lock);
        old_res = ldlm_resource_find(ns, name, hash);
        if (old_res) {
                /* someone won the race and added the resource before */
                ldlm_resource_getref(old_res);
                spin_unlock(&ns->ns_hash_lock);
                OBD_SLAB_FREE(res, ldlm_resource_slab, sizeof *res);
                /* synchronize WRT resource creation */
                if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                        down(&old_res->lr_lvb_sem);
                        up(&old_res->lr_lvb_sem);
                }
                RETURN(old_res);
        }

        /* we won! let's add the resource */
        bucket = ns->ns_hash + hash;
        list_add(&res->lr_hash, bucket);
        ns->ns_resources++;
        ldlm_namespace_get_locked(ns);

        if (parent == NULL) {
                list_add(&res->lr_childof, &ns->ns_root_list);
        } else {
                res->lr_parent = parent;
                list_add(&res->lr_childof, &parent->lr_children);
        }
        spin_unlock(&ns->ns_hash_lock);

        if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                int rc;

                OBD_FAIL_TIMEOUT(OBD_FAIL_LDLM_CREATE_RESOURCE, 2);
                rc = ns->ns_lvbo->lvbo_init(res);
                if (rc)
                        CERROR("%s: lvbo_init failed for resource "
                               LPU64": rc %d\n", ns->ns_name,
                               name.name[0], rc);
                /* we create resource with locked lr_lvb_sem */
                up(&res->lr_lvb_sem);
        }

        RETURN(res);
}

/* Args: unlocked namespace
 * Locks: takes and releases ns->ns_lock and res->lr_lock
 * Returns: referenced, unlocked ldlm_resource or NULL */
struct ldlm_resource *
ldlm_resource_get(struct ldlm_namespace *ns, struct ldlm_resource *parent,
                  struct ldlm_res_id name, ldlm_type_t type, int create)
{
        __u32 hash = ldlm_hash_fn(parent, name);
        struct ldlm_resource *res = NULL;
        ENTRY;

        LASSERT(ns != NULL);
        LASSERT(ns->ns_hash != NULL);
        LASSERT(name.name[0] != 0);

        spin_lock(&ns->ns_hash_lock);
        res = ldlm_resource_find(ns, name, hash);
        if (res) {
                ldlm_resource_getref(res);
                spin_unlock(&ns->ns_hash_lock);
                /* synchronize WRT resource creation */
                if (ns->ns_lvbo && ns->ns_lvbo->lvbo_init) {
                        down(&res->lr_lvb_sem);
                        up(&res->lr_lvb_sem);
                }
                RETURN(res);
        }
        spin_unlock(&ns->ns_hash_lock);

        if (create == 0)
                RETURN(NULL);

        res = ldlm_resource_add(ns, parent, name, hash, type);
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

void __ldlm_resource_putref_final(struct ldlm_resource *res)
{
        struct ldlm_namespace *ns = res->lr_namespace;

        LASSERT_SPIN_LOCKED(&ns->ns_hash_lock);

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

        /* Pass 0 as second argument to not wake up ->ns_waitq yet, will do it
         * later. */
        ldlm_namespace_put_locked(ns, 0);
        list_del_init(&res->lr_hash);
        list_del_init(&res->lr_childof);

        ns->ns_resources--;
        if (ns->ns_resources == 0)
                wake_up(&ns->ns_waitq);
}

int ldlm_resource_putref_internal(struct ldlm_resource *res, int locked)
{
        struct ldlm_namespace *ns = res->lr_namespace;
        ENTRY;

        CDEBUG(D_INFO, "putref res: %p count: %d\n", res,
               atomic_read(&res->lr_refcount) - 1);
        LASSERTF(atomic_read(&res->lr_refcount) > 0, "%d",
                 atomic_read(&res->lr_refcount));
        LASSERTF(atomic_read(&res->lr_refcount) < LI_POISON, "%d",
                 atomic_read(&res->lr_refcount));

        if (locked && !atomic_dec_and_test(&res->lr_refcount))
                RETURN(0);
        if (!locked && !atomic_dec_and_lock(&res->lr_refcount,
                                            &ns->ns_hash_lock))
                RETURN(0);

        __ldlm_resource_putref_final(res);

        if (!locked)
                spin_unlock(&ns->ns_hash_lock);

        if (ns->ns_lvbo && ns->ns_lvbo->lvbo_free)
                ns->ns_lvbo->lvbo_free(res);

        LASSERT(res->lr_lvb_inode == NULL);

        OBD_SLAB_FREE(res, ldlm_resource_slab, sizeof *res);

        RETURN(1);
}

int ldlm_resource_putref(struct ldlm_resource *res)
{
        return ldlm_resource_putref_internal(res, 0);
}

int ldlm_resource_putref_locked(struct ldlm_resource *res)
{
        return ldlm_resource_putref_internal(res, 1);
}

void ldlm_resource_add_lock(struct ldlm_resource *res, struct list_head *head,
                            struct ldlm_lock *lock)
{
        check_res_locked(res);

        ldlm_resource_dump(D_INFO, res);
        CDEBUG(D_OTHER, "About to add this lock:\n");
        ldlm_lock_dump(D_OTHER, lock, 0);

        if (lock->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                return;
        }

        LASSERT(list_empty(&lock->l_res_link));

        list_add_tail(&lock->l_res_link, head);
}

void ldlm_resource_insert_lock_after(struct ldlm_lock *original,
                                     struct ldlm_lock *new)
{
        struct ldlm_resource *res = original->l_resource;

        check_res_locked(res);

        ldlm_resource_dump(D_INFO, res);
        CDEBUG(D_OTHER, "About to insert this lock after %p:\n", original);
        ldlm_lock_dump(D_OTHER, new, 0);

        if (new->l_destroyed) {
                CDEBUG(D_OTHER, "Lock destroyed, not adding to resource\n");
                goto out;
        }

        LASSERT(list_empty(&new->l_res_link));

        list_add(&new->l_res_link, &original->l_res_link);
 out:;
}

void ldlm_resource_unlink_lock(struct ldlm_lock *lock)
{
        int type = lock->l_resource->lr_type;

        check_res_locked(lock->l_resource);
        if (type == LDLM_IBITS || type == LDLM_PLAIN)
                ldlm_unlink_lock_skiplist(lock);
        else if (type == LDLM_EXTENT)
                ldlm_extent_unlink_lock(lock);
        list_del_init(&lock->l_res_link);
}

void ldlm_res2desc(struct ldlm_resource *res, struct ldlm_resource_desc *desc)
{
        desc->lr_type = res->lr_type;
        desc->lr_name = res->lr_name;
}

void ldlm_dump_all_namespaces(ldlm_side_t client, int level)
{
        struct list_head *tmp;

        if (!((libcfs_debug | D_ERROR) & level))
                return;

        mutex_down(ldlm_namespace_lock(client));

        list_for_each(tmp, ldlm_namespace_list(client)) {
                struct ldlm_namespace *ns;
                ns = list_entry(tmp, struct ldlm_namespace, ns_list_chain);
                ldlm_namespace_dump(level, ns);
        }

        mutex_up(ldlm_namespace_lock(client));
}

void ldlm_namespace_dump(int level, struct ldlm_namespace *ns)
{
        struct list_head *tmp;

        if (!((libcfs_debug | D_ERROR) & level))
                return;

        CDEBUG(level, "--- Namespace: %s (rc: %d, side: %s)\n",
               ns->ns_name, ns->ns_refcount,
               ns_is_client(ns) ? "client" : "server");

        if (cfs_time_before(cfs_time_current(), ns->ns_next_dump))
                return;

        spin_lock(&ns->ns_hash_lock);
        tmp = ns->ns_root_list.next;
        while (tmp != &ns->ns_root_list) {
                struct ldlm_resource *res;
                res = list_entry(tmp, struct ldlm_resource, lr_childof);

                ldlm_resource_getref(res);
                spin_unlock(&ns->ns_hash_lock);

                lock_res(res);
                ldlm_resource_dump(level, res);
                unlock_res(res);

                spin_lock(&ns->ns_hash_lock);
                tmp = tmp->next;
                ldlm_resource_putref_locked(res);
        }
        ns->ns_next_dump = cfs_time_shift(10);
        spin_unlock(&ns->ns_hash_lock);
}

void ldlm_resource_dump(int level, struct ldlm_resource *res)
{
        struct list_head *tmp;
        int pos;

        CLASSERT(RES_NAME_SIZE == 4);

        if (!((libcfs_debug | D_ERROR) & level))
                return;

        CDEBUG(level, "--- Resource: %p ("LPU64"/"LPU64"/"LPU64"/"LPU64
               ") (rc: %d)\n", res, res->lr_name.name[0], res->lr_name.name[1],
               res->lr_name.name[2], res->lr_name.name[3],
               atomic_read(&res->lr_refcount));

        if (!list_empty(&res->lr_granted)) {
                pos = 0;
                CDEBUG(level, "Granted locks:\n");
                list_for_each(tmp, &res->lr_granted) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
        if (!list_empty(&res->lr_converting)) {
                pos = 0;
                CDEBUG(level, "Converting locks:\n");
                list_for_each(tmp, &res->lr_converting) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
        if (!list_empty(&res->lr_waiting)) {
                pos = 0;
                CDEBUG(level, "Waiting locks:\n");
                list_for_each(tmp, &res->lr_waiting) {
                        struct ldlm_lock *lock;
                        lock = list_entry(tmp, struct ldlm_lock, l_res_link);
                        ldlm_lock_dump(level, lock, ++pos);
                }
        }
}
