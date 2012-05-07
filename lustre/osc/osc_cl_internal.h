/*
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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Internal interfaces of OSC layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#ifndef OSC_CL_INTERNAL_H
#define OSC_CL_INTERNAL_H

#ifdef __KERNEL__
# include <libcfs/libcfs.h>
#else
# include <liblustre.h>
#endif

#include <obd.h>
/* osc_build_res_name() */
#include <obd_ost.h>
#include <cl_object.h>
#include "osc_internal.h"

/** \defgroup osc osc
 *  @{
 */

/**
 * State maintained by osc layer for each IO context.
 */
struct osc_io {
        /** super class */
        struct cl_io_slice oi_cl;
        /** true if this io is lockless. */
        int                oi_lockless;

        struct obdo        oi_oa;
        struct osc_setattr_cbargs {
                int               opc_rc;
                cfs_completion_t  opc_sync;
        } oi_setattr_cbarg;
};

/**
 * State of transfer for osc.
 */
struct osc_req {
        struct cl_req_slice    or_cl;
};

/**
 * State maintained by osc layer for the duration of a system call.
 */
struct osc_session {
        struct osc_io       os_io;
};

struct osc_thread_info {
        struct ldlm_res_id      oti_resname;
        ldlm_policy_data_t      oti_policy;
        struct cl_lock_descr    oti_descr;
        struct cl_attr          oti_attr;
        struct lustre_handle    oti_handle;
        struct cl_page_list     oti_plist;
};

struct osc_object {
        struct cl_object   oo_cl;
        struct lov_oinfo  *oo_oinfo;
        /**
         * True if locking against this stripe got -EUSERS.
         */
        int                oo_contended;
        cfs_time_t         oo_contention_time;
#ifdef INVARIANT_CHECK
        /**
         * IO context used for invariant checks in osc_lock_has_pages().
         */
        struct cl_io       oo_debug_io;
        /** Serialization object for osc_object::oo_debug_io. */
        cfs_mutex_t        oo_debug_mutex;
#endif
        /**
         * List of pages in transfer.
         */
        cfs_list_t         oo_inflight[CRT_NR];
        /**
         * Lock, protecting ccc_object::cob_inflight, because a seat-belt is
         * locked during take-off and landing.
         */
        cfs_spinlock_t     oo_seatbelt;
};

/*
 * Lock "micro-states" for osc layer.
 */
enum osc_lock_state {
        OLS_NEW,
        OLS_ENQUEUED,
        OLS_UPCALL_RECEIVED,
        OLS_GRANTED,
        OLS_RELEASED,
        OLS_BLOCKED,
        OLS_CANCELLED
};

/**
 * osc-private state of cl_lock.
 *
 * Interaction with DLM.
 *
 * CLIO enqueues all DLM locks through ptlrpcd (that is, in "async" mode).
 *
 * Once receive upcall is invoked, osc_lock remembers a handle of DLM lock in
 * osc_lock::ols_handle and a pointer to that lock in osc_lock::ols_lock.
 *
 * This pointer is protected through a reference, acquired by
 * osc_lock_upcall0(). Also, an additional reference is acquired by
 * ldlm_lock_addref() call protecting the lock from cancellation, until
 * osc_lock_unuse() releases it.
 *
 * Below is a description of how lock references are acquired and released
 * inside of DLM.
 *
 * - When new lock is created and enqueued to the server (ldlm_cli_enqueue())
 *      - ldlm_lock_create()
 *          - ldlm_lock_new(): initializes a lock with 2 references. One for
 *            the caller (released when reply from the server is received, or on
 *            error), and another for the hash table.
 *      - ldlm_lock_addref_internal(): protects the lock from cancellation.
 *
 * - When reply is received from the server (osc_enqueue_interpret())
 *      - ldlm_cli_enqueue_fini()
 *          - LDLM_LOCK_PUT(): releases caller reference acquired by
 *            ldlm_lock_new().
 *          - if (rc != 0)
 *                ldlm_lock_decref(): error case: matches ldlm_cli_enqueue().
 *      - ldlm_lock_decref(): for async locks, matches ldlm_cli_enqueue().
 *
 * - When lock is being cancelled (ldlm_lock_cancel())
 *      - ldlm_lock_destroy()
 *          - LDLM_LOCK_PUT(): releases hash-table reference acquired by
 *            ldlm_lock_new().
 *
 * osc_lock is detached from ldlm_lock by osc_lock_detach() that is called
 * either when lock is cancelled (osc_lock_blocking()), or when locks is
 * deleted without cancellation (e.g., from cl_locks_prune()). In the latter
 * case ldlm lock remains in memory, and can be re-attached to osc_lock in the
 * future.
 */
struct osc_lock {
        struct cl_lock_slice     ols_cl;
        /** underlying DLM lock */
        struct ldlm_lock        *ols_lock;
        /** lock value block */
        struct ost_lvb           ols_lvb;
        /** DLM flags with which osc_lock::ols_lock was enqueued */
        int                      ols_flags;
        /** osc_lock::ols_lock handle */
        struct lustre_handle     ols_handle;
        struct ldlm_enqueue_info ols_einfo;
        enum osc_lock_state      ols_state;

        /**
         * How many pages are using this lock for io, currently only used by
         * read-ahead. If non-zero, the underlying dlm lock won't be cancelled
         * during recovery to avoid deadlock. see bz16774.
         *
         * \see osc_page::ops_lock
         * \see osc_page_addref_lock(), osc_page_putref_lock()
         */
        cfs_atomic_t             ols_pageref;

        /**
         * true, if ldlm_lock_addref() was called against
         * osc_lock::ols_lock. This is used for sanity checking.
         *
         * \see osc_lock::ols_has_ref
         */
        unsigned                  ols_hold :1,
        /**
         * this is much like osc_lock::ols_hold, except that this bit is
         * cleared _after_ reference in released in osc_lock_unuse(). This
         * fine distinction is needed because:
         *
         *     - if ldlm lock still has a reference, osc_ast_data_get() needs
         *       to return associated cl_lock (so that a flag is needed that is
         *       cleared after ldlm_lock_decref() returned), and
         *
         *     - ldlm_lock_decref() can invoke blocking ast (for a
         *       LDLM_FL_CBPENDING lock), and osc_lock functions like
         *       osc_lock_cancel() called from there need to know whether to
         *       release lock reference (so that a flag is needed that is
         *       cleared before ldlm_lock_decref() is called).
         */
                                 ols_has_ref:1,
        /**
         * inherit the lockless attribute from top level cl_io.
         * If true, osc_lock_enqueue is able to tolerate the -EUSERS error.
         */
                                 ols_locklessable:1,
        /**
         * set by osc_lock_use() to wait until blocking AST enters into
         * osc_ldlm_blocking_ast0(), so that cl_lock mutex can be used for
         * further synchronization.
         */
                                 ols_ast_wait:1,
        /**
         * If the data of this lock has been flushed to server side.
         */
                                 ols_flush:1,
        /**
         * if set, the osc_lock is a glimpse lock. For glimpse locks, we treat
         * the EVAVAIL error as torerable, this will make upper logic happy
         * to wait all glimpse locks to each OSTs to be completed.
         * Glimpse lock converts to normal lock if the server lock is
         * granted.
         * Glimpse lock should be destroyed immediately after use.
         */
                                 ols_glimpse:1,
        /**
         * For async glimpse lock.
         */
                                 ols_agl:1;
        /**
         * IO that owns this lock. This field is used for a dead-lock
         * avoidance by osc_lock_enqueue_wait().
         *
         * XXX: unfortunately, the owner of a osc_lock is not unique, 
         * the lock may have multiple users, if the lock is granted and
         * then matched.
         */
        struct osc_io           *ols_owner;
};


/**
 * Page state private for osc layer.
 */
struct osc_page {
        struct cl_page_slice  ops_cl;
        /**
         * Page queues used by osc to detect when RPC can be formed.
         */
        struct osc_async_page ops_oap;
        /**
         * An offset within page from which next transfer starts. This is used
         * by cl_page_clip() to submit partial page transfers.
         */
        int                   ops_from;
        /**
         * An offset within page at which next transfer ends.
         *
         * \see osc_page::ops_from.
         */
        int                   ops_to;
        /**
         * Boolean, true iff page is under transfer. Used for sanity checking.
         */
        unsigned              ops_transfer_pinned:1,
        /**
         * True for a `temporary page' created by read-ahead code, probably
         * outside of any DLM lock.
         */
                              ops_temp:1,
        /**
         * Set if the page must be transferred with OBD_BRW_SRVLOCK.
         */
                              ops_srvlock:1;
        /**
         * Linkage into a per-osc_object list of pages in flight. For
         * debugging.
         */
        cfs_list_t            ops_inflight;
        /**
         * Thread that submitted this page for transfer. For debugging.
         */
        cfs_task_t           *ops_submitter;
        /**
         * Submit time - the time when the page is starting RPC. For debugging.
         */
        cfs_time_t            ops_submit_time;

        /**
         * A lock of which we hold a reference covers this page. Only used by
         * read-ahead: for a readahead page, we hold it's covering lock to
         * prevent it from being canceled during recovery.
         *
         * \see osc_lock::ols_pageref
         * \see osc_page_addref_lock(), osc_page_putref_lock().
         */
        struct cl_lock       *ops_lock;
};

extern cfs_mem_cache_t *osc_page_kmem;
extern cfs_mem_cache_t *osc_lock_kmem;
extern cfs_mem_cache_t *osc_object_kmem;
extern cfs_mem_cache_t *osc_thread_kmem;
extern cfs_mem_cache_t *osc_session_kmem;
extern cfs_mem_cache_t *osc_req_kmem;

extern struct lu_device_type osc_device_type;
extern struct lu_context_key osc_key;
extern struct lu_context_key osc_session_key;

#define OSC_FLAGS (ASYNC_URGENT|ASYNC_READY)

int osc_lock_init(const struct lu_env *env,
                  struct cl_object *obj, struct cl_lock *lock,
                  const struct cl_io *io);
int osc_io_init  (const struct lu_env *env,
                  struct cl_object *obj, struct cl_io *io);
int osc_req_init (const struct lu_env *env, struct cl_device *dev,
                  struct cl_req *req);
struct lu_object *osc_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *dev);
struct cl_page   *osc_page_init   (const struct lu_env *env,
                                   struct cl_object *obj,
                                   struct cl_page *page, cfs_page_t *vmpage);

void osc_lock_build_res(const struct lu_env *env, const struct osc_object *obj,
                        struct ldlm_res_id *resname);
void osc_index2policy  (ldlm_policy_data_t *policy, const struct cl_object *obj,
                        pgoff_t start, pgoff_t end);
int  osc_lvb_print     (const struct lu_env *env, void *cookie,
                        lu_printer_t p, const struct ost_lvb *lvb);
void osc_io_submit_page(const struct lu_env *env,
                        struct osc_io *oio, struct osc_page *opg,
                        enum cl_req_type crt);

void osc_object_set_contended  (struct osc_object *obj);
void osc_object_clear_contended(struct osc_object *obj);
int  osc_object_is_contended   (struct osc_object *obj);

int  osc_lock_is_lockless      (const struct osc_lock *olck);

/*****************************************************************************
 *
 * Accessors.
 *
 */

static inline struct osc_thread_info *osc_env_info(const struct lu_env *env)
{
        struct osc_thread_info *info;

        info = lu_context_key_get(&env->le_ctx, &osc_key);
        LASSERT(info != NULL);
        return info;
}

static inline struct osc_session *osc_env_session(const struct lu_env *env)
{
        struct osc_session *ses;

        ses = lu_context_key_get(env->le_ses, &osc_session_key);
        LASSERT(ses != NULL);
        return ses;
}

static inline struct osc_io *osc_env_io(const struct lu_env *env)
{
        return &osc_env_session(env)->os_io;
}

static inline int osc_is_object(const struct lu_object *obj)
{
        return obj->lo_dev->ld_type == &osc_device_type;
}

static inline struct osc_device *lu2osc_dev(const struct lu_device *d)
{
        LINVRNT(d->ld_type == &osc_device_type);
        return container_of0(d, struct osc_device, od_cl.cd_lu_dev);
}

static inline struct obd_export *osc_export(const struct osc_object *obj)
{
        return lu2osc_dev(obj->oo_cl.co_lu.lo_dev)->od_exp;
}

static inline struct osc_object *cl2osc(const struct cl_object *obj)
{
        LINVRNT(osc_is_object(&obj->co_lu));
        return container_of0(obj, struct osc_object, oo_cl);
}

static inline ldlm_mode_t osc_cl_lock2ldlm(enum cl_lock_mode mode)
{
        LASSERT(mode == CLM_READ || mode == CLM_WRITE || mode == CLM_GROUP);
        if (mode == CLM_READ)
                return LCK_PR;
        else if (mode == CLM_WRITE)
                return LCK_PW;
        else
                return LCK_GROUP;
}

static inline enum cl_lock_mode osc_ldlm2cl_lock(ldlm_mode_t mode)
{
        LASSERT(mode == LCK_PR || mode == LCK_PW || mode == LCK_GROUP);
        if (mode == LCK_PR)
                return CLM_READ;
        else if (mode == LCK_PW)
                return CLM_WRITE;
        else
                return CLM_GROUP;
}

static inline struct osc_page *cl2osc_page(const struct cl_page_slice *slice)
{
        LINVRNT(osc_is_object(&slice->cpl_obj->co_lu));
        return container_of0(slice, struct osc_page, ops_cl);
}

static inline struct osc_lock *cl2osc_lock(const struct cl_lock_slice *slice)
{
        LINVRNT(osc_is_object(&slice->cls_obj->co_lu));
        return container_of0(slice, struct osc_lock, ols_cl);
}

static inline struct osc_lock *osc_lock_at(const struct cl_lock *lock)
{
        return cl2osc_lock(cl_lock_at(lock, &osc_device_type));
}

static inline int osc_io_srvlock(struct osc_io *oio)
{
        return (oio->oi_lockless && !oio->oi_cl.cis_io->ci_no_srvlock);
}

/** @} osc */

#endif /* OSC_CL_INTERNAL_H */
