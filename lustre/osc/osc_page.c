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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011 Whamcloud, Inc.
 *
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Implementation of cl_page for OSC layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#define DEBUG_SUBSYSTEM S_OSC

#include "osc_cl_internal.h"

/** \addtogroup osc 
 *  @{ 
 */

/* 
 * Comment out osc_page_protected because it may sleep inside the
 * the client_obd_list_lock.
 * client_obd_list_lock -> osc_ap_completion -> osc_completion ->
 *   -> osc_page_protected -> osc_page_is_dlocked -> osc_match_base
 *   -> ldlm_lock_match -> sptlrpc_import_check_ctx -> sleep.
 */
#if 0
static int osc_page_is_dlocked(const struct lu_env *env,
                               const struct osc_page *opg,
                               enum cl_lock_mode mode, int pending, int unref)
{
        struct cl_page         *page;
        struct osc_object      *obj;
        struct osc_thread_info *info;
        struct ldlm_res_id     *resname;
        struct lustre_handle   *lockh;
        ldlm_policy_data_t     *policy;
        ldlm_mode_t             dlmmode;
        int                     flags;

        cfs_might_sleep();

        info = osc_env_info(env);
        resname = &info->oti_resname;
        policy = &info->oti_policy;
        lockh = &info->oti_handle;
        page = opg->ops_cl.cpl_page;
        obj = cl2osc(opg->ops_cl.cpl_obj);

        flags = LDLM_FL_TEST_LOCK | LDLM_FL_BLOCK_GRANTED;
        if (pending)
                flags |= LDLM_FL_CBPENDING;

        dlmmode = osc_cl_lock2ldlm(mode) | LCK_PW;
        osc_lock_build_res(env, obj, resname);
        osc_index2policy(policy, page->cp_obj, page->cp_index, page->cp_index);
        return osc_match_base(osc_export(obj), resname, LDLM_EXTENT, policy,
                              dlmmode, &flags, NULL, lockh, unref);
}

/**
 * Checks an invariant that a page in the cache is covered by a lock, as
 * needed.
 */
static int osc_page_protected(const struct lu_env *env,
                              const struct osc_page *opg,
                              enum cl_lock_mode mode, int unref)
{
        struct cl_object_header *hdr;
        struct cl_lock          *scan;
        struct cl_page          *page;
        struct cl_lock_descr    *descr;
        int result;

        LINVRNT(!opg->ops_temp);

        page = opg->ops_cl.cpl_page;
        if (page->cp_owner != NULL &&
            cl_io_top(page->cp_owner)->ci_lockreq == CILR_NEVER)
                /*
                 * If IO is done without locks (liblustre, or lloop), lock is
                 * not required.
                 */
                result = 1;
        else
                /* otherwise check for a DLM lock */
        result = osc_page_is_dlocked(env, opg, mode, 1, unref);
        if (result == 0) {
                /* maybe this page is a part of a lockless io? */
                hdr = cl_object_header(opg->ops_cl.cpl_obj);
                descr = &osc_env_info(env)->oti_descr;
                descr->cld_mode = mode;
                descr->cld_start = page->cp_index;
                descr->cld_end   = page->cp_index;
                cfs_spin_lock(&hdr->coh_lock_guard);
                cfs_list_for_each_entry(scan, &hdr->coh_locks, cll_linkage) {
                        /*
                         * Lock-less sub-lock has to be either in HELD state
                         * (when io is actively going on), or in CACHED state,
                         * when top-lock is being unlocked:
                         * cl_io_unlock()->cl_unuse()->...->lov_lock_unuse().
                         */
                        if ((scan->cll_state == CLS_HELD ||
                             scan->cll_state == CLS_CACHED) &&
                            cl_lock_ext_match(&scan->cll_descr, descr)) {
                                struct osc_lock *olck;

                                olck = osc_lock_at(scan);
                                result = osc_lock_is_lockless(olck);
                                break;
                        }
                }
                cfs_spin_unlock(&hdr->coh_lock_guard);
        }
        return result;
}
#else
static int osc_page_protected(const struct lu_env *env,
                              const struct osc_page *opg,
                              enum cl_lock_mode mode, int unref)
{
        return 1;
}
#endif

/*****************************************************************************
 *
 * Page operations.
 *
 */
static void osc_page_fini(const struct lu_env *env,
                          struct cl_page_slice *slice)
{
        struct osc_page *opg = cl2osc_page(slice);
        CDEBUG(D_TRACE, "%p\n", opg);
        LASSERT(opg->ops_lock == NULL);
        OBD_SLAB_FREE_PTR(opg, osc_page_kmem);
}

static void osc_page_transfer_get(struct osc_page *opg, const char *label)
{
        struct cl_page *page = cl_page_top(opg->ops_cl.cpl_page);

        LASSERT(!opg->ops_transfer_pinned);
        cl_page_get(page);
        lu_ref_add_atomic(&page->cp_reference, label, page);
        opg->ops_transfer_pinned = 1;
}

static void osc_page_transfer_put(const struct lu_env *env,
                                  struct osc_page *opg)
{
        struct cl_page *page = cl_page_top(opg->ops_cl.cpl_page);

        if (opg->ops_transfer_pinned) {
                lu_ref_del(&page->cp_reference, "transfer", page);
                opg->ops_transfer_pinned = 0;
                cl_page_put(env, page);
        }
}

/**
 * This is called once for every page when it is submitted for a transfer
 * either opportunistic (osc_page_cache_add()), or immediate
 * (osc_page_submit()).
 */
static void osc_page_transfer_add(const struct lu_env *env,
                                  struct osc_page *opg, enum cl_req_type crt)
{
        struct osc_object *obj;

        LINVRNT(cl_page_is_vmlocked(env, opg->ops_cl.cpl_page));

        obj = cl2osc(opg->ops_cl.cpl_obj);
        cfs_spin_lock(&obj->oo_seatbelt);
        cfs_list_add(&opg->ops_inflight, &obj->oo_inflight[crt]);
        opg->ops_submitter = cfs_current();
        cfs_spin_unlock(&obj->oo_seatbelt);
}

static int osc_page_cache_add(const struct lu_env *env,
                              const struct cl_page_slice *slice,
                              struct cl_io *unused)
{
        struct osc_page   *opg = cl2osc_page(slice);
        struct osc_object *obj = cl2osc(opg->ops_cl.cpl_obj);
        int result;
        /* All cacheable IO is async-capable */
        int brw_flags = OBD_BRW_ASYNC;
        int noquota = 0;

        LINVRNT(osc_page_protected(env, opg, CLM_WRITE, 0));
        ENTRY;

        /* Set the OBD_BRW_SRVLOCK before the page is queued. */
        brw_flags |= opg->ops_srvlock ? OBD_BRW_SRVLOCK : 0;
        if (!client_is_remote(osc_export(obj)) &&
            cfs_capable(CFS_CAP_SYS_RESOURCE)) {
                brw_flags |= OBD_BRW_NOQUOTA;
                noquota = OBD_BRW_NOQUOTA;
        }

        osc_page_transfer_get(opg, "transfer\0cache");
        result = osc_queue_async_io(env, osc_export(obj), NULL, obj->oo_oinfo,
                                    &opg->ops_oap, OBD_BRW_WRITE | noquota,
                                    opg->ops_from, opg->ops_to - opg->ops_from,
                                    brw_flags, 0);
        if (result != 0)
                osc_page_transfer_put(env, opg);
        else
                osc_page_transfer_add(env, opg, CRT_WRITE);
        RETURN(result);
}

void osc_index2policy(ldlm_policy_data_t *policy, const struct cl_object *obj,
                      pgoff_t start, pgoff_t end)
{
        memset(policy, 0, sizeof *policy);
        policy->l_extent.start = cl_offset(obj, start);
        policy->l_extent.end   = cl_offset(obj, end + 1) - 1;
}

static int osc_page_addref_lock(const struct lu_env *env,
                                struct osc_page *opg,
                                struct cl_lock *lock)
{
        struct osc_lock *olock;
        int              rc;

        LASSERT(opg->ops_lock == NULL);

        olock = osc_lock_at(lock);
        if (cfs_atomic_inc_return(&olock->ols_pageref) <= 0) {
                cfs_atomic_dec(&olock->ols_pageref);
                cl_lock_put(env, lock);
                rc = 1;
        } else {
                opg->ops_lock = lock;
                rc = 0;
        }
        return rc;
}

static void osc_page_putref_lock(const struct lu_env *env,
                                 struct osc_page *opg)
{
        struct cl_lock  *lock = opg->ops_lock;
        struct osc_lock *olock;

        LASSERT(lock != NULL);
        olock = osc_lock_at(lock);

        cfs_atomic_dec(&olock->ols_pageref);
        opg->ops_lock = NULL;

        /*
         * Note: usually this won't be the last reference of the lock, but if
         * it is, then all the lock_put do is at most just freeing some memory,
         * so it would be OK that caller is holding spinlocks.
         */
        LASSERT(cfs_atomic_read(&lock->cll_ref) > 1 || olock->ols_hold == 0);
        cl_lock_put(env, lock);
}

static int osc_page_is_under_lock(const struct lu_env *env,
                                  const struct cl_page_slice *slice,
                                  struct cl_io *unused)
{
        struct cl_lock *lock;
        int             result;

        ENTRY;
        lock = cl_lock_at_page(env, slice->cpl_obj, slice->cpl_page,
                               NULL, 1, 0);
        if (lock != NULL &&
            osc_page_addref_lock(env, cl2osc_page(slice), lock) == 0)
                result = -EBUSY;
        else
                result = -ENODATA;
        RETURN(result);
}

static void osc_page_disown(const struct lu_env *env,
                            const struct cl_page_slice *slice,
                            struct cl_io *io)
{
        struct osc_page *opg = cl2osc_page(slice);

        if (unlikely(opg->ops_lock))
                osc_page_putref_lock(env, opg);
}

static void osc_page_completion_read(const struct lu_env *env,
                                     const struct cl_page_slice *slice,
                                     int ioret)
{
        struct osc_page *opg = cl2osc_page(slice);

        if (likely(opg->ops_lock))
                osc_page_putref_lock(env, opg);
}

static int osc_page_fail(const struct lu_env *env,
                         const struct cl_page_slice *slice,
                         struct cl_io *unused)
{
        /*
         * Cached read?
         */
        LBUG();
        return 0;
}


static const char *osc_list(cfs_list_t *head)
{
        return cfs_list_empty(head) ? "-" : "+";
}

static inline cfs_time_t osc_submit_duration(struct osc_page *opg)
{
        if (opg->ops_submit_time == 0)
                return 0;

        return (cfs_time_current() - opg->ops_submit_time);
}

static int osc_page_print(const struct lu_env *env,
                          const struct cl_page_slice *slice,
                          void *cookie, lu_printer_t printer)
{
        struct osc_page       *opg = cl2osc_page(slice);
        struct osc_async_page *oap = &opg->ops_oap;
        struct osc_object     *obj = cl2osc(slice->cpl_obj);
        struct client_obd     *cli = &osc_export(obj)->exp_obd->u.cli;
        struct lov_oinfo      *loi = obj->oo_oinfo;

        return (*printer)(env, cookie, LUSTRE_OSC_NAME"-page@%p: "
                          "1< %#x %d %u %s %s %s > "
                          "2< "LPU64" %u %u %#x %#x | %p %p %p %p %p > "
                          "3< %s %p %d %lu %d > "
                          "4< %d %d %d %lu %s | %s %s %s %s > "
                          "5< %s %s %s %s | %d %s %s | %d %s %s>\n",
                          opg,
                          /* 1 */
                          oap->oap_magic, oap->oap_cmd,
                          oap->oap_interrupted,
                          osc_list(&oap->oap_pending_item),
                          osc_list(&oap->oap_urgent_item),
                          osc_list(&oap->oap_rpc_item),
                          /* 2 */
                          oap->oap_obj_off, oap->oap_page_off, oap->oap_count,
                          oap->oap_async_flags, oap->oap_brw_flags,
                          oap->oap_request,
                          oap->oap_cli, oap->oap_loi, oap->oap_caller_ops,
                          oap->oap_caller_data,
                          /* 3 */
                          osc_list(&opg->ops_inflight),
                          opg->ops_submitter, opg->ops_transfer_pinned,
                          osc_submit_duration(opg), opg->ops_srvlock,
                          /* 4 */
                          cli->cl_r_in_flight, cli->cl_w_in_flight,
                          cli->cl_max_rpcs_in_flight,
                          cli->cl_avail_grant,
                          osc_list(&cli->cl_cache_waiters),
                          osc_list(&cli->cl_loi_ready_list),
                          osc_list(&cli->cl_loi_hp_ready_list),
                          osc_list(&cli->cl_loi_write_list),
                          osc_list(&cli->cl_loi_read_list),
                          /* 5 */
                          osc_list(&loi->loi_ready_item),
                          osc_list(&loi->loi_hp_ready_item),
                          osc_list(&loi->loi_write_item),
                          osc_list(&loi->loi_read_item),
                          loi->loi_read_lop.lop_num_pending,
                          osc_list(&loi->loi_read_lop.lop_pending),
                          osc_list(&loi->loi_read_lop.lop_urgent),
                          loi->loi_write_lop.lop_num_pending,
                          osc_list(&loi->loi_write_lop.lop_pending),
                          osc_list(&loi->loi_write_lop.lop_urgent));
}

static void osc_page_delete(const struct lu_env *env,
                            const struct cl_page_slice *slice)
{
        struct osc_page       *opg = cl2osc_page(slice);
        struct osc_object     *obj = cl2osc(opg->ops_cl.cpl_obj);
        struct osc_async_page *oap = &opg->ops_oap;
        int rc;

        LINVRNT(opg->ops_temp || osc_page_protected(env, opg, CLM_READ, 1));

        ENTRY;
        CDEBUG(D_TRACE, "%p\n", opg);
        osc_page_transfer_put(env, opg);
        rc = osc_teardown_async_page(osc_export(obj), NULL, obj->oo_oinfo, oap);
        if (rc) {
                CL_PAGE_DEBUG(D_ERROR, env, cl_page_top(slice->cpl_page),
                              "Trying to teardown failed: %d\n", rc);
                LASSERT(0);
        }
        cfs_spin_lock(&obj->oo_seatbelt);
        cfs_list_del_init(&opg->ops_inflight);
        cfs_spin_unlock(&obj->oo_seatbelt);
        EXIT;
}

void osc_page_clip(const struct lu_env *env, const struct cl_page_slice *slice,
                   int from, int to)
{
        struct osc_page       *opg = cl2osc_page(slice);
        struct osc_async_page *oap = &opg->ops_oap;

        LINVRNT(osc_page_protected(env, opg, CLM_READ, 0));

        opg->ops_from = from;
        opg->ops_to   = to;
        cfs_spin_lock(&oap->oap_lock);
        oap->oap_async_flags |= ASYNC_COUNT_STABLE;
        cfs_spin_unlock(&oap->oap_lock);
}

static int osc_page_cancel(const struct lu_env *env,
                           const struct cl_page_slice *slice)
{
        struct osc_page *opg       = cl2osc_page(slice);
        struct osc_async_page *oap = &opg->ops_oap;
        int rc = 0;

        LINVRNT(osc_page_protected(env, opg, CLM_READ, 0));

        client_obd_list_lock(&oap->oap_cli->cl_loi_list_lock);
        /* Check if the transferring against this page
         * is completed, or not even queued. */
        if (opg->ops_transfer_pinned)
                /* FIXME: may not be interrupted.. */
                rc = osc_oap_interrupted(env, oap);
        LASSERT(ergo(rc == 0, opg->ops_transfer_pinned == 0));
        client_obd_list_unlock(&oap->oap_cli->cl_loi_list_lock);
        return rc;
}

static const struct cl_page_operations osc_page_ops = {
        .cpo_fini          = osc_page_fini,
        .cpo_print         = osc_page_print,
        .cpo_delete        = osc_page_delete,
        .cpo_is_under_lock = osc_page_is_under_lock,
        .cpo_disown        = osc_page_disown,
        .io = {
                [CRT_READ] = {
                        .cpo_cache_add  = osc_page_fail,
                        .cpo_completion = osc_page_completion_read
                },
                [CRT_WRITE] = {
                        .cpo_cache_add  = osc_page_cache_add
                }
        },
        .cpo_clip           = osc_page_clip,
        .cpo_cancel         = osc_page_cancel
};

static int osc_make_ready(const struct lu_env *env, void *data, int cmd)
{
        struct osc_page *opg  = data;
        struct cl_page  *page = cl_page_top(opg->ops_cl.cpl_page);
        int result;

        LASSERT(cmd == OBD_BRW_WRITE); /* no cached reads */
        LINVRNT(osc_page_protected(env, opg, CLM_WRITE, 1));

        ENTRY;
        result = cl_page_make_ready(env, page, CRT_WRITE);
        if (result == 0)
                opg->ops_submit_time = cfs_time_current();
        RETURN(result);
}

static int osc_refresh_count(const struct lu_env *env, void *data, int cmd)
{
        struct cl_page   *page;
        struct osc_page  *osc = data;
        struct cl_object *obj;
        struct cl_attr   *attr = &osc_env_info(env)->oti_attr;

        int result;
        loff_t kms;

        LINVRNT(osc_page_protected(env, osc, CLM_READ, 1));

        /* readpage queues with _COUNT_STABLE, shouldn't get here. */
        LASSERT(!(cmd & OBD_BRW_READ));
        LASSERT(osc != NULL);
        page = osc->ops_cl.cpl_page;
        obj = osc->ops_cl.cpl_obj;

        cl_object_attr_lock(obj);
        result = cl_object_attr_get(env, obj, attr);
        cl_object_attr_unlock(obj);
        if (result < 0)
                return result;
        kms = attr->cat_kms;
        if (cl_offset(obj, page->cp_index) >= kms)
                /* catch race with truncate */
                return 0;
        else if (cl_offset(obj, page->cp_index + 1) > kms)
                /* catch sub-page write at end of file */
                return kms % CFS_PAGE_SIZE;
        else
                return CFS_PAGE_SIZE;
}

static int osc_completion(const struct lu_env *env,
                          void *data, int cmd, struct obdo *oa, int rc)
{
        struct osc_page       *opg  = data;
        struct osc_async_page *oap  = &opg->ops_oap;
        struct cl_page        *page = cl_page_top(opg->ops_cl.cpl_page);
        struct osc_object     *obj  = cl2osc(opg->ops_cl.cpl_obj);
        enum cl_req_type crt;

        LINVRNT(osc_page_protected(env, opg, CLM_READ, 1));
        LINVRNT(cl_page_is_vmlocked(env, page));

        ENTRY;

        cmd &= ~OBD_BRW_NOQUOTA;
        LASSERT(equi(page->cp_state == CPS_PAGEIN,  cmd == OBD_BRW_READ));
        LASSERT(equi(page->cp_state == CPS_PAGEOUT, cmd == OBD_BRW_WRITE));
        LASSERT(opg->ops_transfer_pinned);

        /*
         * page->cp_req can be NULL if io submission failed before
         * cl_req was allocated.
         */
        if (page->cp_req != NULL)
                cl_req_page_done(env, page);
        LASSERT(page->cp_req == NULL);

        /* As the transfer for this page is being done, clear the flags */
        cfs_spin_lock(&oap->oap_lock);
        oap->oap_async_flags = 0;
        cfs_spin_unlock(&oap->oap_lock);

        crt = cmd == OBD_BRW_READ ? CRT_READ : CRT_WRITE;
        /* Clear opg->ops_transfer_pinned before VM lock is released. */
        opg->ops_transfer_pinned = 0;

        cfs_spin_lock(&obj->oo_seatbelt);
        LASSERT(opg->ops_submitter != NULL);
        LASSERT(!cfs_list_empty(&opg->ops_inflight));
        cfs_list_del_init(&opg->ops_inflight);
        cfs_spin_unlock(&obj->oo_seatbelt);

        opg->ops_submit_time = 0;

        cl_page_completion(env, page, crt, rc);

        /* statistic */
        if (rc == 0 && oap->oap_brw_flags & OBD_BRW_SRVLOCK) {
                struct lu_device *ld    = opg->ops_cl.cpl_obj->co_lu.lo_dev;
                struct osc_stats *stats = &lu2osc_dev(ld)->od_stats;
                int bytes = oap->oap_count;

                if (crt == CRT_READ)
                        stats->os_lockless_reads += bytes;
                else
                        stats->os_lockless_writes += bytes;
        }

        /*
         * This has to be the last operation with the page, as locks are
         * released in cl_page_completion() and nothing except for the
         * reference counter protects page from concurrent reclaim.
         */
        lu_ref_del(&page->cp_reference, "transfer", page);
        /*
         * As page->cp_obj is pinned by a reference from page->cp_req, it is
         * safe to call cl_page_put() without risking object destruction in a
         * non-blocking context.
         */
        cl_page_put(env, page);
        RETURN(0);
}

const static struct obd_async_page_ops osc_async_page_ops = {
        .ap_make_ready    = osc_make_ready,
        .ap_refresh_count = osc_refresh_count,
        .ap_completion    = osc_completion
};

struct cl_page *osc_page_init(const struct lu_env *env,
                              struct cl_object *obj,
                              struct cl_page *page, cfs_page_t *vmpage)
{
        struct osc_object *osc = cl2osc(obj);
        struct osc_page   *opg;
        int result;

        OBD_SLAB_ALLOC_PTR_GFP(opg, osc_page_kmem, CFS_ALLOC_IO);
        if (opg != NULL) {
                void *oap = &opg->ops_oap;

                opg->ops_from = 0;
                opg->ops_to   = CFS_PAGE_SIZE;

                result = osc_prep_async_page(osc_export(osc),
                                             NULL, osc->oo_oinfo, vmpage,
                                             cl_offset(obj, page->cp_index),
                                             &osc_async_page_ops,
                                             opg, (void **)&oap, 1, NULL);
                if (result == 0) {
                        struct osc_io *oio = osc_env_io(env);
                        opg->ops_srvlock = osc_io_srvlock(oio);
                        cl_page_slice_add(page, &opg->ops_cl, obj,
                                          &osc_page_ops);
                }
                /*
                 * Cannot assert osc_page_protected() here as read-ahead
                 * creates temporary pages outside of a lock.
                 */
#ifdef INVARIANT_CHECK
                opg->ops_temp = !osc_page_protected(env, opg, CLM_READ, 1);
#endif
                CFS_INIT_LIST_HEAD(&opg->ops_inflight);
        } else
                result = -ENOMEM;
        return ERR_PTR(result);
}

/**
 * Helper function called by osc_io_submit() for every page in an immediate
 * transfer (i.e., transferred synchronously).
 */
void osc_io_submit_page(const struct lu_env *env,
                        struct osc_io *oio, struct osc_page *opg,
                        enum cl_req_type crt)
{
        struct osc_async_page *oap = &opg->ops_oap;
        struct client_obd     *cli = oap->oap_cli;
        int flags = 0;

        LINVRNT(osc_page_protected(env, opg,
                                   crt == CRT_WRITE ? CLM_WRITE : CLM_READ, 1));

        oap->oap_page_off   = opg->ops_from;
        oap->oap_count      = opg->ops_to - opg->ops_from;
        /* Give a hint to OST that requests are coming from kswapd - bug19529 */
        if (cfs_memory_pressure_get())
                oap->oap_brw_flags |= OBD_BRW_MEMALLOC;
        oap->oap_brw_flags |= OBD_BRW_SYNC;
        if (osc_io_srvlock(oio))
                oap->oap_brw_flags |= OBD_BRW_SRVLOCK;

        oap->oap_cmd = crt == CRT_WRITE ? OBD_BRW_WRITE : OBD_BRW_READ;
        if (!client_is_remote(osc_export(cl2osc(opg->ops_cl.cpl_obj))) &&
            cfs_capable(CFS_CAP_SYS_RESOURCE)) {
                oap->oap_brw_flags |= OBD_BRW_NOQUOTA;
                oap->oap_cmd |= OBD_BRW_NOQUOTA;
        }

        if (oap->oap_cmd & OBD_BRW_READ)
                flags = ASYNC_COUNT_STABLE;
        else if (!(oap->oap_brw_page.flag & OBD_BRW_FROM_GRANT))
                osc_enter_cache_try(env, cli, oap->oap_loi, oap, 1);

        cfs_spin_lock(&oap->oap_lock);
        oap->oap_async_flags |= OSC_FLAGS | flags;
        cfs_spin_unlock(&oap->oap_lock);

        osc_oap_to_pending(oap);
        osc_page_transfer_get(opg, "transfer\0imm");
        osc_page_transfer_add(env, opg, crt);
}

/** @} osc */
