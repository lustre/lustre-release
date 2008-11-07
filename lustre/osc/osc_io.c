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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Implementation of cl_io for OSC layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

/** \addtogroup osc osc @{ */

#define DEBUG_SUBSYSTEM S_OSC

#include "osc_cl_internal.h"

/*****************************************************************************
 *
 * Type conversions.
 *
 */

static struct osc_req *cl2osc_req(const struct cl_req_slice *slice)
{
        LINVRNT(slice->crs_dev->cd_lu_dev.ld_type == &osc_device_type);
        return container_of0(slice, struct osc_req, or_cl);
}

static struct osc_io *cl2osc_io(const struct lu_env *env,
                                const struct cl_io_slice *slice)
{
        struct osc_io *oio = container_of0(slice, struct osc_io, oi_cl);
        LINVRNT(oio == osc_env_io(env));
        return oio;
}

static struct osc_page *osc_cl_page_osc(struct cl_page *page)
{
        const struct cl_page_slice *slice;

        slice = cl_page_at(page, &osc_device_type);
        LASSERT(slice != NULL);

        return cl2osc_page(slice);
}


/*****************************************************************************
 *
 * io operations.
 *
 */

static void osc_io_fini(const struct lu_env *env, const struct cl_io_slice *io)
{
}

struct cl_page *osc_oap2cl_page(struct osc_async_page *oap)
{
        return container_of(oap, struct osc_page, ops_oap)->ops_cl.cpl_page;
}

static void osc_io_unplug(const struct lu_env *env, struct osc_object *osc,
                          struct client_obd *cli)
{
        loi_list_maint(cli, osc->oo_oinfo);
        osc_check_rpcs(env, cli);
        client_obd_list_unlock(&cli->cl_loi_list_lock);
}

/**
 * How many pages osc_io_submit() queues before checking whether an RPC is
 * ready.
 */
#define OSC_QUEUE_GRAIN (32)

/**
 * An implementation of cl_io_operations::cio_io_submit() method for osc
 * layer. Iterates over pages in the in-queue, prepares each for io by calling
 * cl_page_prep() and then either submits them through osc_io_submit_page()
 * or, if page is already submitted, changes osc flags through
 * osc_set_async_flags_base().
 */
static int osc_io_submit(const struct lu_env *env,
                         const struct cl_io_slice *ios,
                         enum cl_req_type crt, struct cl_2queue *queue)
{
        struct cl_page    *page;
        struct cl_page    *tmp;
        struct osc_object *osc0 = NULL;
        struct client_obd *cli  = NULL;
        struct osc_object *osc  = NULL; /* to keep gcc happy */
        struct osc_page   *opg;
        struct cl_io      *io;

        struct cl_page_list *qin      = &queue->c2_qin;
        struct cl_page_list *qout     = &queue->c2_qout;
        int queued = 0;
        int result = 0;

        LASSERT(qin->pl_nr > 0);

        CDEBUG(D_INFO, "%i %i\n", qin->pl_nr, crt);
        /*
         * NOTE: here @page is a top-level page. This is done to avoid
         *       creation of sub-page-list.
         */
        cl_page_list_for_each_safe(page, tmp, qin) {
                struct osc_async_page *oap;
                struct obd_export     *exp;

                /* Top level IO. */
                io = page->cp_owner;
                LASSERT(io != NULL);

                opg = osc_cl_page_osc(page);
                oap = &opg->ops_oap;
                osc = cl2osc(opg->ops_cl.cpl_obj);
                exp = osc_export(osc);

                /*
                 * This can be checked without cli->cl_loi_list_lock, because
                 * ->oap_*_item are always manipulated when the page is owned.
                 */
                if (!list_empty(&oap->oap_urgent_item) ||
                    !list_empty(&oap->oap_rpc_item)) {
                        result = -EBUSY;
                        break;
                }

                if (osc0 == NULL) { /* first iteration */
                        cli = &exp->exp_obd->u.cli;
                        osc0 = osc;
                } else /* check that all pages are against the same object
                        * (for now) */
                        LASSERT(osc == osc0);
                if (queued++ == 0)
                        client_obd_list_lock(&cli->cl_loi_list_lock);
                result = cl_page_prep(env, io, page, crt);
                if (result == 0) {
                        cl_page_list_move(qout, qin, page);
                        if (list_empty(&oap->oap_pending_item)) {
                                osc_io_submit_page(env, cl2osc_io(env, ios),
                                                   opg, crt);
                        } else {
                                result = osc_set_async_flags_base(cli,
                                                                  osc->oo_oinfo,
                                                                  oap,
                                                                  OSC_FLAGS);
                                if (result != 0)
                                        break;
                        }
                } else {
                        LASSERT(result < 0);
                        if (result != -EALREADY)
                                break;
                        /*
                         * Handle -EALREADY error: for read case, the page is
                         * already in UPTODATE state; for write, the page
                         * is not dirty.
                         */
                        result = 0;
                }
                /*
                 * Don't keep client_obd_list_lock() for too long.
                 *
                 * XXX lock_need_resched() should be used here, but it is not
                 * available in the older of supported kernels.
                 */
                if (queued > OSC_QUEUE_GRAIN || cfs_need_resched()) {
                        queued = 0;
                        osc_io_unplug(env, osc, cli);
                        cfs_cond_resched();
                }
        }

        LASSERT(ergo(result == 0, cli != NULL));
        LASSERT(ergo(result == 0, osc == osc0));

        if (queued > 0)
                osc_io_unplug(env, osc, cli);
        CDEBUG(D_INFO, "%i/%i %i\n", qin->pl_nr, qout->pl_nr, result);
        return qout->pl_nr > 0 ? 0 : result;
}

static void osc_page_touch_at(const struct lu_env *env,
                              struct cl_object *obj, pgoff_t idx, unsigned to)
{
        struct lov_oinfo  *loi  = cl2osc(obj)->oo_oinfo;
        struct cl_attr    *attr = &osc_env_info(env)->oti_attr;
        int valid;
        __u64 kms;

        /* offset within stripe */
        kms = cl_offset(obj, idx) + to;

        cl_object_attr_lock(obj);
        /*
         * XXX old code used
         *
         *         ll_inode_size_lock(inode, 0); lov_stripe_lock(lsm);
         *
         * here
         */
        CDEBUG(D_INODE, "stripe KMS %sincreasing "LPU64"->"LPU64" "LPU64"\n",
               kms > loi->loi_kms ? "" : "not ", loi->loi_kms, kms,
               loi->loi_lvb.lvb_size);

        valid = 0;
        if (kms > loi->loi_kms) {
                attr->cat_kms = kms;
                valid |= CAT_KMS;
        }
        if (kms > loi->loi_lvb.lvb_size) {
                attr->cat_size = kms;
                valid |= CAT_SIZE;
        }
        cl_object_attr_set(env, obj, attr, valid);
        cl_object_attr_unlock(obj);
}

/**
 * This is called when a page is accessed within file in a way that creates
 * new page, if one were missing (i.e., if there were a hole at that place in
 * the file, or accessed page is beyond the current file size). Examples:
 * ->commit_write() and ->nopage() methods.
 *
 * Expand stripe KMS if necessary.
 */
static void osc_page_touch(const struct lu_env *env,
                           struct osc_page *opage, unsigned to)
{
        struct cl_page    *page = opage->ops_cl.cpl_page;
        struct cl_object  *obj  = opage->ops_cl.cpl_obj;

        osc_page_touch_at(env, obj, page->cp_index, to);
}

/**
 * Implements cl_io_operations::cio_prepare_write() method for osc layer.
 *
 * \retval -EIO transfer initiated against this osc will most likely fail
 * \retval 0    transfer initiated against this osc will most likely succeed.
 *
 * The reason for this check is to immediately return an error to the caller
 * in the case of a deactivated import. Note, that import can be deactivated
 * later, while pages, dirtied by this IO, are still in the cache, but this is
 * irrelevant, because that would still return an error to the application (if
 * it does fsync), but many applications don't do fsync because of performance
 * issues, and we wanted to return an -EIO at write time to notify the
 * application.
 */
static int osc_io_prepare_write(const struct lu_env *env,
                                const struct cl_io_slice *ios,
                                const struct cl_page_slice *slice,
                                unsigned from, unsigned to)
{
        struct osc_device *dev = lu2osc_dev(slice->cpl_obj->co_lu.lo_dev);
        struct obd_import *imp = class_exp2cliimp(dev->od_exp);

        ENTRY;

        /*
         * This implements OBD_BRW_CHECK logic from old client.
         */

        RETURN(imp == NULL || imp->imp_invalid ? -EIO : 0);
}

static int osc_io_commit_write(const struct lu_env *env,
                               const struct cl_io_slice *ios,
                               const struct cl_page_slice *slice,
                               unsigned from, unsigned to)
{
        LASSERT(to > 0);

        ENTRY;
        /*
         * XXX instead of calling osc_page_touch() here and in
         * osc_io_fault_start() it might be more logical to introduce
         * cl_page_touch() method, that generic cl_io_commit_write() and page
         * fault code calls.
         */
        osc_page_touch(env, cl2osc_page(slice), to);
        RETURN(0);
}

static int osc_io_fault_start(const struct lu_env *env,
                              const struct cl_io_slice *ios)
{
        struct cl_io       *io;
        struct cl_fault_io *fio;

        ENTRY;

        io  = ios->cis_io;
        fio = &io->u.ci_fault;
        CDEBUG(D_INFO, "%lu %i %i\n",
               fio->ft_index, fio->ft_writable, fio->ft_nob);
        /*
         * If mapping is writeable, adjust kms to cover this page,
         * but do not extend kms beyond actual file size.
         * See bug 10919.
         */
        if (fio->ft_writable)
                osc_page_touch_at(env, ios->cis_obj,
                                  fio->ft_index, fio->ft_nob);
        RETURN(0);
}

static int osc_punch_upcall(void *a, int rc)
{
        struct osc_punch_cbargs *args = a;

        args->opc_rc = rc;
        complete(&args->opc_sync);
        return 0;
}

#ifdef __KERNEL__
/**
 * Checks that there are no pages being written in the extent being truncated.
 */
static void osc_trunc_check(const struct lu_env *env, struct cl_io *io,
                            struct osc_io *oio, size_t size)
{
        struct osc_page     *cp;
        struct osc_object   *obj;
        struct cl_object    *clob;
        struct cl_page      *page;
        struct cl_page_list *list;
        int                  partial;
        pgoff_t              start;

        clob    = oio->oi_cl.cis_obj;
        obj     = cl2osc(clob);
        start   = cl_index(clob, size);
        partial = cl_offset(clob, start) < size;
        list    = &osc_env_info(env)->oti_plist;

        /*
         * Complain if there are pages in the truncated region.
         *
         * XXX this is quite expensive check.
         */
        cl_page_list_init(list);
        cl_page_gang_lookup(env, clob, io, start + partial, CL_PAGE_EOF, list);

        cl_page_list_for_each(page, list)
                CL_PAGE_DEBUG(D_ERROR, env, page, "exists %lu\n", start);

        cl_page_list_disown(env, io, list);
        cl_page_list_fini(env, list);

        spin_lock(&obj->oo_seatbelt);
        list_for_each_entry(cp, &obj->oo_inflight[CRT_WRITE], ops_inflight) {
                page = cp->ops_cl.cpl_page;
                if (page->cp_index >= start + partial) {
                        cfs_task_t *submitter;

                        submitter = cp->ops_submitter;
                        /*
                         * XXX Linux specific debugging stuff.
                         */
                        CL_PAGE_DEBUG(D_ERROR, env, page, "%s/%i %lu\n",
                                      submitter->comm, submitter->pid, start);
                        libcfs_debug_dumpstack(submitter);
                }
        }
        spin_unlock(&obj->oo_seatbelt);
}
#else /* __KERNEL__ */
# define osc_trunc_check(env, io, oio, size) do {;} while (0)
#endif

static int osc_io_trunc_start(const struct lu_env *env,
                              const struct cl_io_slice *slice)
{
        struct cl_io            *io     = slice->cis_io;
        struct osc_io           *oio    = cl2osc_io(env, slice);
        struct cl_object        *obj    = slice->cis_obj;
        struct lov_oinfo        *loi    = cl2osc(obj)->oo_oinfo;
        struct cl_attr          *attr   = &osc_env_info(env)->oti_attr;
        struct obdo             *oa     = &oio->oi_oa;
        struct osc_punch_cbargs *cbargs = &oio->oi_punch_cbarg;
        struct obd_capa         *capa;
        loff_t                   size   = io->u.ci_truncate.tr_size;
        int                      result;

        memset(oa, 0, sizeof(*oa));

        osc_trunc_check(env, io, oio, size);

        cl_object_attr_lock(obj);
        result = cl_object_attr_get(env, obj, attr);
        if (result == 0) {
                attr->cat_size = attr->cat_kms = size;
                result = cl_object_attr_set(env, obj, attr, CAT_SIZE|CAT_KMS);
        }
        cl_object_attr_unlock(obj);

        if (result == 0) {
                oa->o_id = loi->loi_id;
                oa->o_gr = loi->loi_gr;
                oa->o_mtime = attr->cat_mtime;
                oa->o_atime = attr->cat_atime;
                oa->o_ctime = attr->cat_ctime;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLATIME |
                        OBD_MD_FLCTIME | OBD_MD_FLMTIME;
                if (oio->oi_lockless) {
                        oa->o_flags = OBD_FL_TRUNCLOCK;
                        oa->o_valid |= OBD_MD_FLFLAGS;
                }
                oa->o_size = size;
                oa->o_blocks = OBD_OBJECT_EOF;
                oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

                capa = io->u.ci_truncate.tr_capa;
                init_completion(&cbargs->opc_sync);
                result = osc_punch_base(osc_export(cl2osc(obj)), oa, capa,
                                        osc_punch_upcall, cbargs, PTLRPCD_SET);
        }
        return result;
}

static void osc_io_trunc_end(const struct lu_env *env,
                             const struct cl_io_slice *slice)
{
        struct cl_io            *io     = slice->cis_io;
        struct osc_io           *oio    = cl2osc_io(env, slice);
        struct osc_punch_cbargs *cbargs = &oio->oi_punch_cbarg;
        struct obdo             *oa     = &oio->oi_oa;
        int result;

        wait_for_completion(&cbargs->opc_sync);

        result = io->ci_result = cbargs->opc_rc;
        if (result == 0) {
                struct cl_object *obj = slice->cis_obj;
                if (oio->oi_lockless == 0) {
                        struct cl_attr *attr = &osc_env_info(env)->oti_attr;
                        int valid = 0;

                        /* Update kms & size */
                        if (oa->o_valid & OBD_MD_FLSIZE) {
                                attr->cat_size = oa->o_size;
                                attr->cat_kms  = oa->o_size;
                                valid |= CAT_KMS|CAT_SIZE;
                        }
                        if (oa->o_valid & OBD_MD_FLBLOCKS) {
                                attr->cat_blocks = oa->o_blocks;
                                valid |= CAT_BLOCKS;
                        }
                        if (oa->o_valid & OBD_MD_FLMTIME) {
                                attr->cat_mtime = oa->o_mtime;
                                valid |= CAT_MTIME;
                        }
                        if (oa->o_valid & OBD_MD_FLCTIME) {
                                attr->cat_ctime = oa->o_ctime;
                                valid |= CAT_CTIME;
                        }
                        if (oa->o_valid & OBD_MD_FLATIME) {
                                attr->cat_atime = oa->o_atime;
                                valid |= CAT_ATIME;
                        }
                        cl_object_attr_lock(obj);
                        result = cl_object_attr_set(env, obj, attr, valid);
                        cl_object_attr_unlock(obj);
                } else {  /* lockless truncate */
                        struct osc_device *osd = lu2osc_dev(obj->co_lu.lo_dev);
                        /* XXX: Need a lock. */
                        osd->od_stats.os_lockless_truncates++;
                }
        }

        /* return result; */
}

static const struct cl_io_operations osc_io_ops = {
        .op = {
                [CIT_READ] = {
                        .cio_fini   = osc_io_fini
                },
                [CIT_WRITE] = {
                        .cio_fini   = osc_io_fini
                },
                [CIT_TRUNC] = {
                        .cio_start  = osc_io_trunc_start,
                        .cio_end    = osc_io_trunc_end
                },
                [CIT_FAULT] = {
                        .cio_fini   = osc_io_fini,
                        .cio_start  = osc_io_fault_start
                },
                [CIT_MISC] = {
                        .cio_fini   = osc_io_fini
                }
        },
        .req_op = {
                 [CRT_READ] = {
                         .cio_submit    = osc_io_submit
                 },
                 [CRT_WRITE] = {
                         .cio_submit    = osc_io_submit
                 }
         },
        .cio_prepare_write = osc_io_prepare_write,
        .cio_commit_write  = osc_io_commit_write
};

/*****************************************************************************
 *
 * Transfer operations.
 *
 */

static int osc_req_prep(const struct lu_env *env,
                        const struct cl_req_slice *slice)
{
        return 0;
}

static void osc_req_completion(const struct lu_env *env,
                               const struct cl_req_slice *slice, int ioret)
{
        struct osc_req *or;

        or = cl2osc_req(slice);
        OBD_SLAB_FREE_PTR(or, osc_req_kmem);
}

/**
 * Implementation of struct cl_req_operations::cro_attr_set() for osc
 * layer. osc is responsible for struct obdo::o_id and struct obdo::o_gr
 * fields.
 */
static void osc_req_attr_set(const struct lu_env *env,
                             const struct cl_req_slice *slice,
                             const struct cl_object *obj,
                             struct cl_req_attr *attr, obd_valid flags)
{
        struct lov_oinfo *oinfo;
        struct cl_req    *clerq;
        struct cl_page   *apage; /* _some_ page in @clerq */
        struct cl_lock   *lock;  /* _some_ lock protecting @apage */
        struct osc_lock  *olck;
        struct osc_page  *opg;
        struct obdo      *oa;

        oa = attr->cra_oa;
        oinfo = cl2osc(obj)->oo_oinfo;
        if (flags & OBD_MD_FLID) {
                oa->o_id = oinfo->loi_id;
                oa->o_valid |= OBD_MD_FLID;
        }
        if (flags & OBD_MD_FLGROUP) {
                oa->o_gr = oinfo->loi_gr;
                oa->o_valid |= OBD_MD_FLGROUP;
        }
        if (flags & OBD_MD_FLHANDLE) {
                clerq = slice->crs_req;
                LASSERT(!list_empty(&clerq->crq_pages));
                apage = container_of(clerq->crq_pages.next,
                                     struct cl_page, cp_flight);
                opg = osc_cl_page_osc(apage);
                apage = opg->ops_cl.cpl_page; /* now apage is a sub-page */
                lock = cl_lock_at_page(env, apage->cp_obj, apage, NULL, 1, 1);
                if (lock != NULL) {
                        olck = osc_lock_at(lock);
                        LASSERT(olck != NULL);
                        /* check for lockless io. */
                        if (olck->ols_lock != NULL) {
                                oa->o_handle = olck->ols_lock->l_remote_handle;
                                oa->o_valid |= OBD_MD_FLHANDLE;
                        }
                        cl_lock_put(env, lock);
                } else {
                        /* Should only be possible with liblustre */
                        LASSERT(LIBLUSTRE_CLIENT);
                }
        }
}

static const struct cl_req_operations osc_req_ops = {
        .cro_prep       = osc_req_prep,
        .cro_attr_set   = osc_req_attr_set,
        .cro_completion = osc_req_completion
};


int osc_io_init(const struct lu_env *env,
                struct cl_object *obj, struct cl_io *io)
{
        struct osc_io *oio = osc_env_io(env);

        CL_IO_SLICE_CLEAN(oio, oi_cl);
        cl_io_slice_add(io, &oio->oi_cl, obj, &osc_io_ops);
        return 0;
}

int osc_req_init(const struct lu_env *env, struct cl_device *dev,
                 struct cl_req *req)
{
        struct osc_req *or;
        int result;

        OBD_SLAB_ALLOC_PTR(or, osc_req_kmem);
        if (or != NULL) {
                cl_req_slice_add(req, &or->or_cl, dev, &osc_req_ops);
                result = 0;
        } else
                result = -ENOMEM;
        return result;
}

/** @} osc */
