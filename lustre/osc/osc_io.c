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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Implementation of cl_io for OSC layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSC

#include <lustre_obdo.h>
#include <lustre_osc.h>

#include "osc_internal.h"

/** \addtogroup osc
 *  @{
 */

/*****************************************************************************
 *
 * io operations.
 *
 */

static void osc_io_fini(const struct lu_env *env, const struct cl_io_slice *io)
{
}

void osc_read_ahead_release(const struct lu_env *env, void *cbdata)
{
	struct ldlm_lock *dlmlock = cbdata;
	struct lustre_handle lockh;

	ldlm_lock2handle(dlmlock, &lockh);
	ldlm_lock_decref(&lockh, LCK_PR);
	LDLM_LOCK_PUT(dlmlock);
}
EXPORT_SYMBOL(osc_read_ahead_release);

static int osc_io_read_ahead(const struct lu_env *env,
			     const struct cl_io_slice *ios,
			     pgoff_t start, struct cl_read_ahead *ra)
{
	struct osc_object	*osc = cl2osc(ios->cis_obj);
	struct ldlm_lock	*dlmlock;
	int			result = -ENODATA;
	ENTRY;

	dlmlock = osc_dlmlock_at_pgoff(env, osc, start, 0);
	if (dlmlock != NULL) {
		LASSERT(dlmlock->l_ast_data == osc);
		if (dlmlock->l_req_mode != LCK_PR) {
			struct lustre_handle lockh;
			ldlm_lock2handle(dlmlock, &lockh);
			ldlm_lock_addref(&lockh, LCK_PR);
			ldlm_lock_decref(&lockh, dlmlock->l_req_mode);
		}

		ra->cra_rpc_size = osc_cli(osc)->cl_max_pages_per_rpc;
		ra->cra_end = cl_index(osc2cl(osc),
				       dlmlock->l_policy_data.l_extent.end);
		ra->cra_release = osc_read_ahead_release;
		ra->cra_cbdata = dlmlock;
		result = 0;
	}

	RETURN(result);
}

/**
 * An implementation of cl_io_operations::cio_io_submit() method for osc
 * layer. Iterates over pages in the in-queue, prepares each for io by calling
 * cl_page_prep() and then either submits them through osc_io_submit_page()
 * or, if page is already submitted, changes osc flags through
 * osc_set_async_flags().
 */
int osc_io_submit(const struct lu_env *env, const struct cl_io_slice *ios,
		  enum cl_req_type crt, struct cl_2queue *queue)
{
	struct cl_page	  *page;
	struct cl_page	  *tmp;
	struct client_obd *cli  = NULL;
	struct osc_object *osc  = NULL;	/* to keep gcc happy */
	struct osc_page	  *opg;
	struct cl_io	  *io;
	struct list_head  list = LIST_HEAD_INIT(list);

	struct cl_page_list *qin      = &queue->c2_qin;
	struct cl_page_list *qout     = &queue->c2_qout;
	unsigned int queued = 0;
	int result = 0;
	int brw_flags;
	unsigned int max_pages;

	LASSERT(qin->pl_nr > 0);

	CDEBUG(D_CACHE|D_READA, "%d %d\n", qin->pl_nr, crt);

	osc = cl2osc(ios->cis_obj);
	cli = osc_cli(osc);
	max_pages = cli->cl_max_pages_per_rpc;

	brw_flags = osc_io_srvlock(cl2osc_io(env, ios)) ? OBD_BRW_SRVLOCK : 0;
	brw_flags |= crt == CRT_WRITE ? OBD_BRW_WRITE : OBD_BRW_READ;
	if (crt == CRT_READ && ios->cis_io->ci_ndelay)
		brw_flags |= OBD_BRW_NDELAY;

	page = cl_page_list_first(qin);
	if (page->cp_type == CPT_TRANSIENT)
		brw_flags |= OBD_BRW_NOCACHE;

        /*
         * NOTE: here @page is a top-level page. This is done to avoid
         *       creation of sub-page-list.
         */
        cl_page_list_for_each_safe(page, tmp, qin) {
                struct osc_async_page *oap;

                /* Top level IO. */
                io = page->cp_owner;
                LASSERT(io != NULL);

		opg = osc_cl_page_osc(page, osc);
		oap = &opg->ops_oap;
		LASSERT(osc == oap->oap_obj);

		if (!list_empty(&oap->oap_pending_item) ||
		    !list_empty(&oap->oap_rpc_item)) {
			CDEBUG(D_CACHE, "Busy oap %p page %p for submit.\n",
			       oap, opg);
                        result = -EBUSY;
                        break;
                }

                result = cl_page_prep(env, io, page, crt);
		if (result != 0) {
                        LASSERT(result < 0);
                        if (result != -EALREADY)
                                break;
                        /*
                         * Handle -EALREADY error: for read case, the page is
                         * already in UPTODATE state; for write, the page
                         * is not dirty.
                         */
                        result = 0;
			continue;
                }

		spin_lock(&oap->oap_lock);
		oap->oap_async_flags = ASYNC_URGENT|ASYNC_READY;
		oap->oap_async_flags |= ASYNC_COUNT_STABLE;
		spin_unlock(&oap->oap_lock);

		osc_page_submit(env, opg, crt, brw_flags);
		list_add_tail(&oap->oap_pending_item, &list);

		if (page->cp_sync_io != NULL)
			cl_page_list_move(qout, qin, page);
		else /* async IO */
			cl_page_list_del(env, qin, page);

		if (++queued == max_pages) {
			queued = 0;
			result = osc_queue_sync_pages(env, io, osc, &list,
						      brw_flags);
			if (result < 0)
				break;
		}
	}

	if (queued > 0)
		result = osc_queue_sync_pages(env, io, osc, &list, brw_flags);

	/* Update c/mtime for sync write. LU-7310 */
	if (crt == CRT_WRITE && qout->pl_nr > 0 && result == 0) {
		struct cl_object *obj   = ios->cis_obj;
		struct cl_attr *attr = &osc_env_info(env)->oti_attr;

		cl_object_attr_lock(obj);
		attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
		cl_object_attr_update(env, obj, attr, CAT_MTIME | CAT_CTIME);
		cl_object_attr_unlock(obj);
	}

	CDEBUG(D_INFO, "%d/%d %d\n", qin->pl_nr, qout->pl_nr, result);
	return qout->pl_nr > 0 ? 0 : result;
}
EXPORT_SYMBOL(osc_io_submit);

/**
 * This is called to update the attributes when modifying a specific page,
 * both when making new pages and when doing updates to existing cached pages.
 *
 * Expand stripe KMS if necessary.
 */
void osc_page_touch_at(const struct lu_env *env, struct cl_object *obj,
		       pgoff_t idx, size_t to)
{
	struct lov_oinfo  *loi  = cl2osc(obj)->oo_oinfo;
	struct cl_attr    *attr = &osc_env_info(env)->oti_attr;
	int valid;
	__u64 kms;

	ENTRY;

	/* offset within stripe */
	kms = cl_offset(obj, idx) + to;

	cl_object_attr_lock(obj);
	CDEBUG(D_INODE, "stripe KMS %sincreasing %llu->%llu %llu\n",
	       kms > loi->loi_kms ? "" : "not ", loi->loi_kms, kms,
	       loi->loi_lvb.lvb_size);

	attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
	valid = CAT_MTIME | CAT_CTIME;
	if (kms > loi->loi_kms) {
		attr->cat_kms = kms;
		valid |= CAT_KMS;
	}
	if (kms > loi->loi_lvb.lvb_size) {
		attr->cat_size = kms;
		valid |= CAT_SIZE;
	}
	cl_object_attr_update(env, obj, attr, valid);
	cl_object_attr_unlock(obj);

	EXIT;
}

int osc_io_commit_async(const struct lu_env *env,
			const struct cl_io_slice *ios,
			struct cl_page_list *qin, int from, int to,
			cl_commit_cbt cb)
{
	struct cl_io    *io = ios->cis_io;
	struct osc_io   *oio = cl2osc_io(env, ios);
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct cl_page  *page;
	struct cl_page  *last_page;
	struct osc_page *opg;
	int result = 0;
	ENTRY;

	LASSERT(qin->pl_nr > 0);

	/* Handle partial page cases */
	last_page = cl_page_list_last(qin);
	if (oio->oi_lockless) {
		page = cl_page_list_first(qin);
		if (page == last_page) {
			cl_page_clip(env, page, from, to);
		} else {
			if (from != 0)
				cl_page_clip(env, page, from, PAGE_SIZE);
			if (to != PAGE_SIZE)
				cl_page_clip(env, last_page, 0, to);
		}
	}

	while (qin->pl_nr > 0) {
		struct osc_async_page *oap;

		page = cl_page_list_first(qin);
		opg = osc_cl_page_osc(page, osc);
		oap = &opg->ops_oap;

		LASSERTF(osc == oap->oap_obj,
			 "obj mismatch: %p / %p\n", osc, oap->oap_obj);

		if (!list_empty(&oap->oap_rpc_item)) {
			CDEBUG(D_CACHE, "Busy oap %p page %p for submit.\n",
			       oap, opg);
			result = -EBUSY;
			break;
		}

		/* The page may be already in dirty cache. */
		if (list_empty(&oap->oap_pending_item)) {
			result = osc_page_cache_add(env, &opg->ops_cl, io);
			if (result != 0)
				break;
		}

		osc_page_touch_at(env, osc2cl(osc), osc_index(opg),
				  page == last_page ? to : PAGE_SIZE);

		cl_page_list_del(env, qin, page);

		(*cb)(env, io, page);
		/* Can't access page any more. Page can be in transfer and
		 * complete at any time. */
	}

	/* for sync write, kernel will wait for this page to be flushed before
	 * osc_io_end() is called, so release it earlier.
	 * for mkwrite(), it's known there is no further pages. */
	if (cl_io_is_sync_write(io) && oio->oi_active != NULL) {
		osc_extent_release(env, oio->oi_active);
		oio->oi_active = NULL;
	}

	CDEBUG(D_INFO, "%d %d\n", qin->pl_nr, result);
	RETURN(result);
}
EXPORT_SYMBOL(osc_io_commit_async);

static bool osc_import_not_healthy(struct obd_import *imp)
{
	return imp->imp_invalid || imp->imp_deactive ||
	       !(imp->imp_state == LUSTRE_IMP_FULL ||
		 imp->imp_state == LUSTRE_IMP_IDLE);
}

int osc_io_iter_init(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct osc_object *osc = cl2osc(ios->cis_obj);
	struct obd_import *imp = osc_cli(osc)->cl_import;
	struct osc_io *oio = osc_env_io(env);
	int rc = -EIO;
	ENTRY;

	spin_lock(&imp->imp_lock);
	/**
	 * check whether this OSC device is available for non-delay read,
	 * fast switching mirror if we haven't tried all mirrors.
	 */
	if (ios->cis_io->ci_type == CIT_READ && ios->cis_io->ci_ndelay &&
	    !ios->cis_io->ci_tried_all_mirrors && osc_import_not_healthy(imp)) {
		rc = -EWOULDBLOCK;
	} else if (likely(!imp->imp_invalid)) {
		atomic_inc(&osc->oo_nr_ios);
		oio->oi_is_active = 1;
		rc = 0;
	}
	spin_unlock(&imp->imp_lock);

	if (cfs_capable(CFS_CAP_SYS_RESOURCE))
		oio->oi_cap_sys_resource = 1;

	RETURN(rc);
}
EXPORT_SYMBOL(osc_io_iter_init);

int osc_io_write_iter_init(const struct lu_env *env,
			   const struct cl_io_slice *ios)
{
	struct cl_io *io = ios->cis_io;
	struct osc_io *oio = osc_env_io(env);
	struct osc_object *osc = cl2osc(ios->cis_obj);
	unsigned long npages;
	ENTRY;

	if (cl_io_is_append(io))
		RETURN(osc_io_iter_init(env, ios));

	npages = io->u.ci_rw.crw_count >> PAGE_SHIFT;
	if (io->u.ci_rw.crw_pos & ~PAGE_MASK)
		++npages;

	oio->oi_lru_reserved = osc_lru_reserve(osc_cli(osc), npages);

	RETURN(osc_io_iter_init(env, ios));
}
EXPORT_SYMBOL(osc_io_write_iter_init);

void osc_io_iter_fini(const struct lu_env *env,
		      const struct cl_io_slice *ios)
{
	struct osc_io *oio = osc_env_io(env);

	if (oio->oi_is_active) {
		struct osc_object *osc = cl2osc(ios->cis_obj);

		oio->oi_is_active = 0;
		LASSERT(atomic_read(&osc->oo_nr_ios) > 0);
		if (atomic_dec_and_test(&osc->oo_nr_ios))
			wake_up_all(&osc->oo_io_waitq);
	}
}
EXPORT_SYMBOL(osc_io_iter_fini);

void osc_io_write_iter_fini(const struct lu_env *env,
			    const struct cl_io_slice *ios)
{
	struct osc_io *oio = osc_env_io(env);
	struct osc_object *osc = cl2osc(ios->cis_obj);

	if (oio->oi_lru_reserved > 0) {
		osc_lru_unreserve(osc_cli(osc), oio->oi_lru_reserved);
		oio->oi_lru_reserved = 0;
	}
	oio->oi_write_osclock = NULL;

	osc_io_iter_fini(env, ios);
}
EXPORT_SYMBOL(osc_io_write_iter_fini);

int osc_io_fault_start(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct cl_io       *io;
	struct cl_fault_io *fio;
	ENTRY;

	io  = ios->cis_io;
	fio = &io->u.ci_fault;
	CDEBUG(D_INFO, "%lu %d %zu\n",
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
EXPORT_SYMBOL(osc_io_fault_start);


static int osc_async_upcall(void *a, int rc)
{
	struct osc_async_cbargs *args = a;

        args->opc_rc = rc;
	complete(&args->opc_sync);
        return 0;
}

/**
 * Checks that there are no pages being written in the extent being truncated.
 */
static int trunc_check_cb(const struct lu_env *env, struct cl_io *io,
			  struct osc_page *ops , void *cbdata)
{
	struct cl_page *page = ops->ops_cl.cpl_page;
	struct osc_async_page *oap;
	__u64 start = *(__u64 *)cbdata;

	oap = &ops->ops_oap;
	if (oap->oap_cmd & OBD_BRW_WRITE &&
	    !list_empty(&oap->oap_pending_item))
		CL_PAGE_DEBUG(D_ERROR, env, page, "exists %llu/%s.\n",
				start, current->comm);

	if (PageLocked(page->cp_vmpage))
		CDEBUG(D_CACHE, "page %p index %lu locked for %d.\n",
		       ops, osc_index(ops), oap->oap_cmd & OBD_BRW_RWMASK);

	return CLP_GANG_OKAY;
}

static void osc_trunc_check(const struct lu_env *env, struct cl_io *io,
			    struct osc_io *oio, __u64 size)
{
	struct cl_object *clob;
	int     partial;
	pgoff_t start;

        clob    = oio->oi_cl.cis_obj;
        start   = cl_index(clob, size);
        partial = cl_offset(clob, start) < size;

        /*
         * Complain if there are pages in the truncated region.
         */
	osc_page_gang_lookup(env, io, cl2osc(clob),
				start + partial, CL_PAGE_EOF,
				trunc_check_cb, (void *)&size);
}

static int osc_io_setattr_start(const struct lu_env *env,
                                const struct cl_io_slice *slice)
{
        struct cl_io            *io     = slice->cis_io;
        struct osc_io           *oio    = cl2osc_io(env, slice);
        struct cl_object        *obj    = slice->cis_obj;
        struct lov_oinfo        *loi    = cl2osc(obj)->oo_oinfo;
        struct cl_attr          *attr   = &osc_env_info(env)->oti_attr;
        struct obdo             *oa     = &oio->oi_oa;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	__u64                    size   = io->u.ci_setattr.sa_attr.lvb_size;
	unsigned int ia_avalid = io->u.ci_setattr.sa_avalid;
	enum op_xvalid ia_xvalid = io->u.ci_setattr.sa_xvalid;
	int result = 0;

	ENTRY;
	/* truncate cache dirty pages first */
	if (cl_io_is_trunc(io))
		result = osc_cache_truncate_start(env, cl2osc(obj), size,
						  &oio->oi_trunc);

	if (result == 0 && oio->oi_lockless == 0) {
		cl_object_attr_lock(obj);
		result = cl_object_attr_get(env, obj, attr);
		if (result == 0) {
			struct ost_lvb *lvb = &io->u.ci_setattr.sa_attr;
			unsigned int cl_valid = 0;

			if (ia_avalid & ATTR_SIZE) {
				attr->cat_size = size;
				attr->cat_kms = size;
				cl_valid = (CAT_SIZE | CAT_KMS);
			}
			if (ia_avalid & ATTR_MTIME_SET) {
				attr->cat_mtime = lvb->lvb_mtime;
				cl_valid |= CAT_MTIME;
			}
			if (ia_avalid & ATTR_ATIME_SET) {
				attr->cat_atime = lvb->lvb_atime;
				cl_valid |= CAT_ATIME;
			}
			if (ia_xvalid & OP_XVALID_CTIME_SET) {
				attr->cat_ctime = lvb->lvb_ctime;
				cl_valid |= CAT_CTIME;
			}
			result = cl_object_attr_update(env, obj, attr,
						       cl_valid);
		}
		cl_object_attr_unlock(obj);
	}
	memset(oa, 0, sizeof(*oa));
	if (result == 0) {
		oa->o_oi = loi->loi_oi;
		obdo_set_parent_fid(oa, io->u.ci_setattr.sa_parent_fid);
		oa->o_stripe_idx = io->u.ci_setattr.sa_stripe_index;
		oa->o_layout = io->u.ci_setattr.sa_layout;
		oa->o_valid |= OBD_MD_FLID | OBD_MD_FLGROUP |
			OBD_MD_FLOSTLAYOUT;
		if (ia_avalid & ATTR_CTIME) {
			oa->o_valid |= OBD_MD_FLCTIME;
			oa->o_ctime = attr->cat_ctime;
		}
		if (ia_avalid & ATTR_ATIME) {
			oa->o_valid |= OBD_MD_FLATIME;
			oa->o_atime = attr->cat_atime;
		}
		if (ia_avalid & ATTR_MTIME) {
			oa->o_valid |= OBD_MD_FLMTIME;
			oa->o_mtime = attr->cat_mtime;
		}
		if (ia_avalid & ATTR_SIZE) {
			oa->o_size = size;
			oa->o_blocks = OBD_OBJECT_EOF;
			oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

			if (oio->oi_lockless) {
				oa->o_flags = OBD_FL_SRVLOCK;
				oa->o_valid |= OBD_MD_FLFLAGS;
			}

			if (io->ci_layout_version > 0) {
				/* verify layout version */
				oa->o_valid |= OBD_MD_LAYOUT_VERSION;
				oa->o_layout_version = io->ci_layout_version;
			}
		} else {
			LASSERT(oio->oi_lockless == 0);
		}

		if (ia_xvalid & OP_XVALID_FLAGS) {
			oa->o_flags = io->u.ci_setattr.sa_attr_flags;
			oa->o_valid |= OBD_MD_FLFLAGS;
		}

		init_completion(&cbargs->opc_sync);

		if (ia_avalid & ATTR_SIZE)
			result = osc_punch_send(osc_export(cl2osc(obj)),
						oa, osc_async_upcall, cbargs);
		else
			result = osc_setattr_async(osc_export(cl2osc(obj)),
						   oa, osc_async_upcall,
						   cbargs, PTLRPCD_SET);

		cbargs->opc_rpc_sent = result == 0;
	}

	RETURN(result);
}

void osc_io_setattr_end(const struct lu_env *env,
			const struct cl_io_slice *slice)
{
	struct cl_io     *io  = slice->cis_io;
	struct osc_io    *oio = cl2osc_io(env, slice);
	struct cl_object *obj = slice->cis_obj;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	struct cl_attr  *attr = &osc_env_info(env)->oti_attr;
	struct obdo *oa = &oio->oi_oa;
	unsigned int cl_valid = 0;
	int result = 0;

	if (cbargs->opc_rpc_sent) {
		wait_for_completion(&cbargs->opc_sync);
		result = io->ci_result = cbargs->opc_rc;
	}

	if (result == 0) {
		if (oio->oi_lockless) {
			/* lockless truncate */
			struct osc_device *osd = lu2osc_dev(obj->co_lu.lo_dev);

			LASSERT(cl_io_is_trunc(io));
			/* XXX: Need a lock. */
			osd->od_stats.os_lockless_truncates++;
		}
	}

	if (cl_io_is_trunc(io)) {
		__u64 size = io->u.ci_setattr.sa_attr.lvb_size;
		cl_object_attr_lock(obj);
		if (oa->o_valid & OBD_MD_FLBLOCKS) {
			attr->cat_blocks = oa->o_blocks;
			cl_valid |= CAT_BLOCKS;
		}

		cl_object_attr_update(env, obj, attr, cl_valid);
		cl_object_attr_unlock(obj);
		osc_trunc_check(env, io, oio, size);
		osc_cache_truncate_end(env, oio->oi_trunc);
		oio->oi_trunc = NULL;
	}
}
EXPORT_SYMBOL(osc_io_setattr_end);

struct osc_data_version_args {
	struct osc_io *dva_oio;
};

static int
osc_data_version_interpret(const struct lu_env *env, struct ptlrpc_request *req,
			   void *arg, int rc)
{
	struct osc_data_version_args *dva = arg;
	struct osc_io *oio = dva->dva_oio;
	const struct ost_body *body;

	ENTRY;
	if (rc < 0)
		GOTO(out, rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_OST_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	lustre_get_wire_obdo(&req->rq_import->imp_connect_data, &oio->oi_oa,
			     &body->oa);
	EXIT;
out:
	oio->oi_cbarg.opc_rc = rc;
	complete(&oio->oi_cbarg.opc_sync);

	return 0;
}

static int osc_io_data_version_start(const struct lu_env *env,
				     const struct cl_io_slice *slice)
{
	struct cl_data_version_io *dv	= &slice->cis_io->u.ci_data_version;
	struct osc_io		*oio	= cl2osc_io(env, slice);
	struct obdo		*oa	= &oio->oi_oa;
	struct osc_async_cbargs	*cbargs	= &oio->oi_cbarg;
	struct osc_object	*obj	= cl2osc(slice->cis_obj);
	struct lov_oinfo	*loi	= obj->oo_oinfo;
	struct obd_export	*exp	= osc_export(obj);
	struct ptlrpc_request	*req;
	struct ost_body		*body;
	struct osc_data_version_args *dva;
	int rc;

	ENTRY;
	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	if (dv->dv_flags & (LL_DV_RD_FLUSH | LL_DV_WR_FLUSH)) {
		oa->o_valid |= OBD_MD_FLFLAGS;
		oa->o_flags |= OBD_FL_SRVLOCK;
		if (dv->dv_flags & LL_DV_WR_FLUSH)
			oa->o_flags |= OBD_FL_FLUSH;
	}

	init_completion(&cbargs->opc_sync);

	req = ptlrpc_request_alloc(class_exp2cliimp(exp), &RQF_OST_GETATTR);
	if (req == NULL)
		RETURN(-ENOMEM);

	rc = ptlrpc_request_pack(req, LUSTRE_OST_VERSION, OST_GETATTR);
	if (rc < 0) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	body = req_capsule_client_get(&req->rq_pill, &RMF_OST_BODY);
	lustre_set_wire_obdo(&req->rq_import->imp_connect_data, &body->oa, oa);

	ptlrpc_request_set_replen(req);
	req->rq_interpret_reply = osc_data_version_interpret;
	CLASSERT(sizeof(*dva) <= sizeof(req->rq_async_args));
	dva = ptlrpc_req_async_args(req);
	dva->dva_oio = oio;

	ptlrpcd_add_req(req);

	RETURN(0);
}

static void osc_io_data_version_end(const struct lu_env *env,
				    const struct cl_io_slice *slice)
{
	struct cl_data_version_io *dv = &slice->cis_io->u.ci_data_version;
	struct osc_io		*oio    = cl2osc_io(env, slice);
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;

	ENTRY;
	wait_for_completion(&cbargs->opc_sync);

	if (cbargs->opc_rc != 0) {
		slice->cis_io->ci_result = cbargs->opc_rc;
	} else {
		slice->cis_io->ci_result = 0;
		if (!(oio->oi_oa.o_valid &
		      (OBD_MD_LAYOUT_VERSION | OBD_MD_FLDATAVERSION)))
			slice->cis_io->ci_result = -ENOTSUPP;

		if (oio->oi_oa.o_valid & OBD_MD_LAYOUT_VERSION)
			dv->dv_layout_version = oio->oi_oa.o_layout_version;
		if (oio->oi_oa.o_valid & OBD_MD_FLDATAVERSION)
			dv->dv_data_version = oio->oi_oa.o_data_version;
	}

	EXIT;
}

int osc_io_read_start(const struct lu_env *env,
		      const struct cl_io_slice *slice)
{
	struct cl_object *obj  = slice->cis_obj;
	struct cl_attr	 *attr = &osc_env_info(env)->oti_attr;
	int rc = 0;
	ENTRY;

	if (!slice->cis_io->ci_noatime) {
		cl_object_attr_lock(obj);
		attr->cat_atime = ktime_get_real_seconds();
		rc = cl_object_attr_update(env, obj, attr, CAT_ATIME);
		cl_object_attr_unlock(obj);
	}

	RETURN(rc);
}
EXPORT_SYMBOL(osc_io_read_start);

int osc_io_write_start(const struct lu_env *env,
		       const struct cl_io_slice *slice)
{
	struct cl_object *obj   = slice->cis_obj;
	struct cl_attr   *attr  = &osc_env_info(env)->oti_attr;
	int rc = 0;
	ENTRY;

	OBD_FAIL_TIMEOUT(OBD_FAIL_OSC_DELAY_SETTIME, 1);
	cl_object_attr_lock(obj);
	attr->cat_mtime = attr->cat_ctime = ktime_get_real_seconds();
	rc = cl_object_attr_update(env, obj, attr, CAT_MTIME | CAT_CTIME);
	cl_object_attr_unlock(obj);

	RETURN(rc);
}
EXPORT_SYMBOL(osc_io_write_start);

int osc_fsync_ost(const struct lu_env *env, struct osc_object *obj,
		  struct cl_fsync_io *fio)
{
	struct osc_io    *oio   = osc_env_io(env);
	struct obdo      *oa    = &oio->oi_oa;
	struct lov_oinfo *loi   = obj->oo_oinfo;
	struct osc_async_cbargs *cbargs = &oio->oi_cbarg;
	int rc = 0;
	ENTRY;

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;

	/* reload size abd blocks for start and end of sync range */
	oa->o_size = fio->fi_start;
	oa->o_blocks = fio->fi_end;
	oa->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;

	obdo_set_parent_fid(oa, fio->fi_fid);

	init_completion(&cbargs->opc_sync);

	rc = osc_sync_base(obj, oa, osc_async_upcall, cbargs, PTLRPCD_SET);
	RETURN(rc);
}
EXPORT_SYMBOL(osc_fsync_ost);

int osc_io_fsync_start(const struct lu_env *env,
		       const struct cl_io_slice *slice)
{
	struct cl_io       *io  = slice->cis_io;
	struct cl_fsync_io *fio = &io->u.ci_fsync;
	struct cl_object   *obj = slice->cis_obj;
	struct osc_object  *osc = cl2osc(obj);
	pgoff_t start  = cl_index(obj, fio->fi_start);
	pgoff_t end    = cl_index(obj, fio->fi_end);
	int     result = 0;
	ENTRY;

	if (fio->fi_end == OBD_OBJECT_EOF)
		end = CL_PAGE_EOF;

	result = osc_cache_writeback_range(env, osc, start, end, 0,
					   fio->fi_mode == CL_FSYNC_DISCARD);
	if (result > 0) {
		fio->fi_nr_written += result;
		result = 0;
	}
	if (fio->fi_mode == CL_FSYNC_ALL) {
		int rc;

		/* we have to wait for writeback to finish before we can
		 * send OST_SYNC RPC. This is bad because it causes extents
		 * to be written osc by osc. However, we usually start
		 * writeback before CL_FSYNC_ALL so this won't have any real
		 * problem. */
		rc = osc_cache_wait_range(env, osc, start, end);
		if (result == 0)
			result = rc;
		rc = osc_fsync_ost(env, osc, fio);
		if (result == 0)
			result = rc;
	}

	RETURN(result);
}

void osc_io_fsync_end(const struct lu_env *env,
		      const struct cl_io_slice *slice)
{
	struct cl_fsync_io *fio = &slice->cis_io->u.ci_fsync;
	struct cl_object   *obj = slice->cis_obj;
	pgoff_t start = cl_index(obj, fio->fi_start);
	pgoff_t end   = cl_index(obj, fio->fi_end);
	int result = 0;

	if (fio->fi_mode == CL_FSYNC_LOCAL) {
		result = osc_cache_wait_range(env, cl2osc(obj), start, end);
	} else if (fio->fi_mode == CL_FSYNC_ALL) {
		struct osc_io           *oio    = cl2osc_io(env, slice);
		struct osc_async_cbargs *cbargs = &oio->oi_cbarg;

		wait_for_completion(&cbargs->opc_sync);
		if (result == 0)
			result = cbargs->opc_rc;
	}
	slice->cis_io->ci_result = result;
}
EXPORT_SYMBOL(osc_io_fsync_end);

static int osc_io_ladvise_start(const struct lu_env *env,
				const struct cl_io_slice *slice)
{
	int			 result = 0;
	struct cl_io		*io = slice->cis_io;
	struct osc_io		*oio = cl2osc_io(env, slice);
	struct cl_object	*obj = slice->cis_obj;
	struct lov_oinfo	*loi = cl2osc(obj)->oo_oinfo;
	struct cl_ladvise_io	*lio = &io->u.ci_ladvise;
	struct obdo		*oa = &oio->oi_oa;
	struct osc_async_cbargs	*cbargs = &oio->oi_cbarg;
	struct lu_ladvise	*ladvise;
	struct ladvise_hdr	*ladvise_hdr;
	int			 buf_size;
	int			 num_advise = 1;
	ENTRY;

	/* TODO: add multiple ladvise support in CLIO */
	buf_size = offsetof(typeof(*ladvise_hdr), lah_advise[num_advise]);
	if (osc_env_info(env)->oti_ladvise_buf.lb_len < buf_size)
		lu_buf_realloc(&osc_env_info(env)->oti_ladvise_buf, buf_size);

	ladvise_hdr = osc_env_info(env)->oti_ladvise_buf.lb_buf;
	if (ladvise_hdr == NULL)
		RETURN(-ENOMEM);

	memset(ladvise_hdr, 0, buf_size);
	ladvise_hdr->lah_magic = LADVISE_MAGIC;
	ladvise_hdr->lah_count = num_advise;
	ladvise_hdr->lah_flags = lio->li_flags;

	memset(oa, 0, sizeof(*oa));
	oa->o_oi = loi->loi_oi;
	oa->o_valid = OBD_MD_FLID;
	obdo_set_parent_fid(oa, lio->li_fid);

	ladvise = ladvise_hdr->lah_advise;
	ladvise->lla_start = lio->li_start;
	ladvise->lla_end = lio->li_end;
	ladvise->lla_advice = lio->li_advice;

	if (lio->li_flags & LF_ASYNC) {
		result = osc_ladvise_base(osc_export(cl2osc(obj)), oa,
					  ladvise_hdr, NULL, NULL, NULL);
	} else {
		init_completion(&cbargs->opc_sync);
		result = osc_ladvise_base(osc_export(cl2osc(obj)), oa,
					  ladvise_hdr, osc_async_upcall,
					  cbargs, PTLRPCD_SET);
		cbargs->opc_rpc_sent = result == 0;
	}
	RETURN(result);
}

static void osc_io_ladvise_end(const struct lu_env *env,
			       const struct cl_io_slice *slice)
{
	struct cl_io		*io = slice->cis_io;
	struct osc_io		*oio = cl2osc_io(env, slice);
	struct osc_async_cbargs	*cbargs = &oio->oi_cbarg;
	int			 result = 0;
	struct cl_ladvise_io	*lio = &io->u.ci_ladvise;

	if ((!(lio->li_flags & LF_ASYNC)) && cbargs->opc_rpc_sent) {
		wait_for_completion(&cbargs->opc_sync);
		result = cbargs->opc_rc;
	}
	slice->cis_io->ci_result = result;
}

void osc_io_end(const struct lu_env *env, const struct cl_io_slice *slice)
{
	struct osc_io *oio = cl2osc_io(env, slice);

	if (oio->oi_active) {
		osc_extent_release(env, oio->oi_active);
		oio->oi_active = NULL;
	}
}
EXPORT_SYMBOL(osc_io_end);

static const struct cl_io_operations osc_io_ops = {
	.op = {
		[CIT_READ] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start  = osc_io_read_start,
			.cio_fini   = osc_io_fini
		},
		[CIT_WRITE] = {
			.cio_iter_init = osc_io_write_iter_init,
			.cio_iter_fini = osc_io_write_iter_fini,
			.cio_start  = osc_io_write_start,
			.cio_end    = osc_io_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_SETATTR] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start  = osc_io_setattr_start,
			.cio_end    = osc_io_setattr_end
		},
		[CIT_DATA_VERSION] = {
			.cio_start  = osc_io_data_version_start,
			.cio_end    = osc_io_data_version_end,
		},
		[CIT_FAULT] = {
			.cio_iter_init = osc_io_iter_init,
			.cio_iter_fini = osc_io_iter_fini,
			.cio_start  = osc_io_fault_start,
			.cio_end    = osc_io_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_FSYNC] = {
			.cio_start  = osc_io_fsync_start,
			.cio_end    = osc_io_fsync_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_LADVISE] = {
			.cio_start  = osc_io_ladvise_start,
			.cio_end    = osc_io_ladvise_end,
			.cio_fini   = osc_io_fini
		},
		[CIT_MISC] = {
			.cio_fini   = osc_io_fini
		}
	},
	.cio_read_ahead		    = osc_io_read_ahead,
	.cio_submit                 = osc_io_submit,
	.cio_commit_async           = osc_io_commit_async
};

/*****************************************************************************
 *
 * Transfer operations.
 *
 */

int osc_io_init(const struct lu_env *env,
                struct cl_object *obj, struct cl_io *io)
{
        struct osc_io *oio = osc_env_io(env);

        CL_IO_SLICE_CLEAN(oio, oi_cl);
        cl_io_slice_add(io, &oio->oi_cl, obj, &osc_io_ops);
        return 0;
}

/** @} osc */
