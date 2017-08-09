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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Implementation of cl_io for LOV layer.
 *
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 *   Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

static inline struct lov_io_sub *lov_sub_alloc(struct lov_io *lio, int index)
{
	struct lov_io_sub *sub;

	if (lio->lis_nr_subios == 0) {
		LASSERT(lio->lis_single_subio_index == -1);
		sub = &lio->lis_single_subio;
		lio->lis_single_subio_index = index;
		memset(sub, 0, sizeof(*sub));
	} else {
		OBD_ALLOC_PTR(sub);
	}

	if (sub != NULL) {
		INIT_LIST_HEAD(&sub->sub_list);
		INIT_LIST_HEAD(&sub->sub_linkage);
		sub->sub_subio_index = index;
	}

	return sub;
}

static inline void lov_sub_free(struct lov_io *lio, struct lov_io_sub *sub)
{
	if (sub->sub_subio_index == lio->lis_single_subio_index) {
		LASSERT(sub == &lio->lis_single_subio);
		lio->lis_single_subio_index = -1;
	} else {
		OBD_FREE_PTR(sub);
	}
}

static void lov_io_sub_fini(const struct lu_env *env, struct lov_io *lio,
			    struct lov_io_sub *sub)
{
	ENTRY;

	cl_io_fini(sub->sub_env, &sub->sub_io);

	if (sub->sub_env != NULL && !IS_ERR(sub->sub_env)) {
		cl_env_put(sub->sub_env, &sub->sub_refcheck);
		sub->sub_env = NULL;
	}
	EXIT;
}

static int lov_io_sub_init(const struct lu_env *env, struct lov_io *lio,
			   struct lov_io_sub *sub)
{
	struct lov_object *lov = lio->lis_object;
	struct cl_io *sub_io;
	struct cl_object *sub_obj;
	struct cl_io *io = lio->lis_cl.cis_io;
	int index = lov_comp_entry(sub->sub_subio_index);
	int stripe = lov_comp_stripe(sub->sub_subio_index);
	int result = 0;
	LASSERT(sub->sub_env == NULL);
	ENTRY;

	if (unlikely(!lov_r0(lov, index)->lo_sub ||
		     !lov_r0(lov, index)->lo_sub[stripe]))
		RETURN(-EIO);

	/* obtain new environment */
	sub->sub_env = cl_env_get(&sub->sub_refcheck);
	if (IS_ERR(sub->sub_env))
		result = PTR_ERR(sub->sub_env);

	sub_obj = lovsub2cl(lov_r0(lov, index)->lo_sub[stripe]);
	sub_io  = &sub->sub_io;

	sub_io->ci_obj    = sub_obj;
	sub_io->ci_result = 0;

	sub_io->ci_parent  = io;
	sub_io->ci_lockreq = io->ci_lockreq;
	sub_io->ci_type    = io->ci_type;
	sub_io->ci_no_srvlock = io->ci_no_srvlock;
	sub_io->ci_noatime = io->ci_noatime;
	sub_io->ci_pio = io->ci_pio;

	result = cl_io_sub_init(sub->sub_env, sub_io, io->ci_type, sub_obj);

	if (result < 0)
		lov_io_sub_fini(env, lio, sub);

	RETURN(result);
}

struct lov_io_sub *lov_sub_get(const struct lu_env *env,
			       struct lov_io *lio, int index)
{
	struct lov_io_sub *sub;
	int rc = 0;

	ENTRY;

	list_for_each_entry(sub, &lio->lis_subios, sub_list) {
		if (sub->sub_subio_index == index) {
			rc = 1;
			break;
		}
	}

	if (rc == 0) {
		sub = lov_sub_alloc(lio, index);
		if (sub == NULL)
			GOTO(out, rc = -ENOMEM);

		rc = lov_io_sub_init(env, lio, sub);
		if (rc < 0) {
			lov_sub_free(lio, sub);
			GOTO(out, rc);
		}

		list_add_tail(&sub->sub_list, &lio->lis_subios);
		lio->lis_nr_subios++;
	}
out:
	if (rc < 0)
		sub = ERR_PTR(rc);
	RETURN(sub);
}

/*****************************************************************************
 *
 * Lov io operations.
 *
 */

int lov_page_index(const struct cl_page *page)
{
	const struct cl_page_slice *slice;
	ENTRY;

	slice = cl_page_at(page, &lov_device_type);
	LASSERT(slice != NULL);
	LASSERT(slice->cpl_obj != NULL);

	RETURN(cl2lov_page(slice)->lps_index);
}

static int lov_io_subio_init(const struct lu_env *env, struct lov_io *lio,
                             struct cl_io *io)
{
	ENTRY;

	LASSERT(lio->lis_object != NULL);

	INIT_LIST_HEAD(&lio->lis_subios);
	lio->lis_single_subio_index = -1;
	lio->lis_nr_subios = 0;

	RETURN(0);
}

static int lov_io_slice_init(struct lov_io *lio,
			     struct lov_object *obj, struct cl_io *io)
{
	ENTRY;

	io->ci_result = 0;
	lio->lis_object = obj;

	LASSERT(obj->lo_lsm != NULL);

	switch (io->ci_type) {
	case CIT_READ:
	case CIT_WRITE:
		lio->lis_pos = io->u.ci_rw.rw_range.cir_pos;
		lio->lis_endpos = lio->lis_pos + io->u.ci_rw.rw_range.cir_count;
		lio->lis_io_endpos = lio->lis_endpos;
		if (cl_io_is_append(io)) {
			LASSERT(io->ci_type == CIT_WRITE);

			/* If there is LOV EA hole, then we may cannot locate
			 * the current file-tail exactly. */
			if (unlikely(obj->lo_lsm->lsm_entries[0]->lsme_pattern &
				     LOV_PATTERN_F_HOLE))
				RETURN(-EIO);

			lio->lis_pos = 0;
			lio->lis_endpos = OBD_OBJECT_EOF;
		}
		break;

        case CIT_SETATTR:
                if (cl_io_is_trunc(io))
                        lio->lis_pos = io->u.ci_setattr.sa_attr.lvb_size;
                else
                        lio->lis_pos = 0;
                lio->lis_endpos = OBD_OBJECT_EOF;
                break;

	case CIT_DATA_VERSION:
		lio->lis_pos = 0;
		lio->lis_endpos = OBD_OBJECT_EOF;
		break;

        case CIT_FAULT: {
                pgoff_t index = io->u.ci_fault.ft_index;
                lio->lis_pos = cl_offset(io->ci_obj, index);
                lio->lis_endpos = cl_offset(io->ci_obj, index + 1);
                break;
        }

	case CIT_FSYNC: {
		lio->lis_pos = io->u.ci_fsync.fi_start;
		lio->lis_endpos = io->u.ci_fsync.fi_end;
		break;
	}

	case CIT_LADVISE: {
		lio->lis_pos = io->u.ci_ladvise.li_start;
		lio->lis_endpos = io->u.ci_ladvise.li_end;
		break;
	}

        case CIT_MISC:
                lio->lis_pos = 0;
                lio->lis_endpos = OBD_OBJECT_EOF;
                break;

        default:
                LBUG();
        }

	RETURN(0);
}

static void lov_io_fini(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_object *lov = cl2lov(ios->cis_obj);

	ENTRY;

	LASSERT(list_empty(&lio->lis_active));

	while (!list_empty(&lio->lis_subios)) {
		struct lov_io_sub *sub = list_entry(lio->lis_subios.next,
						    struct lov_io_sub,
						    sub_list);

		list_del_init(&sub->sub_list);
		lio->lis_nr_subios--;

		lov_io_sub_fini(env, lio, sub);
		lov_sub_free(lio, sub);
	}
	LASSERT(lio->lis_nr_subios == 0);

	LASSERT(atomic_read(&lov->lo_active_ios) > 0);
	if (atomic_dec_and_test(&lov->lo_active_ios))
		wake_up_all(&lov->lo_waitq);
	EXIT;
}

static void lov_io_sub_inherit(struct lov_io_sub *sub, struct lov_io *lio,
			       loff_t start, loff_t end)
{
	struct cl_io *io = &sub->sub_io;
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	struct cl_io *parent = lio->lis_cl.cis_io;
	int index = lov_comp_entry(sub->sub_subio_index);
	int stripe = lov_comp_stripe(sub->sub_subio_index);

	io->ci_pio = parent->ci_pio;
	switch (io->ci_type) {
	case CIT_SETATTR: {
		io->u.ci_setattr.sa_attr = parent->u.ci_setattr.sa_attr;
		io->u.ci_setattr.sa_attr_flags =
			parent->u.ci_setattr.sa_attr_flags;
		io->u.ci_setattr.sa_valid = parent->u.ci_setattr.sa_valid;
		io->u.ci_setattr.sa_stripe_index = stripe;
		io->u.ci_setattr.sa_parent_fid =
					parent->u.ci_setattr.sa_parent_fid;
		if (cl_io_is_trunc(io)) {
			loff_t new_size = parent->u.ci_setattr.sa_attr.lvb_size;

			new_size = lov_size_to_stripe(lsm, index, new_size,
						      stripe);
			io->u.ci_setattr.sa_attr.lvb_size = new_size;
		}
		lov_lsm2layout(lsm, lsm->lsm_entries[index],
			       &io->u.ci_setattr.sa_layout);
		break;
	}
	case CIT_DATA_VERSION: {
		io->u.ci_data_version.dv_data_version = 0;
		io->u.ci_data_version.dv_flags =
			parent->u.ci_data_version.dv_flags;
		break;
	}
	case CIT_FAULT: {
		struct cl_object *obj = parent->ci_obj;
		loff_t off = cl_offset(obj, parent->u.ci_fault.ft_index);

		io->u.ci_fault = parent->u.ci_fault;
		off = lov_size_to_stripe(lsm, index, off, stripe);
		io->u.ci_fault.ft_index = cl_index(obj, off);
		break;
	}
	case CIT_FSYNC: {
		io->u.ci_fsync.fi_start = start;
		io->u.ci_fsync.fi_end = end;
		io->u.ci_fsync.fi_fid = parent->u.ci_fsync.fi_fid;
		io->u.ci_fsync.fi_mode = parent->u.ci_fsync.fi_mode;
		break;
	}
	case CIT_READ:
	case CIT_WRITE: {
		io->u.ci_rw.rw_ptask = parent->u.ci_rw.rw_ptask;
		io->u.ci_rw.rw_iter = parent->u.ci_rw.rw_iter;
		io->u.ci_rw.rw_iocb = parent->u.ci_rw.rw_iocb;
		io->u.ci_rw.rw_file = parent->u.ci_rw.rw_file;
		io->u.ci_rw.rw_sync = parent->u.ci_rw.rw_sync;
		if (cl_io_is_append(parent)) {
			io->u.ci_rw.rw_append = 1;
		} else {
			io->u.ci_rw.rw_range.cir_pos = start;
			io->u.ci_rw.rw_range.cir_count = end - start;
		}
		break;
	}
	case CIT_LADVISE: {
		io->u.ci_ladvise.li_start = start;
		io->u.ci_ladvise.li_end = end;
		io->u.ci_ladvise.li_fid = parent->u.ci_ladvise.li_fid;
		io->u.ci_ladvise.li_advice = parent->u.ci_ladvise.li_advice;
		io->u.ci_ladvise.li_flags = parent->u.ci_ladvise.li_flags;
		break;
	}
	default:
		break;
	}
}

static loff_t lov_offset_mod(loff_t val, int delta)
{
        if (val != OBD_OBJECT_EOF)
                val += delta;
        return val;
}

static int lov_io_iter_init(const struct lu_env *env,
			    const struct cl_io_slice *ios)
{
	struct cl_io         *io = ios->cis_io;
	struct lov_io        *lio = cl2lov_io(env, ios);
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	struct lov_io_sub    *sub;
	struct lov_layout_entry *le;
	struct lu_extent ext;
	int index;
	int rc = 0;

        ENTRY;

	ext.e_start = lio->lis_pos;
	ext.e_end = lio->lis_endpos;

	index = 0;
	lov_foreach_layout_entry(lio->lis_object, le) {
		struct lov_layout_raid0 *r0 = &le->lle_raid0;
		u64 start;
		u64 end;
		int stripe;

		index++;
		if (!lu_extent_is_overlapped(&ext, &le->lle_extent))
			continue;

		CDEBUG(D_VFSTRACE, "component[%d] flags %#x\n",
		       index - 1, lsm->lsm_entries[index - 1]->lsme_flags);
		if (!lsm_entry_inited(lsm, index - 1)) {
			/* truncate IO will trigger write intent as well, and
			 * it's handled in lov_io_setattr_iter_init() */
			if (io->ci_type == CIT_WRITE || cl_io_is_mkwrite(io)) {
				io->ci_need_write_intent = 1;
				/* execute it in main thread */
				io->ci_pio = 0;
				rc = -ENODATA;
				break;
			}

			/* Read from uninitialized components should return
			 * zero filled pages. */
			continue;
		}

		for (stripe = 0; stripe < r0->lo_nr; stripe++) {
			if (!lov_stripe_intersects(lsm, index - 1, stripe,
						   &ext, &start, &end))
				continue;

			if (unlikely(r0->lo_sub[stripe] == NULL)) {
				if (ios->cis_io->ci_type == CIT_READ ||
				    ios->cis_io->ci_type == CIT_WRITE ||
				    ios->cis_io->ci_type == CIT_FAULT)
					RETURN(-EIO);

				continue;
			}

			end = lov_offset_mod(end, 1);
			sub = lov_sub_get(env, lio,
					  lov_comp_index(index - 1, stripe));
			if (IS_ERR(sub)) {
				rc = PTR_ERR(sub);
				break;
			}

			lov_io_sub_inherit(sub, lio, start, end);
			rc = cl_io_iter_init(sub->sub_env, &sub->sub_io);
			if (rc != 0)
				cl_io_iter_fini(sub->sub_env, &sub->sub_io);
			if (rc != 0)
				break;

			CDEBUG(D_VFSTRACE,
				"shrink stripe: {%d, %d} range: [%llu, %llu)\n",
				index, stripe, start, end);

			list_add_tail(&sub->sub_linkage, &lio->lis_active);
		}
		if (rc != 0)
			break;
	}
	RETURN(rc);
}

static int lov_io_rw_iter_init(const struct lu_env *env,
			       const struct cl_io_slice *ios)
{
	struct cl_io *io = ios->cis_io;
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	struct lov_stripe_md_entry *lse;
	struct cl_io_range *range = &io->u.ci_rw.rw_range;
	loff_t start = range->cir_pos;
	loff_t next;
	int index;

	LASSERT(io->ci_type == CIT_READ || io->ci_type == CIT_WRITE);
	ENTRY;

	if (cl_io_is_append(io))
		RETURN(lov_io_iter_init(env, ios));

	index = lov_lsm_entry(lsm, range->cir_pos);
	if (index < 0) { /* non-existing layout component */
		if (io->ci_type == CIT_READ) {
			/* TODO: it needs to detect the next component and
			 * then set the next pos */
			io->ci_continue = 0;
			/* execute it in main thread */
			io->ci_pio = 0;

			RETURN(lov_io_iter_init(env, ios));
		}

		RETURN(-ENODATA);
	}

	lse = lov_lse(lio->lis_object, index);

	next = MAX_LFS_FILESIZE;
	if (lse->lsme_stripe_count > 1) {
		unsigned long ssize = lse->lsme_stripe_size;

		lov_do_div64(start, ssize);
		next = (start + 1) * ssize;
		if (next <= start * ssize)
			next = MAX_LFS_FILESIZE;
	}

	LASSERTF(range->cir_pos >= lse->lsme_extent.e_start,
		 "pos %lld, [%lld, %lld)\n", range->cir_pos,
		 lse->lsme_extent.e_start, lse->lsme_extent.e_end);
	next = min_t(__u64, next, lse->lsme_extent.e_end);
	next = min_t(loff_t, next, lio->lis_io_endpos);

	io->ci_continue  = next < lio->lis_io_endpos;
	range->cir_count = next - range->cir_pos;
	lio->lis_pos     = range->cir_pos;
	lio->lis_endpos  = range->cir_pos + range->cir_count;
	CDEBUG(D_VFSTRACE,
	       "stripe: {%d, %llu} range: [%llu, %llu) end: %llu, count: %zd\n",
	       index, start, lio->lis_pos, lio->lis_endpos,
	       lio->lis_io_endpos, range->cir_count);

	if (!io->ci_continue) {
		/* the last piece of IO, execute it in main thread */
		io->ci_pio = 0;
	}

	if (io->ci_pio) {
		/* it only splits IO here for parallel IO,
		 * there will be no actual IO going to occur,
		 * so it doesn't need to invoke lov_io_iter_init()
		 * to initialize sub IOs. */
		if (!lsm_entry_inited(lsm, index)) {
			io->ci_need_write_intent = 1;
			RETURN(-ENODATA);
		}
		RETURN(0);
	}

	/*
	 * XXX The following call should be optimized: we know, that
	 * [lio->lis_pos, lio->lis_endpos) intersects with exactly one stripe.
	 */
	RETURN(lov_io_iter_init(env, ios));
}

static int lov_io_setattr_iter_init(const struct lu_env *env,
				    const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = ios->cis_io;
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	int index;
	ENTRY;

	if (cl_io_is_trunc(io) && lio->lis_pos > 0) {
		index = lov_lsm_entry(lsm, lio->lis_pos - 1);
		if (index > 0 && !lsm_entry_inited(lsm, index)) {
			io->ci_need_write_intent = 1;
			RETURN(io->ci_result = -ENODATA);
		}
	}

	RETURN(lov_io_iter_init(env, ios));
}

static int lov_io_call(const struct lu_env *env, struct lov_io *lio,
		       int (*iofunc)(const struct lu_env *, struct cl_io *))
{
	struct cl_io *parent = lio->lis_cl.cis_io;
	struct lov_io_sub *sub;
	int rc = 0;

	ENTRY;
	list_for_each_entry(sub, &lio->lis_active, sub_linkage) {
		rc = iofunc(sub->sub_env, &sub->sub_io);
		if (rc)
			break;

		if (parent->ci_result == 0)
			parent->ci_result = sub->sub_io.ci_result;
	}
	RETURN(rc);
}

static int lov_io_lock(const struct lu_env *env, const struct cl_io_slice *ios)
{
        ENTRY;
        RETURN(lov_io_call(env, cl2lov_io(env, ios), cl_io_lock));
}

static int lov_io_start(const struct lu_env *env, const struct cl_io_slice *ios)
{
        ENTRY;
        RETURN(lov_io_call(env, cl2lov_io(env, ios), cl_io_start));
}

static int lov_io_end_wrapper(const struct lu_env *env, struct cl_io *io)
{
        ENTRY;
        /*
         * It's possible that lov_io_start() wasn't called against this
         * sub-io, either because previous sub-io failed, or upper layer
         * completed IO.
         */
        if (io->ci_state == CIS_IO_GOING)
                cl_io_end(env, io);
        else
                io->ci_state = CIS_IO_FINISHED;
        RETURN(0);
}

static int lov_io_iter_fini_wrapper(const struct lu_env *env, struct cl_io *io)
{
        cl_io_iter_fini(env, io);
        RETURN(0);
}

static int lov_io_unlock_wrapper(const struct lu_env *env, struct cl_io *io)
{
        cl_io_unlock(env, io);
        RETURN(0);
}

static void lov_io_end(const struct lu_env *env, const struct cl_io_slice *ios)
{
        int rc;

        rc = lov_io_call(env, cl2lov_io(env, ios), lov_io_end_wrapper);
        LASSERT(rc == 0);
}

static void
lov_io_data_version_end(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *parent = lio->lis_cl.cis_io;
	struct lov_io_sub *sub;

	ENTRY;
	list_for_each_entry(sub, &lio->lis_active, sub_linkage) {
		lov_io_end_wrapper(env, &sub->sub_io);

		parent->u.ci_data_version.dv_data_version +=
			sub->sub_io.u.ci_data_version.dv_data_version;

		if (parent->ci_result == 0)
			parent->ci_result = sub->sub_io.ci_result;
	}

	EXIT;
}

static void lov_io_iter_fini(const struct lu_env *env,
                             const struct cl_io_slice *ios)
{
        struct lov_io *lio = cl2lov_io(env, ios);
        int rc;

        ENTRY;
        rc = lov_io_call(env, lio, lov_io_iter_fini_wrapper);
        LASSERT(rc == 0);
	while (!list_empty(&lio->lis_active))
		list_del_init(lio->lis_active.next);
        EXIT;
}

static void lov_io_unlock(const struct lu_env *env,
                          const struct cl_io_slice *ios)
{
        int rc;

        ENTRY;
        rc = lov_io_call(env, cl2lov_io(env, ios), lov_io_unlock_wrapper);
        LASSERT(rc == 0);
        EXIT;
}

static int lov_io_read_ahead(const struct lu_env *env,
			     const struct cl_io_slice *ios,
			     pgoff_t start, struct cl_read_ahead *ra)
{
	struct lov_io		*lio = cl2lov_io(env, ios);
	struct lov_object	*loo = lio->lis_object;
	struct cl_object	*obj = lov2cl(loo);
	struct lov_layout_raid0 *r0;
	struct lov_io_sub	*sub;
	loff_t			 offset;
	loff_t			 suboff;
	pgoff_t			 ra_end;
	unsigned int		 pps; /* pages per stripe */
	int			 stripe;
	int			 index;
	int			 rc;
	ENTRY;

	offset = cl_offset(obj, start);
	index = lov_lsm_entry(loo->lo_lsm, offset);
	if (index < 0 || !lsm_entry_inited(loo->lo_lsm, index))
		RETURN(-ENODATA);

	stripe = lov_stripe_number(loo->lo_lsm, index, offset);

	r0 = lov_r0(loo, index);
	if (unlikely(r0->lo_sub[stripe] == NULL))
		RETURN(-EIO);

	sub = lov_sub_get(env, lio, lov_comp_index(index, stripe));
	if (IS_ERR(sub))
		RETURN(PTR_ERR(sub));

	lov_stripe_offset(loo->lo_lsm, index, offset, stripe, &suboff);
	rc = cl_io_read_ahead(sub->sub_env, &sub->sub_io,
			      cl_index(lovsub2cl(r0->lo_sub[stripe]), suboff),
			      ra);

	CDEBUG(D_READA, DFID " cra_end = %lu, stripes = %d, rc = %d\n",
	       PFID(lu_object_fid(lov2lu(loo))), ra->cra_end, r0->lo_nr, rc);
	if (rc != 0)
		RETURN(rc);

	/**
	 * Adjust the stripe index by layout of comp. ra->cra_end is the
	 * maximum page index covered by an underlying DLM lock.
	 * This function converts cra_end from stripe level to file level, and
	 * make sure it's not beyond stripe and component boundary.
	 */

	/* cra_end is stripe level, convert it into file level */
	ra_end = ra->cra_end;
	if (ra_end != CL_PAGE_EOF)
		ra->cra_end = lov_stripe_pgoff(loo->lo_lsm, index,
					       ra_end, stripe);

	/* boundary of current component */
	ra_end = cl_index(obj, (loff_t)lov_lse(loo, index)->lsme_extent.e_end);
	if (ra_end != CL_PAGE_EOF && ra->cra_end >= ra_end)
		ra->cra_end = ra_end - 1;

	if (r0->lo_nr == 1) /* single stripe file */
		RETURN(0);

	pps = lov_lse(loo, index)->lsme_stripe_size >> PAGE_SHIFT;

	CDEBUG(D_READA, DFID " max_index = %lu, pps = %u, index = %u, "
	       "stripe_size = %u, stripe no = %u, start index = %lu\n",
	       PFID(lu_object_fid(lov2lu(loo))), ra->cra_end, pps, index,
	       lov_lse(loo, index)->lsme_stripe_size, stripe, start);

	/* never exceed the end of the stripe */
	ra->cra_end = min_t(pgoff_t,
			    ra->cra_end, start + pps - start % pps - 1);
	RETURN(0);
}

/**
 * lov implementation of cl_operations::cio_submit() method. It takes a list
 * of pages in \a queue, splits it into per-stripe sub-lists, invokes
 * cl_io_submit() on underlying devices to submit sub-lists, and then splices
 * everything back.
 *
 * Major complication of this function is a need to handle memory cleansing:
 * cl_io_submit() is called to write out pages as a part of VM memory
 * reclamation, and hence it may not fail due to memory shortages (system
 * dead-locks otherwise). To deal with this, some resources (sub-lists,
 * sub-environment, etc.) are allocated per-device on "startup" (i.e., in a
 * not-memory cleansing context), and in case of memory shortage, these
 * pre-allocated resources are used by lov_io_submit() under
 * lov_device::ld_mutex mutex.
 */
static int lov_io_submit(const struct lu_env *env,
			 const struct cl_io_slice *ios,
			 enum cl_req_type crt, struct cl_2queue *queue)
{
	struct cl_page_list	*qin = &queue->c2_qin;
	struct lov_io		*lio = cl2lov_io(env, ios);
	struct lov_io_sub	*sub;
	struct cl_page_list	*plist = &lov_env_info(env)->lti_plist;
	struct cl_page		*page;
	int index;
	int rc = 0;
	ENTRY;

	if (lio->lis_nr_subios == 1) {
		int idx = lio->lis_single_subio_index;

		sub = lov_sub_get(env, lio, idx);
		LASSERT(!IS_ERR(sub));
		LASSERT(sub == &lio->lis_single_subio);
		rc = cl_io_submit_rw(sub->sub_env, &sub->sub_io,
				     crt, queue);
		RETURN(rc);
	}

	cl_page_list_init(plist);
	while (qin->pl_nr > 0) {
		struct cl_2queue  *cl2q = &lov_env_info(env)->lti_cl2q;

		cl_2queue_init(cl2q);

		page = cl_page_list_first(qin);
		cl_page_list_move(&cl2q->c2_qin, qin, page);

		index = lov_page_index(page);
		while (qin->pl_nr > 0) {
			page = cl_page_list_first(qin);
			if (index != lov_page_index(page))
				break;

			cl_page_list_move(&cl2q->c2_qin, qin, page);
		}

		sub = lov_sub_get(env, lio, index);
		if (!IS_ERR(sub)) {
			rc = cl_io_submit_rw(sub->sub_env, &sub->sub_io,
					     crt, cl2q);
		} else {
			rc = PTR_ERR(sub);
		}

		cl_page_list_splice(&cl2q->c2_qin, plist);
		cl_page_list_splice(&cl2q->c2_qout, &queue->c2_qout);
		cl_2queue_fini(env, cl2q);

		if (rc != 0)
			break;
	}

	cl_page_list_splice(plist, qin);
	cl_page_list_fini(env, plist);

	RETURN(rc);
}

static int lov_io_commit_async(const struct lu_env *env,
			       const struct cl_io_slice *ios,
			       struct cl_page_list *queue, int from, int to,
			       cl_commit_cbt cb)
{
	struct cl_page_list *plist = &lov_env_info(env)->lti_plist;
	struct lov_io     *lio = cl2lov_io(env, ios);
	struct lov_io_sub *sub;
	struct cl_page *page;
	int rc = 0;
	ENTRY;

	if (lio->lis_nr_subios == 1) {
		int idx = lio->lis_single_subio_index;

		sub = lov_sub_get(env, lio, idx);
		LASSERT(!IS_ERR(sub));
		LASSERT(sub == &lio->lis_single_subio);
		rc = cl_io_commit_async(sub->sub_env, &sub->sub_io, queue,
					from, to, cb);
		RETURN(rc);
	}

	cl_page_list_init(plist);
	while (queue->pl_nr > 0) {
		int stripe_to = to;
		int index;

		LASSERT(plist->pl_nr == 0);
		page = cl_page_list_first(queue);
		cl_page_list_move(plist, queue, page);

		index = lov_page_index(page);
		while (queue->pl_nr > 0) {
			page = cl_page_list_first(queue);
			if (index != lov_page_index(page))
				break;

			cl_page_list_move(plist, queue, page);
		}

		if (queue->pl_nr > 0) /* still has more pages */
			stripe_to = PAGE_SIZE;

		sub = lov_sub_get(env, lio, index);
		if (!IS_ERR(sub)) {
			rc = cl_io_commit_async(sub->sub_env, &sub->sub_io,
						plist, from, stripe_to, cb);
		} else {
			rc = PTR_ERR(sub);
			break;
		}

		if (plist->pl_nr > 0) /* short write */
			break;

		from = 0;
	}

	/* for error case, add the page back into the qin list */
	LASSERT(ergo(rc == 0, plist->pl_nr == 0));
	while (plist->pl_nr > 0) {
		/* error occurred, add the uncommitted pages back into queue */
		page = cl_page_list_last(plist);
		cl_page_list_move_head(queue, plist, page);
	}

	RETURN(rc);
}

static int lov_io_fault_start(const struct lu_env *env,
			      const struct cl_io_slice *ios)
{
	struct cl_fault_io *fio;
	struct lov_io      *lio;
	struct lov_io_sub  *sub;

	ENTRY;

	fio = &ios->cis_io->u.ci_fault;
	lio = cl2lov_io(env, ios);
	sub = lov_sub_get(env, lio, lov_page_index(fio->ft_page));
	sub->sub_io.u.ci_fault.ft_nob = fio->ft_nob;

	RETURN(lov_io_start(env, ios));
}

static void lov_io_fsync_end(const struct lu_env *env,
			     const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_io_sub *sub;
	unsigned int *written = &ios->cis_io->u.ci_fsync.fi_nr_written;
	ENTRY;

	*written = 0;
	list_for_each_entry(sub, &lio->lis_active, sub_linkage) {
		struct cl_io *subio = &sub->sub_io;

		lov_io_end_wrapper(sub->sub_env, subio);

		if (subio->ci_result == 0)
			*written += subio->u.ci_fsync.fi_nr_written;
	}
	RETURN_EXIT;
}

static const struct cl_io_operations lov_io_ops = {
        .op = {
                [CIT_READ] = {
                        .cio_fini      = lov_io_fini,
                        .cio_iter_init = lov_io_rw_iter_init,
                        .cio_iter_fini = lov_io_iter_fini,
                        .cio_lock      = lov_io_lock,
                        .cio_unlock    = lov_io_unlock,
                        .cio_start     = lov_io_start,
                        .cio_end       = lov_io_end
                },
                [CIT_WRITE] = {
                        .cio_fini      = lov_io_fini,
                        .cio_iter_init = lov_io_rw_iter_init,
                        .cio_iter_fini = lov_io_iter_fini,
                        .cio_lock      = lov_io_lock,
                        .cio_unlock    = lov_io_unlock,
                        .cio_start     = lov_io_start,
                        .cio_end       = lov_io_end
                },
		[CIT_SETATTR] = {
			.cio_fini      = lov_io_fini,
			.cio_iter_init = lov_io_setattr_iter_init,
			.cio_iter_fini = lov_io_iter_fini,
			.cio_lock      = lov_io_lock,
			.cio_unlock    = lov_io_unlock,
			.cio_start     = lov_io_start,
			.cio_end       = lov_io_end
		},
		[CIT_DATA_VERSION] = {
			.cio_fini	= lov_io_fini,
			.cio_iter_init	= lov_io_iter_init,
			.cio_iter_fini	= lov_io_iter_fini,
			.cio_lock	= lov_io_lock,
			.cio_unlock	= lov_io_unlock,
			.cio_start	= lov_io_start,
			.cio_end	= lov_io_data_version_end,
		},
                [CIT_FAULT] = {
                        .cio_fini      = lov_io_fini,
                        .cio_iter_init = lov_io_iter_init,
                        .cio_iter_fini = lov_io_iter_fini,
                        .cio_lock      = lov_io_lock,
                        .cio_unlock    = lov_io_unlock,
                        .cio_start     = lov_io_fault_start,
                        .cio_end       = lov_io_end
                },
		[CIT_FSYNC] = {
			.cio_fini      = lov_io_fini,
			.cio_iter_init = lov_io_iter_init,
			.cio_iter_fini = lov_io_iter_fini,
			.cio_lock      = lov_io_lock,
			.cio_unlock    = lov_io_unlock,
			.cio_start     = lov_io_start,
			.cio_end       = lov_io_fsync_end
		},
		[CIT_LADVISE] = {
			.cio_fini      = lov_io_fini,
			.cio_iter_init = lov_io_iter_init,
			.cio_iter_fini = lov_io_iter_fini,
			.cio_lock      = lov_io_lock,
			.cio_unlock    = lov_io_unlock,
			.cio_start     = lov_io_start,
			.cio_end       = lov_io_end
		},
		[CIT_MISC] = {
			.cio_fini      = lov_io_fini
		}
	},
	.cio_read_ahead		       = lov_io_read_ahead,
	.cio_submit                    = lov_io_submit,
	.cio_commit_async              = lov_io_commit_async,
};

/*****************************************************************************
 *
 * Empty lov io operations.
 *
 */

static void lov_empty_io_fini(const struct lu_env *env,
                              const struct cl_io_slice *ios)
{
	struct lov_object *lov = cl2lov(ios->cis_obj);
	ENTRY;

	if (atomic_dec_and_test(&lov->lo_active_ios))
		wake_up_all(&lov->lo_waitq);
	EXIT;
}

static int lov_empty_io_submit(const struct lu_env *env,
			       const struct cl_io_slice *ios,
			       enum cl_req_type crt, struct cl_2queue *queue)
{
	return -EBADF;
}

static void lov_empty_impossible(const struct lu_env *env,
                                 struct cl_io_slice *ios)
{
        LBUG();
}

#define LOV_EMPTY_IMPOSSIBLE ((void *)lov_empty_impossible)

/**
 * An io operation vector for files without stripes.
 */
static const struct cl_io_operations lov_empty_io_ops = {
        .op = {
                [CIT_READ] = {
                        .cio_fini       = lov_empty_io_fini,
#if 0
                        .cio_iter_init  = LOV_EMPTY_IMPOSSIBLE,
                        .cio_lock       = LOV_EMPTY_IMPOSSIBLE,
                        .cio_start      = LOV_EMPTY_IMPOSSIBLE,
                        .cio_end        = LOV_EMPTY_IMPOSSIBLE
#endif
                },
                [CIT_WRITE] = {
                        .cio_fini      = lov_empty_io_fini,
                        .cio_iter_init = LOV_EMPTY_IMPOSSIBLE,
                        .cio_lock      = LOV_EMPTY_IMPOSSIBLE,
                        .cio_start     = LOV_EMPTY_IMPOSSIBLE,
                        .cio_end       = LOV_EMPTY_IMPOSSIBLE
                },
                [CIT_SETATTR] = {
                        .cio_fini      = lov_empty_io_fini,
                        .cio_iter_init = LOV_EMPTY_IMPOSSIBLE,
                        .cio_lock      = LOV_EMPTY_IMPOSSIBLE,
                        .cio_start     = LOV_EMPTY_IMPOSSIBLE,
                        .cio_end       = LOV_EMPTY_IMPOSSIBLE
                },
                [CIT_FAULT] = {
                        .cio_fini      = lov_empty_io_fini,
                        .cio_iter_init = LOV_EMPTY_IMPOSSIBLE,
                        .cio_lock      = LOV_EMPTY_IMPOSSIBLE,
                        .cio_start     = LOV_EMPTY_IMPOSSIBLE,
                        .cio_end       = LOV_EMPTY_IMPOSSIBLE
                },
		[CIT_FSYNC] = {
			.cio_fini      = lov_empty_io_fini
		},
		[CIT_LADVISE] = {
			.cio_fini   = lov_empty_io_fini
		},
		[CIT_MISC] = {
			.cio_fini      = lov_empty_io_fini
		}
	},
	.cio_submit                    = lov_empty_io_submit,
	.cio_commit_async              = LOV_EMPTY_IMPOSSIBLE
};

int lov_io_init_composite(const struct lu_env *env, struct cl_object *obj,
			  struct cl_io *io)
{
	struct lov_io       *lio = lov_env_io(env);
	struct lov_object   *lov = cl2lov(obj);

	ENTRY;
	INIT_LIST_HEAD(&lio->lis_active);
	io->ci_result = lov_io_slice_init(lio, lov, io);
	if (io->ci_result != 0)
		RETURN(io->ci_result);

	if (io->ci_result == 0) {
		io->ci_result = lov_io_subio_init(env, lio, io);
		if (io->ci_result == 0) {
			cl_io_slice_add(io, &lio->lis_cl, obj, &lov_io_ops);
			atomic_inc(&lov->lo_active_ios);
		}
	}
	RETURN(io->ci_result);
}

int lov_io_init_empty(const struct lu_env *env, struct cl_object *obj,
                      struct cl_io *io)
{
	struct lov_object *lov = cl2lov(obj);
	struct lov_io *lio = lov_env_io(env);
	int result;
	ENTRY;

	lio->lis_object = lov;
	switch (io->ci_type) {
	default:
		LBUG();
	case CIT_MISC:
	case CIT_READ:
		result = 0;
		break;
	case CIT_FSYNC:
	case CIT_LADVISE:
	case CIT_SETATTR:
	case CIT_DATA_VERSION:
		result = +1;
		break;
	case CIT_WRITE:
		result = -EBADF;
		break;
	case CIT_FAULT:
		result = -EFAULT;
		CERROR("Page fault on a file without stripes: "DFID"\n",
		       PFID(lu_object_fid(&obj->co_lu)));
		break;
	}
	if (result == 0) {
		cl_io_slice_add(io, &lio->lis_cl, obj, &lov_empty_io_ops);
		atomic_inc(&lov->lo_active_ios);
	}

	io->ci_result = result < 0 ? result : 0;
	RETURN(result);
}

int lov_io_init_released(const struct lu_env *env, struct cl_object *obj,
			struct cl_io *io)
{
	struct lov_object *lov = cl2lov(obj);
	struct lov_io *lio = lov_env_io(env);
	int result;
	ENTRY;

	LASSERT(lov->lo_lsm != NULL);
	lio->lis_object = lov;

	switch (io->ci_type) {
	default:
		LASSERTF(0, "invalid type %d\n", io->ci_type);
		result = -EOPNOTSUPP;
		break;
	case CIT_MISC:
	case CIT_FSYNC:
	case CIT_LADVISE:
	case CIT_DATA_VERSION:
		result = 1;
		break;
	case CIT_SETATTR:
		/* the truncate to 0 is managed by MDT:
		 * - in open, for open O_TRUNC
		 * - in setattr, for truncate
		 */
		/* the truncate is for size > 0 so triggers a restore */
		if (cl_io_is_trunc(io)) {
			io->ci_restore_needed = 1;
			result = -ENODATA;
		} else
			result = 1;
		break;
	case CIT_READ:
	case CIT_WRITE:
	case CIT_FAULT:
		io->ci_restore_needed = 1;
		result = -ENODATA;
		break;
	}

	if (result == 0) {
		cl_io_slice_add(io, &lio->lis_cl, obj, &lov_empty_io_ops);
		atomic_inc(&lov->lo_active_ios);
	}

	io->ci_result = result < 0 ? result : 0;
	RETURN(result);
}
/** @} lov */
