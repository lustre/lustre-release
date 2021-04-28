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

	if (sub) {
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

	if (sub->sub_env && !IS_ERR(sub->sub_env)) {
		cl_env_put(sub->sub_env, &sub->sub_refcheck);
		sub->sub_env = NULL;
	}
	EXIT;
}

static inline bool
is_index_within_mirror(struct lov_object *lov, int index, int mirror_index)
{
	struct lov_layout_composite *comp = &lov->u.composite;
	struct lov_mirror_entry *lre = &comp->lo_mirrors[mirror_index];

	return (index >= lre->lre_start && index <= lre->lre_end);
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

	LASSERTF(ergo(lov_is_flr(lov),
		      is_index_within_mirror(lov, index,
					     lio->lis_mirror_index)),
		 DFID "iot = %d, index = %d, mirror = %d\n",
		 PFID(lu_object_fid(lov2lu(lov))), io->ci_type, index,
		 lio->lis_mirror_index);

	/* obtain new environment */
	sub->sub_env = cl_env_get(&sub->sub_refcheck);
	if (IS_ERR(sub->sub_env)) {
		result = PTR_ERR(sub->sub_env);
		RETURN(result);
	}

	sub_obj = lovsub2cl(lov_r0(lov, index)->lo_sub[stripe]);
	sub_io  = &sub->sub_io;

	sub_io->ci_obj    = sub_obj;
	sub_io->ci_result = 0;

	sub_io->ci_parent  = io;
	sub_io->ci_lockreq = io->ci_lockreq;
	sub_io->ci_type    = io->ci_type;
	sub_io->ci_no_srvlock = io->ci_no_srvlock;
	sub_io->ci_noatime = io->ci_noatime;
	sub_io->ci_async_readahead = io->ci_async_readahead;
	sub_io->ci_lock_no_expand = io->ci_lock_no_expand;
	sub_io->ci_ndelay = io->ci_ndelay;
	sub_io->ci_layout_version = io->ci_layout_version;
	sub_io->ci_tried_all_mirrors = io->ci_tried_all_mirrors;

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
		if (!sub)
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
	else
		sub->sub_io.ci_noquota = lio->lis_cl.cis_io->ci_noquota;
	RETURN(sub);
}

/*****************************************************************************
 *
 * Lov io operations.
 *
 */
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

/**
 * Decide if it will need write intent RPC
 */
static int lov_io_mirror_write_intent(struct lov_io *lio,
	struct lov_object *obj, struct cl_io *io)
{
	struct lov_layout_composite *comp = &obj->u.composite;
	struct lu_extent *ext = &io->ci_write_intent;
	struct lov_mirror_entry *lre;
	struct lov_mirror_entry *primary;
	struct lov_layout_entry *lle;
	size_t count = 0;
	ENTRY;

	*ext = (typeof(*ext)) { lio->lis_pos, lio->lis_endpos };
	io->ci_need_write_intent = 0;

	if (!(io->ci_type == CIT_WRITE || cl_io_is_mkwrite(io) ||
	      cl_io_is_fallocate(io) || cl_io_is_trunc(io) ||
	      cl_io_is_fault_writable(io)))
		RETURN(0);

	/*
	 * FLR: check if it needs to send a write intent RPC to server.
	 * Writing to sync_pending file needs write intent RPC to change
	 * the file state back to write_pending, so that the layout version
	 * can be increased when the state changes to sync_pending at a later
	 * time. Otherwise there exists a chance that an evicted client may
	 * dirty the file data while resync client is working on it.
	 * Designated I/O is allowed for resync workload.
	 */
	if (lov_flr_state(obj) == LCM_FL_RDONLY ||
	    (lov_flr_state(obj) == LCM_FL_SYNC_PENDING &&
	     io->ci_designated_mirror == 0)) {
		io->ci_need_write_intent = 1;
		RETURN(0);
	}

	LASSERT((lov_flr_state(obj) == LCM_FL_WRITE_PENDING));
	LASSERT(comp->lo_preferred_mirror >= 0);

	/*
	 * need to iterate all components to see if there are
	 * multiple components covering the writing component
	 */
	primary = &comp->lo_mirrors[comp->lo_preferred_mirror];
	LASSERT(!primary->lre_stale);
	lov_foreach_mirror_layout_entry(obj, lle, primary) {
		LASSERT(lle->lle_valid);
		if (!lu_extent_is_overlapped(ext, lle->lle_extent))
			continue;

		ext->e_start = min(ext->e_start, lle->lle_extent->e_start);
		ext->e_end = max(ext->e_end, lle->lle_extent->e_end);
		++count;
	}
	if (count == 0) {
		CERROR(DFID ": cannot find any valid components covering "
		       "file extent "DEXT", mirror: %d\n",
		       PFID(lu_object_fid(lov2lu(obj))), PEXT(ext),
		       primary->lre_mirror_id);
		RETURN(-EIO);
	}

	count = 0;
	lov_foreach_mirror_entry(obj, lre) {
		if (lre == primary)
			continue;

		lov_foreach_mirror_layout_entry(obj, lle, lre) {
			if (!lle->lle_valid)
				continue;

			if (lu_extent_is_overlapped(ext, lle->lle_extent)) {
				++count;
				break;
			}
		}
	}

	CDEBUG(D_VFSTRACE, DFID "there are %zd components to be staled to "
	       "modify file extent "DEXT", iot: %d\n",
	       PFID(lu_object_fid(lov2lu(obj))), count, PEXT(ext), io->ci_type);

	io->ci_need_write_intent = count > 0;

	RETURN(0);
}

static int lov_io_mirror_init(struct lov_io *lio, struct lov_object *obj,
			       struct cl_io *io)
{
	struct lov_layout_composite *comp = &obj->u.composite;
	int index;
	int i;
	int result;
	ENTRY;

	if (!lov_is_flr(obj)) {
		/* only locks/pages are manipulated for CIT_MISC op, no
		 * cl_io_loop() will be called, don't check/set mirror info.
		 */
		if (io->ci_type != CIT_MISC) {
			LASSERT(comp->lo_preferred_mirror == 0);
			lio->lis_mirror_index = comp->lo_preferred_mirror;
		}
		io->ci_ndelay = 0;
		RETURN(0);
	}

	/* transfer the layout version for verification */
	if (io->ci_layout_version == 0)
		io->ci_layout_version = obj->lo_lsm->lsm_layout_gen;

	/* find the corresponding mirror for designated mirror IO */
	if (io->ci_designated_mirror > 0) {
		struct lov_mirror_entry *entry;

		LASSERT(!io->ci_ndelay);

		CDEBUG(D_LAYOUT, "designated I/O mirror state: %d\n",
		      lov_flr_state(obj));

		if ((cl_io_is_trunc(io) || io->ci_type == CIT_WRITE) &&
		    (io->ci_layout_version != obj->lo_lsm->lsm_layout_gen)) {
			/*
			 * For resync I/O, the ci_layout_version was the layout
			 * version when resync starts. If it doesn't match the
			 * current object layout version, it means the layout
			 * has been changed
			 */
			RETURN(-ESTALE);
		}

		io->ci_layout_version |= LU_LAYOUT_RESYNC;

		index = 0;
		lio->lis_mirror_index = -1;
		lov_foreach_mirror_entry(obj, entry) {
			if (entry->lre_mirror_id ==
			    io->ci_designated_mirror) {
				lio->lis_mirror_index = index;
				break;
			}

			index++;
		}

		RETURN(lio->lis_mirror_index < 0 ? -EINVAL : 0);
	}

	result = lov_io_mirror_write_intent(lio, obj, io);
	if (result)
		RETURN(result);

	if (io->ci_need_write_intent) {
		CDEBUG(D_VFSTRACE, DFID " need write intent for [%llu, %llu)\n",
		       PFID(lu_object_fid(lov2lu(obj))),
		       lio->lis_pos, lio->lis_endpos);

		if (cl_io_is_trunc(io)) {
			/**
			 * for truncate, we uses [size, EOF) to judge whether
			 * a write intent needs to be send, but we need to
			 * restore the write extent to [0, size], in truncate,
			 * the byte in the size position is accessed.
			 */
			io->ci_write_intent.e_start = 0;
			io->ci_write_intent.e_end =
					io->u.ci_setattr.sa_attr.lvb_size + 1;
		}
		/* stop cl_io_init() loop */
		RETURN(1);
	}

	if (io->ci_ndelay_tried == 0 || /* first time to try */
	    /* reset the mirror index if layout has changed */
	    lio->lis_mirror_layout_gen != obj->lo_lsm->lsm_layout_gen) {
		lio->lis_mirror_layout_gen = obj->lo_lsm->lsm_layout_gen;
		index = lio->lis_mirror_index = comp->lo_preferred_mirror;
	} else {
		index = lio->lis_mirror_index;
		LASSERT(index >= 0);

		/* move mirror index to the next one */
		index = (index + 1) % comp->lo_mirror_count;
	}

	for (i = 0; i < comp->lo_mirror_count; i++) {
		struct lu_extent ext = { .e_start = lio->lis_pos,
					 .e_end   = lio->lis_pos + 1 };
		struct lov_mirror_entry *lre;
		struct lov_layout_entry *lle;
		bool found = false;

		lre = &comp->lo_mirrors[(index + i) % comp->lo_mirror_count];
		if (!lre->lre_valid)
			continue;

		if (lre->lre_foreign)
			continue;

		lov_foreach_mirror_layout_entry(obj, lle, lre) {
			if (!lle->lle_valid)
				continue;

			if (lu_extent_is_overlapped(&ext, lle->lle_extent)) {
				found = true;
				break;
			}
		} /* each component of the mirror */
		if (found) {
			index = (index + i) % comp->lo_mirror_count;
			break;
		}
	} /* each mirror */

	if (i == comp->lo_mirror_count) {
		CERROR(DFID": failed to find a component covering "
		       "I/O region at %llu\n",
		       PFID(lu_object_fid(lov2lu(obj))), lio->lis_pos);

		dump_lsm(D_ERROR, obj->lo_lsm);

		RETURN(-EIO);
	}

	CDEBUG(D_VFSTRACE, DFID ": flr state: %d, move mirror from %d to %d, "
	       "have retried: %d, mirror count: %d\n",
	       PFID(lu_object_fid(lov2lu(obj))), lov_flr_state(obj),
	       lio->lis_mirror_index, index, io->ci_ndelay_tried,
	       comp->lo_mirror_count);

	lio->lis_mirror_index = index;

	/*
	 * FLR: if all mirrors have been tried once, most likely the network
	 * of this client has been partitioned. We should relinquish CPU for
	 * a while before trying again.
	 */
	if (io->ci_ndelay && io->ci_ndelay_tried > 0 &&
	    (io->ci_ndelay_tried % comp->lo_mirror_count == 0)) {
		schedule_timeout_interruptible(cfs_time_seconds(1) / 100);
		if (signal_pending(current))
			RETURN(-EINTR);

		/**
		 * we'd set ci_tried_all_mirrors to turn off fast mirror
		 * switching for read after we've tried all mirrors several
		 * rounds.
		 */
		io->ci_tried_all_mirrors = io->ci_ndelay_tried %
					   (comp->lo_mirror_count * 4) == 0;
	}
	++io->ci_ndelay_tried;

	CDEBUG(D_VFSTRACE, "use %sdelayed RPC state for this IO\n",
	       io->ci_ndelay ? "non-" : "");

	RETURN(0);
}

static int lov_io_slice_init(struct lov_io *lio,
			     struct lov_object *obj, struct cl_io *io)
{
	int index;
	int result = 0;
	ENTRY;

	io->ci_result = 0;
	lio->lis_object = obj;

	switch (io->ci_type) {
	case CIT_READ:
	case CIT_WRITE:
		lio->lis_pos = io->u.ci_rw.crw_pos;
		lio->lis_endpos = io->u.ci_rw.crw_pos + io->u.ci_rw.crw_count;
		lio->lis_io_endpos = lio->lis_endpos;
		if (cl_io_is_append(io)) {
			LASSERT(io->ci_type == CIT_WRITE);

			/*
			 * If there is LOV EA hole, then we may cannot locate
			 * the current file-tail exactly.
			 */
			if (unlikely(obj->lo_lsm->lsm_entries[0]->lsme_pattern &
				     LOV_PATTERN_F_HOLE))
				GOTO(out, result = -EIO);

			lio->lis_pos = 0;
			lio->lis_endpos = OBD_OBJECT_EOF;
		}
		break;

	case CIT_SETATTR:
		if (cl_io_is_fallocate(io)) {
			lio->lis_pos = io->u.ci_setattr.sa_falloc_offset;
			lio->lis_endpos = io->u.ci_setattr.sa_falloc_end;
		} else if (cl_io_is_trunc(io)) {
			lio->lis_pos = io->u.ci_setattr.sa_attr.lvb_size;
			lio->lis_endpos = OBD_OBJECT_EOF;
		} else {
			lio->lis_pos = 0;
			lio->lis_endpos = OBD_OBJECT_EOF;
		}
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

	case CIT_LSEEK: {
		lio->lis_pos = io->u.ci_lseek.ls_start;
		lio->lis_endpos = OBD_OBJECT_EOF;
		break;
	}

	case CIT_GLIMPSE:
		lio->lis_pos = 0;
		lio->lis_endpos = OBD_OBJECT_EOF;

		if (lov_flr_state(obj) == LCM_FL_RDONLY &&
		    !OBD_FAIL_CHECK(OBD_FAIL_FLR_GLIMPSE_IMMUTABLE))
			/* SoM is accurate, no need glimpse */
			GOTO(out, result = 1);
		break;

	case CIT_MISC:
		lio->lis_pos = 0;
		lio->lis_endpos = OBD_OBJECT_EOF;
		break;

	default:
		LBUG();
	}

	/*
	 * CIT_MISC + ci_ignore_layout can identify the I/O from the OSC layer,
	 * it won't care/access lov layout related info.
	 */
	if (io->ci_ignore_layout && io->ci_type == CIT_MISC)
		GOTO(out, result = 0);

	LASSERT(obj->lo_lsm != NULL);

	result = lov_io_mirror_init(lio, obj, io);
	if (result)
		GOTO(out, result);

	/* check if it needs to instantiate layout */
	if (!(io->ci_type == CIT_WRITE || cl_io_is_mkwrite(io) ||
	      cl_io_is_fallocate(io) ||
	      (cl_io_is_trunc(io) && io->u.ci_setattr.sa_attr.lvb_size > 0)) ||
	      cl_io_is_fault_writable(io))
		GOTO(out, result = 0);

	/*
	 * for truncate, it only needs to instantiate the components
	 * before the truncated size.
	 */
	if (cl_io_is_trunc(io)) {
		io->ci_write_intent.e_start = 0;
		/* for writes, e_end is endpos, the location of the file
		 * pointer after the write is completed, so it is not accessed.
		 * For truncate, 'end' is the size, and *is* acccessed.
		 * In other words, writes are [start, end), but truncate is
		 * [start, size], where both are included.  So add 1 to the
		 * size when creating the write intent to account for this.
		 */
		io->ci_write_intent.e_end =
			io->u.ci_setattr.sa_attr.lvb_size + 1;
	} else {
		io->ci_write_intent.e_start = lio->lis_pos;
		io->ci_write_intent.e_end = lio->lis_endpos;
	}

	index = 0;
	lov_foreach_io_layout(index, lio, &io->ci_write_intent) {
		if (!lsm_entry_inited(obj->lo_lsm, index)) {
			io->ci_need_write_intent = 1;
			break;
		}
	}

	if (io->ci_need_write_intent && io->ci_designated_mirror > 0) {
		/*
		 * REINT_SYNC RPC has already tried to instantiate all of the
		 * components involved, obviously it didn't succeed. Skip this
		 * mirror for now. The server won't be able to figure out
		 * which mirror it should instantiate components
		 */
		CERROR(DFID": trying to instantiate components for designated "
		       "I/O, file state: %d\n",
		       PFID(lu_object_fid(lov2lu(obj))), lov_flr_state(obj));

		io->ci_need_write_intent = 0;
		GOTO(out, result = -EIO);
	}

	if (io->ci_need_write_intent)
		GOTO(out, result = 1);

	EXIT;

out:
	return result;
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
		wake_up(&lov->lo_waitq);
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

	switch (io->ci_type) {
	case CIT_SETATTR: {
		io->u.ci_setattr.sa_attr = parent->u.ci_setattr.sa_attr;
		io->u.ci_setattr.sa_attr_flags =
			parent->u.ci_setattr.sa_attr_flags;
		io->u.ci_setattr.sa_avalid = parent->u.ci_setattr.sa_avalid;
		io->u.ci_setattr.sa_xvalid = parent->u.ci_setattr.sa_xvalid;
		io->u.ci_setattr.sa_falloc_mode =
			parent->u.ci_setattr.sa_falloc_mode;
		io->u.ci_setattr.sa_stripe_index = stripe;
		io->u.ci_setattr.sa_parent_fid =
					parent->u.ci_setattr.sa_parent_fid;
		/* For SETATTR(fallocate) pass the subtype to lower IO */
		io->u.ci_setattr.sa_subtype = parent->u.ci_setattr.sa_subtype;
		if (cl_io_is_fallocate(io)) {
			io->u.ci_setattr.sa_falloc_offset = start;
			io->u.ci_setattr.sa_falloc_end = end;
		}
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
		io->u.ci_wr.wr_sync = cl_io_is_sync_write(parent);
		io->ci_tried_all_mirrors = parent->ci_tried_all_mirrors;
		if (cl_io_is_append(parent)) {
			io->u.ci_wr.wr_append = 1;
		} else {
			io->u.ci_rw.crw_pos = start;
			io->u.ci_rw.crw_count = end - start;
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
	case CIT_LSEEK: {
		io->u.ci_lseek.ls_start = start;
		io->u.ci_lseek.ls_whence = parent->u.ci_lseek.ls_whence;
		io->u.ci_lseek.ls_result = parent->u.ci_lseek.ls_result;
		break;
	}
	case CIT_GLIMPSE:
	case CIT_MISC:
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

static int lov_io_add_sub(const struct lu_env *env, struct lov_io *lio,
			  struct lov_io_sub *sub, u64 start, u64 end)
{
	int rc;

	end = lov_offset_mod(end, 1);
	lov_io_sub_inherit(sub, lio, start, end);
	rc = cl_io_iter_init(sub->sub_env, &sub->sub_io);
	if (rc != 0) {
		cl_io_iter_fini(sub->sub_env, &sub->sub_io);
		return rc;
	}

	list_add_tail(&sub->sub_linkage, &lio->lis_active);

	return rc;
}
static int lov_io_iter_init(const struct lu_env *env,
			    const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	struct lov_io_sub *sub;
	struct lu_extent ext;
	int index;
	int rc = 0;

	ENTRY;

	ext.e_start = lio->lis_pos;
	ext.e_end = lio->lis_endpos;

	lov_foreach_io_layout(index, lio, &ext) {
		struct lov_layout_entry *le = lov_entry(lio->lis_object, index);
		struct lov_layout_raid0 *r0 = &le->lle_raid0;
		u64 start;
		u64 end;
		int stripe;
		bool tested_trunc_stripe = false;

		r0->lo_trunc_stripeno = -1;

		CDEBUG(D_VFSTRACE, "component[%d] flags %#x\n",
		       index, lsm->lsm_entries[index]->lsme_flags);
		if (!lsm_entry_inited(lsm, index)) {
			/*
			 * Read from uninitialized components should return
			 * zero filled pages.
			 */
			continue;
		}

		if (lsm_entry_is_foreign(lsm, index))
			continue;

		if (!le->lle_valid && !ios->cis_io->ci_designated_mirror) {
			CERROR("I/O to invalid component: %d, mirror: %d\n",
			       index, lio->lis_mirror_index);
			RETURN(-EIO);
		}

		for (stripe = 0; stripe < r0->lo_nr; stripe++) {
			if (!lov_stripe_intersects(lsm, index, stripe,
						   &ext, &start, &end))
				continue;

			if (unlikely(!r0->lo_sub[stripe])) {
				if (ios->cis_io->ci_type == CIT_READ ||
				    ios->cis_io->ci_type == CIT_WRITE ||
				    ios->cis_io->ci_type == CIT_FAULT)
					RETURN(-EIO);

				continue;
			}

			if (cl_io_is_trunc(ios->cis_io) &&
			    !tested_trunc_stripe) {
				int prev;
				u64 tr_start;

				prev = (stripe == 0) ? r0->lo_nr - 1 :
							stripe - 1;
				/**
				 * Only involving previous stripe if the
				 * truncate in this component is at the
				 * beginning of this stripe.
				 */
				tested_trunc_stripe = true;
				if (ext.e_start < lsm->lsm_entries[index]->
							lsme_extent.e_start) {
					/* need previous stripe involvement */
					r0->lo_trunc_stripeno = prev;
				} else {
					tr_start = ext.e_start;
					tr_start = lov_do_div64(tr_start,
						      stripe_width(lsm, index));
					/* tr_start %= stripe_swidth */
					if (tr_start == stripe * lsm->
							lsm_entries[index]->
							lsme_stripe_size)
						r0->lo_trunc_stripeno = prev;
				}
			}

			/* if the last stripe is the trunc stripeno */
			if (r0->lo_trunc_stripeno == stripe)
				r0->lo_trunc_stripeno = -1;

			sub = lov_sub_get(env, lio,
					  lov_comp_index(index, stripe));
			if (IS_ERR(sub))
				return PTR_ERR(sub);

			rc = lov_io_add_sub(env, lio, sub, start, end);
			if (rc != 0)
				break;
		}
		if (rc != 0)
			break;

		if (r0->lo_trunc_stripeno != -1) {
			stripe = r0->lo_trunc_stripeno;
			if (unlikely(!r0->lo_sub[stripe])) {
				r0->lo_trunc_stripeno = -1;
				continue;
			}
			sub = lov_sub_get(env, lio,
					  lov_comp_index(index, stripe));
			if (IS_ERR(sub))
				return PTR_ERR(sub);

			/**
			 * the prev sub could be used by another truncate, we'd
			 * skip it. LU-14128 happends when expand truncate +
			 * read get wrong kms.
			 */
			if (!list_empty(&sub->sub_linkage)) {
				r0->lo_trunc_stripeno = -1;
				continue;
			}

			(void)lov_stripe_intersects(lsm, index, stripe, &ext,
						    &start, &end);
			rc = lov_io_add_sub(env, lio, sub, start, end);
			if (rc != 0)
				break;

		}
	}
	RETURN(rc);
}

static int lov_io_rw_iter_init(const struct lu_env *env,
			       const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = ios->cis_io;
	struct lov_stripe_md_entry *lse;
	loff_t start = io->u.ci_rw.crw_pos;
	loff_t next;
	int index;

	LASSERT(io->ci_type == CIT_READ || io->ci_type == CIT_WRITE);
	ENTRY;

	if (cl_io_is_append(io))
		RETURN(lov_io_iter_init(env, ios));

	index = lov_io_layout_at(lio, io->u.ci_rw.crw_pos);
	if (index < 0) { /* non-existing layout component */
		if (io->ci_type == CIT_READ) {
			/*
			 * TODO: it needs to detect the next component and
			 * then set the next pos
			 */
			io->ci_continue = 0;

			RETURN(lov_io_iter_init(env, ios));
		}

		RETURN(-ENODATA);
	}

	if (!lov_entry(lio->lis_object, index)->lle_valid &&
	    !io->ci_designated_mirror)
		RETURN(io->ci_type == CIT_READ ? -EAGAIN : -EIO);

	lse = lov_lse(lio->lis_object, index);

	if (lsme_is_foreign(lse))
		RETURN(-EINVAL);

	next = MAX_LFS_FILESIZE;
	if (lse->lsme_stripe_count > 1) {
		unsigned long ssize = lse->lsme_stripe_size;

		lov_do_div64(start, ssize);
		next = (start + 1) * ssize;
		if (next <= start * ssize)
			next = MAX_LFS_FILESIZE;
	}

	LASSERTF(io->u.ci_rw.crw_pos >= lse->lsme_extent.e_start,
		 "pos %lld, [%lld, %lld)\n", io->u.ci_rw.crw_pos,
		 lse->lsme_extent.e_start, lse->lsme_extent.e_end);
	next = min_t(__u64, next, lse->lsme_extent.e_end);
	next = min_t(loff_t, next, lio->lis_io_endpos);

	io->ci_continue = next < lio->lis_io_endpos;
	io->u.ci_rw.crw_count = next - io->u.ci_rw.crw_pos;
	lio->lis_pos    = io->u.ci_rw.crw_pos;
	lio->lis_endpos = io->u.ci_rw.crw_pos + io->u.ci_rw.crw_count;
	CDEBUG(D_VFSTRACE,
	       "stripe: %llu chunk: [%llu, %llu) %llu, %zd\n",
	       (__u64)start, lio->lis_pos, lio->lis_endpos,
	       (__u64)lio->lis_io_endpos, io->u.ci_rw.crw_count);

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
	int index;
	ENTRY;

	if (cl_io_is_trunc(io) && lio->lis_pos > 0) {
		index = lov_io_layout_at(lio, lio->lis_pos - 1);
		/* no entry found for such offset */
		if (index < 0)
			RETURN(io->ci_result = -ENODATA);
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
	struct cl_data_version_io *pdv = &parent->u.ci_data_version;
	struct lov_io_sub *sub;

	ENTRY;
	list_for_each_entry(sub, &lio->lis_active, sub_linkage) {
		struct cl_data_version_io *sdv = &sub->sub_io.u.ci_data_version;

		lov_io_end_wrapper(sub->sub_env, &sub->sub_io);

		pdv->dv_data_version += sdv->dv_data_version;
		if (pdv->dv_layout_version > sdv->dv_layout_version)
			pdv->dv_layout_version = sdv->dv_layout_version;

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
	index = lov_io_layout_at(lio, offset);
	if (index < 0 || !lsm_entry_inited(loo->lo_lsm, index) ||
	    lsm_entry_is_foreign(loo->lo_lsm, index))
		RETURN(-ENODATA);

	/* avoid readahead to expand to stale components */
	if (!lov_entry(loo, index)->lle_valid)
		RETURN(-EIO);

	stripe = lov_stripe_number(loo->lo_lsm, index, offset);

	r0 = lov_r0(loo, index);
	if (unlikely(!r0->lo_sub[stripe]))
		RETURN(-EIO);

	sub = lov_sub_get(env, lio, lov_comp_index(index, stripe));
	if (IS_ERR(sub))
		RETURN(PTR_ERR(sub));

	lov_stripe_offset(loo->lo_lsm, index, offset, stripe, &suboff);
	rc = cl_io_read_ahead(sub->sub_env, &sub->sub_io,
			      cl_index(lovsub2cl(r0->lo_sub[stripe]), suboff),
			      ra);

	CDEBUG(D_READA, DFID " cra_end = %lu, stripes = %d, rc = %d\n",
	       PFID(lu_object_fid(lov2lu(loo))), ra->cra_end_idx,
		    r0->lo_nr, rc);
	if (rc != 0)
		RETURN(rc);

	/**
	 * Adjust the stripe index by layout of comp. ra->cra_end is the
	 * maximum page index covered by an underlying DLM lock.
	 * This function converts cra_end from stripe level to file level, and
	 * make sure it's not beyond stripe and component boundary.
	 */

	/* cra_end is stripe level, convert it into file level */
	ra_end = ra->cra_end_idx;
	if (ra_end != CL_PAGE_EOF)
		ra->cra_end_idx = lov_stripe_pgoff(loo->lo_lsm, index,
						   ra_end, stripe);

	/* boundary of current component */
	ra_end = cl_index(obj, (loff_t)lov_io_extent(lio, index)->e_end);
	if (ra_end != CL_PAGE_EOF && ra->cra_end_idx >= ra_end)
		ra->cra_end_idx = ra_end - 1;

	if (r0->lo_nr == 1) /* single stripe file */
		RETURN(0);

	pps = lov_lse(loo, index)->lsme_stripe_size >> PAGE_SHIFT;

	CDEBUG(D_READA, DFID " max_index = %lu, pps = %u, index = %d, "
	       "stripe_size = %u, stripe no = %u, start index = %lu\n",
	       PFID(lu_object_fid(lov2lu(loo))), ra->cra_end_idx, pps, index,
	       lov_lse(loo, index)->lsme_stripe_size, stripe, start);

	/* never exceed the end of the stripe */
	ra->cra_end_idx = min_t(pgoff_t, ra->cra_end_idx,
				start + pps - start % pps - 1);
	RETURN(0);
}

int lov_io_lru_reserve(const struct lu_env *env,
		       const struct cl_io_slice *ios, loff_t pos, size_t bytes)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	struct lov_io_sub *sub;
	struct lu_extent ext;
	int index;
	int rc = 0;

	ENTRY;

	ext.e_start = pos;
	ext.e_end = pos + bytes;
	lov_foreach_io_layout(index, lio, &ext) {
		struct lov_layout_entry *le = lov_entry(lio->lis_object, index);
		struct lov_layout_raid0 *r0 = &le->lle_raid0;
		u64 start;
		u64 end;
		int stripe;

		if (!lsm_entry_inited(lsm, index))
			continue;

		if (!le->lle_valid && !ios->cis_io->ci_designated_mirror) {
			CERROR(DFID": I/O to invalid component: %d, mirror: %d\n",
			       PFID(lu_object_fid(lov2lu(lio->lis_object))),
			       index, lio->lis_mirror_index);
			RETURN(-EIO);
		}

		for (stripe = 0; stripe < r0->lo_nr; stripe++) {
			if (!lov_stripe_intersects(lsm, index, stripe,
						   &ext, &start, &end))
				continue;

			if (unlikely(!r0->lo_sub[stripe]))
				RETURN(-EIO);

			sub = lov_sub_get(env, lio,
					  lov_comp_index(index, stripe));
			if (IS_ERR(sub))
				return PTR_ERR(sub);

			rc = cl_io_lru_reserve(sub->sub_env, &sub->sub_io, start,
					       end - start + 1);
			if (rc != 0)
				RETURN(rc);
		}
	}

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
	struct cl_page		*tmp;
	int index;
	int rc = 0;
	ENTRY;

	cl_page_list_init(plist);
	while (qin->pl_nr > 0) {
		struct cl_2queue  *cl2q = &lov_env_info(env)->lti_cl2q;

		page = cl_page_list_first(qin);
		if (lov_page_is_empty(page)) {
			cl_page_list_move(&queue->c2_qout, qin, page);

			/*
			 * it could only be mirror read to get here therefore
			 * the pages will be transient. We don't care about
			 * the return code of cl_page_prep() at all.
			 */
			(void) cl_page_prep(env, ios->cis_io, page, crt);
			cl_page_completion(env, page, crt, 0);
			continue;
		}

		cl_2queue_init(cl2q);
		cl_page_list_move(&cl2q->c2_qin, qin, page);

		index = page->cp_lov_index;
		cl_page_list_for_each_safe(page, tmp, qin) {
			/* this page is not on this stripe */
			if (index != page->cp_lov_index)
				continue;

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
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_io_sub *sub;
	struct cl_page *page;
	int rc = 0;
	ENTRY;

	if (lio->lis_nr_subios == 1) {
		int idx = lio->lis_single_subio_index;

		LASSERT(!lov_page_is_empty(cl_page_list_first(queue)));

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
		LASSERT(!lov_page_is_empty(page));

		cl_page_list_move(plist, queue, page);

		index = page->cp_lov_index;
		while (queue->pl_nr > 0) {
			page = cl_page_list_first(queue);
			if (index != page->cp_lov_index)
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

		if (lov_comp_entry(index) !=
		    lov_comp_entry(page->cp_lov_index))
			cl_io_extent_release(sub->sub_env, &sub->sub_io);
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
	loff_t offset;
	int entry;
	int stripe;

	ENTRY;

	fio = &ios->cis_io->u.ci_fault;
	lio = cl2lov_io(env, ios);

	/**
	 * LU-14502: ft_page could be an existing cl_page associated with
	 * the vmpage covering the fault index, and the page may still
	 * refer to another mirror of an old IO.
	 */
	if (lov_is_flr(lio->lis_object)) {
		offset = cl_offset(ios->cis_obj, fio->ft_index);
		entry = lov_io_layout_at(lio, offset);
		if (entry < 0) {
			CERROR(DFID": page fault index %lu invalid component: "
			       "%d, mirror: %d\n",
			       PFID(lu_object_fid(&ios->cis_obj->co_lu)),
			       fio->ft_index, entry,
			       lio->lis_mirror_index);
			RETURN(-EIO);
		}
		stripe = lov_stripe_number(lio->lis_object->lo_lsm,
					   entry, offset);

		if (fio->ft_page->cp_lov_index !=
		    lov_comp_index(entry, stripe)) {
			CDEBUG(D_INFO, DFID": page fault at index %lu, "
			       "at mirror %u comp entry %u stripe %u, "
			       "been used with comp entry %u stripe %u\n",
			       PFID(lu_object_fid(&ios->cis_obj->co_lu)),
			       fio->ft_index, lio->lis_mirror_index,
			       entry, stripe,
			       lov_comp_entry(fio->ft_page->cp_lov_index),
			       lov_comp_stripe(fio->ft_page->cp_lov_index));

			fio->ft_page->cp_lov_index =
					lov_comp_index(entry, stripe);
		}
	}

	sub = lov_sub_get(env, lio, fio->ft_page->cp_lov_index);
	sub->sub_io.u.ci_fault.ft_nob = fio->ft_nob;

	RETURN(lov_io_start(env, ios));
}

static int lov_io_setattr_start(const struct lu_env *env,
				const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *parent = ios->cis_io;
	struct lov_io_sub *sub;
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;

	ENTRY;

	if (cl_io_is_fallocate(parent)) {
		list_for_each_entry(sub, &lio->lis_active, sub_linkage) {
			loff_t size = parent->u.ci_setattr.sa_attr.lvb_size;
			int index = lov_comp_entry(sub->sub_subio_index);
			int stripe = lov_comp_stripe(sub->sub_subio_index);

			size = lov_size_to_stripe(lsm, index, size, stripe);
			sub->sub_io.u.ci_setattr.sa_attr.lvb_size = size;
			sub->sub_io.u.ci_setattr.sa_avalid =
						parent->u.ci_setattr.sa_avalid;
		}
	}

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

static void lov_io_lseek_end(const struct lu_env *env,
			     const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = lio->lis_cl.cis_io;
	struct lov_stripe_md *lsm = lio->lis_object->lo_lsm;
	struct lov_io_sub *sub;
	loff_t offset = -ENXIO;
	__u64 hole_off = 0;
	bool seek_hole = io->u.ci_lseek.ls_whence == SEEK_HOLE;

	ENTRY;

	list_for_each_entry(sub, &lio->lis_active, sub_linkage) {
		struct cl_io *subio = &sub->sub_io;
		int index = lov_comp_entry(sub->sub_subio_index);
		int stripe = lov_comp_stripe(sub->sub_subio_index);
		loff_t sub_off, lov_off;
		__u64 comp_end = lsm->lsm_entries[index]->lsme_extent.e_end;

		lov_io_end_wrapper(sub->sub_env, subio);

		if (io->ci_result == 0)
			io->ci_result = sub->sub_io.ci_result;

		if (io->ci_result)
			continue;

		CDEBUG(D_INFO, DFID": entry %x stripe %u: SEEK_%s from %lld\n",
		       PFID(lu_object_fid(lov2lu(lio->lis_object))),
		       index, stripe, seek_hole ? "HOLE" : "DATA",
		       subio->u.ci_lseek.ls_start);

		/* first subio with positive result is what we need */
		sub_off = subio->u.ci_lseek.ls_result;
		/* Expected error, offset is out of stripe file size */
		if (sub_off == -ENXIO)
			continue;
		/* Any other errors are not expected with ci_result == 0 */
		if (sub_off < 0) {
			CDEBUG(D_INFO, "unexpected error: rc = %lld\n",
			       sub_off);
			io->ci_result = sub_off;
			continue;
		}
		lov_off = lov_stripe_size(lsm, index, sub_off + 1, stripe) - 1;
		if (lov_off < 0) {
			/* the only way to get negatove lov_off here is too big
			 * result. Return -EOVERFLOW then.
			 */
			io->ci_result = -EOVERFLOW;
			CDEBUG(D_INFO, "offset %llu is too big: rc = %d\n",
			       (u64)lov_off, io->ci_result);
			continue;
		}
		if (lov_off < io->u.ci_lseek.ls_start) {
			io->ci_result = -EINVAL;
			CDEBUG(D_INFO, "offset %lld < start %lld: rc = %d\n",
			       sub_off, io->u.ci_lseek.ls_start, io->ci_result);
			continue;
		}
		/* resulting offset can be out of component range if stripe
		 * object is full and its file size was returned as virtual
		 * hole start. Skip this result, the next component will give
		 * us correct lseek result but keep possible hole offset in
		 * case there is no more components ahead
		 */
		if (lov_off >= comp_end) {
			/* must be SEEK_HOLE case */
			if (likely(seek_hole)) {
				/* save comp end as potential hole offset */
				hole_off = max_t(__u64, comp_end, hole_off);
			} else {
				io->ci_result = -EINVAL;
				CDEBUG(D_INFO,
				       "off %lld >= comp_end %llu: rc = %d\n",
				       lov_off, comp_end, io->ci_result);
			}
			continue;
		}

		CDEBUG(D_INFO, "SEEK_%s: %lld->%lld/%lld: rc = %d\n",
		       seek_hole ? "HOLE" : "DATA",
		       subio->u.ci_lseek.ls_start, sub_off, lov_off,
		       sub->sub_io.ci_result);
		offset = min_t(__u64, offset, lov_off);
	}
	/* no result but some component returns hole as component end */
	if (seek_hole && offset == -ENXIO && hole_off > 0)
		offset = hole_off;

	io->u.ci_lseek.ls_result = offset;
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
			.cio_start     = lov_io_setattr_start,
			.cio_end       = lov_io_end
		},
		[CIT_DATA_VERSION] = {
			.cio_fini       = lov_io_fini,
			.cio_iter_init  = lov_io_iter_init,
			.cio_iter_fini  = lov_io_iter_fini,
			.cio_lock       = lov_io_lock,
			.cio_unlock     = lov_io_unlock,
			.cio_start      = lov_io_start,
			.cio_end        = lov_io_data_version_end,
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
		[CIT_LSEEK] = {
			.cio_fini      = lov_io_fini,
			.cio_iter_init = lov_io_iter_init,
			.cio_iter_fini = lov_io_iter_fini,
			.cio_lock      = lov_io_lock,
			.cio_unlock    = lov_io_unlock,
			.cio_start     = lov_io_start,
			.cio_end       = lov_io_lseek_end
		},
		[CIT_GLIMPSE] = {
			.cio_fini      = lov_io_fini,
		},
		[CIT_MISC] = {
			.cio_fini      = lov_io_fini
		}
	},
	.cio_read_ahead                = lov_io_read_ahead,
	.cio_lru_reserve	       = lov_io_lru_reserve,
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
		wake_up(&lov->lo_waitq);
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
		[CIT_GLIMPSE] = {
			.cio_fini      = lov_empty_io_fini
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
	struct lov_io *lio = lov_env_io(env);
	struct lov_object *lov = cl2lov(obj);
	int result;

	ENTRY;

	INIT_LIST_HEAD(&lio->lis_active);
	result = lov_io_slice_init(lio, lov, io);
	if (result)
		GOTO(out, result);

	result = lov_io_subio_init(env, lio, io);
	if (!result) {
		cl_io_slice_add(io, &lio->lis_cl, obj, &lov_io_ops);
		atomic_inc(&lov->lo_active_ios);
	}
	EXIT;
out:
	io->ci_result = result < 0 ? result : 0;
	return result;
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
	case CIT_GLIMPSE:
	case CIT_READ:
		result = 0;
		break;
	case CIT_FSYNC:
	case CIT_LADVISE:
	case CIT_LSEEK:
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
	case CIT_GLIMPSE:
	case CIT_MISC:
	case CIT_FSYNC:
	case CIT_LADVISE:
	case CIT_DATA_VERSION:
		result = 1;
		break;
	case CIT_SETATTR:
		/*
		 * the truncate to 0 is managed by MDT:
		 * - in open, for open O_TRUNC
		 * - in setattr, for truncate
		 */
		/*
		 * the truncate is for size > 0 so triggers a restore,
		 * also trigger a restore for prealloc/punch
		 */
		if (cl_io_is_trunc(io) || cl_io_is_fallocate(io)) {
			io->ci_restore_needed = 1;
			result = -ENODATA;
		} else
			result = 1;
		break;
	case CIT_READ:
	case CIT_WRITE:
	case CIT_FAULT:
	case CIT_LSEEK:
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

/**
 * Return the index in composite:lo_entries by the file offset
 */
int lov_io_layout_at(struct lov_io *lio, __u64 offset)
{
	struct lov_object *lov = lio->lis_object;
	struct lov_layout_composite *comp = &lov->u.composite;
	int start_index = 0;
	int end_index = comp->lo_entry_count - 1;
	int i;

	LASSERT(lov->lo_type == LLT_COMP);

	/* This is actual file offset so nothing can cover eof. */
	if (offset == LUSTRE_EOF)
		return -1;

	if (lov_is_flr(lov)) {
		struct lov_mirror_entry *lre;

		LASSERT(lio->lis_mirror_index >= 0);

		lre = &comp->lo_mirrors[lio->lis_mirror_index];
		start_index = lre->lre_start;
		end_index = lre->lre_end;
	}

	for (i = start_index; i <= end_index; i++) {
		struct lov_layout_entry *lle = lov_entry(lov, i);

		LASSERT(!lsme_is_foreign(lle->lle_lsme));

		if ((offset >= lle->lle_extent->e_start &&
		     offset < lle->lle_extent->e_end) ||
		    (offset == OBD_OBJECT_EOF &&
		     lle->lle_extent->e_end == OBD_OBJECT_EOF))
			return i;
	}

	return -1;
}

/** @} lov */
