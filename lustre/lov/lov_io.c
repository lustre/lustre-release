// SPDX-License-Identifier: GPL-2.0

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
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Jinshan Xiong <jinshan.xiong@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <linux/lustre/erasure_code.h>
#include "lov_cl_internal.h"

/** \addtogroup lov
 *  @{
 */

/**
 * lov_sub_alloc() - Allocate a new sub IO
 * @lio: top level lov IO structure
 * @index: index into lov (stripe)
 *
 * Return Pointer to allocated lov_io_sub structure
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

/**
 * lov_sub_free() - Release a sub IO
 * @lio: top level lov IO structure
 * @sub: sub io to individual stripe
 */
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
	struct lov_mirror_entry *lre;

	if (mirror_index < 0)
		return false;

	lre = lov_mirror_entry(lov, mirror_index);

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
		      /* within data mirror */
		      is_index_within_mirror(lov, index,
					     lio->lis_mirror_index) ||
		      /* within parity mirror */
		      is_index_within_mirror(lov, index,
					     lov_parity_mirror_index_from_data(
						     lio,
						     lio->lis_mirror_index))),
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
	sub_io->ci_parity_io = io->ci_parity_io;
	sub_io->ci_parity_eof = io->ci_parity_eof;

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

/*
 * Lov io operations.
 */

/**
 * lov_io_subio_init() -  Initilize LOV I/O operation
 * @env: lustre environment
 * @lio: Pointer to struct lov_io
 * @io: highlevel I/O request
 *
 * Return:
 * * %0 on success
 * * %negative on failure
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

/*
 * Decide if it will need write intent RPC
 */
static int lov_io_mirror_write_intent(struct lov_io *lio,
	struct lov_object *obj, struct cl_io *io)
{
	struct lu_object *lobj = lov2lu(obj);
	struct lov_device *dev = lov_object_dev(obj);
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
	      cl_io_is_fallocate(io) || cl_io_is_trunc(io)))
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
	if (primary->lre_stale || !primary->lre_valid) {
		/**
		 * new server could pick a primary mirror which old client
		 * does not recognize, and old client would mark it as
		 * invalid.
		 */
		CERROR("%s:"DFID": cannot find known valid non-stale mirror, could be new server picked a mirror which this client "
		       "does not recognize.\n",
		       lov2obd(dev->ld_lov)->obd_name,
		       PFID(lu_object_fid(lobj)));
		RETURN(-EIO);
	}

	lov_foreach_mirror_layout_entry(obj, lle, primary) {
		LASSERT(lle->lle_valid);
		if (!lu_extent_is_overlapped(ext, lle->lle_extent))
			continue;

		ext->e_start = min(ext->e_start, lle->lle_extent->e_start);
		ext->e_end = max(ext->e_end, lle->lle_extent->e_end);
		++count;
	}
	if (count == 0) {
		CERROR("%s:"DFID": cannot find any valid components covering file extent "
		       DEXT", mirror: %d\n",
		       lov2obd(dev->ld_lov)->obd_name,
		       PFID(lu_object_fid(lobj)), PEXT(ext),
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

	CDEBUG(D_VFSTRACE, DFID "there are %zd components to be staled to modify file extent "
	       DEXT", iot: %d\n",
	       PFID(lu_object_fid(lobj)), count, PEXT(ext), io->ci_type);

	io->ci_need_write_intent = count > 0;

	RETURN(0);
}

static bool lov_find_comp_with_ec(struct lov_io *lio, struct lov_object *lov,
				  int *mirror_index)
{
	struct lov_device *dev = lov_object_dev(lov);
	struct lov_layout_composite *comp = &lov->u.composite;
	struct lu_extent ext = { .e_start = lio->lis_pos,
				 .e_end = lio->lis_endpos };
	unsigned short mirror_count;
	__u16 data_mirror_id;
	int i;

	ENTRY;
	/* EC components are only used in FLR */
	if (!lov_is_flr(lov))
		RETURN(false);

	mirror_count = comp->lo_mirror_count;
	for (i = 0; i < mirror_count; i++) {
		struct lov_layout_entry *parity_lle = NULL;
		struct lov_layout_entry *lle;

		lov_foreach_mirror_layout_entry(lov, lle,
						&comp->lo_mirrors[i]) {
			if (!(lle->lle_lsme->lsme_flags & LCME_FL_PARITY))
				continue;

			/* parity component */
			if (lu_extent_is_overlapped(&ext, lle->lle_extent)) {
				if (lle->lle_lsme->lsme_flags & LCME_FL_STALE) {
					/* skip stale parity component */
					parity_lle = NULL;
					break;
				}

				/*
				 * capture the match while 'lle' is valid --
				 * after the loop it points one past the last
				 * entry (lle_lsme == NULL).
				 */
				parity_lle = lle;
			}
		}
		if (parity_lle) {
			/*
			 * a parity component's mirror_link_id is the id of
			 * the data mirror it protects.
			 */
			data_mirror_id =
				parity_lle->lle_lsme->lsme_mirror_link_id;
			*mirror_index = lov_mirror_index_by_id(
							lov, data_mirror_id);
			if (*mirror_index < 0) {
				CERROR("%s:"DFID": failed to find data mirror %u: rc = %d\n",
				       lov2obd(dev->ld_lov)->obd_name,
				       PFID(lu_object_fid(lov2lu(lov))),
				       data_mirror_id, *mirror_index);
				RETURN(false);
			}
			RETURN(true);
		}
	}

	RETURN(false);
}

/**
 * lov_io_parity_size_comp() - Parity byte span for one data/parity pair
 * @data_lsme: data component stripe metadata
 * @parity_lsme: parity component stripe metadata
 * @data_end: exclusive end of data in file offset space
 *
 * Returns how many bytes of parity are written for data in
 * [data_lsme->lsme_extent.e_start, data_end).
 * May overestimate (holes) but must not be short.
 */
static loff_t lov_io_parity_size_comp(struct lov_stripe_md_entry *data_lsme,
				      struct lov_stripe_md_entry *parity_lsme,
				      loff_t data_end)
{
	struct ec_split_comp sc;
	loff_t comp_start = data_lsme->lsme_extent.e_start;
	loff_t data_upto;
	__u64 stripe_set_size;
	__u64 num_stripe_sets;
	__u64 data_in_extent;
	int num_raid_sets;

	if (data_end <= comp_start)
		return 0;

	data_upto = min_t(__u64, (__u64)data_end,
			  data_lsme->lsme_extent.e_end);
	ec_split_stripes(data_lsme->lsme_stripe_count,
			 parity_lsme->lsme_dstripe_count, &sc);
	num_raid_sets = sc.esc_n0 + sc.esc_n1;

	stripe_set_size = (__u64)data_lsme->lsme_stripe_count *
			  data_lsme->lsme_stripe_size;
	data_in_extent = data_upto - comp_start;
	num_stripe_sets = (data_in_extent + stripe_set_size - 1) /
			  stripe_set_size;

	return num_stripe_sets * num_raid_sets *
	       parity_lsme->lsme_cstripe_count *
	       parity_lsme->lsme_stripe_size;
}

/**
 * lov_io_find_data_comp() - Find data component matching parity extent
 * @obj: lov object
 * @data_lre: data mirror entry
 * @parity_ext: parity component extent
 *
 * Return: matching layout entry, or NULL
 */
static struct lov_layout_entry *
lov_io_find_data_comp(struct lov_object *obj, struct lov_mirror_entry *data_lre,
		      struct lu_extent *parity_ext)
{
	struct lov_layout_entry *data_lle;

	lov_foreach_mirror_layout_entry(obj, data_lle, data_lre) {
		if (lu_extent_is_equal(parity_ext,
				       &data_lle->lle_lsme->lsme_extent))
			return data_lle;
	}

	return NULL;
}

/**
 * lov_io_parity_eof() - Parity mirror EOF from @data_size and RAID geometry
 * @obj: lov object
 * @mirror_index: parity mirror index
 * @data_size: data mirror file size
 *
 * For each parity component below @data_size, add lov_io_parity_size_comp() to
 * its extent start; return the maximum. May overestimate but not underestimate.
 *
 * Return: parity EOF in file offset space, or 0 on error
 */
static loff_t lov_io_parity_eof(struct lov_object *obj, int mirror_index,
				loff_t data_size)
{
	struct lov_device *dev = lov_object_dev(obj);
	struct lov_mirror_entry *parity_lre;
	struct lov_mirror_entry *data_lre;
	struct lov_layout_entry *parity_lle;
	struct lov_layout_entry *data_lle;
	struct lu_extent *ext;
	__u16 data_mirror_id;
	loff_t parity_eof = 0;

	if (data_size == 0)
		return 0;

	parity_lre = lov_mirror_entry(obj, mirror_index);
	parity_lle = lov_entry(obj, parity_lre->lre_start);

	if (!(parity_lle->lle_lsme->lsme_pattern & LOV_PATTERN_PARITY))
		return 0;

	data_mirror_id = parity_lle->lle_lsme->lsme_mirror_link_id;
	data_lre = lov_mirror_by_id(obj, data_mirror_id);
	if (data_lre == NULL)
		return 0;

	lov_foreach_mirror_layout_entry(obj, parity_lle, parity_lre) {
		loff_t seg_eof;

		ext = &parity_lle->lle_lsme->lsme_extent;
		if (data_size <= ext->e_start)
			continue;

		data_lle = lov_io_find_data_comp(obj, data_lre, ext);
		if (data_lle == NULL) {
			CERROR("%s:"DFID": no data component matching parity extent "DEXT" (parity mirror %u, data mirror %u)\n",
			       lov2obd(dev->ld_lov)->obd_name,
			       PFID(lu_object_fid(lov2lu(obj))), PEXT(ext),
			       parity_lre->lre_mirror_id, data_mirror_id);
			continue;
		}

		/*
		 * Or we could just find the last valid data component,
		 * e.g. the one with actual data written? For security, I
		 * prefer not to do this here.
		 */
		seg_eof = ext->e_start +
			  lov_io_parity_size_comp(data_lle->lle_lsme,
						  parity_lle->lle_lsme,
						  data_size);
		if (seg_eof > parity_eof)
			parity_eof = seg_eof;
	}

	CDEBUG(D_INODE, DFID ": parity EOF calc: data_size=%lld parity_eof=%lld\n",
	       PFID(lu_object_fid(lov2lu(obj))), data_size, parity_eof);

	return parity_eof;
}

static loff_t lov_io_top_file_size(const struct lu_env *env,
				   struct lov_object *obj)
{
	struct cl_object *top_obj = cl_object_top(&obj->lo_cl);
	struct cl_attr attr = { 0 };

	cl_object_attr_lock(top_obj);
	if (top_obj->co_ops->coo_attr_get)
		top_obj->co_ops->coo_attr_get(env, top_obj, &attr);
	cl_object_attr_unlock(top_obj);

	return attr.cat_size;
}

static int lov_io_mirror_init(const struct lu_env *env, struct lov_io *lio,
			      struct lov_object *obj, struct cl_io *io)
{
	struct lov_device *dev = lov_object_dev(obj);
	struct lov_layout_composite *comp = &obj->u.composite;
	bool skipped_parity = false;
	int index = -ENOENT;
	int i;
	int result = 0;

	ENTRY;

	if (io->ci_type == CIT_EC_RD) {
		if (lov_find_comp_with_ec(lio, obj, &index)) {
			lio->lis_mirror_index = index;
			GOTO(ndelay_retry, result);
		} else {
			result = -EIO;
			CWARN("%s: "DFID": no updated parity component to restore data: rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(obj))), result);
			RETURN(result);
		}
	}

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

		if ((cl_io_is_trunc(io) || io->ci_type == CIT_WRITE ||
		     cl_io_is_fallocate(io)) &&
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

		if (lio->lis_mirror_index < 0)
			RETURN(-EINVAL);

		/* Set ci_parity_io if this is a parity mirror */
		io->ci_parity_io =
			lov_mirror_entry(obj, lio->lis_mirror_index)->lre_parity;

		/* Calculate parity EOF if this is a parity mirror */
		if (io->ci_parity_io) {
			loff_t file_size;

			/*
			 * Get file size from the top (VVP) layer only.
			 * We can't use cl_object_attr_get() here because it
			 * walks through all layers and the LOV layer would
			 * reset cat_size to 0 before recalculating from
			 * stripe attributes (which may not be populated yet).
			 * The VVP layer's coo_attr_get reads i_size directly
			 * from the inode.
			 */
			file_size = lov_io_top_file_size(env, obj);

			io->ci_parity_eof = lov_io_parity_eof(obj,
					lio->lis_mirror_index, file_size);
			CDEBUG(D_INODE, "designated parity IO: mirror_idx=%d, "
			       "file_size=%llu, parity_eof=%lld\n",
			       lio->lis_mirror_index, file_size,
			       io->ci_parity_eof);
		}

		RETURN(0);
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

		lre = lov_mirror_entry(obj, (index + i) % comp->lo_mirror_count);
		if (!lre->lre_valid)
			continue;

		if (lre->lre_foreign)
			continue;

		/* skip parity for read/fault/lseek unless designated */
		if (lre->lre_parity &&
		    (io->ci_type == CIT_READ || io->ci_type == CIT_FAULT ||
		     io->ci_type == CIT_LSEEK) &&
		    !io->ci_designated_mirror) {
			skipped_parity = true;
			continue;
		}

		lov_foreach_mirror_layout_entry(obj, lle, lre) {
			if (!lle->lle_valid)
				continue;

			if (lu_extent_is_overlapped(&ext, lle->lle_extent)) {
				found = true;
				if (!io->ci_cross_ec &&
				    lle->lle_lsme->lsme_dstripe_count != 0)
					io->ci_cross_ec = 1;
				break;
			}
		} /* each component of the mirror */
		if (found) {
			index = (index + i) % comp->lo_mirror_count;
			break;
		}
	} /* each mirror */

	if (i == comp->lo_mirror_count) {
		/* If we only skipped parity mirrors, return EINVAL */
		if (skipped_parity) {
			CERROR(DFID": only parity mirrors available at %llu\n",
			       PFID(lu_object_fid(lov2lu(obj))), lio->lis_pos);
			RETURN(-EINVAL);
		}

		CERROR(DFID": failed to find a component covering I/O region at %llu\n",
		       PFID(lu_object_fid(lov2lu(obj))), lio->lis_pos);

		dump_lsm(D_ERROR, obj->lo_lsm);

		RETURN(-EIO);
	}

	CDEBUG(D_VFSTRACE, DFID ": flr state: %d, move mirror from %d to %d, have retried: %d, mirror count: %d\n",
	       PFID(lu_object_fid(lov2lu(obj))), lov_flr_state(obj),
	       lio->lis_mirror_index, index, io->ci_ndelay_tried,
	       comp->lo_mirror_count);

	lio->lis_mirror_index = index;

	/* Set ci_parity_io if this is a parity mirror */
	io->ci_parity_io = lov_mirror_entry(obj, index)->lre_parity;

	/* Calculate parity EOF if this is a parity mirror */
	if (io->ci_parity_io) {
		loff_t file_size;

		/*
		 * Get file size from the top (VVP) layer only.
		 * See comment in designated mirror path above.
		 */
		file_size = lov_io_top_file_size(env, obj);

		io->ci_parity_eof = lov_io_parity_eof(obj, index, file_size);
		CDEBUG(D_INODE, "mirror selection parity IO: mirror_idx=%d, "
		       "file_size=%llu, parity_eof=%lld\n",
		       index, file_size, io->ci_parity_eof);
	}

	/* we can't use parity mirrors for write unless designated */
	if (lov_mirror_entry(obj, index)->lre_parity &&
	    io->ci_type == CIT_WRITE &&
	    io->ci_designated_mirror == 0) {
		CERROR(DFID": trying to use parity mirror %d for write\n",
		       PFID(lu_object_fid(lov2lu(obj))), index);
		RETURN(-EINVAL);
	}

	/*
	 * FLR: if all mirrors have been tried once, most likely the network
	 * of this client has been partitioned. We should relinquish CPU for
	 * a while before trying again.
	 */
ndelay_retry:
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

		/* if the read crosses possible erasure code, we'd change
		 * to CIT_EC_RD trying to recover data from parity objects.
		 */
		if (io->ci_type == CIT_READ && io->ci_cross_ec) {
			CDEBUG(D_VFSTRACE, DFID " switch to CIT_EC_RD\n",
			       PFID(lu_object_fid(lov2lu(obj))));
			io->ci_switch_ec_io = 1;
			io->ci_need_restart = 1;
			io->ci_ndelay_tried = 0;
			RETURN(-ENODATA);
		}
	}
	++io->ci_ndelay_tried;

	CDEBUG(D_VFSTRACE, "use %sdelayed RPC state for this IO\n",
	       io->ci_ndelay ? "non-" : "");

	RETURN(0);
}

static int lov_io_slice_init(const struct lu_env *env, struct lov_io *lio,
			     struct lov_object *obj, struct cl_io *io)
{
	int index;
	int result = 0;
	bool rdonly;

	ENTRY;

	io->ci_result = 0;
	lio->lis_object = obj;
	lio->lis_cached_entry = LIS_CACHE_ENTRY_NONE;

	rdonly = lsm_is_rdonly(obj->lo_lsm);
	switch (io->ci_type) {
	case CIT_EC_RD:
		io->u.ci_ec.ec_inner = io->u.ci_ec.ec_outer;
		fallthrough;
	case CIT_READ:
	case CIT_WRITE:
		if (io->ci_type == CIT_WRITE && rdonly) {
			io->ci_need_pccro_clear = 1;
			GOTO(out, result = 1);
		}
		lio->lis_pos = io->u.ci_rw.crw_pos;
		lio->lis_endpos = io->u.ci_rw.crw_pos + io->u.ci_rw.crw_bytes;
		lio->lis_io_endpos = lio->lis_endpos;
		if (io->ci_type == CIT_EC_RD)
			CDEBUG(D_VFSTRACE, "ec read outer [%llu, %llu-%llu)\n",
			       lio->lis_pos, lio->lis_endpos,
			       lio->lis_io_endpos);
		if (cl_io_is_append(io)) {
			/*
			 * If there is LOV EA hole, then we may cannot locate
			 * the current file-tail exactly.
			 */
			if (unlikely(obj->lo_lsm->lsm_entries[0]->lsme_pattern &
				     LOV_PATTERN_F_HOLE))
				GOTO(out, result = -EIO);
		}
		break;

	case CIT_SETATTR:
		if (cl_io_is_fallocate(io)) {
			if (rdonly) {
				io->ci_need_pccro_clear = 1;
				GOTO(out, result = 1);
			}
			lio->lis_pos = io->u.ci_setattr.sa_falloc_offset;
			lio->lis_endpos = io->u.ci_setattr.sa_falloc_end;
		} else if (cl_io_is_trunc(io)) {
			if (rdonly) {
				io->ci_need_pccro_clear = 1;
				GOTO(out, result = 1);
			}
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

		if (cl_io_is_mkwrite(io) && rdonly) {
			io->ci_need_pccro_clear = 1;
			GOTO(out, result = -ENODATA);
		}

		lio->lis_pos = index << PAGE_SHIFT;
		lio->lis_endpos = (index + 1) << PAGE_SHIFT;
		break;
	}

	case CIT_FSYNC: {
		lio->lis_pos = io->u.ci_fsync.fi_start;
		lio->lis_endpos = io->u.ci_fsync.fi_end;
		break;
	}

	case CIT_LADVISE: {
		lio->lis_pos = io->u.ci_ladvise.lio_start;
		lio->lis_endpos = io->u.ci_ladvise.lio_end;
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

	result = lov_io_mirror_init(env, lio, obj, io);
	if (result)
		GOTO(out, result);

	/* check if it needs to instantiate layout */
	if (!(io->ci_type == CIT_WRITE || cl_io_is_mkwrite(io) ||
	      cl_io_is_fallocate(io) ||
	      (cl_io_is_trunc(io) && io->u.ci_setattr.sa_attr.lvb_size > 0)))
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

	CDEBUG(D_LAYOUT, "%llu %llu\n", io->ci_write_intent.e_start,
	       io->ci_write_intent.e_end);

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
		CERROR(DFID": trying to instantiate components for designated I/O, file state: %d\n",
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
	struct lov_io_sub *sub;
	struct cl_io *io = lio->lis_cl.cis_io;

	ENTRY;
	LASSERT(list_empty(&lio->lis_active));

	while ((sub = list_first_entry_or_null(&lio->lis_subios,
					       struct lov_io_sub,
					       sub_list)) != NULL) {
		list_del_init(&sub->sub_list);
		lio->lis_nr_subios--;

		lov_io_sub_fini(env, lio, sub);
		lov_sub_free(lio, sub);
	}
	LASSERT(lio->lis_nr_subios == 0);

	if (!(io->ci_ignore_layout && io->ci_type == CIT_MISC)) {
		LASSERT(atomic_read(&lov->lo_active_ios) > 0);
		if (atomic_dec_and_test(&lov->lo_active_ios))
			wake_up(&lov->lo_waitq);
	}
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
			io->u.ci_setattr.sa_attr_uid =
				parent->u.ci_setattr.sa_attr_uid;
			io->u.ci_setattr.sa_attr_gid =
				parent->u.ci_setattr.sa_attr_gid;
			io->u.ci_setattr.sa_attr_projid =
				parent->u.ci_setattr.sa_attr_projid;
		}
		if (cl_io_is_trunc(io)) {
			loff_t new_size = parent->u.ci_setattr.sa_attr.lvb_size;

			new_size = lov_size_to_stripe(lsm, index, new_size,
						      stripe);
			io->u.ci_setattr.sa_attr.lvb_size = new_size;
			io->u.ci_setattr.sa_attr_uid =
				parent->u.ci_setattr.sa_attr_uid;
			io->u.ci_setattr.sa_attr_gid =
				parent->u.ci_setattr.sa_attr_gid;
			io->u.ci_setattr.sa_attr_projid =
				parent->u.ci_setattr.sa_attr_projid;
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
		loff_t off = parent->u.ci_fault.ft_index << PAGE_SHIFT;

		io->u.ci_fault = parent->u.ci_fault;
		off = lov_size_to_stripe(lsm, index, off, stripe);
		io->u.ci_fault.ft_index = off >> PAGE_SHIFT;
		break;
	}
	case CIT_FSYNC: {
		io->u.ci_fsync.fi_start = start;
		io->u.ci_fsync.fi_end = end;
		io->u.ci_fsync.fi_fid = parent->u.ci_fsync.fi_fid;
		io->u.ci_fsync.fi_mode = parent->u.ci_fsync.fi_mode;
		io->u.ci_fsync.fi_prio = parent->u.ci_fsync.fi_prio;
		break;
	}
	case CIT_READ:
	case CIT_WRITE: {
		io->u.ci_wr.wr_sync = cl_io_is_sync_write(parent);
		io->ci_tried_all_mirrors = parent->ci_tried_all_mirrors;
		if (cl_io_is_append(parent))
			io->u.ci_wr.wr_append = 1;

		io->u.ci_rw.crw_pos = start;
		io->u.ci_rw.crw_bytes = end - start;
		break;
	}
	case CIT_EC_RD: {
		io->u.ci_rw.crw_pos = start;
		io->u.ci_rw.crw_bytes = end - start;
		break;
	}
	case CIT_LADVISE: {
		io->u.ci_ladvise.lio_start = start;
		io->u.ci_ladvise.lio_end = end;
		io->u.ci_ladvise.lio_fid = parent->u.ci_ladvise.lio_fid;
		io->u.ci_ladvise.lio_advice = parent->u.ci_ladvise.lio_advice;
		io->u.ci_ladvise.lio_flags = parent->u.ci_ladvise.lio_flags;
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
	bool is_trunc = cl_io_is_trunc(ios->cis_io);
	struct lov_io_sub *sub;
	struct lu_extent ext;
	int index;
	int rc = 0;

	ENTRY;

	ext.e_start = lio->lis_pos;
	ext.e_end = lio->lis_endpos;

	if (is_trunc) {
		OBD_ALLOC_PTR_ARRAY(lio->lis_trunc_stripe_index,
				    lio->lis_object->u.composite.lo_entry_count);
		if (lio->lis_trunc_stripe_index == NULL)
			RETURN(-ENOMEM);
	}

	lov_foreach_io_layout(index, lio, &ext) {
		struct lov_layout_entry *le = lov_entry(lio->lis_object, index);
		struct lov_layout_raid0 *r0 = &le->lle_raid0;
		u64 start;
		u64 end;
		int stripe;
		bool tested_trunc_stripe = false;

		if (is_trunc)
			lio->lis_trunc_stripe_index[index] = -1;

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

			if (is_trunc && !tested_trunc_stripe) {
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
					lio->lis_trunc_stripe_index[index] = prev;
				} else {
					div64_u64_rem(ext.e_start,
						      stripe_width(lsm, index),
						      &tr_start);
					/* tr_start %= stripe_swidth */
					if (tr_start == stripe * lsm->
							lsm_entries[index]->
							lsme_stripe_size)
						lio->lis_trunc_stripe_index[index] = prev;
				}
			}

			/* if the last stripe is the trunc stripeno */
			if (is_trunc &&
			    lio->lis_trunc_stripe_index[index] == stripe)
				lio->lis_trunc_stripe_index[index] = -1;

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

		if (is_trunc && lio->lis_trunc_stripe_index[index] != -1) {
			stripe = lio->lis_trunc_stripe_index[index];
			if (unlikely(!r0->lo_sub[stripe])) {
				lio->lis_trunc_stripe_index[index] = -1;
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
				lio->lis_trunc_stripe_index[index] = -1;
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

	if (cl_io_is_append(io)) {
		struct lov_layout_entry *lle;
		struct lov_mirror_entry *lre;
		loff_t endpos = 0;

		/* cover the whole inited region for append */
		LASSERT(lio->lis_mirror_index >= 0);
		lre = lov_mirror_entry(lio->lis_object, lio->lis_mirror_index);
		lov_foreach_mirror_layout_entry(lio->lis_object, lle, lre) {
			if (!lsme_inited(lle->lle_lsme))
				break;

			endpos = lle->lle_lsme->lsme_extent.e_end;
		}

		lio->lis_pos = 0;
		if (endpos == OBD_OBJECT_EOF || lio->lis_endpos < endpos)
			lio->lis_endpos = endpos;

		io->u.ci_wr.wr_append_lockpos = lio->lis_endpos;
		RETURN(lov_io_iter_init(env, ios));
	}

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

		start = div64_u64(start, ssize);
		next = (start + 1) * ssize;
		if (next <= start * ssize)
			next = MAX_LFS_FILESIZE;
	}

	LASSERTF(io->u.ci_rw.crw_pos >= lse->lsme_extent.e_start,
		 "pos %lld, [%lld, %lld)\n", io->u.ci_rw.crw_pos,
		 lse->lsme_extent.e_start, lse->lsme_extent.e_end);
	next = min_t(__u64, next, lse->lsme_extent.e_end);
	next = min_t(__u64, next, lio->lis_io_endpos);

	io->ci_continue = next < lio->lis_io_endpos;
	io->u.ci_rw.crw_bytes = next - io->u.ci_rw.crw_pos;
	lio->lis_pos    = io->u.ci_rw.crw_pos;
	lio->lis_endpos = io->u.ci_rw.crw_pos + io->u.ci_rw.crw_bytes;
	CDEBUG(D_VFSTRACE,
	       "stripe: %llu chunk: [%llu, %llu) %llu, %zd\n",
	       (__u64)start, lio->lis_pos, lio->lis_endpos,
	       (__u64)lio->lis_io_endpos, io->u.ci_rw.crw_bytes);

	/*
	 * XXX The following call should be optimized: we know, that
	 * [lio->lis_pos, lio->lis_endpos) intersects with exactly one stripe.
	 */
	RETURN(lov_io_iter_init(env, ios));
}

static int lov_ecio_add_data_sub(const struct lu_env *env, struct lov_io *lio,
				 struct lu_extent *ext, int *err_nr)
{
	struct cl_io *io = lio->lis_cl.cis_io;
	struct lov_object *lov = lio->lis_object;
	struct lov_device *dev = lov_object_dev(lov);
	struct lov_stripe_md *lsm = lov->lo_lsm;
	struct lov_layout_entry *lle;
	struct lov_layout_raid0 *r0;
	struct lu_extent data_ext;
	loff_t file_size;
	int index;
	int rc = 0;

	ENTRY;
	/*
	 * Cap the extent to the actual file size.  lov_io_set_range() expands
	 * the extent to cover full RAID sets for parity calculation, but data
	 * stripes beyond EOF contain no data. If such a stripe is on an
	 * unavailable OST it would be falsely marked degraded, triggering
	 * recovery that corrupts valid data.
	 */
	file_size = io->u.ci_ec.ec_inode_size;
	data_ext = *ext;
	if (data_ext.e_end > file_size)
		data_ext.e_end = file_size;
	if (data_ext.e_end <= data_ext.e_start)
		RETURN(0);

	lov_foreach_io_layout(index, lio, &data_ext) {
		unsigned int stripe;

		if (!lsm_entry_inited(lsm, index))
			continue;

		lle = lov_entry(lov, index);
		if (!lle->lle_valid) {
			CWARN("%s: "DFID": I/O on invalid component %d: rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(lov))), index, -EIO);
			RETURN(-EIO);
		}

		r0 = &lle->lle_raid0;
		for (stripe = 0; stripe < r0->lo_nr; stripe++) {
			struct lov_io_sub *sub;
			u64 sub_start;
			u64 sub_end;

			if (!lov_stripe_intersects(lsm, index, stripe,
						   &data_ext,
						   &sub_start, &sub_end)) {
				/* Clear any READ_ERR set by the lock path
				 * for stripes not covered by this loop - no
				 * data means no recovery needed.
				 */
				if (r0->lo_sub[stripe])
					r0->lo_sub[stripe]->lso_status =
						LSS_OK;
				continue;
			}

			if (unlikely(!r0->lo_sub[stripe])) {
				CWARN("%s: "DFID": stripe %u in comp %d is NULL, rc = %d\n",
				      lov2obd(dev->ld_lov)->obd_name,
				      PFID(lu_object_fid(lov2lu(lov))),
				      stripe, index, -EIO);
				RETURN(-EIO);
			}

			sub = lov_sub_get(env, lio,
					  lov_comp_index(index, stripe));
			if (IS_ERR(sub)) {
				r0->lo_sub[stripe]->lso_status = LSS_READ_ERR;
				(*err_nr)++;
				CDEBUG(D_INFO, DFID": stripe %u in comp %d is unavailable (%d): rc = %ld\n",
				       PFID(lu_object_fid(lov2lu(lov))),
				       stripe, index, *err_nr, PTR_ERR(sub));
				continue;
			}

			rc = lov_io_add_sub(env, lio, sub, sub_start, sub_end);
			if (rc != 0) {
				r0->lo_sub[stripe]->lso_status = LSS_READ_ERR;
				(*err_nr)++;
				CDEBUG(D_INFO, DFID": stripe %u in comp %d is unavailable (%d): rc = %d\n",
				       PFID(lu_object_fid(lov2lu(lov))),
				       stripe, index, *err_nr, rc);
				rc = 0;
				continue;
			} else {
				r0->lo_sub[stripe]->lso_status = LSS_OK;
			}
		}
	}

	RETURN(rc);
}

static int lov_ecio_add_parity_sub(const struct lu_env *env, struct lov_io *lio,
				   struct lu_extent *ext,
				   struct ec_split_comp *sc, int nr)
{
	struct lov_object *lov = lio->lis_object;
	struct lov_device *dev = lov_object_dev(lov);
	struct lov_stripe_md *lsm = lov->lo_lsm;
	struct lov_layout_entry *lle;
	struct lov_layout_raid0 *r0;
	int parity_mir_idx;
	int index;
	int rc = 0;

	ENTRY;
	if (!lov->u.composite.lo_entries ||
	    lov->u.composite.lo_entry_count == 0)
		RETURN(rc);

	parity_mir_idx = lov_parity_mirror_index_from_data(lio,
						lio->lis_mirror_index);
	if (parity_mir_idx < 0) {
		CWARN("%s: "DFID": failed to find valid parity mirror for data mirror %d: rc = %d\n",
		      lov2obd(dev->ld_lov)->obd_name,
		      PFID(lu_object_fid(lov2lu(lov))), lio->lis_mirror_index,
		      parity_mir_idx);
		RETURN(-EINVAL);
	}
	lov_foreach_io_layout_mirror(index, lio, ext, parity_mir_idx) {
		struct lov_stripe_md_entry *lsme;
		struct lov_io_sub *sub;
		u64 offset;
		u64 base_poff;
		u64 dswidth;
		u64 sub_start;
		u64 sub_end;
		u16 dcount;
		int stripe;
		int added = 0;

		lle = lov_entry(lov, index);
		r0 = &lle->lle_raid0;

		if (!lsm_entry_inited(lsm, index))
			continue;

		if (!lle->lle_valid ||
		    !(lle->lle_lsme->lsme_flags & LCME_FL_PARITY)) {
			CWARN("%s: "DFID": I/O on invalid parity component %d: rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(lov))), index, -EIO);
			RETURN(-EIO);
		}

		if (nr > r0->lo_nr) {
			CWARN("%s: "DFID": too few parity (%d) components to recover data (%d): rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(lov))), r0->lo_nr, nr,
			      -EAGAIN);
			RETURN(-EAGAIN);
		}

		lsme = lle->lle_lsme;
		/*
		 * Parity sub-objects use lov_stripe_offset() addressing:
		 * file offset e_start maps to sub-object offset
		 * (e_start / parity_swidth) * stripe_size.
		 * Compute this base for PFL components that don't start at
		 * file offset 0.
		 */
		base_poff = div64_u64(lle->lle_extent->e_start,
				      (u64)lsme->lsme_stripe_count *
				      lsme->lsme_stripe_size) *
			    lsme->lsme_stripe_size;

		/*
		 * Map data file offsets to parity sub-object offsets.
		 * Each data RAID row (data_stripe_count * stripe_size
		 * bytes) produces exactly one stripe_size of parity
		 * per parity sub-object, so:
		 *   sub_obj_offset = data_row * stripe_size
		 *
		 * The original code divided by parity swidth instead
		 * of data swidth, producing wildly wrong offsets when
		 * data_stripe_count != parity_stripe_count.
		 */
		dcount = sc->esc_k0 * sc->esc_n0 +
			 sc->esc_k1 * sc->esc_n1;
		dswidth = (u64)dcount * lsme->lsme_stripe_size;
		/* Defense-in-depth: a non-EC cycle reaches here with a zeroed
		 * @sc (all esc_* == 0), giving dcount == 0 and dswidth == 0.
		 * lov_io_ec_rd_iter_init() now skips this function for
		 * dstripe_count == 0, but guard the div64_u64() below so a
		 * bad caller cannot trap on a divide by zero.
		 */
		if (dswidth == 0)
			continue;

		/* sub_start: floor(data_offset / data_swidth) rows */
		offset = ext->e_start - lle->lle_extent->e_start;
		sub_start = base_poff +
			    div64_u64(offset, dswidth) *
			    lsme->lsme_stripe_size;

		/* sub_end: ceil(data_offset / data_swidth) rows */
		if (ext->e_end > lle->lle_extent->e_end)
			offset = lle->lle_extent->e_end -
				 lle->lle_extent->e_start;
		else
			offset = ext->e_end - lle->lle_extent->e_start;
		sub_end = base_poff +
			  div64_u64(offset + dswidth - 1, dswidth) *
			  lsme->lsme_stripe_size;

		for (stripe = 0; stripe < r0->lo_nr; stripe++) {
			if (unlikely(!r0->lo_sub[stripe]))
				continue;

			sub = lov_sub_get(env, lio,
					  lov_comp_index(index, stripe));
			if (IS_ERR(sub))
				continue;

			/* page read from parity component doesn't cover with
			 * ldlm lock
			 */
			sub->sub_io.ci_lockless = 1;
			rc = lov_io_add_sub(env, lio, sub, sub_start, sub_end);
			if (rc != 0) {
				rc = 0;
				continue;
			}
			added++;
		}
		if (added < nr) {
			CWARN("%s: "DFID": available parity stripes %d < needed %d: rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(lov))),
			      added, nr, -EIO);
			RETURN(-EIO);
		}
	}

	RETURN(rc);
}

static int lov_io_ec_rd_iter_init(const struct lu_env *env,
				  const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = ios->cis_io;
	struct lov_object *lov = lio->lis_object;
	loff_t start = io->u.ci_ec.ec_inner.crw_pos;
	loff_t next;	/* file offset of next read cycle */
	struct lov_stripe_md_entry *lsme;
	struct lu_extent ext;
	struct ec_split_comp sc = { 0 };
	int index;
	int err_nr = 0;
	int rc = 0;

	ENTRY;
	index = lov_io_layout_at(lio, start);
	if (index < 0)
		RETURN(-ENODATA);

	/* use io inner range */
	lsme = lov_lse(lov, index);
	next = MAX_LFS_FILESIZE;
	if (lsme->lsme_dstripe_count >= 1) {
		u64 offset;
		u64 offset_i;
		u64 row;
		u64 cnt;

		/* set next read offset to next raid set with different EC
		 * parameter
		 */
		ec_split_stripes(lsme->lsme_stripe_count,
				 lsme->lsme_dstripe_count, &sc);

		offset = start - lsme->lsme_extent.e_start;
		row = div64_u64(offset, (u64)lsme->lsme_stripe_size *
					lsme->lsme_stripe_count);
		offset_i = div64_u64(offset, lsme->lsme_stripe_size) %
			   lsme->lsme_stripe_count;
		/* cnt is the stripe number from the component start to the
		 * end of the raid set where @offset locates.
		 */
		if (offset_i < sc.esc_k0 * sc.esc_n0) {
			cnt = row * lsme->lsme_stripe_count +
			      sc.esc_k0 * sc.esc_n0;
		} else {
			cnt = row * lsme->lsme_stripe_count +
			      sc.esc_k0 * sc.esc_n0 + sc.esc_k1 * sc.esc_n1;
		}
		next = lsme->lsme_extent.e_start + cnt * lsme->lsme_stripe_size;

		CDEBUG(D_INFO, DFID
		       " next sc(%d/%d/%d/%d), row %lld, offset_i %lld, cnt %lld, next %llu\n",
		       PFID(lu_object_fid(lov2lu(lov))),
		       sc.esc_k0, sc.esc_n0, sc.esc_k1, sc.esc_n1,
		       row, offset_i, cnt, next);
	}
	next = min_t(__u64, next, lsme->lsme_extent.e_end);
	next = min_t(loff_t, next, lio->lis_io_endpos);

	/* set this read cycle range */
	io->ci_continue = next < lio->lis_io_endpos;
	io->u.ci_ec.ec_inner.crw_bytes = next - start;
	lio->lis_pos    = start;
	lio->lis_endpos = next;

	CDEBUG(D_VFSTRACE, "ec read [%llu, %llu-%llu)\n",
	       (__u64)start, (__u64)next, (__u64)lio->lis_io_endpos);

	ext.e_start = start;
	ext.e_end = next;
	/* add data component sub io */
	rc = lov_ecio_add_data_sub(env, lio, &ext, &err_nr);
	if (rc < 0)
		RETURN(rc);
	/* Pre-add parity sub-IOs for an EC component.  Parity reads may be
	 * triggered later in lov_io_ec_rd_start() by transient BRW read
	 * errors on live data OSTs (network blips, fault injection), not
	 * only by imports that were already deactivated at iter_init
	 * time.  lov_sub_get() allocating a fresh parity sub on-demand
	 * there would miss ci_lockless=1 and skip cl_io_iter_init(), so
	 * osc_req_attr_set() would LBUG "uncovered page!" because parity
	 * OSCs have no DLM lock enqueued.
	 */
	if (lsme->lsme_dstripe_count >= 1) {
		rc = lov_ecio_add_parity_sub(env, lio, &ext, &sc, err_nr);
		if (rc < 0)
			RETURN(rc);
	}

	RETURN(rc);
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
		if (rc) {
			/**
			 * fsync race with truncate, we'd continue to other
			 * OST object's fsync to potentially discard
			 * caching pages (osc_cache_writeback_range).
			 */
			if (rc == -ENOENT && parent->ci_type == CIT_FSYNC)
				continue;
			break;
		}

		if (parent->ci_result == 0)
			parent->ci_result = sub->sub_io.ci_result;
	}
	RETURN(rc);
}

static int lov_io_lock(const struct lu_env *env, const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = lio->lis_cl.cis_io;
	struct cl_object *obj = ios->cis_obj;
	struct cl_lock_descr descr = { 0 };
	int rc;

	ENTRY;
	if (io->ci_type == CIT_EC_RD) {
		__u32 enqflags = CEF_MUST | CEF_HEED_ERROR;

		descr.cld_obj = obj;
		descr.cld_start = io->u.ci_ec.ec_inner.crw_pos >> PAGE_SHIFT;
		descr.cld_end = (io->u.ci_ec.ec_inner.crw_pos +
				 io->u.ci_ec.ec_inner.crw_bytes - 1) >>
								PAGE_SHIFT;
		descr.cld_mode = CLM_READ;
		descr.cld_enq_flags = enqflags;

		/* Apply group-lock handling just like vvp_io_one_lock_index().
		 * If the file is group-locked (indicated by non-zero
		 * ci_group_gid), we must request a CLM_GROUP lock with the
		 * correct gid to match the existing group lock, rather than
		 * a regular LCK_PR which would deadlock against it.
		 */
		if (io->ci_group_gid != 0) {
			descr.cld_mode = CLM_GROUP;
			descr.cld_gid  = io->ci_group_gid;
			enqflags |= CEF_LOCK_MATCH;
			descr.cld_enq_flags = enqflags;
		}

		CDEBUG(D_INFO, DFID": ec read lock "DDESCR"\n",
		       PFID(lu_object_fid(lov2lu(lio->lis_object))),
		       PDESCR(&descr));

		/* add data stripe locks */
		rc = cl_io_lock_alloc_add(env, io, &descr);
		if (rc < 0)
			RETURN(rc);
	}

	rc = lov_io_call(env, cl2lov_io(env, ios), cl_io_lock);
	RETURN(rc);
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

	/* Before ending each i/o, we must set lis_cached_entry to tell the
	 * next i/o not to use stale cached lis information.
	 */
	cl2lov_io(env, ios)->lis_cached_entry = LIS_CACHE_ENTRY_NONE;

	rc = lov_io_call(env, cl2lov_io(env, ios), lov_io_end_wrapper);
	LASSERT(rc == 0);
}

enum ec_data_pg_state {
	EC_DPG_ZERO,		/* beyond EOF/RG */
	EC_DPG_UPTODATE,	/* already in page cache */
	EC_DPG_READ,		/* read successfully */
	EC_DPG_ERROR,		/* stripe dead or read failed */
};

/**
 * lov_ec_read_stripe_pages() - read all pages for one data stripe across all
 * page positions in a recovery group.
 *
 * Submits all pages for one stripe in a single
 * cl_io_submit_sync call instead of one per page.
 *
 * @env:        lu_env context
 * @lio:        LOV I/O structure
 * @comp_i:     composite layout component index
 * @stripe_i:   which data stripe (0..dcount-1)
 * @lsme:       stripe metadata entry
 * @soff:       start offset of recovery group
 * @eoff:       end offset of recovery group
 * @pg_start:   first page position in stripe
 * @npages:     number of page positions
 * @out_pages:  array[npages] of cl_page pointers (output)
 * @out_states: array[npages] of page states (output)
 * @dlist:	cl_page_list for pages that need reading (output)
 *
 * Returns 0 on success. Pages in state of EC_DPG_UPTODATE are assumed (owned)
 * in out_pages[], pages in state of EC_DPG_READ are owned in dlist, and pages
 * in state of EC_DPG_ERROR are owned in ec_page_list. Vmpages can be accessed
 * via out_pages[]->cp_vmpage.
 */
static int
lov_ec_read_stripe_pages(const struct lu_env *env, struct lov_io *lio,
			 int comp_i, int stripe_i,
			 struct lov_stripe_md_entry *lsme,
			 unsigned long long soff, unsigned long long eoff,
			 int pg_start, int npages, struct cl_page **out_pages,
			 enum ec_data_pg_state *out_states,
			 struct cl_page_list *dlist)
{
	struct lov_object *lov = lio->lis_object;
	struct cl_object *obj = lov2cl(lov);
	struct cl_io *io = lio->lis_cl.cis_io;
	struct inode *inode = cl2lov(obj)->lo_inode;
	struct lov_layout_raid0 *r0 = lov_r0(lov, comp_i);
	unsigned long ss = lsme->lsme_stripe_size;
	int base_stripe;
	int stripe; /* physical stripe index */
	struct lov_io_sub *sub = NULL;
	struct cl_2queue *queue;
	int need_read = 0;
	int j;
	int rc = 0;

	ENTRY;
	base_stripe = lov_stripe_number(lov->lo_lsm, comp_i, soff);
	/* stripe_i is the i-th stripe within the recovery group */
	stripe = (base_stripe + stripe_i) % r0->lo_nr;
	/* Phase 1: grab all pages, classify them */
	for (j = 0; j < npages; j++) {
		pgoff_t page_idx;
		struct cl_page *clpage;
		struct page *vmpage;
		struct folio *_folio;

		out_pages[j] = NULL;

		page_idx = ((soff + stripe_i * ss) >> PAGE_SHIFT) +
			   pg_start + j;

		if ((page_idx << PAGE_SHIFT) >= eoff ||
		    (page_idx << PAGE_SHIFT) >= io->u.ci_ec.ec_inode_size) {
			out_states[j] = EC_DPG_ZERO;
			continue;
		}

		_folio = get_folio_grab(inode->i_mapping, page_idx,
					FGP_LOCK | FGP_ACCESSED | FGP_CREAT,
					mapping_gfp_mask(inode->i_mapping));
		if (IS_ERR_OR_NULL(_folio))
			GOTO(out_err, rc = -ENOMEM);
		vmpage = fpgptr(_folio);
		if (vmpage->mapping != inode->i_mapping) {
			unlock_page(vmpage);
			put_page(vmpage);
			GOTO(out_err, rc = -EAGAIN);
		}

		/* Create cl_page for this page. Determine state based on:
		 * - PageUptodate: already in cache (UPTODATE)
		 * - LSS_READ_ERR: stripe is down (ERROR)
		 * - Otherwise: needs I/O (READ)
		 */
		clpage = cl_page_find(env, cl_object_top(obj), page_idx, vmpage,
				      CPT_CACHEABLE);
		if (IS_ERR(clpage)) {
			unlock_page(vmpage);
			put_page(vmpage);
			GOTO(out_err, rc = PTR_ERR(clpage));
		}
		cl_page_assume(env, io, clpage);
		out_pages[j] = clpage;
		/* drop vmpage refcount added by get_folio_grab() */
		folio_put(_folio);

		if (PageUptodate(vmpage)) {
			out_states[j] = EC_DPG_UPTODATE;
		} else if (r0->lo_sub[stripe]->lso_status == LSS_READ_ERR) {
			out_states[j] = EC_DPG_ERROR;
			cl_page_list_add(&io->u.ci_ec.ec_page_list, clpage,
					 false);
		} else {
			out_states[j] = EC_DPG_READ;
			need_read++;
		}
	}

	if (need_read == 0)
		RETURN(0);

	/* Phase 2: submit all READ pages in one batch */
	sub = lov_sub_get(env, lio, lov_comp_index(comp_i, stripe));
	if (IS_ERR(sub)) {
		/* Could not get a sub-io for this stripe.  The cl_pages in
		 * out_pages[j] are assumed (owned) but never submitted, so
		 * move them to ec_page_list (matching the submit-failure
		 * path).
		 */
		for (j = 0; j < npages; j++) {
			if (out_states[j] == EC_DPG_READ) {
				cl_page_list_add(&io->u.ci_ec.ec_page_list,
						 out_pages[j], false);
				out_states[j] = EC_DPG_ERROR;
			}
		}
		RETURN(0);
	}

	queue = &lov_env_info(sub->sub_env)->lti_cl2q;
	cl_2queue_init(queue);
	for (j = 0; j < npages; j++) {
		if (out_states[j] == EC_DPG_READ)
			cl_page_list_add(&queue->c2_qin,
					 out_pages[j], false);
	}

	rc = cl_io_submit_sync(sub->sub_env, &sub->sub_io,
			       CRT_READ, queue, 0);
	if (rc) {
		r0->lo_sub[stripe]->lso_status = LSS_READ_ERR;
		/* EC_DPG_READ cl_pages read error, move them to ec_page_list */
		cl_page_list_splice(&queue->c2_qin, &io->u.ci_ec.ec_page_list);
		cl_page_list_splice(&queue->c2_qout, &io->u.ci_ec.ec_page_list);
		cl_2queue_fini(env, queue);
		for (j = 0; j < npages; j++) {
			if (out_states[j] == EC_DPG_READ)
				out_states[j] = EC_DPG_ERROR;
		}
		RETURN(0); /* not fatal, can try parity */
	}

	/* Success: pages are in c2_qout, assumed.  Splice to dlist and NULL
	 * out_pages
	 */
	for (j = 0; j < npages; j++) {
		if (out_states[j] == EC_DPG_READ)
			SetPageUptodate(out_pages[j]->cp_vmpage);
	}
	cl_page_list_splice(&queue->c2_qin, dlist);
	cl_page_list_splice(&queue->c2_qout, dlist);
	cl_2queue_fini(env, queue);

	RETURN(0);

out_err:
	/* Release pages grabbed before the error.
	 * - UPTODATE: valid in the page cache, disown (unlock vmpage) and
	 *   drop the cl_page ref.  No discard.
	 * - READ: assumed/owned but never submitted, so not in dlist nor
	 *   ec_page_list.  Disown to unlock the vmpage and drop the cl_page
	 *   ref so neither leaks.
	 * - ERROR: already in ec_page_list; vvp_io_ec_rd_end will disown and
	 *   fini it, so just NULL the pointer.
	 */
	for (j = 0; j < npages; j++) {
		if (out_pages[j]) {
			if (out_states[j] == EC_DPG_UPTODATE ||
			    out_states[j] == EC_DPG_READ) {
				cl_page_disown(env, io, out_pages[j]);
				cl_page_put(env, out_pages[j]);
			}
			out_pages[j] = NULL;
		}
	}
	RETURN(rc);
}

/**
 * lov_ec_read_parity_stripe() - read all parity pages for one parity stripe
 * across all page positions in a recovery group.
 *
 * @parity_idx: which parity stripe (0..pcount-1)
 * @pg_start:   first page position
 * @npages:     number of page positions
 * @out_vmpages: array[npages] of vmpage pointers (output)
 * @out_clpages: array[npages] of cl_page pointers (output)
 * @plist:      page list to track allocated pages for cleanup
 */
static int
lov_ec_read_parity_stripe(const struct lu_env *env, struct lov_io *lio,
			  int pcomp_i, int parity_idx,
			  struct lov_stripe_md_entry *lsme,
			  unsigned long long parity_foff, int pg_start,
			  int npages, struct page **out_vmpages,
			  struct cl_page **out_clpages,
			  struct cl_page_list *plist)
{
	struct lov_object *lov = lio->lis_object;
	struct cl_object *obj = lov2cl(lov);
	struct lov_layout_raid0 *r0 = lov_r0(lov, pcomp_i);
	int start_stripe;
	int stripe;
	struct lov_io_sub *sub;
	struct cl_object *subobj;
	struct cl_2queue *queue;
	struct cl_sync_io anchor;
	u64 p_foff;
	loff_t obdoff;
	int j;
	int rc = 0;

	ENTRY;

	p_foff = parity_foff + (u64)parity_idx * lsme->lsme_stripe_size;
	start_stripe = lov_stripe_number(lov->lo_lsm, pcomp_i, parity_foff);
	stripe = (start_stripe + parity_idx) % r0->lo_nr;
	lov_stripe_offset(lov->lo_lsm, pcomp_i, p_foff, stripe, &obdoff);

	if (unlikely(!r0->lo_sub[stripe]))
		RETURN(-EIO);

	sub = lov_sub_get(env, lio, lov_comp_index(pcomp_i, stripe));
	if (IS_ERR(sub))
		RETURN(-EIO);

	subobj = lovsub2cl(r0->lo_sub[stripe]);

	/* Phase 1: allocate all pages */
	for (j = 0; j < npages; j++) {
		pgoff_t page_idx = (obdoff >> PAGE_SHIFT) + pg_start + j;
		struct page *vmpage;

		vmpage = alloc_page(GFP_NOFS);
		if (!vmpage)
			GOTO(out_err, rc = -ENOMEM);
		lock_page(vmpage);
		out_vmpages[j] = vmpage;

		out_clpages[j] = cl_page_alloc_sub(env, sub->sub_env, obj,
						   subobj, page_idx, vmpage,
						   CPT_TRANSIENT);
		if (IS_ERR(out_clpages[j])) {
			rc = PTR_ERR(out_clpages[j]);
			out_clpages[j] = NULL;
			unlock_page(vmpage);
			__free_page(vmpage);
			out_vmpages[j] = NULL;
			GOTO(out_err, rc);
		}
	}

	/* Phase 2: submit all pages in one batch.
	 * Parity pages are CPT_TRANSIENT, so we must use
	 * cl_io_submit_rw + cl_sync_io_wait rather than
	 * cl_io_submit_sync (which asserts !CPT_TRANSIENT).
	 */
	queue = &lov_env_info(sub->sub_env)->lti_cl2q;
	cl_2queue_init(queue);
	for (j = 0; j < npages; j++) {
		out_clpages[j]->cp_sync_io = &anchor;
		cl_page_list_add(&queue->c2_qin, out_clpages[j], false);
	}

	cl_sync_io_init(&anchor, npages);
	rc = cl_io_submit_rw(sub->sub_env, &sub->sub_io, CRT_READ, queue);
	if (rc == 0) {
		struct cl_page *clpage;

		/* If some pages weren't sent for any reason (e.g.,
		 * page already up-to-date), count them as completed to
		 * avoid infinite wait.
		 */
		cl_page_list_for_each(clpage, &queue->c2_qin)
			cl_sync_io_note(env, &anchor, 1);
		rc = cl_sync_io_wait(sub->sub_env, &anchor, 0);
	}
	if (rc) {
		/* cl_2queue_fini() puts each cl_page in qin/qout (ref drops
		 * to 0, cl_page freed).  Null out_clpages[] before the
		 * out_err loop so it doesn't cl_page_put() the freed pages
		 * again -- that's a refcount underflow + UAF (LU-12668).
		 * Vmpages are still ours to unlock_page + __free_page.
		 */
		cl_2queue_fini(env, queue);
		for (j = 0; j < npages; j++)
			out_clpages[j] = NULL;
		GOTO(out_err, rc);
	}

	/* Success: move pages to plist for tracking */
	for (j = 0; j < npages; j++)
		SetPageUptodate(out_vmpages[j]);
	cl_page_list_splice(&queue->c2_qin, plist);
	cl_page_list_splice(&queue->c2_qout, plist);
	cl_2queue_fini(env, queue);

	RETURN(0);

out_err:
	for (j = 0; j < npages; j++) {
		if (out_clpages[j]) {
			cl_page_put(env, out_clpages[j]);
			out_clpages[j] = NULL;
		}
		if (out_vmpages[j]) {
			unlock_page(out_vmpages[j]);
			__free_page(out_vmpages[j]);
			out_vmpages[j] = NULL;
		}
	}
	RETURN(rc);
}

/**
 * struct ec_recover_ctx - precomputed EC recovery tables
 *
 * The GF decode tables depend only on which stripes are  missing and which
 * parity stripes are used, not on page data.  Precompute once per recovery
 * group and reuse for every page position.
 */
struct ec_recover_ctx {
	u8		*erc_tbls;
	unsigned char	 erc_dcount;
	unsigned char	 erc_pcount;
	unsigned char	 erc_unavail_nr;
	unsigned int	 erc_tbls_size;
};

/**
 * struct lov_ec_rd_state - heap-allocated working buffers for one EC read
 * cycle (lov_io_ec_rd_start call).  Grouped so alloc/free can be split into
 * helpers and later swapped for pre-allocated pools without churning the
 * call sites.
 *
 * @ecr_err_array:	indices of unavailable data stripes [unavail_nr]
 * @ecr_parity_used:	indices of parity stripes used for recovery [unavail_nr]
 * @ecr_ptrs:		kmapped data page pointers (available + parity) [dcount]
 * @ecr_recov_ptrs:	kmapped recovery destination pointers [pcount]
 * @ecr_zerobuf:	PAGE_SIZE zero buffer for EC_DPG_ZERO slots
 * @ecr_encode_matrix:	Cauchy matrix [dcount * (dcount + pcount)]
 * @ecr_dcount:		data stripe count for this raid set
 * @ecr_pcount:		parity stripe count for this raid set
 * @ecr_temp_matrix:	scratch temp matrix for EC recovery
 *			[dcount * dcount]
 * @ecr_invert_matrix:	scratch inverted matrix for EC recovery
 *			[dcount * dcount]
 * @ecr_decode_matrix:	scratch decode matrix for EC recovery
 *			[pcount * dcount]
 * @ecr_gf_tbls:	GF tables for the RG-wide recovery ctx
 *			[dcount * pcount * 32]
 * @ecr_pp_gf_tbls:	GF tables for the per-page recovery ctx
 *			[dcount * pcount * 32]
 *
 * @ecr_temp_matrix, @ecr_invert_matrix and @ecr_decode_matrix are pure
 * scratch space used only within a single lov_ec_recover_init() call to
 * derive the GF tables; they are not read afterwards, so both the
 * RG-wide and per-page contexts can safely share one set (allocated
 * on-demand on first use).  @ecr_gf_tbls and @ecr_pp_gf_tbls, however,
 * are kept in independent buffers because @ecr_gf_tbls backs the
 * RG-wide ctx (recover_ctx), which must remain valid and unmodified
 * across the whole recovery group for fast-path pages, while
 * @ecr_pp_gf_tbls backs the per-page ctx that is rebuilt for every
 * slow-path page; sharing a single GF-tables buffer would let a
 * per-page rebuild silently corrupt the RG-wide tables.  Both are
 * allocated together on the RG-wide lov_ec_recover_init() call, before
 * the kmap loop starts, even though @ecr_pp_gf_tbls is only used by
 * later per-page calls inside the loop -- per-page calls happen while
 * kmap_local_page() mappings may be atomic (kernels < 5.10), where
 * OBD_ALLOC() must not sleep.  @ecr_decode_matrix is sized for the
 * worst case (pcount) since either context may need an unavail_nr up
 * to pcount.
 */
struct lov_ec_rd_state {
	int		*ecr_err_array;
	int		*ecr_parity_used;
	unsigned char	**ecr_ptrs;
	unsigned char	**ecr_recov_ptrs;
	unsigned char	*ecr_zerobuf;
	u8		*ecr_encode_matrix;
	unsigned int	ecr_dcount;
	unsigned int	ecr_pcount;
	u8		*ecr_temp_matrix;
	u8		*ecr_invert_matrix;
	u8		*ecr_decode_matrix;
	u8		*ecr_gf_tbls;
	u8		*ecr_pp_gf_tbls;
};

static int
lov_ec_recover_init(struct ec_recover_ctx *ctx, struct lov_ec_rd_state *state,
		    int unavail_nr, bool reuse_state_bufs)
{
	int dcount = state->ecr_dcount;
	int pcount = state->ecr_pcount;
	u8 *encode_matrix = state->ecr_encode_matrix;
	int *err_array = state->ecr_err_array;
	int *parity_used = state->ecr_parity_used;
	u8 *temp_matrix = NULL;
	u8 *invert_matrix = NULL;
	u8 *decode_matrix = NULL;
	u8 *tbls = NULL;
	int i, j, k, r;
	int rc = 0;

	ENTRY;

	/* temp_matrix/invert_matrix/decode_matrix are pure scratch space
	 * used only within this call to derive the GF tables, so both the
	 * RG-wide and per-page contexts can share one set, allocated into
	 * @state on-demand on first use.  decode_matrix is sized for the
	 * worst case (pcount) since either context may need an unavail_nr
	 * up to pcount.
	 */
	if (!state->ecr_temp_matrix) {
		OBD_ALLOC(state->ecr_temp_matrix, dcount * dcount);
		if (!state->ecr_temp_matrix)
			GOTO(out, rc = -ENOMEM);
	}
	if (!state->ecr_invert_matrix) {
		OBD_ALLOC(state->ecr_invert_matrix, dcount * dcount);
		if (!state->ecr_invert_matrix)
			GOTO(out, rc = -ENOMEM);
	}
	if (!state->ecr_decode_matrix) {
		OBD_ALLOC(state->ecr_decode_matrix, pcount * dcount);
		if (!state->ecr_decode_matrix)
			GOTO(out, rc = -ENOMEM);
	}
	temp_matrix = state->ecr_temp_matrix;
	invert_matrix = state->ecr_invert_matrix;
	decode_matrix = state->ecr_decode_matrix;

	/* @ecr_gf_tbls (RG-wide) and @ecr_pp_gf_tbls (per-page) are kept
	 * independent: the RG-wide ctx must stay valid and unmodified
	 * across the whole recovery group for fast-path pages, while the
	 * per-page ctx is rebuilt for every slow-path page.  Sharing one
	 * buffer would let a per-page rebuild silently corrupt the
	 * RG-wide tables.
	 */
	if (!state->ecr_gf_tbls) {
		OBD_ALLOC(state->ecr_gf_tbls, dcount * pcount * 32);
		if (!state->ecr_gf_tbls)
			GOTO(out, rc = -ENOMEM);
	}
	if (!state->ecr_pp_gf_tbls) {
		OBD_ALLOC(state->ecr_pp_gf_tbls, dcount * pcount * 32);
		if (!state->ecr_pp_gf_tbls)
			GOTO(out, rc = -ENOMEM);
	}
	if (!reuse_state_bufs)
		tbls = state->ecr_gf_tbls;
	else
		tbls = state->ecr_pp_gf_tbls;

	ctx->erc_dcount = dcount;
	ctx->erc_pcount = pcount;
	ctx->erc_unavail_nr = unavail_nr;
	ctx->erc_tbls_size = dcount * pcount * 32;
	ctx->erc_tbls = tbls;

	/* get rid of coefficient rows of failed data stripes */
	k = 0;
	r = 0;
	for (i = 0; i < dcount && r < dcount; i++, r++) {
		while (k < unavail_nr && err_array[k] == r) {
			k++;
			r++;
		}
		for (j = 0; j < dcount; j++)
			temp_matrix[i * dcount + j] =
				encode_matrix[r * dcount + j];
	}

	/* append coefficient rows of used parity stripes */
	if (parity_used) {
		for (i = 0; i < unavail_nr; i++) {
			int row = dcount + parity_used[i];

			for (j = 0; j < dcount; j++)
				temp_matrix[(dcount - unavail_nr + i) *
					    dcount + j] =
					encode_matrix[row * dcount + j];
		}
	}

	/* invert the matrix; a singular matrix here indicates a logic
	 * error in how err_array/parity_used were constructed
	 */
	rc = gf_invert_matrix(temp_matrix, invert_matrix, dcount);
	if (rc < 0)
		GOTO(out, rc = -EIO);

	/* generate decode matrix by using only rows of failed data stripes
	 * from the inverted matrix
	 */
	for (i = 0; i < unavail_nr; i++) {
		for (j = 0; j < dcount; j++)
			decode_matrix[i * dcount + j] =
				invert_matrix[err_array[i] * dcount + j];
	}

	ec_init_tables(dcount, unavail_nr, decode_matrix, ctx->erc_tbls);
	rc = 0;
out:
	/* The buffers are owned by state and will be freed in
	 * lov_ec_bufs_free(). We just need to handle error cleanup
	 * if allocation failed partway through.
	 */
	if (rc) {
		ctx->erc_tbls = NULL;

		if (!reuse_state_bufs) {
			OBD_FREE(state->ecr_gf_tbls, dcount * pcount * 32);
			state->ecr_gf_tbls = NULL;
		}
		OBD_FREE(state->ecr_pp_gf_tbls, dcount * pcount * 32);
		state->ecr_pp_gf_tbls = NULL;
		OBD_FREE(state->ecr_decode_matrix, pcount * dcount);
		state->ecr_decode_matrix = NULL;
		OBD_FREE(state->ecr_invert_matrix, dcount * dcount);
		state->ecr_invert_matrix = NULL;
		OBD_FREE(state->ecr_temp_matrix, dcount * dcount);
		state->ecr_temp_matrix = NULL;
	}

	RETURN(rc);
}

static void
lov_ec_recover_page(struct ec_recover_ctx *ctx, unsigned char **ptrs,
		    unsigned char **recov_ptrs)
{
	ec_encode_data(PAGE_SIZE, ctx->erc_dcount, ctx->erc_unavail_nr,
		       ctx->erc_tbls, ptrs, recov_ptrs);
}

/**
 * lov_ec_bufs_free() - free per-cycle EC working buffers
 * @state:		state whose buffers to free
 *
 * Safe to call after lov_ec_bufs_alloc() whether it succeeded or not.
 */
static void lov_ec_bufs_free(struct lov_ec_rd_state *state)
{
	unsigned int dcount = state->ecr_dcount;
	unsigned int pcount = state->ecr_pcount;

	OBD_FREE(state->ecr_gf_tbls, dcount * pcount * 32);
	OBD_FREE(state->ecr_pp_gf_tbls, dcount * pcount * 32);
	OBD_FREE(state->ecr_decode_matrix, pcount * dcount);
	OBD_FREE(state->ecr_invert_matrix, dcount * dcount);
	OBD_FREE(state->ecr_temp_matrix, dcount * dcount);
	OBD_FREE(state->ecr_encode_matrix,
		 sizeof(*state->ecr_encode_matrix) *
		 dcount * (dcount + pcount));
	OBD_FREE(state->ecr_zerobuf, sizeof(*state->ecr_zerobuf) * PAGE_SIZE);
	OBD_FREE(state->ecr_recov_ptrs,
		 sizeof(*state->ecr_recov_ptrs) * pcount);
	OBD_FREE(state->ecr_ptrs, sizeof(*state->ecr_ptrs) * dcount);
	OBD_FREE(state->ecr_parity_used,
		 sizeof(*state->ecr_parity_used) * LOV_EC_MAX_CODING_STRIPES);
	OBD_FREE(state->ecr_err_array,
		 sizeof(*state->ecr_err_array) * LOV_EC_MAX_CODING_STRIPES);

	state->ecr_err_array = NULL;
	state->ecr_parity_used = NULL;
	state->ecr_ptrs = NULL;
	state->ecr_recov_ptrs = NULL;
	state->ecr_zerobuf = NULL;
	state->ecr_encode_matrix = NULL;
	state->ecr_temp_matrix = NULL;
	state->ecr_invert_matrix = NULL;
	state->ecr_decode_matrix = NULL;
	state->ecr_gf_tbls = NULL;
	state->ecr_pp_gf_tbls = NULL;
}

/**
 * lov_ec_bufs_alloc() - allocate per-cycle EC working buffers
 * @state:		state to populate
 * @dcount:		data stripe count
 * @pcount:		parity stripe count (0 if non-EC component)
 *
 * Allocates err_array/parity_used (sized to LOV_EC_MAX_CODING_STRIPES),
 * ptrs (dcount), and -- only when pcount > 0 -- recov_ptrs (pcount),
 * zerobuf (PAGE_SIZE), and encode_matrix (dcount*(dcount+pcount)).
 * Also generates the Cauchy encode matrix when pcount > 0.
 *
 * Return: 0 on success, -ENOMEM on failure (all partial allocations freed)
 */
static int lov_ec_bufs_alloc(struct lov_ec_rd_state *state,
			     unsigned int dcount, unsigned int pcount)
{
	int rc = -ENOMEM;

	ENTRY;
	state->ecr_dcount = dcount;
	state->ecr_pcount = pcount;
	state->ecr_err_array = NULL;
	state->ecr_parity_used = NULL;
	state->ecr_ptrs = NULL;
	state->ecr_recov_ptrs = NULL;
	state->ecr_zerobuf = NULL;
	state->ecr_encode_matrix = NULL;
	state->ecr_temp_matrix = NULL;
	state->ecr_invert_matrix = NULL;
	state->ecr_decode_matrix = NULL;
	state->ecr_gf_tbls = NULL;
	state->ecr_pp_gf_tbls = NULL;

	OBD_ALLOC(state->ecr_err_array,
		  sizeof(*state->ecr_err_array) * LOV_EC_MAX_CODING_STRIPES);
	if (!state->ecr_err_array)
		GOTO(out, rc);

	OBD_ALLOC(state->ecr_parity_used,
		  sizeof(*state->ecr_parity_used) * LOV_EC_MAX_CODING_STRIPES);
	if (!state->ecr_parity_used)
		GOTO(out, rc);

	OBD_ALLOC(state->ecr_ptrs, sizeof(*state->ecr_ptrs) * dcount);
	if (!state->ecr_ptrs)
		GOTO(out, rc);

	if (pcount > 0) {
		OBD_ALLOC(state->ecr_recov_ptrs,
			  sizeof(*state->ecr_recov_ptrs) * pcount);
		if (!state->ecr_recov_ptrs)
			GOTO(out, rc);

		OBD_ALLOC(state->ecr_zerobuf,
			  sizeof(*state->ecr_zerobuf) * PAGE_SIZE);
		if (!state->ecr_zerobuf)
			GOTO(out, rc);

		OBD_ALLOC(state->ecr_encode_matrix,
			  sizeof(*state->ecr_encode_matrix) * dcount *
			  (dcount + pcount));
		if (!state->ecr_encode_matrix)
			GOTO(out, rc);

		gf_gen_cauchy1_matrix(state->ecr_encode_matrix,
				      dcount + pcount, dcount);

		/* Recovery context buffers (temp_matrix, invert_matrix,
		 * decode_matrix, gf_tbls) are allocated on-demand in
		 * lov_ec_recover_init() when the RG-wide context is first
		 * built, then reused for per-page contexts. This avoids
		 * sleeping allocations inside the kmap loop while allowing
		 * buffer reuse.
		 */
	}
	rc = 0;
out:
	if (rc)
		lov_ec_bufs_free(state);
	RETURN(rc);
}

/**
 * lov_ec_recover_page_pos() - reconstruct one page position in a recovery group
 * @env:	lu_env context
 * @io:		top-level cl_io
 * @state:	EC working buffers (ptrs, recov_ptrs, zerobuf, encode_matrix,
 *		err_array reused as per-page scratch, parity_used)
 * @recover_ctx: shared recovery tables built for @err_nr full-stripe errors
 * @all_pages:	[npages * dcount] cl_page pointers, indexed [stripe*npages + j]
 * @all_states:	[npages * dcount] page states, same indexing
 * @par_vmpages: [err_nr * npages] parity vmpages, indexed [pstripe*npages + j]
 * @npages:	number of page positions in this RG
 * @j:		page position to reconstruct
 * @err_nr:	number of error stripes for the shared ctx
 * @dcount:	data stripe count
 * @pcount:	parity stripe count
 *
 * For page position @j, classifies each stripe's page state, kmaps available
 * data and parity pages, and calls lov_ec_recover_page() to reconstruct
 * EC_DPG_ERROR pages from parity.  Uses the shared @recover_ctx when the
 * per-page error count (r_j) equals @err_nr (fast path), or builds a per-page
 * ctx for the r_j actual errors (slow path, mixed cached+ERROR at position j).
 *
 * Return: 0 on success, negative errno on per-page recover_init failure.
 * On failure, io->ci_ec.ec_recovery_failed is set so the caller can bail.
 */
static int lov_ec_recover_page_pos(const struct lu_env *env,
				   struct cl_io *io,
				   struct lov_ec_rd_state *state,
				   struct ec_recover_ctx *recover_ctx,
				   struct cl_page **all_pages,
				   enum ec_data_pg_state *all_states,
				   struct page **par_vmpages,
				   int npages, int j, int err_nr,
				   unsigned int dcount, unsigned int pcount)
{
	struct ec_recover_ctx per_page_ctx = { 0 };
	struct ec_recover_ctx *use_ctx = NULL;
	int p_j = 0, r_j = 0;
	int rc = 0;
	int k;

	for (k = 0; k < dcount; k++) {
		struct page *vmpage = NULL;
		int idx = k * npages + j;

		if (all_pages[idx])
			vmpage = all_pages[idx]->cp_vmpage;

		switch (all_states[idx]) {
		case EC_DPG_ZERO:
			state->ecr_ptrs[p_j++] = state->ecr_zerobuf;
			break;
		case EC_DPG_UPTODATE:
		case EC_DPG_READ:
			if (vmpage)
				state->ecr_ptrs[p_j++] =
					kmap_local_page(vmpage);
			break;
		case EC_DPG_ERROR:
			LASSERTF(r_j < pcount,
				 "error data index %d >= pcount %d\n",
				 r_j, pcount);
			state->ecr_err_array[r_j] = k;
			if (vmpage)
				state->ecr_recov_ptrs[r_j] =
					kmap_local_page(vmpage);
			r_j++;
			break;
		}
	}

	/* Skip recovery if no errors, too many errors, or no parity pages
	 * available.
	 */
	if (r_j == 0 || r_j > pcount || !par_vmpages)
		goto skip_recovery;

	/* Fill parity ptrs from batch */
	for (k = 0; k < r_j; k++) {
		int pidx = k * npages + j;

		state->ecr_ptrs[p_j + k] =
			kmap_local_page(par_vmpages[pidx]);
	}

	if (r_j == err_nr) {
		/* Fast path: err_array[0..r_j-1] == the original err_array[]
		 * exactly (same size, same sort order, same elements by
		 * construction).
		 */
		use_ctx = recover_ctx;
	} else {
		/* Slow path: mixed cached+ERROR at j.  Build a per-page ctx
		 * for the r_j actual errors and the first r_j parity stripes.
		 * Reuse the RG-wide buffers already in state to avoid sleeping
		 * allocations while kmap_local mappings are live.
		 */
		rc = lov_ec_recover_init(&per_page_ctx, state, r_j, true);
		if (rc == 0)
			use_ctx = &per_page_ctx;
	}

	if (use_ctx)
		lov_ec_recover_page(use_ctx, state->ecr_ptrs,
				    state->ecr_recov_ptrs);

	/* kunmap parity in reverse order of mapping.  kmap_local_page()
	 * mappings are stack-based and must be released in strict LIFO
	 * order (Documentation/mm/highmem.rst).  The parity pages were
	 * mapped last, in increasing k, so unmap them in decreasing k.
	 */
	for (k = r_j - 1; k >= 0; k--) {
		kunmap_local(state->ecr_ptrs[p_j + k]);
		state->ecr_ptrs[p_j + k] = NULL;
	}

skip_recovery:
	/* kunmap data and recovery pages.  These were acquired
	 * interleaved in the forward k loop above (available data pages
	 * into ecr_ptrs[], error data pages into ecr_recov_ptrs[]), so
	 * re-walk that loop in reverse and unmap each page as it is
	 * encountered, honouring the kmap_local LIFO contract.  p_j and
	 * r_j are decremented to track the next slot exactly as the
	 * forward loop advanced them; the vmpage checks mirror the
	 * "if (vmpage)" guards that gated each kmap_local_page().
	 */
	for (k = (int)dcount - 1; k >= 0; k--) {
		struct page *vmpage = NULL;
		int idx = k * npages + j;

		if (all_pages[idx])
			vmpage = all_pages[idx]->cp_vmpage;

		switch (all_states[idx]) {
		case EC_DPG_ZERO:
			p_j--;
			break;
		case EC_DPG_UPTODATE:
		case EC_DPG_READ:
			if (vmpage) {
				p_j--;
				kunmap_local(state->ecr_ptrs[p_j]);
				state->ecr_ptrs[p_j] = NULL;
			}
			break;
		case EC_DPG_ERROR:
			r_j--;
			if (vmpage) {
				kunmap_local(state->ecr_recov_ptrs[r_j]);
				state->ecr_recov_ptrs[r_j] = NULL;
			}
			break;
		}
	}

	/* Per-page recover_init failed (-ENOMEM or -EIO from singular
	 * matrix): ERROR pages at positions 0..j are already in ec_page_list
	 * and will be disowned by vvp_io_ec_rd_end.
	 */
	if (rc)
		io->u.ci_ec.ec_recovery_failed = true;

	return rc;
}

static int lov_io_ec_rd_start(const struct lu_env *env,
			      const struct cl_io_slice *ios)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = ios->cis_io;
	struct lov_object *lov = lio->lis_object;
	struct lov_device *dev = lov_object_dev(lov);
	struct lov_layout_composite *comp = &lov->u.composite;
	struct lov_layout_entry *lle_d = NULL;	/* data component entry */
	struct lov_layout_entry *lle_p = NULL;	/* parity component entry */
	struct lov_stripe_md_entry *lsme_d;
	struct lov_stripe_md_entry *lsme_p;
	int data_mir_idx;	/* data mirror index */
	int parity_mir_idx;	/* parity mirror index */
	int index;	/* data component index */
	int pindex;	/* parity component index */

	struct lov_ec_rd_state state = { 0 };
	struct ec_recover_ctx recover_ctx = { 0 };
	struct ec_split_comp sc = { 0 };
	unsigned int dcount;	/* erasure parameters: data stripe count */
	unsigned int pcount;	/* erasure parameters: parity stripe count */
	unsigned int raid_set = 0; /* raid set number we are reading from */
	unsigned long ss;		/* stripe size */
	unsigned int pgs_per_stripe;	/* pages per stripe */
	unsigned long RGs;		/* recovery group size */
	unsigned long long size;	/* read size of this cycle */

	int err_nr = 0;				/* # of missing data chunks */

	struct cl_page **all_pages = NULL;
	enum ec_data_pg_state *all_states = NULL;
	unsigned int array_count = 0;

	struct cl_page **par_clpages = NULL;
	struct page **par_vmpages = NULL;
	unsigned int par_arr_cnt;

	struct cl_page_list dlist;
	struct cl_page_list plist;
	struct cl_page *page;
	int i, j, k;
	int rc = 0;

	ENTRY;
	cl_page_list_init(&dlist);
	cl_page_list_init(&plist);

	/* VFS readahead can trigger EC recovery for pages beyond EOF.  These
	 * pages have no data to recover - the VFS will zero-fill them - so
	 * just return success.  Nothing past this raid set can have data
	 * either, so stop cl_io_loop() here instead of letting it walk every
	 * remaining raid set of the request (each cycle costs a getattr and
	 * a lock enqueue).
	 */
	if (lio->lis_pos >= io->u.ci_ec.ec_inode_size) {
		io->u.ci_ec.ec_inner.crw_pos += io->u.ci_ec.ec_inner.crw_bytes;
		io->u.ci_ec.ec_inner.crw_bytes = 0;
		io->ci_continue = 0;

		rc = lov_io_start(env, ios);
		RETURN(rc);
	}

	data_mir_idx = lio->lis_mirror_index;
	/* get data component */
	index = lov_io_layout_at_mirror(lio, lio->lis_pos, data_mir_idx);
	if (index < 0 || !lsm_entry_inited(lov->lo_lsm, index)) {
		CWARN("%s: "DFID": failed to find valid data component covering file offset %llu, mirror: %d: rc = %d\n",
		      lov2obd(dev->ld_lov)->obd_name,
		      PFID(lu_object_fid(lov2lu(lov))), lio->lis_pos,
		      data_mir_idx, index);
		RETURN(index < 0 ? index : -EINVAL);
	}
	parity_mir_idx = lov_parity_mirror_index_from_data(lio, data_mir_idx);
	if (parity_mir_idx < 0) {
		CWARN("%s: "DFID": failed to find valid parity mirror for data mirror %d: rc = %d\n",
		      lov2obd(dev->ld_lov)->obd_name,
		      PFID(lu_object_fid(lov2lu(lov))), data_mir_idx,
		      parity_mir_idx);
		RETURN(parity_mir_idx);
	}
	lle_d = &comp->lo_entries[index];

	/* [lis_pos, lis_endpos] could be a non-ec component, just data read
	 * with dcount <= stripe_count, else must be a ec component read
	 * lov_io_ec_rd_iter_init() has set each read cycle to include stripes
	 * from raid sets with the same EC parameters or with no EC.
	 */
	lsme_d = lle_d->lle_lsme;
	dcount = lsme_d->lsme_dstripe_count;
	if (dcount > 0) {
		u64 offset;
		u64 offset_i;
		u64 row;

		ec_split_stripes(lsme_d->lsme_stripe_count, dcount, &sc);
		/* determine the raid set count and its stripe count */
		offset = lio->lis_pos - lsme_d->lsme_extent.e_start;
		row = div64_u64(offset, (u64)lsme_d->lsme_stripe_size *
					lsme_d->lsme_stripe_count);
		offset_i = div64_u64(offset, lsme_d->lsme_stripe_size) %
			   lsme_d->lsme_stripe_count;
		if (offset_i < sc.esc_k0 * sc.esc_n0) {
			dcount = sc.esc_k0;
			raid_set = row * (sc.esc_n0 + sc.esc_n1) +
				   offset_i / sc.esc_k0;
		} else {
			dcount = sc.esc_k1;
			raid_set = row * (sc.esc_n0 + sc.esc_n1) + sc.esc_n0 +
				   (offset_i - sc.esc_k0 * sc.esc_n0) /
				   sc.esc_k1;
		}
		pcount = lsme_d->lsme_cstripe_count;
	} else {
		/* with stripes with no EC, dcount == 0, set it to 4 */
		if (lsme_d->lsme_stripe_count >= 4)
			dcount = 4;
		else
			dcount = lsme_d->lsme_stripe_count;
		pcount = 0;
	}
	size = min_t(__u64,
		     lsme_d->lsme_extent.e_end - lsme_d->lsme_extent.e_start,
		     lio->lis_endpos - lio->lis_pos);
	ss = lsme_d->lsme_stripe_size;
	LASSERTF(ss >= PAGE_SIZE,
		 "stripe size %lu is smaller than page size %lu\n",
		 ss, PAGE_SIZE);

	/* size data to be read for each cycle, it's recovery group size for
	 * EC, or just data size for non EC read cycle
	 */
	RGs = ss * dcount;
	pgs_per_stripe = (ss + PAGE_SIZE - 1) >> PAGE_SHIFT;

	rc = lov_ec_bufs_alloc(&state, dcount, pcount);
	if (rc)
		GOTO(out, rc);

	if (lsme_d->lsme_dstripe_count > 0) {
		/* get parity component */
		pindex = lov_io_layout_at_mirror(lio, lio->lis_pos,
						 parity_mir_idx);
		if (pindex < 0 || !lsm_entry_inited(lov->lo_lsm, pindex)) {
			CWARN("%s: "DFID": failed to find valid parity component covering file offset %llu, mirror: %d: rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(lov))), lio->lis_pos,
			      parity_mir_idx, pindex);
			GOTO(out_ptrs, rc = pindex < 0 ? pindex : -EINVAL);
		}
		lle_p = &comp->lo_entries[pindex];
		lsme_p = lle_p->lle_lsme;
	}

	CDEBUG(D_INODE, DFID": ec read comp %d (dcount %d pcount %d) from %llu to %llu, RGs %lu pgs_per_stripe %d\n",
	       PFID(lu_object_fid(lov2lu(lov))), index, dcount, pcount,
	       lio->lis_pos, lio->lis_pos + size, RGs, pgs_per_stripe);

	/* read size is within the raid sets of the same EC parameters */
	for (i = 0; i < DIV_ROUND_UP(size, RGs); i++, raid_set++) {
		loff_t soff; /* start offset of a recovery group */
		loff_t eoff; /* end offset of a recovery group */
		unsigned int pg_seq_start;
		unsigned int pg_seq_end;
		unsigned int npages = 0;
		int par_stripes_used = 0;
		loff_t outer_start = io->u.ci_ec.ec_outer.crw_pos;
		loff_t outer_end = io->u.ci_ec.ec_outer.crw_pos +
				  io->u.ci_ec.ec_outer.crw_bytes;

		/* soff is at the beginning of a recovery group/raid set */
		soff = lio->lis_pos + i * RGs;
		eoff = soff + RGs;

		if (eoff > lio->lis_pos + size)
			eoff = lio->lis_pos + size;

		/* each recovery groups contains dcount stripes, each page
		 * in these dcount stripes are calculated to get each page
		 * in the parity stripes.
		 *
		 * If outer read spans more than one stripe in a recovery group,
		 * we need to read the whole stripe.
		 */
		if (outer_start < soff)
			outer_start = soff;
		if (outer_end > eoff)
			outer_end = eoff;
		/* Read the whole stripe when the outer read spans more than
		 * one stripe within this RG (the per-stripe page ranges then
		 * differ between stripes, so only the full range is safe);
		 * otherwise read just the page positions the outer read needs.
		 */
		if (outer_end <= outer_start) {
			pg_seq_start = 0;
			pg_seq_end = 0;
		} else if ((outer_start - soff) / ss !=
			   (outer_end - 1 - soff) / ss) {
			pg_seq_start = 0;
			pg_seq_end = pgs_per_stripe;
		} else {
			pg_seq_start = ((outer_start - soff) >> PAGE_SHIFT) %
				       pgs_per_stripe;
			pg_seq_end = DIV_ROUND_UP(outer_end - soff, PAGE_SIZE) %
				     pgs_per_stripe;
			if (pg_seq_end == 0)
				pg_seq_end = pgs_per_stripe;
		}
		CDEBUG(D_INFO, DFID" read for page series from %d to %d\n",
		       PFID(lu_object_fid(lov2lu(lov))),
		       pg_seq_start, pg_seq_end);

		/* Batched per-stripe reads for this RG */
		npages = pg_seq_end - pg_seq_start;

		array_count = npages * dcount;
		OBD_ALLOC_PTR_ARRAY_LARGE(all_pages, array_count);
		OBD_ALLOC_PTR_ARRAY_LARGE(all_states, array_count);
		if (!all_pages || !all_states)
			GOTO(out_err, rc = -ENOMEM);

		/* Read all pages per stripe: one cl_io_submit_sync per
		 * stripe with all npages pages.  Arrays indexed as
		 * [stripe * npages + page_pos].
		 */
		for (k = 0; k < dcount; k++) {
			rc = lov_ec_read_stripe_pages(env, lio, index, k,
					lsme_d, soff, eoff,
					pg_seq_start, npages,
					&all_pages[k * npages],
					&all_states[k * npages],
					&dlist);
			if (rc) {
				CWARN("%s: "DFID": fail to read stripe %d: rc = %d\n",
				      lov2obd(dev->ld_lov)->obd_name,
				      PFID(lu_object_fid(lov2lu(lov))),
				      k, rc);
				io->u.ci_ec.ec_recovery_failed = true;
				GOTO(rg_cleanup, rc);
			}
		}

		/* Populate err_array from batch read states.  A stripe with
		 * any ERROR page is unavailable.
		 */
		err_nr = 0;
		for (k = 0; k < dcount; k++) {
			int pg;
			bool has_error = false;

			for (pg = 0; pg < npages; pg++) {
				if (all_states[k * npages + pg] ==
				    EC_DPG_ERROR) {
					has_error = true;
					break;
				}
			}
			if (has_error)
				state.ecr_err_array[err_nr++] = k;

			if (err_nr >= LOV_EC_MAX_CODING_STRIPES ||
			    err_nr > pcount)
				break;
		}

		/* Recheck after batch reads: per-page errors may exceed pcount
		 * even when the pre-check was OK (a second OST can die mid-IO,
		 * or all_states reveals more error stripes than lso_status
		 * predicted).
		 * Bail out cleanly so vvp_io_ec_rd_end skips the cache read
		 * and we return -EAGAIN instead of zeros.
		 */
		if (err_nr >= LOV_EC_MAX_CODING_STRIPES || err_nr > pcount) {
			CWARN("%s: "DFID": too many unrecoverable stripes in raid set %d: err_nr %d > pcount %d: rc = %d\n",
			      lov2obd(dev->ld_lov)->obd_name,
			      PFID(lu_object_fid(lov2lu(lov))),
			      raid_set, err_nr, pcount, -EIO);
			io->u.ci_ec.ec_recovery_failed = true;
			GOTO(rg_cleanup, rc = -EAGAIN);
		}

		/* Batch parity reads if needed. par_vmpages/par_clpages
		 * indexed as [parity_stripe * npages + page_pos].
		 */
		par_arr_cnt = npages * err_nr;
		if (err_nr > 0 && err_nr <= pcount) {
			unsigned long long poff;
			int pi, ps;

			poff = lsme_p->lsme_extent.e_start +
				raid_set * (u64)pcount *
				lsme_p->lsme_stripe_size;

			OBD_ALLOC_PTR_ARRAY_LARGE(par_vmpages, par_arr_cnt);
			OBD_ALLOC_PTR_ARRAY_LARGE(par_clpages, par_arr_cnt);
			if (!par_vmpages || !par_clpages) {
				io->u.ci_ec.ec_recovery_failed = true;
				GOTO(rg_cleanup, rc = -ENOMEM);
			}

			/* Read parity stripes until we have enough (err_nr).
			 * Skip dead stripes.
			 */
			for (pi = 0; pi < pcount && par_stripes_used < err_nr;
			     pi++) {
				ps = par_stripes_used;
				rc = lov_ec_read_parity_stripe(env, lio, pindex,
						pi, lsme_p, poff,
						pg_seq_start, npages,
						&par_vmpages[ps * npages],
						&par_clpages[ps * npages],
						&plist);
				if (rc) {
					rc = 0; /* skip, try next */
					continue;
				}
				state.ecr_parity_used[par_stripes_used++] = pi;
			}

			if (par_stripes_used < err_nr) {
				CWARN("%s: "DFID": not enough parity stripes (%d < %d): rc = %d\n",
				      lov2obd(dev->ld_lov)->obd_name,
				      PFID(lu_object_fid(lov2lu(lov))),
				      par_stripes_used, err_nr, -EIO);
				/* plist cleanup handled by rg_cleanup: path */
				io->u.ci_ec.ec_recovery_failed = true;
				GOTO(rg_cleanup, rc = -EIO);
			}

			/* Init recovery tables; allocates working buffers
			 * into state for reuse by per-page contexts.
			 */
			rc = lov_ec_recover_init(&recover_ctx, &state, err_nr,
						 false);
			if (rc) {
				io->u.ci_ec.ec_recovery_failed = true;
				/* plist cleanup handled by rg_cleanup: path */
				GOTO(rg_cleanup, rc);
			}
			/* err_array has been used to build recover_ctx, it is
			 * fine to reuse it in the per-page error array below.
			 */
		}

		/* Per-page reconstruction loop.
		 *
		 * The shared recover_ctx was built for err_nr unavailable
		 * stripes using err_array[].  At page position j, the number
		 * of actual EC_DPG_ERROR stripes (r_j) can be less than
		 * err_nr when some positions on an "error stripe" were
		 * already Uptodate in cache before recovery started.  Using
		 * the shared ctx with r_j < err_nr would write past the end
		 * of recov_ptrs[] and crash in ec_encode_data_base.
		 *
		 * Build a per-page subset in err_array[0..r_j-1] (same sort
		 * order as the original err_array[]) and use the shared ctx
		 * only when r_j == err_nr (full-stripe failure, common case).
		 * Otherwise build a per-page ctx with the err_array[] subset
		 * and the first r_j entries of parity_used[] -- any r_j
		 * distinct parity stripes we already read are enough to
		 * recover r_j data positions.  Reusing err_array[] is safe
		 * because recover_ctx already baked the original contents
		 * into erc_tbls.
		 */
		for (j = 0; j < npages; j++) {
			rc = lov_ec_recover_page_pos(env, io, &state,
						     &recover_ctx, all_pages,
						     all_states, par_vmpages,
						     npages, j, err_nr,
						     dcount, pcount);
			if (rc)
				GOTO(rg_cleanup, rc);
		} /* for each page position */

		/* Mark all recovered pages Uptodate after the entire
		 * reconstruction loop completes.  Doing this inside the
		 * per-page loop would mark pages for later positions
		 * Uptodate before they are actually reconstructed.
		 */
		if (!io->u.ci_ec.ec_recovery_failed) {
			cl_page_list_for_each(page, &io->u.ci_ec.ec_page_list)
				SetPageUptodate(cl_page_vmpage(page));
		}

rg_cleanup:
		/* release parity pages */
		if (par_vmpages) {
			for (k = 0; k < par_arr_cnt; k++) {
				if (par_vmpages[k]) {
					unlock_page(par_vmpages[k]);
					__free_page(par_vmpages[k]);
				}
			}
		}
		/* the owernership of cl_page in par_clpages[] has been
		 * transferred to plist
		 */
		cl_page_list_fini(env, &plist);
		OBD_FREE_PTR_ARRAY_LARGE(par_clpages, par_arr_cnt);
		par_clpages = NULL;
		OBD_FREE_PTR_ARRAY_LARGE(par_vmpages, par_arr_cnt);
		par_vmpages = NULL;

		/* Release data pages */
		cl_page_list_disown(env, &dlist);
		cl_page_list_fini(env, &dlist);

		/* Release pages not in dlist(READ) nor in ec_page_list(ERROR):
		 * - UPTODATE pages: never added to any list
		 */
		for (k = 0; k < array_count; k++) {
			if (all_pages[k]) {
				if (all_states[k] == EC_DPG_UPTODATE) {
					cl_page_disown(env, io, all_pages[k]);
					cl_page_put(env, all_pages[k]);
				}
				all_pages[k] = NULL;
			}
		}

		if (rc)
			GOTO(out_err, rc);

		OBD_FREE_PTR_ARRAY_LARGE(all_states, array_count);
		all_states = NULL;
		OBD_FREE_PTR_ARRAY_LARGE(all_pages, array_count);
		all_pages = NULL;
		/* batch scope */
	} /* for each recovery group */

out_err:
	OBD_FREE_PTR_ARRAY_LARGE(all_states, array_count);
	OBD_FREE_PTR_ARRAY_LARGE(all_pages, array_count);
	/* If bail out in the middle of recovery, we need to cleanup everything,
	 * including kunmap data and parity pages, release them.
	 *
	 * In practice these loops are defensive no-ops:
	 * lov_ec_recover_page_pos() is self-contained and kunmaps/NULLs every
	 * slot it maps before returning (both the parity loop and the
	 * skip_recovery data loop run unconditionally before its return),
	 * so by the time any path reaches out_err, ecr_ptrs[]/ecr_recov_ptrs[]
	 * are all NULL. The reverse iteration and per-slot NULL guards keep
	 * this safe should a future change bail with live mappings; a fully
	 * correct LIFO unwind in that case would need to re-walk
	 * all_pages[]/all_states[] exactly as lov_ec_recover_page_pos() does,
	 * since data and error-data mappings are interleaved in a single
	 * kmap_local stack.
	 */
	if (state.ecr_recov_ptrs)
		for (k = (int)pcount - 1; k >= 0; k--)
			if (state.ecr_recov_ptrs[k])
				kunmap_local(state.ecr_recov_ptrs[k]);
	if (state.ecr_ptrs)
		for (k = (int)dcount - 1; k >= 0; k--)
			if (state.ecr_ptrs[k] &&
			    state.ecr_ptrs[k] != state.ecr_zerobuf)
				kunmap_local(state.ecr_ptrs[k]);
	cl_page_list_disown(env, &dlist);
	cl_page_list_fini(env, &dlist);

out_ptrs:
	lov_ec_bufs_free(&state);
out:
	if (rc != 0)
		CDEBUG(D_INODE,
		       DFID": ec read comp %d failed: rc = %d\n",
		       PFID(lu_object_fid(lov2lu(lov))), index, rc);

	/* inner io advance */
	if (rc == 0) {
		io->u.ci_ec.ec_inner.crw_pos += size;
		io->u.ci_ec.ec_inner.crw_bytes -= size;

		rc = lov_io_start(env, ios);
	}

	RETURN(rc);
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

	OBD_FREE_PTR_ARRAY(lio->lis_trunc_stripe_index,
			   lio->lis_object->u.composite.lo_entry_count);
	lio->lis_trunc_stripe_index = NULL;

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

static int lov_io_read_ahead_prep(const struct lu_env *env,
				  const struct cl_io_slice *ios,
				  pgoff_t start, struct cl_read_ahead *ra)
{
	struct lov_io		*lio = cl2lov_io(env, ios);
	struct lov_object	*loo = lio->lis_object;
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

	offset = start << PAGE_SHIFT;
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
	rc = cl_io_read_ahead_prep(sub->sub_env, &sub->sub_io,
				   suboff >> PAGE_SHIFT, ra);

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
	ra_end = lov_io_extent(lio, index)->e_end >> PAGE_SHIFT;
	if (ra_end != CL_PAGE_EOF && ra->cra_end_idx >= ra_end)
		ra->cra_end_idx = ra_end - 1;

	if (r0->lo_nr == 1) /* single stripe file */
		RETURN(0);

	pps = lov_lse(loo, index)->lsme_stripe_size >> PAGE_SHIFT;

	CDEBUG(D_READA, DFID " max_index = %lu, pps = %u, index = %d, stripe_size = %u, stripe no = %u, start index = %lu\n",
	       PFID(lu_object_fid(lov2lu(loo))), ra->cra_end_idx, pps, index,
	       lov_lse(loo, index)->lsme_stripe_size, stripe, start);

	/* never exceed the end of the stripe */
	ra->cra_end_idx = min_t(pgoff_t, ra->cra_end_idx,
				start + pps - start % pps - 1);
	RETURN(0);
}

static int lov_io_lru_reserve(const struct lu_env *env,
			      const struct cl_io_slice *ios, loff_t pos,
			      size_t bytes)
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

static int lov_dio_submit(const struct lu_env *env,
			  struct cl_io *io,
			  const struct cl_io_slice *ios,
			  enum cl_req_type crt, struct cl_dio_pages *cdp)
{
	struct lov_io *lio = cl2lov_io(env, ios);
	struct lov_io_sub *sub;
	int rc = 0;
	int index;

	ENTRY;

	if (lov_pages_is_empty(cdp)) {
		cl_dio_pages_complete(env, cdp, cdp->cdp_page_count, 0);
		RETURN(0);
	}

	index = cdp->cdp_lov_index;

	sub = lov_sub_get(env, lio, index);
	if (!IS_ERR(sub)) {
		rc = cl_dio_submit_rw(sub->sub_env, &sub->sub_io,
				      crt, cdp);
	} else {
		rc = PTR_ERR(sub);
	}

	RETURN(rc);
}

/**
 * lov_io_submit() - lov implementation of cl_operations::cio_submit() method.
 * @env: lustre execution environment
 * @io: highlevel I/O request
 * @ios: LOV specific IO
 * @crt: Requested transfer type
 * @queue: Page queue
 *
 * lov implementation of cl_operations::cio_submit() method. It takes a list
 * of pages in @queue, splits it into per-stripe sub-lists, invokes
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
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static int lov_io_submit(const struct lu_env *env,
			 struct cl_io *io,
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
			LASSERT(page->cp_type == CPT_TRANSIENT);
			cl_page_complete(env, page, crt, 0);
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
			       cl_commit_cbt cb, enum cl_io_priority prio)
{
	struct cl_page_list *plist = &lov_env_info(env)->lti_plist;
	struct lov_io *lio = cl2lov_io(env, ios);
	bool hp = cl_io_high_prio(prio);
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
					from, to, cb, prio);
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
						plist, from, stripe_to, cb,
						prio);
		} else {
			rc = PTR_ERR(sub);
			break;
		}

		if (plist->pl_nr > 0) /* short write */
			break;

		from = 0;

		if (!hp && lov_comp_entry(index) !=
		    lov_comp_entry(page->cp_lov_index))
			cl_io_extent_release(sub->sub_env, &sub->sub_io, prio);
	}

	if (rc == 0 && hp) {
		list_for_each_entry(sub, &lio->lis_subios, sub_list)
			cl_io_extent_release(sub->sub_env, &sub->sub_io, prio);
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
		offset = fio->ft_index << PAGE_SHIFT;
		entry = lov_io_layout_at(lio, offset);
		if (entry < 0) {
			CERROR(DFID": page fault index %lu invalid component: %d, mirror: %d\n",
			       PFID(lu_object_fid(&ios->cis_obj->co_lu)),
			       fio->ft_index, entry,
			       lio->lis_mirror_index);
			RETURN(-EIO);
		}
		stripe = lov_stripe_number(lio->lis_object->lo_lsm,
					   entry, offset);

		if (fio->ft_page->cp_lov_index !=
		    lov_comp_index(entry, stripe)) {
			CDEBUG(D_INFO, DFID": page fault at index %lu, at mirror %u comp entry %u stripe %u, "
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
	sub->sub_io.u.ci_fault.ft_bytes = fio->ft_bytes;

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
		[CIT_EC_RD] = {
			.cio_fini      = lov_io_fini,
			.cio_iter_init = lov_io_ec_rd_iter_init,
			.cio_iter_fini = lov_io_iter_fini,
			.cio_lock      = lov_io_lock,
			.cio_unlock    = lov_io_unlock,
			.cio_start     = lov_io_ec_rd_start,
			.cio_end       = lov_io_end,
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
	.cio_read_ahead_prep		= lov_io_read_ahead_prep,
	.cio_lru_reserve		= lov_io_lru_reserve,
	.cio_submit			= lov_io_submit,
	.cio_dio_submit			= lov_dio_submit,
	.cio_commit_async		= lov_io_commit_async,
};

/*
 * Empty lov io operations.
 */
static void lov_empty_io_fini(const struct lu_env *env,
			      const struct cl_io_slice *ios)
{
	struct lov_object *lov = cl2lov(ios->cis_obj);
	struct lov_io *lio = cl2lov_io(env, ios);
	struct cl_io *io = lio->lis_cl.cis_io;

	ENTRY;

	if (!(io->ci_type == CIT_MISC && io->ci_ignore_layout) &&
		atomic_dec_and_test(&lov->lo_active_ios))
		wake_up(&lov->lo_waitq);
	EXIT;
}

static int lov_empty_dio_submit(const struct lu_env *env,
				struct cl_io *io,
				const struct cl_io_slice *ios,
				enum cl_req_type crt, struct cl_dio_pages *cdp)
{
	return -EBADF;
}

static int lov_empty_io_submit(const struct lu_env *env,
			       struct cl_io *io,
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

/*
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
	.cio_dio_submit                = lov_empty_dio_submit,
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
	result = lov_io_slice_init(env, lio, lov, io);
	if (result)
		GOTO(out, result);

	result = lov_io_subio_init(env, lio, io);
	if (!result) {
		cl_io_slice_add(io, &lio->lis_cl, obj, &lov_io_ops);
		if (!(io->ci_ignore_layout && io->ci_type == CIT_MISC))
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
	int result = 0;

	ENTRY;

	lio->lis_object = lov;
	switch (io->ci_type) {
	case CIT_MISC:
	case CIT_GLIMPSE:
	case CIT_READ:
	case CIT_EC_RD:
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
	default:
		LBUG();
	}
	if (result == 0) {
		cl_io_slice_add(io, &lio->lis_cl, obj, &lov_empty_io_ops);
		if (!(io->ci_ignore_layout && io->ci_type == CIT_MISC))
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
	case CIT_EC_RD:
		io->ci_restore_needed = 1;
		result = -ENODATA;
		break;
	}

	if (result == 0) {
		cl_io_slice_add(io, &lio->lis_cl, obj, &lov_empty_io_ops);
		if (!(io->ci_ignore_layout && io->ci_type == CIT_MISC))
			atomic_inc(&lov->lo_active_ios);
	}

	io->ci_result = result < 0 ? result : 0;
	RETURN(result);
}

/* confirm this offset is in the given layout entry */
bool lov_io_layout_at_confirm(struct lov_io *lio, int entry, __u64 offset)
{
	struct lov_object *lov = lio->lis_object;
	struct lov_layout_entry *lle = lov_entry(lov, entry);

	if ((offset >= lle->lle_extent->e_start &&
	     offset < lle->lle_extent->e_end) ||
	    (offset == OBD_OBJECT_EOF &&
	     lle->lle_extent->e_end == OBD_OBJECT_EOF))
		return true;
	return false;
}

/**
 * lov_io_layout_at_mirror() - Return the index in composite layout given
 * file offset
 *
 * @lio: Pointer to struct lov_io
 * @offset: Offset in the composite layout
 * @mirror_idx: for FLR, index of the mirror where to find the component
 *
 * Return the index in composite:lo_entries by the file offset
 *
 * Return:
 * * %>=0 composite index where offset is located
 * * %negative on error
 */
int lov_io_layout_at_mirror(struct lov_io *lio, __u64 offset, int mirror_index)
{
	struct lov_object *lov = lio->lis_object;
	struct lov_layout_composite *comp = &lov->u.composite;
	int start_index = 0;
	int end_index = comp->lo_entry_count - 1;
	int i;

	LASSERT(lov->lo_type == LLT_COMP);

	/* This is actual file offset so nothing can cover eof. */
	if (offset == LUSTRE_EOF)
		return -EINVAL;

	if (lov_is_flr(lov)) {
		struct lov_mirror_entry *lre;

		if (mirror_index < 0 ||
		    mirror_index >= lov->u.composite.lo_mirror_count)
			return -EINVAL;

		lre = lov_mirror_entry(lov, mirror_index);
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

	return -EINVAL;
}

int lov_io_layout_at(struct lov_io *lio, __u64 offset)
{
	return lov_io_layout_at_mirror(lio, offset, lio->lis_mirror_index);
}

/** @} lov */
