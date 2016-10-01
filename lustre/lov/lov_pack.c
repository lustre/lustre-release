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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lov/lov_pack.c
 *
 * (Un)packing of OST/MDS requests
 *
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <lustre/lustre_idl.h>
#include <lustre/lustre_user.h>

#include <lustre_net.h>
#include <lustre_swab.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>

#include "lov_cl_internal.h"
#include "lov_internal.h"

void lov_dump_lmm_common(int level, void *lmmp)
{
	struct lov_mds_md *lmm = lmmp;
	struct ost_id	oi;

	lmm_oi_le_to_cpu(&oi, &lmm->lmm_oi);
	CDEBUG(level, "objid "DOSTID", magic 0x%08x, pattern %#x\n",
	       POSTID(&oi), le32_to_cpu(lmm->lmm_magic),
	       le32_to_cpu(lmm->lmm_pattern));
	CDEBUG(level, "stripe_size %u, stripe_count %u, layout_gen %u\n",
	       le32_to_cpu(lmm->lmm_stripe_size),
	       le16_to_cpu(lmm->lmm_stripe_count),
	       le16_to_cpu(lmm->lmm_layout_gen));
}

static void lov_dump_lmm_objects(int level, struct lov_ost_data *lod,
				 int stripe_count)
{
	int i;

	if (stripe_count > LOV_V1_INSANE_STRIPE_COUNT) {
		CDEBUG(level, "bad stripe_count %u > max_stripe_count %u\n",
		       stripe_count, LOV_V1_INSANE_STRIPE_COUNT);
		return;
	}

	for (i = 0; i < stripe_count; ++i, ++lod) {
		struct ost_id oi;

		ostid_le_to_cpu(&lod->l_ost_oi, &oi);
		CDEBUG(level, "stripe %u idx %u subobj "DOSTID"\n", i,
		       le32_to_cpu(lod->l_ost_idx), POSTID(&oi));
	}
}

void lov_dump_lmm_v1(int level, struct lov_mds_md_v1 *lmm)
{
        lov_dump_lmm_common(level, lmm);
        lov_dump_lmm_objects(level, lmm->lmm_objects,
                             le16_to_cpu(lmm->lmm_stripe_count));
}

void lov_dump_lmm_v3(int level, struct lov_mds_md_v3 *lmm)
{
	lov_dump_lmm_common(level, lmm);
	CDEBUG(level, "pool_name "LOV_POOLNAMEF"\n", lmm->lmm_pool_name);
	lov_dump_lmm_objects(level, lmm->lmm_objects,
			     le16_to_cpu(lmm->lmm_stripe_count));
}

void lov_dump_lmm(int level, void *lmm)
{
	int magic;

	magic = le32_to_cpu(((struct lov_mds_md *)lmm)->lmm_magic);
	switch (magic) {
	case LOV_MAGIC_V1:
		lov_dump_lmm_v1(level, (struct lov_mds_md_v1 *)lmm);
		break;
	case LOV_MAGIC_V3:
		lov_dump_lmm_v3(level, (struct lov_mds_md_v3 *)lmm);
		break;
	default:
		CDEBUG(level, "unrecognized lmm_magic %x, assuming %x\n",
		       magic, LOV_MAGIC_V1);
		lov_dump_lmm_common(level, lmm);
		break;
	}
}

/**
 * Pack LOV striping metadata for disk storage format (in little
 * endian byte order).
 *
 * This follows the getxattr() conventions. If \a buf_size is zero
 * then return the size needed. If \a buf_size is too small then
 * return -ERANGE. Otherwise return the size of the result.
 */
ssize_t lov_lsm_pack_v1v3(const struct lov_stripe_md *lsm, void *buf,
			  size_t buf_size)
{
	struct lov_mds_md_v1 *lmmv1 = buf;
	struct lov_mds_md_v3 *lmmv3 = buf;
	struct lov_ost_data_v1 *lmm_objects;
	size_t lmm_size;
	unsigned int i;
	ENTRY;

	lmm_size = lov_mds_md_size(lsm->lsm_entries[0]->lsme_stripe_count,
				   lsm->lsm_magic);
	if (buf_size == 0)
		RETURN(lmm_size);

	if (buf_size < lmm_size)
		RETURN(-ERANGE);

	/* lmmv1 and lmmv3 point to the same struct and have the
	 * same first fields
	 */
	lmmv1->lmm_magic = cpu_to_le32(lsm->lsm_magic);
	lmm_oi_cpu_to_le(&lmmv1->lmm_oi, &lsm->lsm_oi);
	lmmv1->lmm_stripe_size = cpu_to_le32(
				lsm->lsm_entries[0]->lsme_stripe_size);
	lmmv1->lmm_stripe_count = cpu_to_le16(
				lsm->lsm_entries[0]->lsme_stripe_count);
	lmmv1->lmm_pattern = cpu_to_le32(lsm->lsm_entries[0]->lsme_pattern);
	lmmv1->lmm_layout_gen = cpu_to_le16(lsm->lsm_layout_gen);

	if (lsm->lsm_magic == LOV_MAGIC_V3) {
		CLASSERT(sizeof(lsm->lsm_entries[0]->lsme_pool_name) ==
			 sizeof(lmmv3->lmm_pool_name));
		strlcpy(lmmv3->lmm_pool_name,
			lsm->lsm_entries[0]->lsme_pool_name,
			sizeof(lmmv3->lmm_pool_name));
		lmm_objects = lmmv3->lmm_objects;
	} else {
		lmm_objects = lmmv1->lmm_objects;
	}

	if (lsm->lsm_is_released)
		RETURN(lmm_size);

	for (i = 0; i < lsm->lsm_entries[0]->lsme_stripe_count; i++) {
		struct lov_oinfo *loi = lsm->lsm_entries[0]->lsme_oinfo[i];

		ostid_cpu_to_le(&loi->loi_oi, &lmm_objects[i].l_ost_oi);
		lmm_objects[i].l_ost_gen = cpu_to_le32(loi->loi_ost_gen);
		lmm_objects[i].l_ost_idx = cpu_to_le32(loi->loi_ost_idx);
	}

	RETURN(lmm_size);
}

ssize_t lov_lsm_pack(const struct lov_stripe_md *lsm, void *buf,
		     size_t buf_size)
{
	struct lov_comp_md_v1 *lcmv1 = buf;
	struct lov_comp_md_entry_v1 *lcme;
	struct lov_ost_data_v1 *lmm_objects;
	size_t lmm_size;
	unsigned int entry;
	unsigned int offset;
	unsigned int size;
	unsigned int i;
	ENTRY;

	if (lsm->lsm_magic == LOV_MAGIC_V1 || lsm->lsm_magic == LOV_MAGIC_V3)
		return lov_lsm_pack_v1v3(lsm, buf, buf_size);

	lmm_size = lov_comp_md_size(lsm);
	if (buf_size == 0)
		RETURN(lmm_size);

	if (buf_size < lmm_size)
		RETURN(-ERANGE);

	lcmv1->lcm_magic = cpu_to_le32(lsm->lsm_magic);
	lcmv1->lcm_size = cpu_to_le32(lmm_size);
	lcmv1->lcm_layout_gen = cpu_to_le32(lsm->lsm_layout_gen);
	lcmv1->lcm_entry_count = cpu_to_le16(lsm->lsm_entry_count);

	offset = sizeof(*lcmv1) + sizeof(*lcme) * lsm->lsm_entry_count;

	for (entry = 0; entry < lsm->lsm_entry_count; entry++) {
		struct lov_stripe_md_entry *lsme;
		struct lov_mds_md *lmm;
		__u16 stripe_count;

		lsme = lsm->lsm_entries[entry];
		lcme = &lcmv1->lcm_entries[entry];

		lcme->lcme_id = cpu_to_le32(lsme->lsme_id);
		lcme->lcme_flags = cpu_to_le32(lsme->lsme_flags);
		lcme->lcme_extent.e_start =
			cpu_to_le64(lsme->lsme_extent.e_start);
		lcme->lcme_extent.e_end =
			cpu_to_le64(lsme->lsme_extent.e_end);
		lcme->lcme_offset = cpu_to_le32(offset);

		lmm = (struct lov_mds_md *)((char *)lcmv1 + offset);
		lmm->lmm_magic = cpu_to_le32(lsme->lsme_magic);
		/* lmm->lmm_oi not set */
		lmm->lmm_pattern = cpu_to_le32(lsme->lsme_pattern);
		lmm->lmm_stripe_size = cpu_to_le32(lsme->lsme_stripe_size);
		lmm->lmm_stripe_count = cpu_to_le16(lsme->lsme_stripe_count);
		lmm->lmm_layout_gen = cpu_to_le16(lsme->lsme_layout_gen);

		if (lsme->lsme_magic == LOV_MAGIC_V3) {
			struct lov_mds_md_v3 *lmmv3 =
						(struct lov_mds_md_v3 *)lmm;

			strlcpy(lmmv3->lmm_pool_name, lsme->lsme_pool_name,
				sizeof(lmmv3->lmm_pool_name));
			lmm_objects = lmmv3->lmm_objects;
		} else {
			lmm_objects =
				((struct lov_mds_md_v1 *)lmm)->lmm_objects;
		}

		if (lsme_inited(lsme) &&
		    !(lsme->lsme_pattern & LOV_PATTERN_F_RELEASED))
			stripe_count = lsme->lsme_stripe_count;
		else
			stripe_count = 0;

		for (i = 0; i < stripe_count; i++) {
			struct lov_oinfo *loi = lsme->lsme_oinfo[i];

			ostid_cpu_to_le(&loi->loi_oi, &lmm_objects[i].l_ost_oi);
			lmm_objects[i].l_ost_gen =
					cpu_to_le32(loi->loi_ost_gen);
			lmm_objects[i].l_ost_idx =
					cpu_to_le32(loi->loi_ost_idx);
		}

		size = lov_mds_md_size(stripe_count, lsme->lsme_magic);
		lcme->lcme_size = cpu_to_le32(size);
		offset += size;
	} /* for each layout component */

	RETURN(lmm_size);
}

/* Find the max stripecount we should use */
__u16 lov_get_stripe_count(struct lov_obd *lov, __u32 magic, __u16 stripe_count)
{
	__u32 max_stripes = LOV_MAX_STRIPE_COUNT_OLD;

	if (!stripe_count)
		stripe_count = lov->desc.ld_default_stripe_count;
	if (stripe_count > lov->desc.ld_active_tgt_count)
		stripe_count = lov->desc.ld_active_tgt_count;
	if (!stripe_count)
		stripe_count = 1;

	/* stripe count is based on whether ldiskfs can handle
	 * larger EA sizes */
	if (lov->lov_ocd.ocd_connect_flags & OBD_CONNECT_MAX_EASIZE &&
	    lov->lov_ocd.ocd_max_easize)
		max_stripes = lov_mds_md_max_stripe_count(
			lov->lov_ocd.ocd_max_easize, magic);

	if (stripe_count > max_stripes)
		stripe_count = max_stripes;

	return stripe_count;
}

int lov_free_memmd(struct lov_stripe_md **lsmp)
{
	struct lov_stripe_md *lsm = *lsmp;
	int refc;

	*lsmp = NULL;
	refc = atomic_dec_return(&lsm->lsm_refc);
	LASSERT(refc >= 0);
	if (refc == 0)
		lsm_free(lsm);

	return refc;
}

/* Unpack LOV object metadata from disk storage.  It is packed in LE byte
 * order and is opaque to the networking layer.
 */
struct lov_stripe_md *lov_unpackmd(struct lov_obd *lov, void *buf,
				   size_t buf_size)
{
	const struct lsm_operations *op;
	struct lov_stripe_md *lsm;
	u32 magic;
	ENTRY;

	if (buf_size < sizeof(magic))
		RETURN(ERR_PTR(-EINVAL));

	magic = le32_to_cpu(*(u32 *)buf);
	op = lsm_op_find(magic);
	if (op == NULL)
		RETURN(ERR_PTR(-EINVAL));

	lsm = op->lsm_unpackmd(lov, buf, buf_size);

	RETURN(lsm);
}

/* Retrieve object striping information.
 *
 * @lump is a pointer to an in-core struct with lmm_ost_count indicating
 * the maximum number of OST indices which will fit in the user buffer.
 * lmm_magic must be LOV_USER_MAGIC.
 *
 * If @size > 0, User specified limited buffer size, usually the buffer is from
 * ll_lov_setstripe(), and the buffer can only hold basic layout template info.
 */
int lov_getstripe(const struct lu_env *env, struct lov_object *obj,
		  struct lov_stripe_md *lsm, struct lov_user_md __user *lump,
		  size_t size)
{
	/* we use lov_user_md_v3 because it is larger than lov_user_md_v1 */
	struct lov_mds_md *lmmk, *lmm;
	struct lov_user_md_v1 lum;
	size_t	lmmk_size;
	ssize_t	lmm_size, lum_size = 0;
	static bool printed;
	int	rc = 0;
	ENTRY;

	if (lsm->lsm_magic != LOV_MAGIC_V1 && lsm->lsm_magic != LOV_MAGIC_V3 &&
	    lsm->lsm_magic != LOV_MAGIC_COMP_V1) {
		CERROR("bad LSM MAGIC: 0x%08X != 0x%08X nor 0x%08X\n",
		       lsm->lsm_magic, LOV_MAGIC_V1, LOV_MAGIC_V3);
		GOTO(out, rc = -EIO);
	}

	if (!printed) {
		LCONSOLE_WARN("%s: using old ioctl(LL_IOC_LOV_GETSTRIPE) on "
			      DFID", use llapi_layout_get_by_path()\n",
			      current->comm,
			      PFID(&obj->lo_cl.co_lu.lo_header->loh_fid));
		printed = true;
	}

	lmmk_size = lov_comp_md_size(lsm);

	OBD_ALLOC_LARGE(lmmk, lmmk_size);
	if (lmmk == NULL)
		GOTO(out, rc = -ENOMEM);

	lmm_size = lov_lsm_pack(lsm, lmmk, lmmk_size);
	if (lmm_size < 0)
		GOTO(out_free, rc = lmm_size);

	if (cpu_to_le32(LOV_MAGIC) != LOV_MAGIC) {
		if (lmmk->lmm_magic == cpu_to_le32(LOV_MAGIC_V1) ||
		    lmmk->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
			lustre_swab_lov_mds_md(lmmk);
			lustre_swab_lov_user_md_objects(
				(struct lov_user_ost_data *)lmmk->lmm_objects,
				lmmk->lmm_stripe_count);
		} else if (lmmk->lmm_magic == cpu_to_le32(LOV_MAGIC_COMP_V1)) {
			lustre_swab_lov_comp_md_v1(
					(struct lov_comp_md_v1 *)lmmk);
		}
	}

	/* Legacy appication passes limited buffer, we need to figure out
	 * the user buffer size by the passed in lmm_stripe_count. */
	if (copy_from_user(&lum, lump, sizeof(struct lov_user_md_v1)))
		GOTO(out_free, rc = -EFAULT);

	if (lum.lmm_magic == LOV_USER_MAGIC_V1 ||
	    lum.lmm_magic == LOV_USER_MAGIC_V3)
		lum_size = lov_user_md_size(lum.lmm_stripe_count,
					    lum.lmm_magic);

	if (lum_size != 0) {
		struct lov_mds_md *comp_md = lmmk;

		/* Legacy app (ADIO for instance) treats the layout as V1/V3
		 * blindly, we'd return a reasonable V1/V3 for them. */
		if (lmmk->lmm_magic == LOV_MAGIC_COMP_V1) {
			struct lov_comp_md_v1 *comp_v1;
			struct cl_object *cl_obj;
			struct cl_attr attr;
			int i;

			attr.cat_size = 0;
			cl_obj = cl_object_top(&obj->lo_cl);
			cl_object_attr_lock(cl_obj);
			cl_object_attr_get(env, cl_obj, &attr);
			cl_object_attr_unlock(cl_obj);

			/* return the last instantiated component if file size
			 * is non-zero, otherwise, return the last component.*/
			comp_v1 = (struct lov_comp_md_v1 *)lmmk;
			i = attr.cat_size == 0 ? comp_v1->lcm_entry_count : 0;
			for (; i < comp_v1->lcm_entry_count; i++) {
				if (!(comp_v1->lcm_entries[i].lcme_flags &
						LCME_FL_INIT))
					break;
			}
			if (i > 0)
				i--;
			comp_md = (struct lov_mds_md *)((char *)comp_v1 +
					comp_v1->lcm_entries[i].lcme_offset);
		}

		lmm = comp_md;
		lmm_size = lum_size;
	} else {
		lmm = lmmk;
		lmm_size = lmmk_size;
	}
	/**
	 * User specified limited buffer size, usually the buffer is
	 * from ll_lov_setstripe(), and the buffer can only hold basic
	 * layout template info.
	 */
	if (size == 0 || size > lmm_size)
		size = lmm_size;
	if (copy_to_user(lump, lmm, size))
		GOTO(out_free, rc = -EFAULT);

out_free:
	OBD_FREE_LARGE(lmmk, lmmk_size);
out:
	RETURN(rc);
}
