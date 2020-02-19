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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/lov/lov_ea.c
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <linux/math64.h>
#include <linux/sort.h>
#include <libcfs/libcfs.h>

#include <obd_class.h>
#include "lov_internal.h"

static inline void
lu_extent_le_to_cpu(struct lu_extent *dst, const struct lu_extent *src)
{
	dst->e_start = le64_to_cpu(src->e_start);
	dst->e_end = le64_to_cpu(src->e_end);
}

/*
 * Find minimum stripe maxbytes value.  For inactive or
 * reconnecting targets use LUSTRE_EXT3_STRIPE_MAXBYTES.
 */
static loff_t lov_tgt_maxbytes(struct lov_tgt_desc *tgt)
{
	struct obd_import *imp;
	loff_t maxbytes = LUSTRE_EXT3_STRIPE_MAXBYTES;

	if (!tgt->ltd_active)
		return maxbytes;

	imp = tgt->ltd_obd->u.cli.cl_import;
	if (!imp)
		return maxbytes;

	spin_lock(&imp->imp_lock);
	if ((imp->imp_state == LUSTRE_IMP_FULL ||
	    imp->imp_state == LUSTRE_IMP_IDLE) &&
	    (imp->imp_connect_data.ocd_connect_flags & OBD_CONNECT_MAXBYTES) &&
	    imp->imp_connect_data.ocd_maxbytes > 0)
		maxbytes = imp->imp_connect_data.ocd_maxbytes;

	spin_unlock(&imp->imp_lock);

	return maxbytes;
}

static int lsm_lmm_verify_v1v3(struct lov_mds_md *lmm, size_t lmm_size,
			       u16 stripe_count)
{
	if (stripe_count > LOV_V1_INSANE_STRIPE_COUNT) {
		CERROR("bad stripe count %d\n", stripe_count);
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}

	if (lmm_oi_id(&lmm->lmm_oi) == 0) {
		CERROR("zero object id\n");
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}

	if (lov_pattern(le32_to_cpu(lmm->lmm_pattern)) != LOV_PATTERN_MDT &&
	    lov_pattern(le32_to_cpu(lmm->lmm_pattern)) != LOV_PATTERN_RAID0) {
		CERROR("bad striping pattern\n");
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}

	if (lmm->lmm_stripe_size == 0 ||
	    (le32_to_cpu(lmm->lmm_stripe_size)&(LOV_MIN_STRIPE_SIZE-1)) != 0) {
		CERROR("bad stripe size %u\n",
		       le32_to_cpu(lmm->lmm_stripe_size));
		lov_dump_lmm_common(D_WARNING, lmm);
		return -EINVAL;
	}
	return 0;
}

static void lsme_free(struct lov_stripe_md_entry *lsme)
{
	unsigned int stripe_count = lsme->lsme_stripe_count;
	unsigned int i;
	size_t lsme_size;

	if (!lsme_inited(lsme) ||
	    lsme->lsme_pattern & LOV_PATTERN_F_RELEASED)
		stripe_count = 0;
	for (i = 0; i < stripe_count; i++)
		OBD_SLAB_FREE_PTR(lsme->lsme_oinfo[i], lov_oinfo_slab);

	lsme_size = offsetof(typeof(*lsme), lsme_oinfo[stripe_count]);
	OBD_FREE_LARGE(lsme, lsme_size);
}

void lsm_free(struct lov_stripe_md *lsm)
{
	unsigned int entry_count = lsm->lsm_entry_count;
	unsigned int i;
	size_t lsm_size;

	for (i = 0; i < entry_count; i++)
		lsme_free(lsm->lsm_entries[i]);

	lsm_size = offsetof(typeof(*lsm), lsm_entries[entry_count]);
	OBD_FREE(lsm, lsm_size);
}

/**
 * Unpack a struct lov_mds_md into a struct lov_stripe_md_entry.
 *
 * The caller should set id and extent.
 */
static struct lov_stripe_md_entry *
lsme_unpack(struct lov_obd *lov, struct lov_mds_md *lmm, size_t buf_size,
	    const char *pool_name, bool inited, struct lov_ost_data_v1 *objects,
	    loff_t *maxbytes)
{
	struct lov_stripe_md_entry *lsme;
	size_t lsme_size;
	loff_t min_stripe_maxbytes = 0;
	loff_t lov_bytes;
	u32 magic;
	u32 pattern;
	unsigned int stripe_count;
	unsigned int i;
	int rc;

	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3)
		RETURN(ERR_PTR(-EINVAL));

	pattern = le32_to_cpu(lmm->lmm_pattern);
	if (pattern & LOV_PATTERN_F_RELEASED || !inited)
		stripe_count = 0;
	else
		stripe_count = le16_to_cpu(lmm->lmm_stripe_count);

	if (buf_size < (magic == LOV_MAGIC_V1 ? sizeof(struct lov_mds_md_v1) :
						sizeof(struct lov_mds_md_v3))) {
		CERROR("LOV EA %s too small: %zu, need %u\n",
		       magic == LOV_MAGIC_V1 ? "V1" : "V3", buf_size,
		       lov_mds_md_size(stripe_count, magic == LOV_MAGIC_V1 ?
				       LOV_MAGIC_V1 : LOV_MAGIC_V3));
		lov_dump_lmm_common(D_WARNING, lmm);
		return ERR_PTR(-EINVAL);
	}

	rc = lsm_lmm_verify_v1v3(lmm, buf_size, stripe_count);
	if (rc < 0)
		return ERR_PTR(rc);

	lsme_size = offsetof(typeof(*lsme), lsme_oinfo[stripe_count]);
	OBD_ALLOC_LARGE(lsme, lsme_size);
	if (!lsme)
		RETURN(ERR_PTR(-ENOMEM));

	lsme->lsme_magic = magic;
	lsme->lsme_pattern = pattern;
	lsme->lsme_flags = 0;
	lsme->lsme_stripe_size = le32_to_cpu(lmm->lmm_stripe_size);
	/* preserve the possible -1 stripe count for uninstantiated component */
	lsme->lsme_stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
	lsme->lsme_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);

	if (pool_name) {
		size_t pool_name_len;

		pool_name_len = strlcpy(lsme->lsme_pool_name, pool_name,
					sizeof(lsme->lsme_pool_name));
		if (pool_name_len >= sizeof(lsme->lsme_pool_name))
			GOTO(out_lsme, rc = -E2BIG);
	}

	/* with Data-on-MDT set maxbytes to stripe size */
	if (lsme_is_dom(lsme)) {
		if (maxbytes) {
			lov_bytes = lsme->lsme_stripe_size;
			goto out_dom1;
		} else {
			goto out_dom2;
		}
	}

	for (i = 0; i < stripe_count; i++) {
		struct lov_oinfo *loi;
		struct lov_tgt_desc *ltd;

		OBD_SLAB_ALLOC_PTR_GFP(loi, lov_oinfo_slab, GFP_NOFS);
		if (!loi)
			GOTO(out_lsme, rc = -ENOMEM);

		lsme->lsme_oinfo[i] = loi;

		ostid_le_to_cpu(&objects[i].l_ost_oi, &loi->loi_oi);
		loi->loi_ost_idx = le32_to_cpu(objects[i].l_ost_idx);
		loi->loi_ost_gen = le32_to_cpu(objects[i].l_ost_gen);
		if (lov_oinfo_is_dummy(loi))
			continue;

		if (loi->loi_ost_idx >= lov->desc.ld_tgt_count &&
		    !lov2obd(lov)->obd_process_conf) {
			CERROR("%s: OST index %d more than OST count %d\n",
			       (char*)lov->desc.ld_uuid.uuid,
			       loi->loi_ost_idx, lov->desc.ld_tgt_count);
			lov_dump_lmm_v1(D_WARNING, lmm);
			GOTO(out_lsme, rc = -EINVAL);
		}

		ltd = lov->lov_tgts[loi->loi_ost_idx];
		if (!ltd) {
			CERROR("%s: OST index %d missing\n",
			       (char*)lov->desc.ld_uuid.uuid, loi->loi_ost_idx);
			lov_dump_lmm_v1(D_WARNING, lmm);
			continue;
		}

		lov_bytes = lov_tgt_maxbytes(ltd);
		if (min_stripe_maxbytes == 0 || lov_bytes < min_stripe_maxbytes)
			min_stripe_maxbytes = lov_bytes;
	}

	if (maxbytes) {
		if (min_stripe_maxbytes == 0)
			min_stripe_maxbytes = LUSTRE_EXT3_STRIPE_MAXBYTES;

		if (stripe_count == 0)
			stripe_count = lov->desc.ld_tgt_count;

		if (min_stripe_maxbytes <= LLONG_MAX / stripe_count)
			lov_bytes = min_stripe_maxbytes * stripe_count;
		else
			lov_bytes = MAX_LFS_FILESIZE;
out_dom1:
		*maxbytes = min_t(loff_t, lov_bytes, MAX_LFS_FILESIZE);
	}
out_dom2:

	return lsme;

out_lsme:
	for (i = 0; i < stripe_count; i++) {
		struct lov_oinfo *loi = lsme->lsme_oinfo[i];

		if (loi)
			OBD_SLAB_FREE_PTR(lsme->lsme_oinfo[i], lov_oinfo_slab);
	}
	OBD_FREE_LARGE(lsme, lsme_size);

	return ERR_PTR(rc);
}

static struct
lov_stripe_md *lsm_unpackmd_v1v3(struct lov_obd *lov, struct lov_mds_md *lmm,
				 size_t buf_size, const char *pool_name,
				 struct lov_ost_data_v1 *objects)
{
	struct lov_stripe_md *lsm;
	struct lov_stripe_md_entry *lsme;
	size_t lsm_size;
	loff_t maxbytes;
	u32 pattern;
	int rc;

	pattern = le32_to_cpu(lmm->lmm_pattern);

	lsme = lsme_unpack(lov, lmm, buf_size, pool_name, true, objects,
			   &maxbytes);
	if (IS_ERR(lsme))
		RETURN(ERR_CAST(lsme));

	lsme->lsme_flags = LCME_FL_INIT;
	lsme->lsme_extent.e_start = 0;
	lsme->lsme_extent.e_end = LUSTRE_EOF;

	lsm_size = offsetof(typeof(*lsm), lsm_entries[1]);
	OBD_ALLOC(lsm, lsm_size);
	if (!lsm)
		GOTO(out_lsme, rc = -ENOMEM);

	atomic_set(&lsm->lsm_refc, 1);
	spin_lock_init(&lsm->lsm_lock);
	lsm->lsm_maxbytes = maxbytes;
	lmm_oi_le_to_cpu(&lsm->lsm_oi, &lmm->lmm_oi);
	lsm->lsm_magic = le32_to_cpu(lmm->lmm_magic);
	lsm->lsm_layout_gen = le16_to_cpu(lmm->lmm_layout_gen);
	lsm->lsm_entry_count = 1;
	lsm->lsm_is_released = pattern & LOV_PATTERN_F_RELEASED;
	lsm->lsm_entries[0] = lsme;

	return lsm;

out_lsme:
	lsme_free(lsme);

	return ERR_PTR(rc);
}

static inline struct lov_stripe_md *
lsm_unpackmd_v1(struct lov_obd *lov, void *buf, size_t buf_size)
{
	struct lov_mds_md_v1 *lmm = buf;

	return lsm_unpackmd_v1v3(lov, buf, buf_size, NULL, lmm->lmm_objects);
}

const struct lsm_operations lsm_v1_ops = {
        .lsm_unpackmd           = lsm_unpackmd_v1,
};

static inline
struct lov_stripe_md *lsm_unpackmd_v3(struct lov_obd *lov, void *buf,
				      size_t buf_size)
{
	struct lov_mds_md_v3 *lmm = buf;

	return lsm_unpackmd_v1v3(lov, buf, buf_size, lmm->lmm_pool_name,
				 lmm->lmm_objects);
}

const struct lsm_operations lsm_v3_ops = {
	.lsm_unpackmd           = lsm_unpackmd_v3,
};

static int lsm_verify_comp_md_v1(struct lov_comp_md_v1 *lcm,
				 size_t lcm_buf_size)
{
	unsigned int entry_count;
	unsigned int i;
	size_t lcm_size;

	lcm_size = le32_to_cpu(lcm->lcm_size);
	if (lcm_buf_size < lcm_size) {
		CERROR("bad LCM buffer size %zu, expected %zu\n",
		       lcm_buf_size, lcm_size);
		RETURN(-EINVAL);
	}

	entry_count = le16_to_cpu(lcm->lcm_entry_count);
	for (i = 0; i < entry_count; i++) {
		struct lov_comp_md_entry_v1 *lcme = &lcm->lcm_entries[i];
		size_t blob_offset;
		size_t blob_size;

		blob_offset = le32_to_cpu(lcme->lcme_offset);
		blob_size = le32_to_cpu(lcme->lcme_size);

		if (lcm_size < blob_offset || lcm_size < blob_size ||
		    lcm_size < blob_offset + blob_size) {
			CERROR("LCM entry %u has invalid blob: "
			       "LCM size = %zu, offset = %zu, size = %zu\n",
			       le32_to_cpu(lcme->lcme_id),
			       lcm_size, blob_offset, blob_size);
			RETURN(-EINVAL);
		}
	}

	return 0;
}

static struct lov_stripe_md_entry *
lsme_unpack_comp(struct lov_obd *lov, struct lov_mds_md *lmm,
		 size_t lmm_buf_size, bool inited, loff_t *maxbytes)
{
	unsigned int magic;
	unsigned int stripe_count;

	stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
	if (stripe_count == 0 &&
	    lov_pattern(le32_to_cpu(lmm->lmm_pattern)) != LOV_PATTERN_MDT)
		RETURN(ERR_PTR(-EINVAL));
	/* un-instantiated lmm contains no ost id info, i.e. lov_ost_data_v1 */
	if (!inited)
		stripe_count = 0;

	magic = le32_to_cpu(lmm->lmm_magic);
	if (magic != LOV_MAGIC_V1 && magic != LOV_MAGIC_V3)
		RETURN(ERR_PTR(-EINVAL));

	if (lmm_buf_size < lov_mds_md_size(stripe_count, magic))
		RETURN(ERR_PTR(-EINVAL));

	if (magic == LOV_MAGIC_V1) {
		return lsme_unpack(lov, lmm, lmm_buf_size, NULL,
				   inited, lmm->lmm_objects, maxbytes);
	} else {
		struct lov_mds_md_v3 *lmm3 = (struct lov_mds_md_v3 *)lmm;

		return lsme_unpack(lov, lmm, lmm_buf_size, lmm3->lmm_pool_name,
				   inited, lmm3->lmm_objects, maxbytes);
	}
}

static struct lov_stripe_md *
lsm_unpackmd_comp_md_v1(struct lov_obd *lov, void *buf, size_t buf_size)
{
	struct lov_comp_md_v1 *lcm = buf;
	struct lov_stripe_md *lsm;
	size_t lsm_size;
	unsigned int entry_count = 0;
	unsigned int i;
	loff_t maxbytes;
	int rc;

	rc = lsm_verify_comp_md_v1(buf, buf_size);
	if (rc < 0)
		return ERR_PTR(rc);

	entry_count = le16_to_cpu(lcm->lcm_entry_count);

	lsm_size = offsetof(typeof(*lsm), lsm_entries[entry_count]);
	OBD_ALLOC(lsm, lsm_size);
	if (!lsm)
		return ERR_PTR(-ENOMEM);

	atomic_set(&lsm->lsm_refc, 1);
	spin_lock_init(&lsm->lsm_lock);
	lsm->lsm_magic = le32_to_cpu(lcm->lcm_magic);
	lsm->lsm_layout_gen = le32_to_cpu(lcm->lcm_layout_gen);
	lsm->lsm_entry_count = entry_count;
	lsm->lsm_mirror_count = le16_to_cpu(lcm->lcm_mirror_count);
	lsm->lsm_flags = le16_to_cpu(lcm->lcm_flags);
	lsm->lsm_is_released = true;
	lsm->lsm_maxbytes = LLONG_MIN;

	for (i = 0; i < entry_count; i++) {
		struct lov_comp_md_entry_v1 *lcme = &lcm->lcm_entries[i];
		struct lov_stripe_md_entry *lsme;
		size_t blob_offset;
		size_t blob_size;
		void *blob;

		blob_offset = le32_to_cpu(lcme->lcme_offset);
		blob_size = le32_to_cpu(lcme->lcme_size);
		blob = (char *)lcm + blob_offset;

		lsme = lsme_unpack_comp(lov, blob, blob_size,
					le32_to_cpu(lcme->lcme_flags) &
					LCME_FL_INIT,
					(i == entry_count - 1) ? &maxbytes :
								 NULL);
		if (IS_ERR(lsme))
			GOTO(out_lsm, rc = PTR_ERR(lsme));

		if (!(lsme->lsme_pattern & LOV_PATTERN_F_RELEASED))
			lsm->lsm_is_released = false;

		lsm->lsm_entries[i] = lsme;
		lsme->lsme_id = le32_to_cpu(lcme->lcme_id);
		lsme->lsme_flags = le32_to_cpu(lcme->lcme_flags);
		if (lsme->lsme_flags & LCME_FL_NOSYNC)
			lsme->lsme_timestamp =
				le64_to_cpu(lcme->lcme_timestamp);
		lu_extent_le_to_cpu(&lsme->lsme_extent, &lcme->lcme_extent);

		if (i == entry_count - 1) {
			lsm->lsm_maxbytes = (loff_t)lsme->lsme_extent.e_start +
					    maxbytes;
			/*
			 * the last component hasn't been defined, or
			 * lsm_maxbytes overflowed.
			 */
			if (!lsme_is_dom(lsme) &&
			    (lsme->lsme_extent.e_end != LUSTRE_EOF ||
			     lsm->lsm_maxbytes <
			     (loff_t)lsme->lsme_extent.e_start))
				lsm->lsm_maxbytes = MAX_LFS_FILESIZE;
		}
	}

	RETURN(lsm);

out_lsm:
	for (i = 0; i < entry_count; i++)
		if (lsm->lsm_entries[i])
			lsme_free(lsm->lsm_entries[i]);

	OBD_FREE(lsm, lsm_size);

	RETURN(ERR_PTR(rc));
}

const struct lsm_operations lsm_comp_md_v1_ops = {
	.lsm_unpackmd         = lsm_unpackmd_comp_md_v1,
};

void dump_lsm(unsigned int level, const struct lov_stripe_md *lsm)
{
	int i, j;

	CDEBUG(level, "lsm %p, objid "DOSTID", maxbytes %#llx, magic 0x%08X, "
	       "refc: %d, entry: %u, layout_gen %u\n",
	       lsm, POSTID(&lsm->lsm_oi), lsm->lsm_maxbytes, lsm->lsm_magic,
	       atomic_read(&lsm->lsm_refc), lsm->lsm_entry_count,
	       lsm->lsm_layout_gen);

	for (i = 0; i < lsm->lsm_entry_count; i++) {
		struct lov_stripe_md_entry *lse = lsm->lsm_entries[i];

		CDEBUG(level, DEXT ": id: %u, flags: %x, "
		       "magic 0x%08X, layout_gen %u, "
		       "stripe count %u, sstripe size %u, "
		       "pool: ["LOV_POOLNAMEF"]\n",
		       PEXT(&lse->lsme_extent), lse->lsme_id, lse->lsme_flags,
		       lse->lsme_magic, lse->lsme_layout_gen,
		       lse->lsme_stripe_count, lse->lsme_stripe_size,
		       lse->lsme_pool_name);
		if (!lsme_inited(lse) ||
		    lse->lsme_pattern & LOV_PATTERN_F_RELEASED)
			continue;
		for (j = 0; j < lse->lsme_stripe_count; j++) {
			CDEBUG(level, "   oinfo:%p: ostid: "DOSTID
			       " ost idx: %d gen: %d\n",
			       lse->lsme_oinfo[j],
			       POSTID(&lse->lsme_oinfo[j]->loi_oi),
			       lse->lsme_oinfo[j]->loi_ost_idx,
			       lse->lsme_oinfo[j]->loi_ost_gen);
		}
	}
}

int lov_lsm_entry(const struct lov_stripe_md *lsm, __u64 offset)
{
	int i;

	for (i = 0; i < lsm->lsm_entry_count; i++) {
		struct lov_stripe_md_entry *lse = lsm->lsm_entries[i];

		if ((offset >= lse->lsme_extent.e_start &&
		     offset < lse->lsme_extent.e_end) ||
		    (offset == OBD_OBJECT_EOF &&
		     lse->lsme_extent.e_end == OBD_OBJECT_EOF))
			return i;
	}

	return -1;
}
