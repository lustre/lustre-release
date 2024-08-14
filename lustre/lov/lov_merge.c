// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LOV

#include <libcfs/libcfs.h>
#include <cl_object.h>
#include <obd_class.h>
#include "lov_internal.h"

/** Merge the lock value block(&lvb) attributes and KMS from each of the
 * stripes in a file into a single lvb. It is expected that the caller
 * initializes the current atime, mtime, ctime to avoid regressing a more
 * uptodate time on the local client.
 */
int lov_merge_lvb_kms(struct lov_stripe_md *lsm, int index,
		      struct cl_attr *attr)
{
	struct lov_stripe_md_entry *lse = lsm->lsm_entries[index];
	u64 size = 0;
	u64 kms = 0;
	u64 blocks = 0;
	/* XXX: timestamps can be negative by sanity:test_39m,
	 * how can it be? */
	s64 current_mtime = LLONG_MIN;
	s64 current_atime = LLONG_MIN;
	s64 current_ctime = LLONG_MIN;
	int i;
	int rc = 0;

	assert_spin_locked(&lsm->lsm_lock);
	LASSERT(lsm->lsm_lock_owner == current->pid);
	for (i = 0; i < lse->lsme_stripe_count; i++) {
		struct lov_oinfo *loi = lse->lsme_oinfo[i];
		u64 lov_size;
		u64 tmpsize;

		if (OST_LVB_IS_ERR(loi->loi_lvb.lvb_blocks)) {
			rc = OST_LVB_GET_ERR(loi->loi_lvb.lvb_blocks);
			continue;
		}

		if (loi->loi_kms_valid) {
			attr->cat_kms_valid = 1;
			tmpsize = loi->loi_kms;
		} else {
			tmpsize = 0;
		}
		lov_size = lov_stripe_size(lsm, index, tmpsize, i);
		if (lov_size > kms)
			kms = lov_size;

		if (loi->loi_lvb.lvb_size > tmpsize)
			tmpsize = loi->loi_lvb.lvb_size;

		lov_size = lov_stripe_size(lsm, index, tmpsize, i);
		if (lov_size > size)
			size = lov_size;
		/* merge blocks, mtime, atime */
		blocks += loi->loi_lvb.lvb_blocks;
		if (loi->loi_lvb.lvb_mtime > current_mtime)
			current_mtime = loi->loi_lvb.lvb_mtime;
		if (loi->loi_lvb.lvb_atime > current_atime)
			current_atime = loi->loi_lvb.lvb_atime;
		if (loi->loi_lvb.lvb_ctime > current_ctime)
			current_ctime = loi->loi_lvb.lvb_ctime;

		CDEBUG(D_INODE, "MDT ID "DOSTID" on OST[%u]: s=%llu (%d) m=%llu"
		       " a=%llu c=%llu b=%llu\n", POSTID(&lsm->lsm_oi),
		       loi->loi_ost_idx, loi->loi_lvb.lvb_size,
		       loi->loi_kms_valid, loi->loi_lvb.lvb_mtime,
		       loi->loi_lvb.lvb_atime, loi->loi_lvb.lvb_ctime,
		       loi->loi_lvb.lvb_blocks);
	}

	if (!rc) {
		attr->cat_kms    = kms;
		attr->cat_size   = size;
		attr->cat_mtime  = current_mtime;
		attr->cat_atime  = current_atime;
		attr->cat_ctime  = current_ctime;
		attr->cat_blocks = blocks;
	}
	RETURN(rc);
}
