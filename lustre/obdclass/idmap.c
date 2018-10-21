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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/idmap.c
 *
 * Lustre user identity mapping.
 *
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_SEC

#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
# include <linux/uidgid.h>
#endif
#include <lustre_idmap.h>
#include <upcall_cache.h>
#include <md_object.h>
#include <obd_support.h>

/*
 * groups_search() is copied from linux kernel!
 * A simple bsearch.
 */
static int lustre_groups_search(struct group_info *group_info,
				gid_t grp)
{
	int left, right;

	if (!group_info)
		return 0;

	left = 0;
	right = group_info->ngroups;
	while (left < right) {
		int mid = (left + right) / 2;
		int cmp = grp -
			from_kgid(&init_user_ns, CFS_GROUP_AT(group_info, mid));

		if (cmp > 0)
			left = mid + 1;
		else if (cmp < 0)
			right = mid;
		else
			return 1;
	}
	return 0;
}

void lustre_groups_from_list(struct group_info *ginfo, gid_t *glist)
{
#ifdef HAVE_GROUP_INFO_GID
	memcpy(ginfo->gid, glist, ginfo->ngroups * sizeof(__u32));
#else
	int i;
	int count = ginfo->ngroups;

	/* fill group_info from gid array */
	for (i = 0; i < ginfo->nblocks && count > 0; i++) {
		int cp_count = min(CFS_NGROUPS_PER_BLOCK, count);
		int off = i * CFS_NGROUPS_PER_BLOCK;
		int len = cp_count * sizeof(*glist);

		memcpy(ginfo->blocks[i], glist + off, len);
		count -= cp_count;
	}
#endif
}
EXPORT_SYMBOL(lustre_groups_from_list);

/* groups_sort() is copied from linux kernel! */
/* a simple shell-metzner sort */
void lustre_groups_sort(struct group_info *group_info)
{
	int base, max, stride;
	int gidsetsize = group_info->ngroups;

	for (stride = 1; stride < gidsetsize; stride = 3 * stride + 1)
		; /* nothing */
	stride /= 3;

	while (stride) {
		max = gidsetsize - stride;
		for (base = 0; base < max; base++) {
			int left = base;
			int right = left + stride;
			gid_t tmp = from_kgid(&init_user_ns,
					      CFS_GROUP_AT(group_info, right));

			while (left >= 0 &&
			       tmp < from_kgid(&init_user_ns,
					       CFS_GROUP_AT(group_info, left))) {
				CFS_GROUP_AT(group_info, right) =
					CFS_GROUP_AT(group_info, left);
				right = left;
				left -= stride;
			}
			CFS_GROUP_AT(group_info, right) =
						make_kgid(&init_user_ns, tmp);
		}
		stride /= 3;
	}
}
EXPORT_SYMBOL(lustre_groups_sort);

int lustre_in_group_p(struct lu_ucred *mu, gid_t grp)
{
	int rc = 1;

	if (grp != mu->uc_fsgid) {
		struct group_info *group_info = NULL;

		if (mu->uc_ginfo || !mu->uc_identity ||
		    mu->uc_valid == UCRED_OLD)
			if (grp == mu->uc_suppgids[0] ||
			    grp == mu->uc_suppgids[1])
				return 1;

		if (mu->uc_ginfo)
			group_info = mu->uc_ginfo;
		else if (mu->uc_identity)
			group_info = mu->uc_identity->mi_ginfo;

		if (!group_info)
			return 0;

		atomic_inc(&group_info->usage);
		rc = lustre_groups_search(group_info, grp);
		if (atomic_dec_and_test(&group_info->usage))
			groups_free(group_info);
	}
	return rc;
}
EXPORT_SYMBOL(lustre_in_group_p);
