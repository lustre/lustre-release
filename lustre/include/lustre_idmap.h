/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_IDMAP_H
#define _LUSTRE_IDMAP_H

#include <linux/cred.h>

/** \defgroup idmap idmap
 *
 * @{
 */
#define CFS_GROUP_AT(gi, i) ((gi)->gid[(i)])

struct lu_ucred;

static inline void lustre_groups_from_list(struct group_info *ginfo, gid_t *glist)
{
	memcpy(ginfo->gid, glist, ginfo->ngroups * sizeof(u32));
}

static inline void lustre_list_from_groups(gid_t *glist, struct group_info *ginfo)
{
	memcpy(glist, ginfo->gid, ginfo->ngroups * sizeof(u32));
}

void lustre_groups_sort(struct group_info *group_info);
int lustre_groups_search(struct group_info *group_info, gid_t grp);
int lustre_in_group_p(struct lu_ucred *mu, gid_t grp);
int has_proper_groups(struct lu_ucred *ucred);

/** @} idmap */

#endif
