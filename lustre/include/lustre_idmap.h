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

/** \defgroup idmap idmap
 *
 * @{
 */

#include <libcfs/libcfs.h>

#ifdef HAVE_GROUP_INFO_GID

#define CFS_GROUP_AT(gi, i) ((gi)->gid[(i)])

#else  /* !HAVE_GROUP_INFO_GID */

#define CFS_NGROUPS_PER_BLOCK   ((int)(PAGE_SIZE / sizeof(gid_t)))

#define CFS_GROUP_AT(gi, i) \
	((gi)->blocks[(i) / CFS_NGROUPS_PER_BLOCK][(i) % \
	 CFS_NGROUPS_PER_BLOCK])

#endif /* HAVE_GROUP_INFO_GID */

#include <linux/cred.h>

struct lu_ucred;

extern void lustre_groups_from_list(struct group_info *ginfo, gid_t *glist);
extern void lustre_groups_sort(struct group_info *group_info);
extern int lustre_groups_search(struct group_info *group_info, gid_t grp);
extern int lustre_in_group_p(struct lu_ucred *mu, gid_t grp);
extern int has_proper_groups(struct lu_ucred *ucred);

/** @} idmap */

#endif
