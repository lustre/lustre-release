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
 * lustre/lustre/include/lustre_idmap.h
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
        ((gi)->blocks[(i) / CFS_NGROUPS_PER_BLOCK][(i) % CFS_NGROUPS_PER_BLOCK])

#endif /* HAVE_GROUP_INFO_GID */

#include <linux/cred.h>

struct lu_ucred;

extern void lustre_groups_from_list(struct group_info *ginfo, gid_t *glist);
extern void lustre_groups_sort(struct group_info *group_info);
extern int lustre_in_group_p(struct lu_ucred *mu, gid_t grp);

/** @} idmap */

#endif
