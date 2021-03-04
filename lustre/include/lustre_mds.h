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
 * Copyright (c) 2011, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/include/lustre_mds.h
 *
 * MDS data structures.
 * See also lustre_idl.h for wire formats of requests.
 */

#ifndef _LUSTRE_MDS_H
#define _LUSTRE_MDS_H

/** \defgroup mds mds
 *
 * @{
 */

#include <lustre_handles.h>
#include <libcfs/libcfs.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lustre_lib.h>
#include <lustre_dlm.h>
#include <lustre_export.h>

struct md_rejig_data {
	struct md_object	*mrd_obj;
	__u16			mrd_mirror_id;
};

#define MDD_OBD_NAME     "mdd_obd"
#define MDD_OBD_UUID     "mdd_obd_uuid"

static inline int md_should_create(u64 open_flags)
{
	return !(open_flags & MDS_OPEN_DELAY_CREATE) &&
		(open_flags & MDS_FMODE_WRITE) &&
	       !(open_flags & MDS_OPEN_LEASE);
}

/* do NOT or the MAY_*'s, you'll get the weakest */
static inline int mds_accmode(u64 open_flags)
{
	unsigned int may_mask = 0;

	if (open_flags & MDS_FMODE_READ)
		may_mask |= MAY_READ;
	if (open_flags & (MDS_FMODE_WRITE | MDS_OPEN_TRUNC | MDS_OPEN_APPEND))
		may_mask |= MAY_WRITE;
	if (open_flags & MDS_FMODE_EXEC)
		may_mask = MAY_EXEC;

	return may_mask;
}

/** @} mds */

#endif
