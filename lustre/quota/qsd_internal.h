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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
 */

#include "lquota_internal.h"

#ifndef _QSD_INTERNAL_H
#define _QSD_INTERNAL_H

struct qsd_type_info;

/*
 * A QSD instance implements quota enforcement support for a given OSD.
 * The instance can be created via qsd_init() and then freed with qsd_fini().
 * This structure gathers all quota parameters and pointers to on-disk indexes
 * required on quota slave to:
 * i. acquire/release quota space from the QMT;
 * ii. allocate this quota space to local requests.
 */
struct qsd_instance {
	/* name of service which created this qsd instance */
	char			 qsd_svname[MAX_OBD_NAME];

	/* dt_device associated with this qsd instance */
	struct dt_device	*qsd_dev;

	/* procfs directory where information related to the underlying slaves
	 * are exported */
	cfs_proc_dir_entry_t	*qsd_proc;

	/* We create 2 quota slave instances:
	 * - one for user quota
	 * - one for group quota
	 *
	 * This will have to be revisited if new quota types are added in the
	 * future. For the time being, we can just use an array. */
	struct qsd_qtype_info	*qsd_type_array[MAXQUOTAS];
};

/*
 * Per-type quota information.
 * Quota slave instance for a specific quota type. The qsd instance has one such
 * structure for each quota type (i.e. user & group).
 */
struct qsd_qtype_info {
	/* quota type, either USRQUOTA or GRPQUOTA
	 * immutable after creation. */
	int			 qqi_qtype;

	/* back pointer to qsd device
	 * immutable after creation. */
	struct qsd_instance	*qqi_qsd;

	/* Local index files storing quota settings for this quota type */
	struct dt_object	*qqi_acct_obj; /* accounting object */
};
#endif /* _QSD_INTERNAL_H */
