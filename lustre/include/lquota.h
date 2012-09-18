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

#include <dt_object.h>
#include <lustre_fid.h>
#include <lustre_dlm.h>

#ifndef _LUSTRE_LQUOTA_H
#define _LUSTRE_LQUOTA_H

/*
 * Space accounting support
 * Format of an accounting record, providing disk usage information for a given
 * user or group
 */
struct acct_rec { /* 16 bytes */
	__u64 bspace;  /* current space in use */
	__u64 ispace;  /* current # inodes in use */
};

/*
 * Quota enforcement support on slaves
 */

struct qsd_instance;

/* The quota slave feature is implemented under the form of a library.
 * The API is the following:
 *
 * - qsd_init(): the user (mostly the OSD layer) should first allocate a qsd
 *               instance via qsd_init(). This sets up on-disk objects
 *               associated with the quota slave feature and initiates the quota
 *               reintegration procedure if needed. qsd_init() should typically
 *               be called when ->ldo_start is invoked.
 *
 * - qsd_fini(): is used to release a qsd_instance structure allocated with
 *               qsd_init(). This releases all quota slave objects and frees the
 *               structures associated with the qsd_instance.
 *
 * Below are the function prototypes to be used by OSD layer to manage quota
 * enforcement. Arguments are documented where each function is defined.  */

struct qsd_instance *qsd_init(const struct lu_env *, char *, struct dt_device *,
			      cfs_proc_dir_entry_t *);

void qsd_fini(const struct lu_env *, struct qsd_instance *);

/* helper function used by MDT & OFD to retrieve quota accounting information
 * on slave */
int lquotactl_slv(const struct lu_env *, struct dt_device *,
		  struct obd_quotactl *);

#ifdef LPROCFS
/* dumb procfs handler which always report success, for backward compatibility
 * purpose */
int lprocfs_quota_rd_type_dumb(char *, char **, off_t, int, int *, void *);
int lprocfs_quota_wr_type_dumb(struct file *, const char *, unsigned long,
			       void *);
#endif /* LPROCFS */
#endif /* _LUSTRE_LQUOTA_H */
