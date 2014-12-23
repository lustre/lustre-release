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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osd-zfs/osd_lproc.c
 *
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mike Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_OSD

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

#include "osd_internal.h"

#ifdef LPROCFS

static int osd_stats_init(struct osd_device *osd)
{
	int result;
	ENTRY;

	osd->od_stats = lprocfs_alloc_stats(LPROC_OSD_LAST, 0);
	if (osd->od_stats != NULL) {
		result = lprocfs_register_stats(osd->od_proc_entry, "stats",
				osd->od_stats);
		if (result)
			GOTO(out, result);

		lprocfs_counter_init(osd->od_stats, LPROC_OSD_GET_PAGE,
				LPROCFS_CNTR_AVGMINMAX|LPROCFS_CNTR_STDDEV,
				"get_page", "usec");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_NO_PAGE,
				LPROCFS_CNTR_AVGMINMAX,
				"get_page_failures", "num");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_ACCESS,
				LPROCFS_CNTR_AVGMINMAX,
				"cache_access", "pages");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_HIT,
				LPROCFS_CNTR_AVGMINMAX,
				"cache_hit", "pages");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_CACHE_MISS,
				LPROCFS_CNTR_AVGMINMAX,
				"cache_miss", "pages");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_COPY_IO,
				LPROCFS_CNTR_AVGMINMAX,
				"copy", "pages");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_ZEROCOPY_IO,
				LPROCFS_CNTR_AVGMINMAX,
				"zerocopy", "pages");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_TAIL_IO,
				LPROCFS_CNTR_AVGMINMAX,
				"tail", "pages");
#ifdef OSD_THANDLE_STATS
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_STARTING,
				LPROCFS_CNTR_AVGMINMAX,
				"thandle_starting", "usec");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_OPEN,
				LPROCFS_CNTR_AVGMINMAX,
				"thandle_open", "usec");
		lprocfs_counter_init(osd->od_stats, LPROC_OSD_THANDLE_CLOSING,
				LPROCFS_CNTR_AVGMINMAX,
				"thandle_closing", "usec");
#endif
	} else {
		result = -ENOMEM;
	}

out:
	RETURN(result);
}

static int zfs_osd_fstype_seq_show(struct seq_file *m, void *data)
{
	return seq_printf(m, "zfs\n");
}
LPROC_SEQ_FOPS_RO(zfs_osd_fstype);

static int zfs_osd_mntdev_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	return seq_printf(m, "%s\n", osd->od_mntdev);
}
LPROC_SEQ_FOPS_RO(zfs_osd_mntdev);

static ssize_t
lprocfs_osd_force_sync_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct dt_device  *dt = m->private;
	struct lu_env      env;
	int rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;
	rc = dt_sync(&env, dt);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LPROC_SEQ_FOPS_WO_TYPE(zfs, osd_force_sync);

static int zfs_osd_iused_est_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);
	LASSERT(osd != NULL);

	return seq_printf(m, "%d\n", osd->od_quota_iused_est);
}

static ssize_t
zfs_osd_iused_est_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct dt_device  *dt = m->private;
	struct osd_device *osd = osd_dt_dev(dt);
	int                rc, val;

	LASSERT(osd != NULL);

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_quota_iused_est = !!val;

	return count;
}
LPROC_SEQ_FOPS(zfs_osd_iused_est);

LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_blksize);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_filestotal);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_filesfree);

struct lprocfs_seq_vars lprocfs_osd_obd_vars[] = {
	{ .name	=	"blocksize",
	  .fops	=	&zfs_dt_blksize_fops		},
	{ .name	=	"kbytestotal",
	  .fops	=	&zfs_dt_kbytestotal_fops	},
	{ .name	=	"kbytesfree",
	  .fops	=	&zfs_dt_kbytesfree_fops		},
	{ .name	=	"kbytesavail",
	  .fops	=	&zfs_dt_kbytesavail_fops	},
	{ .name	=	"filestotal",
	  .fops	=	&zfs_dt_filestotal_fops		},
	{ .name	=	"filesfree",
	  .fops	=	&zfs_dt_filesfree_fops		},
	{ .name	=	"fstype",
	  .fops	=	&zfs_osd_fstype_fops		},
	{ .name	=	"mntdev",
	  .fops	=	&zfs_osd_mntdev_fops		},
	{ .name	=	"force_sync",
	  .fops	=	&zfs_osd_force_sync_fops	},
	{ .name	=	"quota_iused_estimate",
	  .fops	=	&zfs_osd_iused_est_fops		},
	{ 0 }
};

int osd_procfs_init(struct osd_device *osd, const char *name)
{
	struct obd_type *type;
	int		 rc;
	ENTRY;

	if (osd->od_proc_entry)
		RETURN(0);

	/* at the moment there is no linkage between lu_type
	 * and obd_type, so we lookup obd_type this way */
	type = class_search_type(LUSTRE_OSD_ZFS_NAME);

	LASSERT(name != NULL);
	LASSERT(type != NULL);

	osd->od_proc_entry = lprocfs_seq_register(name, type->typ_procroot,
			lprocfs_osd_obd_vars, &osd->od_dt_dev);
	if (IS_ERR(osd->od_proc_entry)) {
		rc = PTR_ERR(osd->od_proc_entry);
		CERROR("Error %d setting up lprocfs for %s\n", rc, name);
		osd->od_proc_entry = NULL;
		GOTO(out, rc);
	}

	rc = osd_stats_init(osd);

	GOTO(out, rc);
out:
	if (rc)
		osd_procfs_fini(osd);
	return rc;
}

int osd_procfs_fini(struct osd_device *osd)
{
	ENTRY;

	if (osd->od_stats)
		lprocfs_free_stats(&osd->od_stats);

	if (osd->od_proc_entry) {
		lprocfs_remove(&osd->od_proc_entry);
		osd->od_proc_entry = NULL;
	}

	RETURN(0);
}

#endif
