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
 */
/*
 * Copyright (c) 2012, Intel Corporation.
 * Use is subject to license terms.
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

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>

#include "udmu.h"
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

static int lprocfs_osd_rd_fstype(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return snprintf(page, count, "zfs\n");
}

static int lprocfs_osd_rd_mntdev(char *page, char **start, off_t off, int count,
				int *eof, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)data);

	LASSERT(osd != NULL);
	*eof = 1;

	return snprintf(page, count, "%s\n", osd->od_mntdev);
}

static int lprocfs_osd_wr_force_sync(struct file *file, const char *buffer,
					unsigned long count, void *data)
{
	struct dt_device  *dt = data;
	struct lu_env      env;
	int rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;
	rc = dt_sync(&env, dt);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}

static int lprocfs_osd_rd_iused_est(char *page, char **start, off_t off, int count,
					int *eof, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)data);
	LASSERT(osd != NULL);

	return snprintf(page, count, "%d\n", osd->od_quota_iused_est);
}

static int lprocfs_osd_wr_iused_est(struct file *file, const char *buffer,
					unsigned long count, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)data);
	int                rc, val;

	LASSERT(osd != NULL);

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	osd->od_quota_iused_est = !!val;

	return count;
}

struct lprocfs_vars lprocfs_osd_obd_vars[] = {
	{ "blocksize",		lprocfs_dt_rd_blksize,	0, 0 },
	{ "kbytestotal",	lprocfs_dt_rd_kbytestotal,	0, 0 },
	{ "kbytesfree",		lprocfs_dt_rd_kbytesfree,	0, 0 },
	{ "kbytesavail",	lprocfs_dt_rd_kbytesavail,	0, 0 },
	{ "filestotal",		lprocfs_dt_rd_filestotal,	0, 0 },
	{ "filesfree",		lprocfs_dt_rd_filesfree,	0, 0 },
	{ "fstype",          lprocfs_osd_rd_fstype,      0, 0 },
	{ "mntdev",          lprocfs_osd_rd_mntdev,      0, 0 },
	{ "force_sync",      0, lprocfs_osd_wr_force_sync     },
	{ "quota_iused_estimate",  lprocfs_osd_rd_iused_est,
		lprocfs_osd_wr_iused_est,   0, 0 },
	{ 0 }
};

struct lprocfs_vars lprocfs_osd_module_vars[] = {
	{ "num_refs",        lprocfs_rd_numrefs,         0, 0 },
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

	osd->od_proc_entry = lprocfs_register(name, type->typ_procroot,
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
