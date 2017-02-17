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
 * Copyright (c) 2012, 2016, Intel Corporation.
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

#ifdef CONFIG_PROC_FS

#define pct(a, b) (b ? a * 100 / b : 0)

static void display_brw_stats(struct seq_file *seq, char *name, char *units,
			      struct obd_histogram *read,
			      struct obd_histogram *write, int scale)
{
	unsigned long read_tot, write_tot, r, w, read_cum = 0, write_cum = 0;
	int i;

	seq_printf(seq, "\n%26s read      |     write\n", " ");
	seq_printf(seq, "%-22s %-5s %% cum %% |  %-11s %% cum %%\n",
		   name, units, units);

	read_tot = lprocfs_oh_sum(read);
	write_tot = lprocfs_oh_sum(write);
	for (i = 0; i < OBD_HIST_MAX; i++) {
		r = read->oh_buckets[i];
		w = write->oh_buckets[i];
		read_cum += r;
		write_cum += w;
		if (read_cum == 0 && write_cum == 0)
			continue;

		if (!scale)
			seq_printf(seq, "%u", i);
		else if (i < 10)
			seq_printf(seq, "%u", scale << i);
		else if (i < 20)
			seq_printf(seq, "%uK", scale << (i-10));
		else
			seq_printf(seq, "%uM", scale << (i-20));

		seq_printf(seq, ":\t\t%10lu %3lu %3lu   | %4lu %3lu %3lu\n",
			   r, pct(r, read_tot), pct(read_cum, read_tot),
			   w, pct(w, write_tot), pct(write_cum, write_tot));

		if (read_cum == read_tot && write_cum == write_tot)
			break;
	}
}

static void brw_stats_show(struct seq_file *seq, struct brw_stats *brw_stats)
{
	struct timespec64 now;

	/* this sampling races with updates */
	ktime_get_real_ts64(&now);
	seq_printf(seq, "snapshot_time:         %llu.%09lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);

	display_brw_stats(seq, "pages per bulk r/w", "rpcs",
			  &brw_stats->hist[BRW_R_PAGES],
			  &brw_stats->hist[BRW_W_PAGES], 1);
	display_brw_stats(seq, "discontiguous pages", "rpcs",
			  &brw_stats->hist[BRW_R_DISCONT_PAGES],
			  &brw_stats->hist[BRW_W_DISCONT_PAGES], 0);
#if 0
	display_brw_stats(seq, "discontiguous blocks", "rpcs",
			  &brw_stats->hist[BRW_R_DISCONT_BLOCKS],
			  &brw_stats->hist[BRW_W_DISCONT_BLOCKS], 0);

	display_brw_stats(seq, "disk fragmented I/Os", "ios",
			  &brw_stats->hist[BRW_R_DIO_FRAGS],
			  &brw_stats->hist[BRW_W_DIO_FRAGS], 0);
#endif
	display_brw_stats(seq, "disk I/Os in flight", "ios",
			  &brw_stats->hist[BRW_R_RPC_HIST],
			  &brw_stats->hist[BRW_W_RPC_HIST], 0);

	display_brw_stats(seq, "I/O time (1/1000s)", "ios",
			  &brw_stats->hist[BRW_R_IO_TIME],
			  &brw_stats->hist[BRW_W_IO_TIME], 1000 / HZ);

	display_brw_stats(seq, "disk I/O size", "ios",
			  &brw_stats->hist[BRW_R_DISK_IOSIZE],
			  &brw_stats->hist[BRW_W_DISK_IOSIZE], 1);
}

#undef pct

static int osd_brw_stats_seq_show(struct seq_file *seq, void *v)
{
	struct osd_device *osd = seq->private;

	brw_stats_show(seq, &osd->od_brw_stats);

	return 0;
}

static ssize_t osd_brw_stats_seq_write(struct file *file,
				       const char __user *buf,
				       size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct osd_device *osd = seq->private;
	int i;

	for (i = 0; i < BRW_LAST; i++)
		lprocfs_oh_clear(&osd->od_brw_stats.hist[i]);

	return len;
}

LPROC_SEQ_FOPS(osd_brw_stats);

static int osd_stats_init(struct osd_device *osd)
{
	int result, i;
	ENTRY;

	for (i = 0; i < BRW_LAST; i++)
		spin_lock_init(&osd->od_brw_stats.hist[i].oh_lock);

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
		result = lprocfs_seq_create(osd->od_proc_entry, "brw_stats",
					    0644, &osd_brw_stats_fops, osd);
	} else {
		result = -ENOMEM;
	}

out:
	RETURN(result);
}

static int zfs_osd_fstype_seq_show(struct seq_file *m, void *data)
{
	seq_puts(m, "zfs\n");
	return 0;
}
LPROC_SEQ_FOPS_RO(zfs_osd_fstype);

static int zfs_osd_mntdev_seq_show(struct seq_file *m, void *data)
{
	struct osd_device *osd = osd_dt_dev((struct dt_device *)m->private);

	LASSERT(osd != NULL);
	seq_printf(m, "%s\n", osd->od_mntdev);
	return 0;
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

LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_blksize);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_filestotal);
LPROC_SEQ_FOPS_RO_TYPE(zfs, dt_filesfree);

struct lprocfs_vars lprocfs_osd_obd_vars[] = {
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
					      lprocfs_osd_obd_vars,
					      &osd->od_dt_dev);
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
