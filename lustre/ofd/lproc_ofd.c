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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/lproc_ofd.c
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>

#include "ofd_internal.h"

#ifdef LPROCFS

static int lprocfs_ofd_rd_seqs(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	*eof = 1;
	return snprintf(page, count, "%u\n", ofd->ofd_seq_count);
}

static int lprocfs_ofd_rd_tot_dirty(char *page, char **start, off_t off,
				    int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, LPU64"\n", ofd->ofd_tot_dirty);
}

static int lprocfs_ofd_rd_tot_granted(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, LPU64"\n", ofd->ofd_tot_granted);
}

static int lprocfs_ofd_rd_tot_pending(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, LPU64"\n", ofd->ofd_tot_pending);
}

static int lprocfs_ofd_rd_grant_precreate(char *page, char **start, off_t off,
					  int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;

	LASSERT(obd != NULL);
	*eof = 1;
	return snprintf(page, count, "%ld\n",
			obd->obd_self_export->exp_filter_data.fed_grant);
}

static int lprocfs_ofd_rd_grant_ratio(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%d%%\n",
			(int) ofd_grant_reserved(ofd, 100));
}

static int lprocfs_ofd_wr_grant_ratio(struct file *file, const char *buffer,
				      unsigned long count, void *data)
{
	struct obd_device	*obd = (struct obd_device *)data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 100 || val < 0)
		return -EINVAL;

	if (val == 0)
		CWARN("%s: disabling grant error margin\n", obd->obd_name);
	if (val > 50)
		CWARN("%s: setting grant error margin >50%%, be warned that "
		      "a huge part of the free space is now reserved for "
		      "grants\n", obd->obd_name);

	spin_lock(&ofd->ofd_grant_lock);
	ofd->ofd_grant_ratio = ofd_grant_ratio_conv(val);
	spin_unlock(&ofd->ofd_grant_lock);
	return count;
}

static int lprocfs_ofd_rd_precreate_batch(char *page, char **start, off_t off,
					  int count, int *eof, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	LASSERT(obd != NULL);
	*eof = 1;
	return snprintf(page, count, "%d\n", ofd->ofd_precreate_batch);
}

static int lprocfs_ofd_wr_precreate_batch(struct file *file, const char *buffer,
					  unsigned long count, void *data)
{
	struct obd_device *obd = (struct obd_device *)data;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	int val;
	int rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 1)
		return -EINVAL;

	spin_lock(&ofd->ofd_batch_lock);
	ofd->ofd_precreate_batch = val;
	spin_unlock(&ofd->ofd_batch_lock);
	return count;
}

static int lprocfs_ofd_rd_last_id(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd;
	struct ofd_seq		*oseq = NULL;
	int			retval = 0, rc;

	if (obd == NULL)
		return 0;

	ofd = ofd_dev(obd->obd_lu_dev);

	read_lock(&ofd->ofd_seq_list_lock);
	cfs_list_for_each_entry(oseq, &ofd->ofd_seq_list, os_list) {
		__u64 seq;

		seq = ostid_seq(&oseq->os_oi) == 0 ?
		      fid_idif_seq(ostid_id(&oseq->os_oi),
				   ofd->ofd_lut.lut_lsd.lsd_osd_index) :
		      ostid_seq(&oseq->os_oi);
		rc = snprintf(page, count, DOSTID"\n", seq,
			      ostid_id(&oseq->os_oi));
		if (rc < 0) {
			retval = rc;
			break;
		}
		page += rc;
		count -= rc;
		retval += rc;
	}
	read_unlock(&ofd->ofd_seq_list_lock);
	return retval;
}

int lprocfs_ofd_rd_fmd_max_num(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 rc;

	rc = snprintf(page, count, "%u\n", ofd->ofd_fmd_max_num);
	return rc;
}

int lprocfs_ofd_wr_fmd_max_num(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 65536 || val < 1)
		return -EINVAL;

	ofd->ofd_fmd_max_num = val;
	return count;
}

int lprocfs_ofd_rd_fmd_max_age(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 rc;

	rc = snprintf(page, count, "%ld\n", ofd->ofd_fmd_max_age / CFS_HZ);
	return rc;
}

int lprocfs_ofd_wr_fmd_max_age(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 65536 || val < 1)
		return -EINVAL;

	ofd->ofd_fmd_max_age = val * CFS_HZ;
	return count;
}

static int lprocfs_ofd_rd_capa(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	int			 rc;

	rc = snprintf(page, count, "capability on: %s\n",
		      obd->u.filter.fo_fl_oss_capa ? "oss" : "");
	return rc;
}

static int lprocfs_ofd_wr_capa(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	int			 val, rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val & ~0x1) {
		CERROR("invalid capability mode, only 0/1 are accepted.\n"
		       " 1: enable oss fid capability\n"
		       " 0: disable oss fid capability\n");
		return -EINVAL;
	}

	obd->u.filter.fo_fl_oss_capa = val;
	LCONSOLE_INFO("OSS %s %s fid capability.\n", obd->obd_name,
		      val ? "enabled" : "disabled");
	return count;
}

static int lprocfs_ofd_rd_capa_count(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	return snprintf(page, count, "%d %d\n",
			capa_count[CAPA_SITE_CLIENT],
			capa_count[CAPA_SITE_SERVER]);
}

int lprocfs_ofd_rd_degraded(char *page, char **start, off_t off,
			    int count, int *eof, void *data)
{
	struct obd_device *obd = data;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return snprintf(page, count, "%u\n", ofd->ofd_raid_degraded);
}

int lprocfs_ofd_wr_degraded(struct file *file, const char *buffer,
			    unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val, rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_raid_degraded = !!val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}

int lprocfs_ofd_rd_fstype(char *page, char **start, off_t off, int count,
			  int *eof, void *data)
{
	struct obd_device *obd = data;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct lu_device  *d;

	LASSERT(ofd->ofd_osd);
	d = &ofd->ofd_osd->dd_lu_dev;
	LASSERT(d->ld_type);
	return snprintf(page, count, "%s\n", d->ld_type->ldt_name);
}

int lprocfs_ofd_rd_syncjournal(char *page, char **start, off_t off,
			       int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 rc;

	rc = snprintf(page, count, "%u\n", ofd->ofd_syncjournal);
	return rc;
}

int lprocfs_ofd_wr_syncjournal(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -EINVAL;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_syncjournal = !!val;
	ofd_slc_set(ofd);
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}

static char *sync_on_cancel_states[] = {"never",
					"blocking",
					"always" };

int lprocfs_ofd_rd_sync_lock_cancel(char *page, char **start, off_t off,
				    int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 rc;

	rc = snprintf(page, count, "%s\n",
		      sync_on_cancel_states[ofd->ofd_sync_lock_cancel]);
	return rc;
}

int lprocfs_ofd_wr_sync_lock_cancel(struct file *file, const char *buffer,
				    unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val = -1;
	int			 i;

	for (i = 0 ; i < NUM_SYNC_ON_CANCEL_STATES; i++) {
		if (memcmp(buffer, sync_on_cancel_states[i],
			   strlen(sync_on_cancel_states[i])) == 0) {
			val = i;
			break;
		}
	}
	if (val == -1) {
		int rc;

		rc = lprocfs_write_helper(buffer, count, &val);
		if (rc)
			return rc;
	}

	if (val < 0 || val > 2)
		return -EINVAL;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_sync_lock_cancel = val;
	spin_unlock(&ofd->ofd_flags_lock);
	return count;
}

int lprocfs_ofd_rd_grant_compat_disable(char *page, char **start, off_t off,
					int count, int *eof, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 rc;

	rc = snprintf(page, count, "%u\n", ofd->ofd_grant_compat_disable);
	return rc;
}

int lprocfs_ofd_wr_grant_compat_disable(struct file *file, const char *buffer,
					unsigned long count, void *data)
{
	struct obd_device	*obd = data;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -EINVAL;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_grant_compat_disable = !!val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}

static struct lprocfs_vars lprocfs_ofd_obd_vars[] = {
	{ "uuid",		 lprocfs_rd_uuid, 0, 0 },
	{ "blocksize",		 lprocfs_rd_blksize, 0, 0 },
	{ "kbytestotal",	 lprocfs_rd_kbytestotal, 0, 0 },
	{ "kbytesfree",		 lprocfs_rd_kbytesfree, 0, 0 },
	{ "kbytesavail",	 lprocfs_rd_kbytesavail, 0, 0 },
	{ "filestotal",		 lprocfs_rd_filestotal, 0, 0 },
	{ "filesfree",		 lprocfs_rd_filesfree, 0, 0 },
	{ "seqs_allocated",	 lprocfs_ofd_rd_seqs, 0, 0 },
	{ "fstype",		 lprocfs_ofd_rd_fstype, 0, 0 },
	{ "last_id",		 lprocfs_ofd_rd_last_id, 0, 0 },
	{ "tot_dirty",		 lprocfs_ofd_rd_tot_dirty,   0, 0 },
	{ "tot_pending",	 lprocfs_ofd_rd_tot_pending, 0, 0 },
	{ "tot_granted",	 lprocfs_ofd_rd_tot_granted, 0, 0 },
	{ "grant_precreate",	 lprocfs_ofd_rd_grant_precreate, 0, 0 },
	{ "grant_ratio",	 lprocfs_ofd_rd_grant_ratio,
				 lprocfs_ofd_wr_grant_ratio, 0, 0 },
	{ "precreate_batch",	 lprocfs_ofd_rd_precreate_batch,
				 lprocfs_ofd_wr_precreate_batch, 0 },
	{ "recovery_status",	 lprocfs_obd_rd_recovery_status, 0, 0 },
	{ "recovery_time_soft",	 lprocfs_obd_rd_recovery_time_soft,
				 lprocfs_obd_wr_recovery_time_soft, 0},
	{ "recovery_time_hard",  lprocfs_obd_rd_recovery_time_hard,
				 lprocfs_obd_wr_recovery_time_hard, 0},
	{ "evict_client",	 0, lprocfs_wr_evict_client, 0,
				 &lprocfs_evict_client_fops},
	{ "num_exports",	 lprocfs_rd_num_exports,   0, 0 },
	{ "degraded",		 lprocfs_ofd_rd_degraded,
				 lprocfs_ofd_wr_degraded, 0},
	{ "sync_journal",	 lprocfs_ofd_rd_syncjournal,
				 lprocfs_ofd_wr_syncjournal, 0 },
	{ "sync_on_lock_cancel", lprocfs_ofd_rd_sync_lock_cancel,
				 lprocfs_ofd_wr_sync_lock_cancel, 0 },
	{ "instance",		 lprocfs_target_rd_instance, 0 },
	{ "ir_factor",		 lprocfs_obd_rd_ir_factor,
				 lprocfs_obd_wr_ir_factor, 0},
	{ "grant_compat_disable", lprocfs_ofd_rd_grant_compat_disable,
				  lprocfs_ofd_wr_grant_compat_disable, 0 },
	{ "client_cache_count",	 lprocfs_ofd_rd_fmd_max_num,
				 lprocfs_ofd_wr_fmd_max_num, 0 },
	{ "client_cache_seconds", lprocfs_ofd_rd_fmd_max_age,
				  lprocfs_ofd_wr_fmd_max_age, 0 },
	{ "capa",		 lprocfs_ofd_rd_capa,
				 lprocfs_ofd_wr_capa, 0 },
	{ "capa_count",		 lprocfs_ofd_rd_capa_count, 0, 0 },
	{ "job_cleanup_interval", lprocfs_rd_job_interval,
				  lprocfs_wr_job_interval, 0},
	{ 0 }
};

static struct lprocfs_vars lprocfs_ofd_module_vars[] = {
	{ "num_refs",	  lprocfs_rd_numrefs,	0, 0 },
	{ 0 }
};

void lprocfs_ofd_init_vars(struct lprocfs_static_vars *lvars)
{
	lvars->module_vars  = lprocfs_ofd_module_vars;
	lvars->obd_vars     = lprocfs_ofd_obd_vars;
}

void ofd_stats_counter_init(struct lprocfs_stats *stats)
{
	LASSERT(stats && stats->ls_num == LPROC_OFD_STATS_LAST);
	lprocfs_counter_init(stats, LPROC_OFD_STATS_READ,
			     LPROCFS_CNTR_AVGMINMAX, "read", "bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_WRITE,
			     LPROCFS_CNTR_AVGMINMAX, "write", "bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SETATTR,
			     0, "setattr", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_PUNCH,
			     0, "punch", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SYNC,
			     0, "sync", "reqs");
}
#endif /* LPROCFS */
