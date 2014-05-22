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
#include <lustre_lfsck.h>

#include "ofd_internal.h"

#ifdef LPROCFS

static int ofd_seqs_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m, "%u\n", ofd->ofd_seq_count);
}
LPROC_SEQ_FOPS_RO(ofd_seqs);

static int ofd_tot_dirty_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	return seq_printf(m, LPU64"\n", ofd->ofd_tot_dirty);
}
LPROC_SEQ_FOPS_RO(ofd_tot_dirty);

static int ofd_tot_granted_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	return seq_printf(m, LPU64"\n", ofd->ofd_tot_granted);
}
LPROC_SEQ_FOPS_RO(ofd_tot_granted);

static int ofd_tot_pending_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	return seq_printf(m, LPU64"\n", ofd->ofd_tot_pending);
}
LPROC_SEQ_FOPS_RO(ofd_tot_pending);

static int ofd_grant_precreate_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	return seq_printf(m, "%ld\n",
			  obd->obd_self_export->exp_filter_data.fed_grant);
}
LPROC_SEQ_FOPS_RO(ofd_grant_precreate);

static int ofd_grant_ratio_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	return seq_printf(m, "%d%%\n",
			  (int) ofd_grant_reserved(ofd, 100));
}

static ssize_t
ofd_grant_ratio_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file         *m = file->private_data;
	struct obd_device       *obd = m->private;
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
LPROC_SEQ_FOPS(ofd_grant_ratio);

static int ofd_precreate_batch_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	return seq_printf(m, "%d\n", ofd->ofd_precreate_batch);
}

static ssize_t
ofd_precreate_batch_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
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
LPROC_SEQ_FOPS(ofd_precreate_batch);

static int ofd_last_id_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
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
		rc = seq_printf(m, DOSTID"\n", seq, ostid_id(&oseq->os_oi));
		if (rc < 0) {
			retval = rc;
			break;
		}
		retval += rc;
	}
	read_unlock(&ofd->ofd_seq_list_lock);
	return retval;
}
LPROC_SEQ_FOPS_RO(ofd_last_id);

static int ofd_fmd_max_num_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m, "%u\n", ofd->ofd_fmd_max_num);
}

static ssize_t
ofd_fmd_max_num_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
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
LPROC_SEQ_FOPS(ofd_fmd_max_num);

static int ofd_fmd_max_age_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m, "%ld\n", ofd->ofd_fmd_max_age / HZ);
}

static ssize_t
ofd_fmd_max_age_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	int			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 65536 || val < 1)
		return -EINVAL;

	ofd->ofd_fmd_max_age = val * HZ;
	return count;
}
LPROC_SEQ_FOPS(ofd_fmd_max_age);

static int ofd_capa_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;

	return seq_printf(m, "capability on: %s\n",
			  obd->u.filter.fo_fl_oss_capa ? "oss" : "");
}

static ssize_t
ofd_capa_seq_write(struct file *file, const char *__user buffer, size_t count,
		   loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
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
LPROC_SEQ_FOPS(ofd_capa);

static int ofd_capa_count_seq_show(struct seq_file *m, void *data)
{
	return seq_printf(m, "%d %d\n", capa_count[CAPA_SITE_CLIENT],
			  capa_count[CAPA_SITE_SERVER]);
}
LPROC_SEQ_FOPS_RO(ofd_capa_count);

static int ofd_degraded_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m, "%u\n", ofd->ofd_raid_degraded);
}

static ssize_t
ofd_degraded_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
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
LPROC_SEQ_FOPS(ofd_degraded);

static int ofd_fstype_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct lu_device  *d;

	LASSERT(ofd->ofd_osd);
	d = &ofd->ofd_osd->dd_lu_dev;
	LASSERT(d->ld_type);
	return seq_printf(m, "%s\n", d->ld_type->ldt_name);
}
LPROC_SEQ_FOPS_RO(ofd_fstype);

static int ofd_syncjournal_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m, "%u\n", ofd->ofd_syncjournal);
}

static ssize_t
ofd_syncjournal_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
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
LPROC_SEQ_FOPS(ofd_syncjournal);

/* This must be longer than the longest string below */
#define SYNC_STATES_MAXLEN 16
static char *sync_on_cancel_states[] = {"never",
					"blocking",
					"always" };

static int ofd_sync_lock_cancel_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct lu_target	*tgt = obd->u.obt.obt_lut;

	return seq_printf(m, "%s\n",
			  sync_on_cancel_states[tgt->lut_sync_lock_cancel]);
}

static ssize_t
ofd_sync_lock_cancel_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct lu_target	*tgt = obd->u.obt.obt_lut;
	char			 kernbuf[SYNC_STATES_MAXLEN];
	int			 val = -1;
	int			 i;

	if (count == 0 || count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	if (kernbuf[count - 1] == '\n')
		kernbuf[count - 1] = 0;

	for (i = 0 ; i < NUM_SYNC_ON_CANCEL_STATES; i++) {
		if (strcmp(kernbuf, sync_on_cancel_states[i]) == 0) {
			val = i;
			break;
		}
	}

	/* Legacy numeric codes */
	if (val == -1) {
		int rc;

		/* Safe to use userspace buffer as lprocfs_write_helper will
		 * use copy from user for parsing */
		rc = lprocfs_write_helper(buffer, count, &val);
		if (rc)
			return rc;
	}

	if (val < 0 || val > 2)
		return -EINVAL;

	spin_lock(&tgt->lut_flags_lock);
	tgt->lut_sync_lock_cancel = val;
	spin_unlock(&tgt->lut_flags_lock);
	return count;
}
LPROC_SEQ_FOPS(ofd_sync_lock_cancel);

static int ofd_grant_compat_disable_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m, "%u\n", ofd->ofd_grant_compat_disable);
}

static ssize_t
ofd_grant_compat_disable_seq_write(struct file *file,
				   const char __user *buffer,
				   size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
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
LPROC_SEQ_FOPS(ofd_grant_compat_disable);

static int ofd_soft_sync_limit_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	return lprocfs_uint_seq_show(m, &ofd->ofd_soft_sync_limit);
}

static ssize_t
ofd_soft_sync_limit_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return lprocfs_uint_seq_write(file, buffer, count,
				      (loff_t *) &ofd->ofd_soft_sync_limit);
}
LPROC_SEQ_FOPS(ofd_soft_sync_limit);

static int ofd_lfsck_speed_limit_seq_show(struct seq_file *m, void *data)
{
	struct obd_device       *obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	return lfsck_get_speed(m, ofd->ofd_osd);
}

static ssize_t
ofd_lfsck_speed_limit_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	__u32			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc != 0)
		return rc;

	rc = lfsck_set_speed(ofd->ofd_osd, val);

	return rc != 0 ? rc : count;
}
LPROC_SEQ_FOPS(ofd_lfsck_speed_limit);

static int ofd_lfsck_layout_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return lfsck_dump(m, ofd->ofd_osd, LT_LAYOUT);
}
LPROC_SEQ_FOPS_RO(ofd_lfsck_layout);

static int ofd_lfsck_verify_pfid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return seq_printf(m,
			  "switch: %s\ndetected: "LPU64"\nrepaired: "LPU64"\n",
			  ofd->ofd_lfsck_verify_pfid ? "on" : "off",
			  ofd->ofd_inconsistency_self_detected,
			  ofd->ofd_inconsistency_self_repaired);
}

static ssize_t
ofd_lfsck_verify_pfid_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	__u32			 val;
	int			 rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc != 0)
		return rc;

	ofd->ofd_lfsck_verify_pfid = !!val;

	return count;
}
LPROC_SEQ_FOPS(ofd_lfsck_verify_pfid);

LPROC_SEQ_FOPS_RO_TYPE(ofd, uuid);
LPROC_SEQ_FOPS_RO_TYPE(ofd, blksize);
LPROC_SEQ_FOPS_RO_TYPE(ofd, kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(ofd, kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(ofd, kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(ofd, filestotal);
LPROC_SEQ_FOPS_RO_TYPE(ofd, filesfree);

LPROC_SEQ_FOPS_RO_TYPE(ofd, recovery_status);
LPROC_SEQ_FOPS_RW_TYPE(ofd, recovery_time_soft);
LPROC_SEQ_FOPS_RW_TYPE(ofd, recovery_time_hard);
LPROC_SEQ_FOPS_WO_TYPE(ofd, evict_client);
LPROC_SEQ_FOPS_RO_TYPE(ofd, num_exports);
LPROC_SEQ_FOPS_RO_TYPE(ofd, target_instance);
LPROC_SEQ_FOPS_RW_TYPE(ofd, ir_factor);
LPROC_SEQ_FOPS_RW_TYPE(ofd, job_interval);

struct lprocfs_seq_vars lprocfs_ofd_obd_vars[] = {
	{ .name =	"uuid",
	  .fops =	&ofd_uuid_fops			},
	{ .name =	"blocksize",
	  .fops =	&ofd_blksize_fops		},
	{ .name =	"kbytestotal",
	  .fops =	&ofd_kbytestotal_fops		},
	{ .name =	"kbytesfree",
	  .fops =	&ofd_kbytesfree_fops		},
	{ .name =	"kbytesavail",
	  .fops =	&ofd_kbytesavail_fops		},
	{ .name =	"filestotal",
	  .fops =	&ofd_filestotal_fops		},
	{ .name =	"filesfree",
	  .fops =	&ofd_filesfree_fops		},
	{ .name =	"seqs_allocated",
	  .fops =	&ofd_seqs_fops			},
	{ .name =	"fstype",
	  .fops =	&ofd_fstype_fops		},
	{ .name =	"last_id",
	  .fops =	&ofd_last_id_fops		},
	{ .name =	"tot_dirty",
	  .fops =	&ofd_tot_dirty_fops		},
	{ .name =	"tot_pending",
	  .fops =	&ofd_tot_pending_fops		},
	{ .name =	"tot_granted",
	  .fops =	&ofd_tot_granted_fops		},
	{ .name =	"grant_precreate",
	  .fops =	&ofd_grant_precreate_fops	},
	{ .name =	"grant_ratio",
	  .fops =	&ofd_grant_ratio_fops		},
	{ .name =	"precreate_batch",
	  .fops =	&ofd_precreate_batch_fops	},
	{ .name =	"recovery_status",
	  .fops =	&ofd_recovery_status_fops	},
	{ .name =	"recovery_time_soft",
	  .fops =	&ofd_recovery_time_soft_fops	},
	{ .name =	"recovery_time_hard",
	  .fops =	&ofd_recovery_time_hard_fops	},
	{ .name =	"evict_client",
	  .fops =	&ofd_evict_client_fops		},
	{ .name =	"num_exports",
	  .fops =	&ofd_num_exports_fops		},
	{ .name =	"degraded",
	  .fops =	&ofd_degraded_fops		},
	{ .name =	"sync_journal",
	  .fops =	&ofd_syncjournal_fops		},
	{ .name =	"sync_on_lock_cancel",
	  .fops =	&ofd_sync_lock_cancel_fops	},
	{ .name =	"instance",
	  .fops =	&ofd_target_instance_fops	},
	{ .name =	"ir_factor",
	  .fops =	&ofd_ir_factor_fops		},
	{ .name =	"grant_compat_disable",
	  .fops =	&ofd_grant_compat_disable_fops	},
	{ .name =	"client_cache_count",
	  .fops =	&ofd_fmd_max_num_fops		},
	{ .name =	"client_cache_seconds",
	  .fops =	&ofd_fmd_max_age_fops		},
	{ .name =	"capa",
	  .fops =	&ofd_capa_fops			},
	{ .name =	"capa_count",
	  .fops =	&ofd_capa_count_fops		},
	{ .name =	"job_cleanup_interval",
	  .fops =	&ofd_job_interval_fops		},
	{ .name =	"soft_sync_limit",
	  .fops =	&ofd_soft_sync_limit_fops	},
	{ .name =	"lfsck_speed_limit",
	  .fops =	&ofd_lfsck_speed_limit_fops	},
	{ .name =	"lfsck_layout",
	  .fops =	&ofd_lfsck_layout_fops		},
	{ .name	=	"lfsck_verify_pfid",
	  .fops	=	&ofd_lfsck_verify_pfid_fops	},
	{ 0 }
};

void ofd_stats_counter_init(struct lprocfs_stats *stats)
{
	LASSERT(stats && stats->ls_num >= LPROC_OFD_STATS_LAST);

	lprocfs_counter_init(stats, LPROC_OFD_STATS_READ,
			     LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_WRITE,
			     LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_GETATTR,
			     0, "getattr", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SETATTR,
			     0, "setattr", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_PUNCH,
			     0, "punch", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SYNC,
			     0, "sync", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_DESTROY,
			     0, "destroy", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_CREATE,
			     0, "create", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_STATFS,
			     0, "statfs", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_GET_INFO,
			     0, "get_info", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SET_INFO,
			     0, "set_info", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_QUOTACTL,
			     0, "quotactl", "reqs");
}

#endif /* LPROCFS */
