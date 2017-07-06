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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#include <lprocfs_status.h>
#include <obd_class.h>
#include <linux/seq_file.h>
#include "lod_internal.h"
#include <uapi/linux/lustre_param.h>

/*
 * Notice, all the functions below (except for lod_procfs_init() and
 * lod_procfs_fini()) are not supposed to be used directly. They are
 * called by Linux kernel's procfs.
 */

#ifdef CONFIG_PROC_FS

/**
 * Show default stripe size.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_stripesize_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%llu\n",
		   lod->lod_desc.ld_default_stripe_size);
	return 0;
}

/**
 * Set default stripe size.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string containing the maximum number of bytes stored in
 *			each object before moving to the next object in the
 *			layout (if any)
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_stripesize_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	__s64 val;
	int rc;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, '1');
	if (rc)
		return rc;
	if (val < 0)
		return -ERANGE;

	lod_fix_desc_stripe_size(&val);
	lod->lod_desc.ld_default_stripe_size = val;

	return count;
}
LPROC_SEQ_FOPS(lod_stripesize);

/**
 * Show default stripe offset.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_stripeoffset_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%lld\n", lod->lod_desc.ld_default_stripe_offset);
	return 0;
}

/**
 * Set default stripe offset.
 *
 * Usually contains -1 allowing Lustre to balance objects among OST
 * otherwise may cause severe OST imbalance.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string describing starting OST index for new files
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_stripeoffset_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	__s64 val;
	int rc;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < -1)
		return -ERANGE;

	lod->lod_desc.ld_default_stripe_offset = val;

	return count;
}
LPROC_SEQ_FOPS(lod_stripeoffset);

/**
 * Show default striping pattern (LOV_PATTERN_*).
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_stripetype_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%u\n", lod->lod_desc.ld_pattern);
	return 0;
}

/**
 * Set default striping pattern (a number, not a human-readable string).
 *
 * \param[in] file	proc file
 * \param[in] buffer	string containing the default striping pattern for new
 *			files. This is an integer LOV_PATTERN_* value
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_stripetype_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	int rc;
	__u32 pattern;
	__s64 val;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0)
		return -ERANGE;

	pattern = val;
	lod_fix_desc_pattern(&pattern);
	lod->lod_desc.ld_pattern = pattern;

	return count;
}
LPROC_SEQ_FOPS(lod_stripetype);

/**
 * Show default number of stripes.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success,
 * \retval negative	error code if failed
 */
static int lod_stripecount_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%d\n",
		   (__s16)(lod->lod_desc.ld_default_stripe_count + 1) - 1);
	return 0;
}

/**
 * Set default number of stripes.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string containing the default number of stripes
 *			for new files
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code otherwise
 */
static ssize_t
lod_stripecount_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	int rc;
	__s64 val;
	__u32 stripe_count;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < -1)
		return -ERANGE;

	stripe_count = val;
	lod_fix_desc_stripe_count(&stripe_count);
	lod->lod_desc.ld_default_stripe_count = stripe_count;

	return count;
}
LPROC_SEQ_FOPS(lod_stripecount);

/**
 * Show number of targets.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_numobd_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%u\n", lod->lod_desc.ld_tgt_count);
	return 0;
}
LPROC_SEQ_FOPS_RO(lod_numobd);

/**
 * Show number of active targets.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_activeobd_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%u\n", lod->lod_desc.ld_active_tgt_count);
	return 0;
}
LPROC_SEQ_FOPS_RO(lod_activeobd);

/**
 * Show UUID of LOD device.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_desc_uuid_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%s\n", lod->lod_desc.ld_uuid.uuid);
	return 0;
}
LPROC_SEQ_FOPS_RO(lod_desc_uuid);

/**
 * Show QoS priority parameter.
 *
 * The printed value is a percentage value (0-100%) indicating the priority
 * of free space compared to performance. 0% means select OSTs equally
 * regardless of their free space, 100% means select OSTs only by their free
 * space even if it results in very imbalanced load on the OSTs.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_qos_priofree_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod = lu2lod_dev(dev->obd_lu_dev);

	LASSERT(lod != NULL);
	seq_printf(m, "%d%%\n",
		   (lod->lod_qos.lq_prio_free * 100 + 255) >> 8);
	return 0;
}

/**
 * Set QoS free space priority parameter.
 *
 * Set the relative priority of free OST space compared to OST load when OSTs
 * are space imbalanced.  See lod_qos_priofree_seq_show() for description of
 * this parameter.  See lod_qos_thresholdrr_seq_write() and lq_threshold_rr to
 * determine what constitutes "space imbalanced" OSTs.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which contains the free space priority (0-100)
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_qos_priofree_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	int rc;
	__s64 val;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0 || val > 100)
		return -EINVAL;
	lod->lod_qos.lq_prio_free = (val << 8) / 100;
	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_reset = 1;

	return count;
}
LPROC_SEQ_FOPS(lod_qos_priofree);

/**
 * Show threshold for "same space on all OSTs" rule.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_qos_thresholdrr_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%d%%\n",
		   (lod->lod_qos.lq_threshold_rr * 100 + 255) >> 8);
	return 0;
}

/**
 * Set threshold for "same space on all OSTs" rule.
 *
 * This sets the maximum percentage difference of free space between the most
 * full and most empty OST in the currently available OSTs. If this percentage
 * is exceeded, use the QoS allocator to select OSTs based on their available
 * space so that more full OSTs are chosen less often, otherwise use the
 * round-robin allocator for efficiency and performance.

 * \param[in] file	proc file
 * \param[in] buffer	string containing percentage difference of free space
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_qos_thresholdrr_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	int rc;
	__s64 val;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, '%');
	if (rc)
		return rc;

	if (val > 100 || val < 0)
		return -EINVAL;

	lod->lod_qos.lq_threshold_rr = (val << 8) / 100;
	lod->lod_qos.lq_dirty = 1;

	return count;
}
LPROC_SEQ_FOPS(lod_qos_thresholdrr);

/**
 * Show expiration period used to refresh cached statfs data, which
 * is used to implement QoS/RR striping allocation algorithm.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_qos_maxage_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%u Sec\n", lod->lod_desc.ld_qos_maxage);
	return 0;
}

/**
 * Set expiration period used to refresh cached statfs data.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string contains maximum age of statfs data in seconds
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_qos_maxage_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lustre_cfg_bufs bufs;
	struct lod_device *lod;
	struct lu_device *next;
	struct lustre_cfg *lcfg;
	char str[32];
	unsigned int i;
	int rc;
	__s64 val;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val <= 0)
		return -EINVAL;
	lod->lod_desc.ld_qos_maxage = val;

	/*
	 * propogate the value down to OSPs
	 */
	lustre_cfg_bufs_reset(&bufs, NULL);
	snprintf(str, 32, "%smaxage=%u", PARAM_OSP, (__u32)val);
	lustre_cfg_bufs_set_string(&bufs, 1, str);
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (lcfg == NULL)
		return -ENOMEM;
	lustre_cfg_init(lcfg, LCFG_PARAM, &bufs);

	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, i) {
		next = &OST_TGT(lod,i)->ltd_ost->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(NULL, next, lcfg);
		if (rc)
			CERROR("can't set maxage on #%d: %d\n", i, rc);
	}
	lod_putref(lod, &lod->lod_ost_descs);
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));

	return count;
}
LPROC_SEQ_FOPS(lod_qos_maxage);

static void *lod_osts_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_device *dev = p->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	lod_getref(&lod->lod_ost_descs); /* released in lod_osts_seq_stop */
	if (*pos >= lod->lod_ost_bitmap->size)
		return NULL;

	*pos = find_next_bit(lod->lod_ost_bitmap->data,
				 lod->lod_ost_bitmap->size, *pos);
	if (*pos < lod->lod_ost_bitmap->size)
		return OST_TGT(lod,*pos);
	else
		return NULL;
}

static void lod_osts_seq_stop(struct seq_file *p, void *v)
{
	struct obd_device *dev = p->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	lod_putref(lod, &lod->lod_ost_descs);
}

static void *lod_osts_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_device *dev = p->private;
	struct lod_device *lod = lu2lod_dev(dev->obd_lu_dev);

	if (*pos >= lod->lod_ost_bitmap->size - 1)
		return NULL;

	*pos = find_next_bit(lod->lod_ost_bitmap->data,
				 lod->lod_ost_bitmap->size, *pos + 1);
	if (*pos < lod->lod_ost_bitmap->size)
		return OST_TGT(lod,*pos);
	else
		return NULL;
}

/**
 * Show active/inactive status for OST found by lod_osts_seq_next().
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_osts_seq_show(struct seq_file *p, void *v)
{
	struct obd_device   *obd = p->private;
	struct lod_ost_desc *ost_desc = v;
	struct lod_device   *lod;
	int                  idx, rc, active;
	struct dt_device    *next;
	struct obd_statfs    sfs;

	LASSERT(obd->obd_lu_dev);
	lod = lu2lod_dev(obd->obd_lu_dev);

	idx = ost_desc->ltd_index;
	next = OST_TGT(lod,idx)->ltd_ost;
	if (next == NULL)
		return -EINVAL;

	/* XXX: should be non-NULL env, but it's very expensive */
	active = 1;
	rc = dt_statfs(NULL, next, &sfs);
	if (rc == -ENOTCONN) {
		active = 0;
		rc = 0;
	} else if (rc)
		return rc;

	seq_printf(p, "%d: %s %sACTIVE\n", idx,
		   obd_uuid2str(&ost_desc->ltd_uuid),
		   active ? "" : "IN");
	return 0;
}

static const struct seq_operations lod_osts_sops = {
	.start	= lod_osts_seq_start,
	.stop	= lod_osts_seq_stop,
	.next	= lod_osts_seq_next,
	.show	= lod_osts_seq_show,
};

static int lod_osts_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &lod_osts_sops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = PDE_DATA(inode);
	return 0;
}

LPROC_SEQ_FOPS_RO_TYPE(lod, uuid);

LPROC_SEQ_FOPS_RO_TYPE(lod, dt_blksize);
LPROC_SEQ_FOPS_RO_TYPE(lod, dt_kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(lod, dt_kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(lod, dt_kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(lod, dt_filestotal);
LPROC_SEQ_FOPS_RO_TYPE(lod, dt_filesfree);

/**
 * Show whether special failout mode for testing is enabled or not.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static int lod_lmv_failout_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	seq_printf(m, "%d\n", lod->lod_lmv_failout ? 1 : 0);
	return 0;
}

/**
 * Enable/disable a special failout mode for testing.
 *
 * This determines whether the LMV will try to continue processing a striped
 * directory even if it has a (partly) corrupted entry in the master directory,
 * or if it will abort upon finding a corrupted slave directory entry.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string: 0 or non-zero to disable or enable LMV failout
 * \param[in] count	@buffer length
 * \param[in] off	unused for single entry
 *
 * \retval @count	on success
 * \retval negative	error code if failed
 */
static ssize_t
lod_lmv_failout_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	__s64 val = 0;
	int rc;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	lod->lod_lmv_failout = !!val;

	return count;
}
LPROC_SEQ_FOPS(lod_lmv_failout);

static struct lprocfs_vars lprocfs_lod_obd_vars[] = {
	{ .name	=	"uuid",
	  .fops	=	&lod_uuid_fops		},
	{ .name	=	"stripesize",
	  .fops	=	&lod_stripesize_fops	},
	{ .name	=	"stripeoffset",
	  .fops	=	&lod_stripeoffset_fops	},
	{ .name	=	"stripecount",
	  .fops	=	&lod_stripecount_fops	},
	{ .name	=	"stripetype",
	  .fops	=	&lod_stripetype_fops	},
	{ .name	=	"numobd",
	  .fops	=	&lod_numobd_fops	},
	{ .name	=	"activeobd",
	  .fops	=	&lod_activeobd_fops	},
	{ .name	=	"desc_uuid",
	  .fops	=	&lod_desc_uuid_fops	},
	{ .name	=	"qos_prio_free",
	  .fops	=	&lod_qos_priofree_fops	},
	{ .name	=	"qos_threshold_rr",
	  .fops	=	&lod_qos_thresholdrr_fops },
	{ .name	=	"qos_maxage",
	  .fops	=	&lod_qos_maxage_fops	},
	{ .name	=	"lmv_failout",
	  .fops	=	&lod_lmv_failout_fops	},
	{ NULL }
};

static struct lprocfs_vars lprocfs_lod_osd_vars[] = {
	{ .name = "blocksize",	 .fops = &lod_dt_blksize_fops },
	{ .name = "kbytestotal", .fops = &lod_dt_kbytestotal_fops },
	{ .name = "kbytesfree",	 .fops = &lod_dt_kbytesfree_fops },
	{ .name = "kbytesavail", .fops = &lod_dt_kbytesavail_fops },
	{ .name = "filestotal",	 .fops = &lod_dt_filestotal_fops },
	{ .name = "filesfree",	 .fops = &lod_dt_filesfree_fops },
	{ .name = NULL }
};

static const struct file_operations lod_proc_target_fops = {
	.owner   = THIS_MODULE,
	.open    = lod_osts_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lprocfs_seq_release,
};

/**
 * Initialize procfs entries for LOD.
 *
 * \param[in] lod	LOD device
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
int lod_procfs_init(struct lod_device *lod)
{
	struct obd_device	*obd = lod2obd(lod);
	struct proc_dir_entry	*lov_proc_dir = NULL;
	struct obd_type		*type;
	int			 rc;

	obd->obd_vars = lprocfs_lod_obd_vars;
	rc = lprocfs_obd_setup(obd);
	if (rc) {
		CERROR("%s: cannot setup procfs entry: %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	rc = lprocfs_add_vars(obd->obd_proc_entry, lprocfs_lod_osd_vars,
			      &lod->lod_dt_dev);
	if (rc) {
		CERROR("%s: cannot setup procfs entry: %d\n",
		       obd->obd_name, rc);
		GOTO(out, rc);
	}

	rc = lprocfs_seq_create(obd->obd_proc_entry, "target_obd",
				0444, &lod_proc_target_fops, obd);
	if (rc) {
		CWARN("%s: Error adding the target_obd file %d\n",
		      obd->obd_name, rc);
		GOTO(out, rc);
	}

	lod->lod_pool_proc_entry = lprocfs_register("pools",
						    obd->obd_proc_entry,
						    NULL, NULL);
	if (IS_ERR(lod->lod_pool_proc_entry)) {
		rc = PTR_ERR(lod->lod_pool_proc_entry);
		lod->lod_pool_proc_entry = NULL;
		CWARN("%s: Failed to create pool proc file: %d\n",
		      obd->obd_name, rc);
		GOTO(out, rc);
	}

	/* If the real LOV is present which is the case for setups
	 * with both server and clients on the same node then use
	 * the LOV's proc root */
	type = class_search_type(LUSTRE_LOV_NAME);
	if (type != NULL && type->typ_procroot != NULL)
		lov_proc_dir = type->typ_procroot;
	else
		lov_proc_dir = obd->obd_type->typ_procsym;

	if (lov_proc_dir == NULL)
		RETURN(0);

	/* for compatibility we link old procfs's LOV entries to lod ones */
	lod->lod_symlink = lprocfs_add_symlink(obd->obd_name, lov_proc_dir,
					       "../lod/%s", obd->obd_name);
	if (lod->lod_symlink == NULL)
		CERROR("cannot create LOV symlink for /proc/fs/lustre/lod/%s\n",
		       obd->obd_name);
	RETURN(0);

out:
	lprocfs_obd_cleanup(obd);

	return rc;
}

/**
 * Cleanup procfs entries registred for LOD.
 *
 * \param[in] lod	LOD device
 */
void lod_procfs_fini(struct lod_device *lod)
{
	struct obd_device *obd = lod2obd(lod);

	if (lod->lod_symlink != NULL) {
		lprocfs_remove(&lod->lod_symlink);
		lod->lod_symlink = NULL;
	}

	if (lod->lod_pool_proc_entry != NULL) {
		lprocfs_remove(&lod->lod_pool_proc_entry);
		lod->lod_pool_proc_entry = NULL;
	}

	lprocfs_obd_cleanup(obd);
}

#endif /* CONFIG_PROC_FS */

