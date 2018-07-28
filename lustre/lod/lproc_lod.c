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
 * Copyright (c) 2012, 2017, Intel Corporation.
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
#include <uapi/linux/lustre/lustre_param.h>

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
static int lod_dom_stripesize_seq_show(struct seq_file *m, void *v)
{
	struct obd_device *dev = m->private;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	seq_printf(m, "%u\n", lod->lod_dom_max_stripesize);
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
lod_dom_stripesize_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct lod_device *lod;
	s64 val;
	int rc;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, '1');
	if (rc)
		return rc;
	if (val < 0)
		return -ERANGE;

	/* 1GB is the limit */
	if (val > (1ULL << 30))
		return -ERANGE;
	else if (val > 0) {
		if (val < LOV_MIN_STRIPE_SIZE) {
			LCONSOLE_INFO("Increasing provided stripe size to "
				      "a minimum value %u\n",
				      LOV_MIN_STRIPE_SIZE);
			val = LOV_MIN_STRIPE_SIZE;
		} else if (val & (LOV_MIN_STRIPE_SIZE - 1)) {
			val &= ~(LOV_MIN_STRIPE_SIZE - 1);
			LCONSOLE_WARN("Changing provided stripe size to %llu "
				      "(a multiple of minimum %u)\n",
				      val, LOV_MIN_STRIPE_SIZE);
		}
	}

	lod->lod_dom_max_stripesize = val;

	return count;
}
LPROC_SEQ_FOPS(lod_dom_stripesize);

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
	s64 val;
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
static ssize_t stripeoffset_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%lld\n", lod->lod_desc.ld_default_stripe_offset);
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
static ssize_t stripeoffset_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	long val;
	int rc;

	rc = kstrtol(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < -1 || val > LOV_MAX_STRIPE_COUNT)
		return -ERANGE;

	lod->lod_desc.ld_default_stripe_offset = val;

	return count;
}
LUSTRE_RW_ATTR(stripeoffset);

/**
 * Show default striping pattern (LOV_PATTERN_*).
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static ssize_t stripetype_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%u\n", lod->lod_desc.ld_pattern);
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
static ssize_t stripetype_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u32 pattern;
	int rc;

	rc = kstrtouint(buffer, 0, &pattern);
	if (rc)
		return rc;

	lod_fix_desc_pattern(&pattern);
	lod->lod_desc.ld_pattern = pattern;

	return count;
}
LUSTRE_RW_ATTR(stripetype);

/**
 * Show default number of stripes.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success,
 * \retval negative	error code if failed
 */
static ssize_t stripecount_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%d\n",
		       (s16)(lod->lod_desc.ld_default_stripe_count + 1) - 1);
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
static ssize_t stripecount_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u32 stripe_count;
	int rc;

	rc = kstrtouint(buffer, 0, &stripe_count);
	if (rc)
		return rc;

	lod_fix_desc_stripe_count(&stripe_count);
	lod->lod_desc.ld_default_stripe_count = stripe_count;

	return count;
}
LUSTRE_RW_ATTR(stripecount);

/**
 * Show number of targets.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static ssize_t numobd_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%u\n", lod->lod_desc.ld_tgt_count);
}
LUSTRE_RO_ATTR(numobd);

/**
 * Show number of active targets.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static ssize_t activeobd_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%u\n", lod->lod_desc.ld_active_tgt_count);
}
LUSTRE_RO_ATTR(activeobd);

/**
 * Show UUID of LOD device.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static ssize_t desc_uuid_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%s\n", lod->lod_desc.ld_uuid.uuid);
}
LUSTRE_RO_ATTR(desc_uuid);

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
static ssize_t qos_prio_free_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%d%%\n",
		       (lod->lod_qos.lq_prio_free * 100 + 255) >> 8);
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
static ssize_t qos_prio_free_store(struct kobject *kobj, struct attribute *attr,
				   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val > 100)
		return -EINVAL;
	lod->lod_qos.lq_prio_free = (val << 8) / 100;
	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_reset = 1;

	return count;
}
LUSTRE_RW_ATTR(qos_prio_free);

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
static ssize_t qos_maxage_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%u Sec\n", lod->lod_desc.ld_qos_maxage);
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
static ssize_t qos_maxage_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lustre_cfg_bufs bufs;
	struct lu_device *next;
	struct lustre_cfg *lcfg;
	char str[32];
	unsigned int i;
	int rc;
	u32 val;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val <= 0)
		return -EINVAL;
	lod->lod_desc.ld_qos_maxage = val;

	/*
	 * propogate the value down to OSPs
	 */
	lustre_cfg_bufs_reset(&bufs, NULL);
	snprintf(str, 32, "%smaxage=%u", PARAM_OSP, val);
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
LUSTRE_RW_ATTR(qos_maxage);

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

/**
 * Show whether special failout mode for testing is enabled or not.
 *
 * \param[in] m		seq file
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	error code if failed
 */
static ssize_t lmv_failout_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return sprintf(buf, "%d\n", lod->lod_lmv_failout ? 1 : 0);
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
static ssize_t lmv_failout_store(struct kobject *kobj, struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	bool val = 0;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	lod->lod_lmv_failout = val;

	return count;
}
LUSTRE_RW_ATTR(lmv_failout);

static struct lprocfs_vars lprocfs_lod_obd_vars[] = {
	{ .name	=	"stripesize",
	  .fops	=	&lod_stripesize_fops	},
	{ .name	=	"qos_threshold_rr",
	  .fops	=	&lod_qos_thresholdrr_fops },
	{ .name =	"dom_stripesize",
	  .fops =	&lod_dom_stripesize_fops	},
	{ NULL }
};

static const struct file_operations lod_proc_target_fops = {
	.owner   = THIS_MODULE,
	.open    = lod_osts_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lprocfs_seq_release,
};

static struct attribute *lod_attrs[] = {
	&lustre_attr_stripeoffset.attr,
	&lustre_attr_stripecount.attr,
	&lustre_attr_stripetype.attr,
	&lustre_attr_activeobd.attr,
	&lustre_attr_desc_uuid.attr,
	&lustre_attr_lmv_failout.attr,
	&lustre_attr_numobd.attr,
	&lustre_attr_qos_maxage.attr,
	&lustre_attr_qos_prio_free.attr,
	NULL,
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
	struct obd_device *obd = lod2obd(lod);
	struct proc_dir_entry *lov_proc_dir;
	struct obd_type *type;
	struct kobject *lov;
	int rc;

	lod->lod_dt_dev.dd_ktype.default_attrs = lod_attrs;
	rc = dt_tunables_init(&lod->lod_dt_dev, obd->obd_type, obd->obd_name,
			      NULL);
	if (rc) {
		CERROR("%s: failed to setup DT tunables: %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	obd->obd_vars = lprocfs_lod_obd_vars;
	obd->obd_proc_entry = lprocfs_register(obd->obd_name,
					       obd->obd_type->typ_procroot,
					       obd->obd_vars, obd);
	if (IS_ERR(obd->obd_proc_entry)) {
		rc = PTR_ERR(obd->obd_proc_entry);
		CERROR("%s: error %d setting up lprocfs\n",
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

	lov = kset_find_obj(lustre_kset, "lov");
	if (lov) {
		rc = sysfs_create_link(lov, &lod->lod_dt_dev.dd_kobj,
				       obd->obd_name);
		kobject_put(lov);
	}

	lod->lod_debugfs = ldebugfs_add_symlink(obd->obd_name, "lov",
						"../lod/%s", obd->obd_name);
	if (!lod->lod_debugfs)
		CERROR("%s: failed to create LOV debugfs symlink\n",
		       obd->obd_name);

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
	dt_tunables_fini(&lod->lod_dt_dev);

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
	struct kobject *lov;

	if (lod->lod_symlink != NULL) {
		lprocfs_remove(&lod->lod_symlink);
		lod->lod_symlink = NULL;
	}

	lov = kset_find_obj(lustre_kset, "lov");
	if (lov) {
		sysfs_remove_link(lov, obd->obd_name);
		kobject_put(lov);
	}

	if (!IS_ERR_OR_NULL(lod->lod_debugfs))
		ldebugfs_remove(&lod->lod_debugfs);

	if (obd->obd_proc_entry) {
		lprocfs_remove(&obd->obd_proc_entry);
		obd->obd_proc_entry = NULL;
	}

	dt_tunables_fini(&lod->lod_dt_dev);
}

#endif /* CONFIG_PROC_FS */

