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
 * Show DoM default stripe size.
 */
static ssize_t dom_stripesize_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return snprintf(buf, PAGE_SIZE, "%u\n", lod->lod_dom_max_stripesize);
}

/**
 * Set DoM default stripe size.
 */
static ssize_t dom_stripesize_store(struct kobject *kobj,
				    struct attribute *attr, const char *buffer,
				    size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc < 0)
		return rc;

	/* 1GB is the limit */
	if (val > (1ULL << 30))
		return -ERANGE;

	if (val > 0) {
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

LUSTRE_RW_ATTR(dom_stripesize);

static ssize_t stripesize_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return snprintf(buf, PAGE_SIZE, "%llu\n",
			lod->lod_ost_descs.ltd_lov_desc.ld_default_stripe_size);
}

static ssize_t stripesize_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc < 0)
		return rc;

	lod_fix_desc_stripe_size(&val);
	lod->lod_ost_descs.ltd_lov_desc.ld_default_stripe_size = val;

	return count;
}

LUSTRE_RW_ATTR(stripesize);

/**
 * Show default stripe offset.
 */
static ssize_t stripeoffset_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return snprintf(buf, PAGE_SIZE, "%lld\n",
		lod->lod_ost_descs.ltd_lov_desc.ld_default_stripe_offset);
}

/**
 * Set default stripe offset.
 *
 * Usually contains -1 allowing Lustre to balance objects among OST
 * otherwise may cause severe OST imbalance.
 */
static ssize_t stripeoffset_store(struct kobject *kobj,
				    struct attribute *attr,
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

	lod->lod_ost_descs.ltd_lov_desc.ld_default_stripe_offset = val;

	return count;
}

LUSTRE_RW_ATTR(stripeoffset);

/**
 * Show default striping pattern (LOV_PATTERN_*).
 */
static ssize_t __stripetype_show(struct kobject *kobj, struct attribute *attr,
				 char *buf, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	return snprintf(buf, PAGE_SIZE, "%u\n", ltd->ltd_lov_desc.ld_pattern);
}

static ssize_t mdt_stripetype_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	return __stripetype_show(kobj, attr, buf, true);
}

static ssize_t stripetype_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	return __stripetype_show(kobj, attr, buf, false);
}

/**
 * Set default striping pattern (a number, not a human-readable string).
 */
static ssize_t __stripetype_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;
	u32 pattern;
	int rc;

	rc = kstrtouint(buffer, 0, &pattern);
	if (rc)
		return rc;

	if (is_mdt)
		lod_fix_lmv_desc_pattern(&pattern);
	else
		lod_fix_desc_pattern(&pattern);

	ltd->ltd_lov_desc.ld_pattern = pattern;

	return count;
}

static ssize_t mdt_stripetype_store(struct kobject *kobj,
				    struct attribute *attr, const char *buffer,
				    size_t count)
{
	return __stripetype_store(kobj, attr, buffer, count, true);
}

static ssize_t stripetype_store(struct kobject *kobj,
				    struct attribute *attr, const char *buffer,
				    size_t count)
{
	return __stripetype_store(kobj, attr, buffer, count, false);
}

LUSTRE_RW_ATTR(mdt_stripetype);
LUSTRE_RW_ATTR(stripetype);

/**
 * Show default number of stripes.
 */
static ssize_t __stripecount_show(struct kobject *kobj, struct attribute *attr,
				  char *buf, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lov_desc *desc = is_mdt ? &lod->lod_mdt_descs.ltd_lov_desc :
					 &lod->lod_ost_descs.ltd_lov_desc;

	return snprintf(buf, PAGE_SIZE, "%d\n",
		      (s16)(desc->ld_default_stripe_count + 1) - 1);
}

static ssize_t mdt_stripecount_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	return __stripecount_show(kobj, attr, buf, true);
}

static ssize_t stripecount_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	return __stripecount_show(kobj, attr, buf, false);
}

/**
 * Set default number of stripes.
 */
static ssize_t __stripecount_store(struct kobject *kobj, struct attribute *attr,
				   const char *buffer, size_t count,
				   bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;
	int stripe_count;
	int rc;

	rc = kstrtoint(buffer, 0, &stripe_count);
	if (rc)
		return rc;

	if (stripe_count < -1)
		return -ERANGE;

	lod_fix_desc_stripe_count(&stripe_count);
	ltd->ltd_lov_desc.ld_default_stripe_count = stripe_count;

	return count;
}

static ssize_t mdt_stripecount_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	return __stripecount_store(kobj, attr, buffer, count, true);
}

static ssize_t stripecount_store(struct kobject *kobj,
				 struct attribute *attr,
				 const char *buffer, size_t count)
{
	return __stripecount_store(kobj, attr, buffer, count, false);
}

LUSTRE_RW_ATTR(mdt_stripecount);
LUSTRE_RW_ATTR(stripecount);

/**
 * Show number of targets.
 */
static ssize_t __numobd_show(struct kobject *kobj, struct attribute *attr,
			     char *buf, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	return snprintf(buf, PAGE_SIZE, "%u\n", ltd->ltd_lov_desc.ld_tgt_count);
}

static ssize_t mdt_numobd_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	return __numobd_show(kobj, attr, buf, true);
}

static ssize_t numobd_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	return __numobd_show(kobj, attr, buf, false);
}

LUSTRE_RO_ATTR(mdt_numobd);
LUSTRE_RO_ATTR(numobd);

/**
 * Show number of active targets.
 */
static ssize_t __activeobd_show(struct kobject *kobj, struct attribute *attr,
				char *buf, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	return snprintf(buf, PAGE_SIZE, "%u\n",
			ltd->ltd_lov_desc.ld_active_tgt_count);
}

static ssize_t mdt_activeobd_show(struct kobject *kobj, struct attribute *attr,
				  char *buf)
{
	return __activeobd_show(kobj, attr, buf, true);
}

static ssize_t activeobd_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	return __activeobd_show(kobj, attr, buf, false);
}

LUSTRE_RO_ATTR(mdt_activeobd);
LUSTRE_RO_ATTR(activeobd);

/**
 * Show UUID of LOD device.
 */
static ssize_t desc_uuid_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return snprintf(buf, PAGE_SIZE, "%s\n",
		       lod->lod_ost_descs.ltd_lov_desc.ld_uuid.uuid);
}
LUSTRE_RO_ATTR(desc_uuid);

/**
 * Show QoS priority parameter.
 *
 * The printed value is a percentage value (0-100%) indicating the priority
 * of free space compared to performance. 0% means select OSTs equally
 * regardless of their free space, 100% means select OSTs only by their free
 * space even if it results in very imbalanced load on the OSTs.
 */
static ssize_t __qos_prio_free_show(struct kobject *kobj,
				    struct attribute *attr, char *buf,
				    bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	return snprintf(buf, PAGE_SIZE, "%d%%\n",
		       (ltd->ltd_qos.lq_prio_free * 100 + 255) >> 8);
}

static ssize_t mdt_qos_prio_free_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	return __qos_prio_free_show(kobj, attr, buf, true);
}

static ssize_t qos_prio_free_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
{
	return __qos_prio_free_show(kobj, attr, buf, false);
}

/**
 * Set QoS free space priority parameter.
 *
 * Set the relative priority of free OST space compared to OST load when OSTs
 * are space imbalanced.  See qos_priofree_show() for description of
 * this parameter.  See qos_threshold_rr_store() and lq_threshold_rr to
 * determine what constitutes "space imbalanced" OSTs.
 */
static ssize_t __qos_prio_free_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count,
				     bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val > 100)
		return -EINVAL;
	ltd->ltd_qos.lq_prio_free = (val << 8) / 100;
	ltd->ltd_qos.lq_dirty = 1;
	ltd->ltd_qos.lq_reset = 1;

	return count;
}

static ssize_t mdt_qos_prio_free_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	return __qos_prio_free_store(kobj, attr, buffer, count, true);
}

static ssize_t qos_prio_free_store(struct kobject *kobj, struct attribute *attr,
				   const char *buffer, size_t count)
{
	return __qos_prio_free_store(kobj, attr, buffer, count, false);
}

LUSTRE_RW_ATTR(mdt_qos_prio_free);
LUSTRE_RW_ATTR(qos_prio_free);

/**
 * Show threshold for "same space on all OSTs" rule.
 */
static ssize_t __qos_threshold_rr_show(struct kobject *kobj,
				       struct attribute *attr, char *buf,
				       bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	return snprintf(buf, PAGE_SIZE, "%d%%\n",
		       (ltd->ltd_qos.lq_threshold_rr * 100 + 255) >> 8);
}

static ssize_t mdt_qos_threshold_rr_show(struct kobject *kobj,
					 struct attribute *attr, char *buf)
{
	return __qos_threshold_rr_show(kobj, attr, buf, true);
}

static ssize_t qos_threshold_rr_show(struct kobject *kobj,
				     struct attribute *attr, char *buf)
{
	return __qos_threshold_rr_show(kobj, attr, buf, false);
}

/**
 * Set threshold for "same space on all OSTs" rule.
 *
 * This sets the maximum percentage difference of free space between the most
 * full and most empty OST in the currently available OSTs. If this percentage
 * is exceeded, use the QoS allocator to select OSTs based on their available
 * space so that more full OSTs are chosen less often, otherwise use the
 * round-robin allocator for efficiency and performance.
 */
static ssize_t __qos_threshold_rr_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer, size_t count,
					bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;
	char buf[6], *tmp;
	unsigned int val;
	int rc;

	/* "100%\n\0" should be largest string */
	if (count >= sizeof(buf))
		return -ERANGE;

	strncpy(buf, buffer, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
	tmp = strchr(buf, '%');
	if (tmp)
		*tmp = '\0';

	rc = kstrtouint(buf, 0, &val);
	if (rc)
		return rc;

	if (val > 100)
		return -EINVAL;
	ltd->ltd_qos.lq_threshold_rr = (val << 8) / 100;
	ltd->ltd_qos.lq_dirty = 1;

	return count;
}

static ssize_t mdt_qos_threshold_rr_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer, size_t count)
{
	return __qos_threshold_rr_store(kobj, attr, buffer, count, true);
}

static ssize_t qos_threshold_rr_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	return __qos_threshold_rr_store(kobj, attr, buffer, count, false);
}

LUSTRE_RW_ATTR(mdt_qos_threshold_rr);
LUSTRE_RW_ATTR(qos_threshold_rr);

/**
 * Show expiration period used to refresh cached statfs data, which
 * is used to implement QoS/RR striping allocation algorithm.
 */
static ssize_t __qos_maxage_show(struct kobject *kobj, struct attribute *attr,
				 char *buf, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	return snprintf(buf, PAGE_SIZE, "%u Sec\n",
		       ltd->ltd_lov_desc.ld_qos_maxage);
}

static ssize_t mdt_qos_maxage_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	return __qos_maxage_show(kobj, attr, buf, true);
}

static ssize_t qos_maxage_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	return __qos_maxage_show(kobj, attr, buf, true);
}

/**
 * Set expiration period used to refresh cached statfs data.
 */
static ssize_t __qos_maxage_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count, bool is_mdt)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;
	struct lustre_cfg_bufs bufs;
	struct lu_device *next;
	struct lustre_cfg *lcfg;
	char str[32];
	struct lu_tgt_desc *tgt;
	int rc;
	u32 val;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val <= 0)
		return -EINVAL;

	ltd->ltd_lov_desc.ld_qos_maxage = val;

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

	lod_getref(ltd);
	ltd_foreach_tgt(ltd, tgt) {
		next = &tgt->ltd_tgt->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(NULL, next, lcfg);
		if (rc)
			CERROR("can't set maxage on #%d: %d\n",
			       tgt->ltd_index, rc);
	}
	lod_putref(lod, ltd);
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));

	return count;
}

static ssize_t mdt_qos_maxage_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buffer, size_t count)
{
	return __qos_maxage_store(kobj, attr, buffer, count, true);
}

static ssize_t qos_maxage_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	return __qos_maxage_store(kobj, attr, buffer, count, false);
}

LUSTRE_RW_ATTR(mdt_qos_maxage);
LUSTRE_RW_ATTR(qos_maxage);

static void *lod_tgts_seq_start(struct seq_file *p, loff_t *pos, bool is_mdt)
{
	struct obd_device *obd = p->private;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	LASSERT(obd != NULL);

	lod_getref(ltd); /* released in lod_tgts_seq_stop */
	if (*pos >= ltd->ltd_tgt_bitmap->size)
		return NULL;

	*pos = find_next_bit(ltd->ltd_tgt_bitmap->data,
			     ltd->ltd_tgt_bitmap->size, *pos);
	if (*pos < ltd->ltd_tgt_bitmap->size)
		return LTD_TGT(ltd, *pos);
	else
		return NULL;
}

static void *lod_mdts_seq_start(struct seq_file *p, loff_t *pos)
{
	return lod_tgts_seq_start(p, pos, true);
}

static void *lod_osts_seq_start(struct seq_file *p, loff_t *pos)
{
	return lod_tgts_seq_start(p, pos, false);
}

static void lod_tgts_seq_stop(struct seq_file *p, void *v, bool is_mdt)
{
	struct obd_device *obd = p->private;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	LASSERT(obd != NULL);
	lod_putref(lod, ltd);
}

static void lod_mdts_seq_stop(struct seq_file *p, void *v)
{
	lod_tgts_seq_stop(p, v, true);
}

static void lod_osts_seq_stop(struct seq_file *p, void *v)
{
	lod_tgts_seq_stop(p, v, false);
}

static void *lod_tgts_seq_next(struct seq_file *p, void *v, loff_t *pos,
			       bool is_mdt)
{
	struct obd_device *obd = p->private;
	struct lod_device *lod = lu2lod_dev(obd->obd_lu_dev);
	struct lu_tgt_descs *ltd = is_mdt ? &lod->lod_mdt_descs :
					    &lod->lod_ost_descs;

	if (*pos >= ltd->ltd_tgt_bitmap->size - 1)
		return NULL;

	*pos = find_next_bit(ltd->ltd_tgt_bitmap->data,
			     ltd->ltd_tgt_bitmap->size, *pos + 1);
	if (*pos < ltd->ltd_tgt_bitmap->size)
		return LTD_TGT(ltd, *pos);
	else
		return NULL;
}

static void *lod_mdts_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	return lod_tgts_seq_next(p, v, pos, true);
}

static void *lod_osts_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	return lod_tgts_seq_next(p, v, pos, false);
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
static int lod_tgts_seq_show(struct seq_file *p, void *v)
{
	struct obd_device *obd = p->private;
	struct lu_tgt_desc *tgt = v;
	struct dt_device *next;
	int rc, active;

	LASSERT(obd->obd_lu_dev);

	next = tgt->ltd_tgt;
	if (!next)
		return -EINVAL;

	/* XXX: should be non-NULL env, but it's very expensive */
	active = 1;
	rc = dt_statfs(NULL, next, &tgt->ltd_statfs);
	if (rc == -ENOTCONN) {
		active = 0;
		rc = 0;
	} else if (rc)
		return rc;

	seq_printf(p, "%d: %s %sACTIVE\n", tgt->ltd_index,
		   obd_uuid2str(&tgt->ltd_uuid),
		   active ? "" : "IN");
	return 0;
}

static const struct seq_operations lod_mdts_sops = {
	.start	= lod_mdts_seq_start,
	.stop	= lod_mdts_seq_stop,
	.next	= lod_mdts_seq_next,
	.show	= lod_tgts_seq_show,
};

static const struct seq_operations lod_osts_sops = {
	.start	= lod_osts_seq_start,
	.stop	= lod_osts_seq_stop,
	.next	= lod_osts_seq_next,
	.show	= lod_tgts_seq_show,
};

static int lod_mdts_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file *seq;
	int rc;

	rc = seq_open(file, &lod_mdts_sops);
	if (rc)
		return rc;

	seq = file->private_data;
	seq->private = PDE_DATA(inode);
	return 0;
}

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
 */
static ssize_t lmv_failout_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return snprintf(buf, PAGE_SIZE, "%d\n", lod->lod_lmv_failout ? 1 : 0);
}

/**
 * Enable/disable a special failout mode for testing.
 *
 * This determines whether the LMV will try to continue processing a striped
 * directory even if it has a (partly) corrupted entry in the master directory,
 * or if it will abort upon finding a corrupted slave directory entry.
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
	{ NULL }
};

static const struct file_operations lod_proc_mdt_fops = {
	.owner   = THIS_MODULE,
	.open    = lod_mdts_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lprocfs_seq_release,
};

static const struct file_operations lod_proc_target_fops = {
	.owner   = THIS_MODULE,
	.open    = lod_osts_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lprocfs_seq_release,
};

static struct attribute *lod_attrs[] = {
	&lustre_attr_dom_stripesize.attr,
	&lustre_attr_stripesize.attr,
	&lustre_attr_stripeoffset.attr,
	&lustre_attr_stripecount.attr,
	&lustre_attr_stripetype.attr,
	&lustre_attr_activeobd.attr,
	&lustre_attr_desc_uuid.attr,
	&lustre_attr_lmv_failout.attr,
	&lustre_attr_numobd.attr,
	&lustre_attr_qos_maxage.attr,
	&lustre_attr_qos_prio_free.attr,
	&lustre_attr_qos_threshold_rr.attr,
	&lustre_attr_mdt_stripecount.attr,
	&lustre_attr_mdt_stripetype.attr,
	&lustre_attr_mdt_activeobd.attr,
	&lustre_attr_mdt_numobd.attr,
	&lustre_attr_mdt_qos_maxage.attr,
	&lustre_attr_mdt_qos_prio_free.attr,
	&lustre_attr_mdt_qos_threshold_rr.attr,
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
	struct lprocfs_vars ldebugfs_obd_vars[] = { { NULL } };
	struct obd_device *obd = lod2obd(lod);
	struct obd_type *type;
	struct kobject *lov;
	int rc;

	lod->lod_dt_dev.dd_ktype.default_attrs = lod_attrs;
	rc = dt_tunables_init(&lod->lod_dt_dev, obd->obd_type, obd->obd_name,
			      ldebugfs_obd_vars);
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

	rc = lprocfs_seq_create(obd->obd_proc_entry, "mdt_obd",
				0444, &lod_proc_mdt_fops, obd);
	if (rc) {
		CWARN("%s: Error adding the target_obd file %d\n",
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
	if (!lov) {
		CERROR("%s: lov subsystem not found\n", obd->obd_name);
		GOTO(out, rc = -ENODEV);
	}

	rc = sysfs_create_link(lov, &lod->lod_dt_dev.dd_kobj,
			       obd->obd_name);
	if (rc)
		CERROR("%s: failed to create LOV sysfs symlink\n",
		       obd->obd_name);
	kobject_put(lov);

	lod->lod_debugfs = ldebugfs_add_symlink(obd->obd_name, "lov",
						"../lod/%s", obd->obd_name);
	if (!lod->lod_debugfs)
		CERROR("%s: failed to create LOV debugfs symlink\n",
		       obd->obd_name);

	type = container_of(lov, struct obd_type, typ_kobj);
	if (!type->typ_procroot)
		RETURN(0);

	/* for compatibility we link old procfs's LOV entries to lod ones */
	lod->lod_symlink = lprocfs_add_symlink(obd->obd_name,
					       type->typ_procroot,
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

	debugfs_remove_recursive(lod->lod_debugfs);

	if (obd->obd_proc_entry) {
		lprocfs_remove(&obd->obd_proc_entry);
		obd->obd_proc_entry = NULL;
	}

	dt_tunables_fini(&lod->lod_dt_dev);
}

#endif /* CONFIG_PROC_FS */
