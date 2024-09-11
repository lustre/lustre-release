// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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

static ssize_t dom_stripesize_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 lod->lod_dom_stripesize_max_kb << 10);
}

static inline int dom_stripesize_max_kb_update(struct lod_device *lod,
					       __u64 val)
{
	/* 1GB is the limit */
	if (val > (1ULL << 20))
		return -ERANGE;

	if (val > 0) {
		if (val < LOD_DOM_MIN_SIZE_KB) {
			LCONSOLE_INFO("Increasing provided stripe size to a minimum value %u\n",
				      LOD_DOM_MIN_SIZE_KB);
			val = LOD_DOM_MIN_SIZE_KB;
		} else if (val & (LOD_DOM_MIN_SIZE_KB - 1)) {
			val &= ~(LOD_DOM_MIN_SIZE_KB - 1);
			LCONSOLE_WARN("Changing provided stripe size to %llu (a multiple of minimum %u)\n",
				      val, LOD_DOM_MIN_SIZE_KB);
		}
	}
	spin_lock(&lod->lod_lsfs_lock);
	lod->lod_dom_stripesize_max_kb = val;
	lod_dom_stripesize_recalc(lod);
	spin_unlock(&lod->lod_lsfs_lock);
	return 0;
}

static ssize_t dom_stripesize_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc < 0)
		return rc;

	rc = dom_stripesize_max_kb_update(lod, val >> 10);
	if (rc)
		return rc;
	return count;
}

/* Old attribute name is still supported */
LUSTRE_RW_ATTR(dom_stripesize);

/**
 * Show DoM maximum allowed stripe size.
 */
static ssize_t dom_stripesize_max_kb_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 lod->lod_dom_stripesize_max_kb);
}

/**
 * Set DoM maximum allowed stripe size.
 */
static ssize_t dom_stripesize_max_kb_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "KiB");
	if (rc < 0)
		return rc;

	rc = dom_stripesize_max_kb_update(lod, val >> 10);
	if (rc)
		return rc;
	return count;
}
LUSTRE_RW_ATTR(dom_stripesize_max_kb);

/**
 * Show DoM default stripe size.
 */
static ssize_t dom_stripesize_cur_kb_show(struct kobject *kobj,
					  struct attribute *attr,
					  char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 lod->lod_dom_stripesize_cur_kb);
}

LUSTRE_RO_ATTR(dom_stripesize_cur_kb);

/**
 * Show DoM threshold.
 */
static ssize_t dom_threshold_free_mb_show(struct kobject *kobj,
					  struct attribute *attr, char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%llu\n",
			 lod->lod_dom_threshold_free_mb);
}

/**
 * Set DoM default stripe size.
 */
static ssize_t dom_threshold_free_mb_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	u64 val;
	int rc;

	rc = sysfs_memparse_total(buffer, count, &val,
				  lod->lod_lsfs_total_mb << 20, "MiB");
	if (rc < 0)
		return rc;

	val >>= 20;
	spin_lock(&lod->lod_lsfs_lock);
	lod->lod_dom_threshold_free_mb = val;
	lod_dom_stripesize_recalc(lod);
	spin_unlock(&lod->lod_lsfs_lock);

	return count;
}

LUSTRE_RW_ATTR(dom_threshold_free_mb);

static ssize_t stripesize_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%llu\n",
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

	return scnprintf(buf, PAGE_SIZE, "%lld\n",
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

static ssize_t max_stripecount_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%u\n", lod->lod_max_stripecount);
}

static ssize_t max_stripecount_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	long val;
	int rc;

	rc = kstrtol(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 0 || val > LOV_MAX_STRIPE_COUNT)
		return -ERANGE;

	lod->lod_max_stripecount = val;

	return count;
}

LUSTRE_RW_ATTR(max_stripecount);

static ssize_t max_mdt_stripecount_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%u\n", lod->lod_max_mdt_stripecount);
}

static ssize_t max_mdt_stripecount_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	long val;
	int rc;

	rc = kstrtol(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 0 || val > LMV_MAX_STRIPE_COUNT) /* any limitation? */
		return -ERANGE;

	lod->lod_max_mdt_stripecount = val;

	return count;
}

LUSTRE_RW_ATTR(max_mdt_stripecount);

static ssize_t max_stripes_per_mdt_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%u\n", lod->lod_max_stripes_per_mdt);
}

static ssize_t max_stripes_per_mdt_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	long val;
	int rc;

	rc = kstrtol(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 1 || val > LMV_MAX_STRIPES_PER_MDT) /* any limitation? */
		return -ERANGE;

	lod->lod_max_stripes_per_mdt = val;

	return count;
}

LUSTRE_RW_ATTR(max_stripes_per_mdt);


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

	return scnprintf(buf, PAGE_SIZE, "%u\n", ltd->ltd_lov_desc.ld_pattern);
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

	return scnprintf(buf, PAGE_SIZE, "%d\n",
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

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 ltd->ltd_lov_desc.ld_tgt_count);
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

	return scnprintf(buf, PAGE_SIZE, "%u\n",
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

	return scnprintf(buf, PAGE_SIZE, "%s\n",
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

	return scnprintf(buf, PAGE_SIZE, "%d%%\n",
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

	ltd->ltd_qos.lq_prio_free = (val << 8) / 100;
	set_bit(LQ_DIRTY, &ltd->ltd_qos.lq_flags);
	set_bit(LQ_RESET, &ltd->ltd_qos.lq_flags);

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

	return scnprintf(buf, PAGE_SIZE, "%d%%\n",
			 (ltd->ltd_qos.lq_threshold_rr * 100 +
			  (QOS_THRESHOLD_MAX - 1)) / QOS_THRESHOLD_MAX);
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
	ltd->ltd_qos.lq_threshold_rr = (val * QOS_THRESHOLD_MAX) / 100;
	set_bit(LQ_DIRTY, &ltd->ltd_qos.lq_flags);

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

	return scnprintf(buf, PAGE_SIZE, "%u\n",
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
	if (*pos >= ltd->ltd_tgts_size)
		return NULL;

	*pos = find_next_bit(ltd->ltd_tgt_bitmap,
			     ltd->ltd_tgts_size, *pos);
	if (*pos < ltd->ltd_tgts_size)
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

	(*pos)++;
	if (*pos > ltd->ltd_tgts_size - 1)
		return NULL;

	*pos = find_next_bit(ltd->ltd_tgt_bitmap,
			     ltd->ltd_tgts_size, *pos);
	if (*pos < ltd->ltd_tgts_size)
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
	seq->private = pde_data(inode);
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
	seq->private = pde_data(inode);
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

	return scnprintf(buf, PAGE_SIZE, "%d\n", lod->lod_lmv_failout ? 1 : 0);
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

static ssize_t mdt_hash_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%s\n",
		mdt_hash_name[lod->lod_mdt_descs.ltd_lmv_desc.ld_pattern]);
}

static ssize_t mdt_hash_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device, dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);
	char *hash;
	int len;
	int rc = -EINVAL;
	int i;

	hash = kstrndup(buffer, count, GFP_KERNEL);
	if (!hash)
		return -ENOMEM;

	if (kstrtoint(hash, 10, &i) == 0 && lmv_is_known_hash_type(i)) {
		lod->lod_mdt_descs.ltd_lmv_desc.ld_pattern = i;
		GOTO(out, rc = count);
	}

	len = strcspn(hash, "\n ");
	hash[len] = '\0';
	for (i = LMV_HASH_TYPE_ALL_CHARS; i < ARRAY_SIZE(mdt_hash_name); i++) {
		if (strcmp(hash, mdt_hash_name[i]) == 0) {
			lod->lod_mdt_descs.ltd_lmv_desc.ld_pattern = i;
			GOTO(out, rc = count);
		}
	}
out:
	kfree(hash);

	return rc;
}
LUSTRE_RW_ATTR(mdt_hash);

static ssize_t dist_txn_check_space_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lod_device *lod = dt2lod_dev(dt);

	return scnprintf(buf, PAGE_SIZE, "%d\n", lod->lod_dist_txn_check_space);
}

static ssize_t dist_txn_check_space_store(struct kobject *kobj,
					  struct attribute *attr,
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

	lod->lod_dist_txn_check_space = val;

	return count;
}
LUSTRE_RW_ATTR(dist_txn_check_space);

static const struct proc_ops lod_proc_mdt_fops = {
	PROC_OWNER(THIS_MODULE)
	.proc_open	= lod_mdts_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= lprocfs_seq_release,
};

static int lod_spill_threshold_pct_seq_show(struct seq_file *m, void *v)
{
	struct lod_pool_desc *pool = m->private;

	LASSERT(pool != NULL);
	seq_printf(m, "%d\n", pool->pool_spill_threshold_pct);

	return 0;
}

static ssize_t
lod_spill_threshold_pct_seq_write(struct file *file, const char __user *buffer,
				  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lod_pool_desc *pool = m->private;
	int rc;
	int val;

	LASSERT(pool != NULL);

	rc = kstrtoint_from_user(buffer, count, 0, &val);
	if (rc)
		return rc;

	if (val > 100 || val < 0)
		return -EINVAL;

	pool->pool_spill_threshold_pct = val;
	pool->pool_spill_expire = 0;
	if (pool->pool_spill_threshold_pct == 0) {
		pool->pool_spill_is_active = false;
		pool->pool_spill_target[0] = '\0';
	}

	return count;
}
LPROC_SEQ_FOPS(lod_spill_threshold_pct);

static int lod_spill_target_seq_show(struct seq_file *m, void *v)
{
	struct lod_pool_desc *pool = m->private;

	LASSERT(pool != NULL);
	seq_printf(m, "%s\n", pool->pool_spill_target);

	return 0;
}

static DEFINE_MUTEX(lod_spill_loop_mutex);

static int lod_spill_check_loop(struct lod_device *lod,
				const char *pool,
				const char *destarg)
{
	char dest[LOV_MAXPOOLNAME + 1];
	struct lod_pool_desc *tgt;
	int rc = 0;

	strncpy(dest, destarg, sizeof(dest));

	/*
	 * pool1 -> pool2 -> pool3 ++> pool1
	 * pool1 -> pool2 ++>pool3 -> pool1
	 */
	while (1) {
		tgt = lod_pool_find(lod, dest);
		if (!tgt) {
			/* no more steps, we're fine */
			break;
		}

		strncpy(dest, tgt->pool_spill_target, sizeof(dest));
		lod_pool_putref(tgt);

		if (strcmp(dest, pool) == 0) {
			rc = -ELOOP;
			break;
		}
	}
	return rc;
}

static ssize_t
lod_spill_target_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lod_pool_desc *pool = m->private;
	struct lod_device *lod;
	char tgt_name[LOV_MAXPOOLNAME + 1];
	int rc;


	LASSERT(pool != NULL);
	lod = lu2lod_dev(pool->pool_lobd->obd_lu_dev);

	if (count == 0) {
		pool->pool_spill_target[0] = '\0';
		pool->pool_spill_is_active = false;
		return count;
	}

	if (count > sizeof(tgt_name) - 1)
		return -E2BIG;
	if (copy_from_user(tgt_name, buffer, count))
		return -EFAULT;
	tgt_name[count] = '\0';

	if (strcmp(pool->pool_name, tgt_name) == 0)
		return -ELOOP;
	if (!lod_pool_exists(lod, tgt_name)) {
		pool->pool_spill_target[0] = '\0';
		pool->pool_spill_expire = 0;
		return -ENODEV;
	}

	/* serialize all checks to protect against racing settings */
	mutex_lock(&lod_spill_loop_mutex);

	rc = lod_spill_check_loop(lod, pool->pool_name, tgt_name);
	if (rc == 0) {
		strncpy(pool->pool_spill_target, tgt_name,
			sizeof(pool->pool_spill_target));
		rc = count;
	}

	mutex_unlock(&lod_spill_loop_mutex);

	return rc;
}
LPROC_SEQ_FOPS(lod_spill_target);

static int lod_spill_is_active_seq_show(struct seq_file *m, void *v)
{
	struct lod_pool_desc *pool = m->private;
	struct lod_device *lod;
	struct lu_env env;
	int rc;

	if (!pool)
		return -ENODEV;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;

	lod = lu2lod_dev(pool->pool_lobd->obd_lu_dev);
	lod_spill_target_refresh(&env, lod, pool);
	lu_env_fini(&env);

	seq_printf(m, "%d\n", pool->pool_spill_is_active ? 1 : 0);

	return 0;
}
LPROC_SEQ_FOPS_RO(lod_spill_is_active);

static int lod_spill_hit_seq_show(struct seq_file *m, void *v)
{
	struct lod_pool_desc  *pool = m->private;

	LASSERT(pool != NULL);
	seq_printf(m, "%d\n", atomic_read(&pool->pool_spill_hit));
	return 0;
}
LPROC_SEQ_FOPS_RO(lod_spill_hit);

static int lod_spill_status_seq_show(struct seq_file *m, void *v)
{
	struct lod_pool_desc *pool = m->private;
	__u64 avail_bytes = 0, total_bytes = 0;
	struct lu_tgt_pool *osts;
	struct lod_device *lod;
	struct lu_env env;
	int rc, i;

	if (!pool)
		return -ENODEV;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;

	lod = lu2lod_dev(pool->pool_lobd->obd_lu_dev);

	osts = &(pool->pool_obds);
	for (i = 0; i < osts->op_count; i++) {
		int idx = osts->op_array[i];
		struct lod_tgt_desc *tgt;
		struct obd_statfs *sfs;

		if (!test_bit(idx, lod->lod_ost_bitmap))
			continue;
		tgt = OST_TGT(lod, idx);
		if (tgt->ltd_active == 0)
			continue;
		sfs = &tgt->ltd_statfs;

		avail_bytes += sfs->os_bavail * sfs->os_bsize;
		total_bytes += sfs->os_blocks * sfs->os_bsize;
		seq_printf(m, "%d: %llu %llu\n", idx,
			avail_bytes >> 10, total_bytes >> 10);
	}
	seq_printf(m, "total: %llu\navail: %llu\nusage: %llu\nusage%%: %llu\n"
		   "active: %s\nthreshold: %dexpire: %d\n",
		   total_bytes >> 10, avail_bytes >> 10,
		   (total_bytes - avail_bytes) >> 10,
		   (total_bytes * pool->pool_spill_threshold_pct / 100) >> 10,
		   pool->pool_spill_is_active ? "on" : "off",
		   pool->pool_spill_threshold_pct,
		   (int)(pool->pool_spill_expire - ktime_get_seconds()));
	lu_env_fini(&env);

	return 0;
}
LPROC_SEQ_FOPS_RO(lod_spill_status);

struct lprocfs_vars lprocfs_lod_spill_vars[] = {
	{ .name	=	"spill_threshold_pct",
	  .fops	=	&lod_spill_threshold_pct_fops },
	{ .name	=	"spill_target",
	  .fops	=	&lod_spill_target_fops },
	{ .name	=	"spill_is_active",
	  .fops	=	&lod_spill_is_active_fops },
	{ .name	=	"spill_hit",
	  .fops	=	&lod_spill_hit_fops },
	{ .name	=	"spill_status",
	  .fops	=	&lod_spill_status_fops },
	{ NULL }
};

static struct proc_ops lod_proc_target_fops = {
	PROC_OWNER(THIS_MODULE)
	.proc_open	= lod_osts_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= lprocfs_seq_release,
};

static struct attribute *lod_attrs[] = {
	&lustre_attr_dom_stripesize.attr,
	&lustre_attr_dom_stripesize_max_kb.attr,
	&lustre_attr_dom_stripesize_cur_kb.attr,
	&lustre_attr_dom_threshold_free_mb.attr,
	&lustre_attr_stripesize.attr,
	&lustre_attr_stripeoffset.attr,
	&lustre_attr_stripecount.attr,
	&lustre_attr_max_stripecount.attr,
	&lustre_attr_max_mdt_stripecount.attr,
	&lustre_attr_max_stripes_per_mdt.attr,
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
	&lustre_attr_mdt_hash.attr,
	&lustre_attr_dist_txn_check_space.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(lod); /* creates lod_groups from lod_attrs */

int lod_tgt_weights_seq_show(struct seq_file *m, struct lod_device *lod,
			     struct lu_tgt_pool *tgts, bool is_mdt)
{
	int i;

	if (!tgts->op_count)
		return 0;

	down_read(&tgts->op_rw_sem);
	for (i = 0; i < tgts->op_count; i++) {
		u32 *op_array = tgts->op_array;
		struct lod_tgt_desc *tgt = is_mdt ? MDT_TGT(lod, op_array[i]) :
						 OST_TGT(lod, op_array[i]);
		struct lu_svr_qos *svr = tgt->ltd_qos.ltq_svr;

		seq_printf(m, "- { %s: %d, tgt_weight: %llu, tgt_penalty: %llu, tgt_penalty_per_obj: %llu, tgt_avail: %llu, tgt_last_used: %llu, svr_nid: %s, svr_bavail: %llu, svr_iavail: %llu, svr_penalty: %llu, svr_penalty_per_obj: %llu, svr_last_used: %llu }\n",
			   is_mdt ? "mdt_idx" : "ost_idx", tgt->ltd_index,
			   tgt->ltd_qos.ltq_weight,
			   tgt->ltd_qos.ltq_penalty,
			   tgt->ltd_qos.ltq_penalty_per_obj,
			   tgt->ltd_qos.ltq_avail, tgt->ltd_qos.ltq_used,
			   svr->lsq_uuid.uuid, svr->lsq_bavail, svr->lsq_iavail,
			   svr->lsq_penalty, svr->lsq_penalty_per_obj,
			   svr->lsq_used);
	}
	up_read(&tgts->op_rw_sem);

	return 0;
}

int lod_tgt_weights_seq_write(struct seq_file *m, const char __user *buf,
			      size_t count, struct lod_device *lod,
			      struct lu_tgt_pool *tgts, bool is_mdt)
{
	int i;

	if (!tgts->op_count)
		return count;

	down_read(&tgts->op_rw_sem);
	down_write(&lod->lod_ost_descs.ltd_qos.lq_rw_sem);
	for (i = 0; i < tgts->op_count; i++) {
		u32 *op_array = tgts->op_array;
		struct lod_tgt_desc *tgt = is_mdt ? MDT_TGT(lod, op_array[i]) :
						 OST_TGT(lod, op_array[i]);

		tgt->ltd_qos.ltq_weight = 0;
		tgt->ltd_qos.ltq_penalty = 0;
		tgt->ltd_qos.ltq_svr->lsq_penalty = 0;
	}
	set_bit(LQ_DIRTY, &lod->lod_ost_descs.ltd_qos.lq_flags);
	up_write(&lod->lod_ost_descs.ltd_qos.lq_rw_sem);
	up_read(&tgts->op_rw_sem);

	return count;
}

static int lod_mdt_weights_seq_show(struct seq_file *m, void *data)
{
	struct lod_device *lod = m->private;
	struct lu_tgt_pool *tgts = &lod->lod_mdt_descs.ltd_tgt_pool;

	return lod_tgt_weights_seq_show(m, lod, tgts, true);
}

static ssize_t
lod_mdt_weights_seq_write(struct file *file, const char __user *buf,
		      size_t count, loff_t *off)
{

	struct seq_file *m = file->private_data;
	struct lod_device *lod = m->private;
	struct lu_tgt_pool *tgts = &lod->lod_mdt_descs.ltd_tgt_pool;

	return lod_tgt_weights_seq_write(m, buf, count, lod, tgts, true);
}
LDEBUGFS_SEQ_FOPS(lod_mdt_weights);

static int lod_ost_weights_seq_show(struct seq_file *m, void *data)
{
	struct lod_device *lod = m->private;
	struct lu_tgt_pool *tgts = &lod->lod_ost_descs.ltd_tgt_pool;

	return lod_tgt_weights_seq_show(m, lod, tgts, false);
}

static ssize_t
lod_ost_weights_seq_write(struct file *file, const char __user *buf,
		      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct lod_device *lod = m->private;
	struct lu_tgt_pool *tgts = &lod->lod_ost_descs.ltd_tgt_pool;

	return lod_tgt_weights_seq_write(m, buf, count, lod, tgts, false);
}
LDEBUGFS_SEQ_FOPS(lod_ost_weights);

static struct ldebugfs_vars ldebugfs_lod_vars[] = {
	{ .name	=	"qos_mdt_weights",
	  .fops	=	&lod_mdt_weights_fops,
	  .proc_mode =	0444 },
	{ .name	=	"qos_ost_weights",
	  .fops	=	&lod_ost_weights_fops,
	  .proc_mode =	0444 },
	{ 0 }
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
	struct obd_type *type;
	struct kobject *lov;
	int rc;

	lod->lod_dt_dev.dd_ktype.default_groups = KOBJ_ATTR_GROUPS(lod);
	rc = dt_tunables_init(&lod->lod_dt_dev, obd->obd_type, obd->obd_name,
			      NULL);
	if (rc) {
		CERROR("%s: failed to setup DT tunables: %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	obd->obd_proc_entry = lprocfs_register(obd->obd_name,
					       obd->obd_type->typ_procroot,
					       NULL, obd);
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
		CWARN("%s: Failed to create pools proc file: %d\n",
		      obd->obd_name, rc);
		GOTO(out, rc);
	}

	lod->lod_spill_proc_entry = lprocfs_register("pool",
						    obd->obd_proc_entry,
						    NULL, NULL);
	if (IS_ERR(lod->lod_spill_proc_entry)) {
		rc = PTR_ERR(lod->lod_spill_proc_entry);
		lod->lod_spill_proc_entry = NULL;
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

	obd->obd_debugfs_entry = debugfs_create_dir(obd->obd_name,
						    obd->obd_type->typ_debugfs_entry);


	ldebugfs_add_vars(obd->obd_debugfs_entry, ldebugfs_lod_vars, lod);

	lod->lod_debugfs = ldebugfs_add_symlink(obd->obd_name, "lov",
						"../lod/%s", obd->obd_name);
	if (!lod->lod_debugfs)
		CERROR("%s: failed to create LOV debugfs symlink\n",
		       obd->obd_name);

	lod->lod_pool_debugfs = debugfs_create_dir("pool",
						   obd->obd_debugfs_entry);

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

	debugfs_remove_recursive(lod->lod_pool_debugfs);
	debugfs_remove_recursive(lod->lod_debugfs);
	debugfs_remove_recursive(obd->obd_debugfs_entry);

	if (obd->obd_proc_entry) {
		lprocfs_remove(&obd->obd_proc_entry);
		obd->obd_proc_entry = NULL;
	}

	dt_tunables_fini(&lod->lod_dt_dev);
}

#endif /* CONFIG_PROC_FS */
