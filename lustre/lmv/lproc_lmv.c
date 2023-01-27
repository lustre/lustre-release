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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <lprocfs_status.h>
#include <obd_class.h>

#include "lmv_internal.h"

static ssize_t numobd_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n", obd->u.lmv.lmv_mdt_count);
}
LUSTRE_RO_ATTR(numobd);

static ssize_t activeobd_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
		obd->u.lmv.lmv_mdt_descs.ltd_lmv_desc.ld_active_tgt_count);
}
LUSTRE_RO_ATTR(activeobd);

static ssize_t desc_uuid_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%s\n",
			obd->u.lmv.lmv_mdt_descs.ltd_lmv_desc.ld_uuid.uuid);
}
LUSTRE_RO_ATTR(desc_uuid);

static ssize_t qos_maxage_show(struct kobject *kobj,
			       struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			obd->u.lmv.lmv_mdt_descs.ltd_lmv_desc.ld_qos_maxage);
}

static ssize_t qos_maxage_store(struct kobject *kobj,
				struct attribute *attr,
				const char *buffer,
				size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	obd->u.lmv.lmv_mdt_descs.ltd_lmv_desc.ld_qos_maxage = val;

	return count;
}
LUSTRE_RW_ATTR(qos_maxage);

static ssize_t qos_prio_free_show(struct kobject *kobj,
				  struct attribute *attr,
				  char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u%%\n",
			(obd->u.lmv.lmv_qos.lq_prio_free * 100 + 255) >> 8);
}

static ssize_t qos_prio_free_store(struct kobject *kobj,
				   struct attribute *attr,
				   const char *buffer,
				   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lmv_obd *lmv = &obd->u.lmv;
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

	lmv->lmv_qos.lq_prio_free = (val << 8) / 100;
	set_bit(LQ_DIRTY, &lmv->lmv_qos.lq_flags);
	set_bit(LQ_RESET, &lmv->lmv_qos.lq_flags);

	return count;
}
LUSTRE_RW_ATTR(qos_prio_free);

static ssize_t qos_threshold_rr_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u%%\n",
			(obd->u.lmv.lmv_qos.lq_threshold_rr * 100 +
			(QOS_THRESHOLD_MAX - 1)) / QOS_THRESHOLD_MAX);
}

static ssize_t qos_threshold_rr_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer,
				      size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lmv_obd *lmv = &obd->u.lmv;
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

	lmv->lmv_qos.lq_threshold_rr = (val * QOS_THRESHOLD_MAX) / 100;
	set_bit(LQ_DIRTY, &lmv->lmv_qos.lq_flags);

	return count;
}
LUSTRE_RW_ATTR(qos_threshold_rr);

#ifdef CONFIG_PROC_FS
static void *lmv_tgt_seq_start(struct seq_file *p, loff_t *pos)
{
	struct obd_device *obd = p->private;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lu_tgt_desc *tgt;

	while (*pos < lmv->lmv_mdt_descs.ltd_tgts_size) {
		tgt = lmv_tgt(lmv, (__u32)*pos);
		if (tgt)
			return tgt;

		++*pos;
	}

	return NULL;
}

static void lmv_tgt_seq_stop(struct seq_file *p, void *v)
{
}

static void *lmv_tgt_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct obd_device *obd = p->private;
	struct lmv_obd *lmv = &obd->u.lmv;
	struct lu_tgt_desc *tgt;

	++*pos;
	while (*pos < lmv->lmv_mdt_descs.ltd_tgts_size) {
		tgt = lmv_tgt(lmv, (__u32)*pos);
		if (tgt)
			return tgt;

		++*pos;
	}

	return NULL;
}

static int lmv_tgt_seq_show(struct seq_file *p, void *v)
{
	struct lmv_tgt_desc     *tgt = v;

	if (!tgt)
		return 0;

	seq_printf(p, "%u: %s %sACTIVE\n",
		   tgt->ltd_index, tgt->ltd_uuid.uuid,
		   tgt->ltd_active ? "" : "IN");
	return 0;
}

static const struct seq_operations lmv_tgt_sops = {
        .start                 = lmv_tgt_seq_start,
        .stop                  = lmv_tgt_seq_stop,
        .next                  = lmv_tgt_seq_next,
        .show                  = lmv_tgt_seq_show,
};

static int lmv_target_seq_open(struct inode *inode, struct file *file)
{
        struct seq_file         *seq;
        int                     rc;

        rc = seq_open(file, &lmv_tgt_sops);
        if (rc)
                return rc;

	seq = file->private_data;
	seq->private = pde_data(inode);
	return 0;
}

static const struct proc_ops lmv_proc_target_fops = {
	PROC_OWNER(THIS_MODULE)
	.proc_open	= lmv_target_seq_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= seq_release,
};
#endif /* CONFIG_PROC_FS */

static struct attribute *lmv_attrs[] = {
	&lustre_attr_activeobd.attr,
	&lustre_attr_desc_uuid.attr,
	&lustre_attr_numobd.attr,
	&lustre_attr_qos_maxage.attr,
	&lustre_attr_qos_prio_free.attr,
	&lustre_attr_qos_threshold_rr.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(lmv); /* creates lmv_groups */

int lmv_tunables_init(struct obd_device *obd)
{
	int rc;

	obd->obd_ktype.default_groups = KOBJ_ATTR_GROUPS(lmv);
	rc = lprocfs_obd_setup(obd, true);
	if (rc)
		goto out_failed;
#ifdef CONFIG_PROC_FS
	rc = lprocfs_alloc_md_stats(obd, 0);
	if (rc) {
		lprocfs_obd_cleanup(obd);
		goto out_failed;
	}

	rc = lprocfs_seq_create(obd->obd_proc_entry, "target_obd",
				0444, &lmv_proc_target_fops, obd);
	if (rc) {
		lprocfs_free_md_stats(obd);
		lprocfs_obd_cleanup(obd);
		CWARN("%s: error adding LMV target_obd file: rc = %d\n",
		      obd->obd_name, rc);
		rc = 0;
	}
#endif /* CONFIG_PROC_FS */
out_failed:
	return rc;
}
