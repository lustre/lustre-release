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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
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
#include <lustre_param.h>

#ifdef LPROCFS
static int lod_rd_stripesize(char *page, char **start, off_t off, int count,
			     int *eof, void *data)
{
	struct obd_device *dev  = (struct obd_device *)data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, LPU64"\n",
			lod->lod_desc.ld_default_stripe_size);
}

static int lod_wr_stripesize(struct file *file, const char *buffer,
			     unsigned long count, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;
	__u64 val;
	int rc;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_write_u64_helper(buffer, count, &val);
	if (rc)
		return rc;

	lod_fix_desc_stripe_size(&val);
	lod->lod_desc.ld_default_stripe_size = val;
	return count;
}

static int lod_rd_stripeoffset(char *page, char **start, off_t off, int count,
			       int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, LPU64"\n",
			lod->lod_desc.ld_default_stripe_offset);
}

static int lod_wr_stripeoffset(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;
	__u64 val;
	int rc;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_write_u64_helper(buffer, count, &val);
	if (rc)
		return rc;

	lod->lod_desc.ld_default_stripe_offset = val;
	return count;
}

static int lod_rd_stripetype(char *page, char **start, off_t off, int count,
			     int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%u\n", lod->lod_desc.ld_pattern);
}

static int lod_wr_stripetype(struct file *file, const char *buffer,
			     unsigned long count, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;
	int val, rc;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	lod_fix_desc_pattern(&val);
	lod->lod_desc.ld_pattern = val;
	return count;
}

static int lod_rd_stripecount(char *page, char **start, off_t off, int count,
			      int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%d\n",
			(__s16)(lod->lod_desc.ld_default_stripe_count + 1) - 1);
}

static int lod_wr_stripecount(struct file *file, const char *buffer,
			      unsigned long count, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;
	int val, rc;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	lod_fix_desc_stripe_count(&val);
	lod->lod_desc.ld_default_stripe_count = val;
	return count;
}

static int lod_rd_numobd(char *page, char **start, off_t off, int count,
			 int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device*)data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%u\n", lod->lod_desc.ld_tgt_count);

}

static int lod_rd_activeobd(char *page, char **start, off_t off, int count,
			    int *eof, void *data)
{
	struct obd_device* dev = (struct obd_device*)data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%u\n",
			lod->lod_desc.ld_active_tgt_count);
}

static int lod_rd_desc_uuid(char *page, char **start, off_t off, int count,
			    int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device*) data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod  = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%s\n", lod->lod_desc.ld_uuid.uuid);
}

/* free priority (0-255): how badly user wants to choose empty osts */
static int lod_rd_qos_priofree(char *page, char **start, off_t off, int count,
			       int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device*) data;
	struct lod_device *lod = lu2lod_dev(dev->obd_lu_dev);

	LASSERT(lod != NULL);
	*eof = 1;
	return snprintf(page, count, "%d%%\n",
			(lod->lod_qos.lq_prio_free * 100 + 255) >> 8);
}

static int lod_wr_qos_priofree(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;
	int val, rc;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 100)
		return -EINVAL;
	lod->lod_qos.lq_prio_free = (val << 8) / 100;
	lod->lod_qos.lq_dirty = 1;
	lod->lod_qos.lq_reset = 1;
	return count;
}

static int lod_rd_qos_thresholdrr(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device*) data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%d%%\n",
			(lod->lod_qos.lq_threshold_rr * 100 + 255) >> 8);
}

static int lod_wr_qos_thresholdrr(struct file *file, const char *buffer,
				  unsigned long count, void *data)
{
	struct obd_device *dev = (struct obd_device *)data;
	struct lod_device *lod;
	int val, rc;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 100 || val < 0)
		return -EINVAL;

	lod->lod_qos.lq_threshold_rr = (val << 8) / 100;
	lod->lod_qos.lq_dirty = 1;
	return count;
}

static int lod_rd_qos_maxage(char *page, char **start, off_t off, int count,
			     int *eof, void *data)
{
	struct obd_device *dev = (struct obd_device*) data;
	struct lod_device *lod;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);
	*eof = 1;
	return snprintf(page, count, "%u Sec\n", lod->lod_desc.ld_qos_maxage);
}

static int lod_wr_qos_maxage(struct file *file, const char *buffer,
			     unsigned long count, void *data)
{
	struct obd_device	*dev = (struct obd_device *)data;
	struct lustre_cfg_bufs	 bufs;
	struct lod_device	*lod;
	struct lu_device	*next;
	struct lustre_cfg	*lcfg;
	char			 str[32];
	int			 val, rc, i;

	LASSERT(dev != NULL);
	lod = lu2lod_dev(dev->obd_lu_dev);

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val <= 0)
		return -EINVAL;
	lod->lod_desc.ld_qos_maxage = val;

	/*
	 * propogate the value down to OSPs
	 */
	lustre_cfg_bufs_reset(&bufs, NULL);
	sprintf(str, "%smaxage=%d", PARAM_OSP, val);
	lustre_cfg_bufs_set_string(&bufs, 1, str);
	lcfg = lustre_cfg_new(LCFG_PARAM, &bufs);
	lod_getref(&lod->lod_ost_descs);
	lod_foreach_ost(lod, i) {
		next = &OST_TGT(lod,i)->ltd_ost->dd_lu_dev;
		rc = next->ld_ops->ldo_process_config(NULL, next, lcfg);
		if (rc)
			CERROR("can't set maxage on #%d: %d\n", i, rc);
	}
	lod_putref(lod, &lod->lod_ost_descs);
	lustre_cfg_free(lcfg);

	return count;
}

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

	return seq_printf(p, "%d: %s %sACTIVE\n", idx,
			  obd_uuid2str(&ost_desc->ltd_uuid),
			  active ? "" : "IN");
}

static const struct seq_operations lod_osts_sops = {
	.start	= lod_osts_seq_start,
	.stop	= lod_osts_seq_stop,
	.next	= lod_osts_seq_next,
	.show	= lod_osts_seq_show,
};

static int lod_osts_seq_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry *dp = PDE(inode);
	struct seq_file *seq;
	int rc;

	LPROCFS_ENTRY_AND_CHECK(dp);
	rc = seq_open(file, &lod_osts_sops);
	if (rc) {
		LPROCFS_EXIT();
		return rc;
	}

	seq = file->private_data;
	seq->private = dp->data;
	return 0;
}

static struct lprocfs_vars lprocfs_lod_obd_vars[] = {
	{ "uuid",         lprocfs_rd_uuid,        0, 0 },
	{ "stripesize",   lod_rd_stripesize,      lod_wr_stripesize, 0 },
	{ "stripeoffset", lod_rd_stripeoffset,    lod_wr_stripeoffset, 0 },
	{ "stripecount",  lod_rd_stripecount,     lod_wr_stripecount, 0 },
	{ "stripetype",   lod_rd_stripetype,      lod_wr_stripetype, 0 },
	{ "numobd",       lod_rd_numobd,          0, 0 },
	{ "activeobd",    lod_rd_activeobd,       0, 0 },
	{ "desc_uuid",    lod_rd_desc_uuid,       0, 0 },
	{ "qos_prio_free",lod_rd_qos_priofree,    lod_wr_qos_priofree, 0 },
	{ "qos_threshold_rr",  lod_rd_qos_thresholdrr, lod_wr_qos_thresholdrr, 0 },
	{ "qos_maxage",   lod_rd_qos_maxage,      lod_wr_qos_maxage, 0 },
	{ 0 }
};

static struct lprocfs_vars lprocfs_lod_osd_vars[] = {
	{ "blocksize",    lprocfs_dt_rd_blksize, 0, 0 },
	{ "kbytestotal",  lprocfs_dt_rd_kbytestotal, 0, 0 },
	{ "kbytesfree",   lprocfs_dt_rd_kbytesfree, 0, 0 },
	{ "kbytesavail",  lprocfs_dt_rd_kbytesavail, 0, 0 },
	{ "filestotal",   lprocfs_dt_rd_filestotal, 0, 0 },
	{ "filesfree",    lprocfs_dt_rd_filesfree, 0, 0 },
	{ 0 }
};

static struct lprocfs_vars lprocfs_lod_module_vars[] = {
	{ "num_refs",     lprocfs_rd_numrefs,     0, 0 },
	{ 0 }
};

void lprocfs_lod_init_vars(struct lprocfs_static_vars *lvars)
{
	lvars->module_vars	= lprocfs_lod_module_vars;
	lvars->obd_vars		= lprocfs_lod_obd_vars;
}

static const struct file_operations lod_proc_target_fops = {
	.owner   = THIS_MODULE,
	.open    = lod_osts_seq_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = lprocfs_seq_release,
};

int lod_procfs_init(struct lod_device *lod)
{
	struct obd_device *obd = lod2obd(lod);
	struct lprocfs_static_vars lvars;
	cfs_proc_dir_entry_t *lov_proc_dir;
	int rc;

	lprocfs_lod_init_vars(&lvars);
	rc = lprocfs_obd_setup(obd, lvars.obd_vars);
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

	/* for compatibility we link old procfs's OSC entries to osp ones */
	lov_proc_dir = lprocfs_srch(proc_lustre_root, "lov");
	if (lov_proc_dir != NULL && strstr(obd->obd_name, "lov") != NULL)
		lod->lod_symlink = lprocfs_add_symlink(obd->obd_name,
						       lov_proc_dir,
						       "../lod/%s",
						       obd->obd_name);

	RETURN(0);

out:
	lprocfs_obd_cleanup(obd);

	return rc;
}

void lod_procfs_fini(struct lod_device *lod)
{
	struct obd_device *obd = lod2obd(lod);

	if (lod->lod_symlink != NULL)
		lprocfs_remove(&lod->lod_symlink);

	if (lod->lod_pool_proc_entry != NULL) {
		lprocfs_remove(&lod->lod_pool_proc_entry);
		lod->lod_pool_proc_entry = NULL;
	}

	lprocfs_obd_cleanup(obd);
}

#endif /* LPROCFS */

