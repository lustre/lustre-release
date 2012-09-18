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
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LQUOTA

#include <linux/version.h>
#include <lprocfs_status.h>
#include <obd.h>
#include <linux/seq_file.h>
#include <lustre_fsfilt.h>

#include "lquota_internal.h"
#include "quota_internal.h"

#ifdef LPROCFS
/* structure allocated at seq_open time and release when seq_release is called.
 * It is passed to seq_start/stop/next/show which can thus use the same lu_env
 * to be used with the iterator API */
struct lquota_procfs {
	struct dt_object	*lqp_obj;
	struct lu_env		 lqp_env;
};

/* global shared environment */
static void *lprocfs_quota_seq_start(struct seq_file *p, loff_t *pos)
{
	struct lquota_procfs	*lqp = p->private;
	const struct dt_it_ops	*iops;
	struct dt_it		*it;
	loff_t			 offset = *pos;
	int			 rc;

	LASSERT(lqp);

	if (offset == 0)
		return SEQ_START_TOKEN;
	offset--;

	if (lqp->lqp_obj == NULL)
		/* accounting not enabled. */
		return NULL;

	/* initialize iterator */
	iops = &lqp->lqp_obj->do_index_ops->dio_it;
	it = iops->init(&lqp->lqp_env, lqp->lqp_obj, 0, BYPASS_CAPA);
	if (IS_ERR(it)) {
		CERROR("%s: failed to initialize iterator: rc = %ld\n",
		       lqp->lqp_obj->do_lu.lo_dev->ld_obd->obd_name,
		       PTR_ERR(it));
		return NULL;
	}

	/* move on to the first valid record */
	rc = iops->load(&lqp->lqp_env, it, 0);
	if (rc < 0) { /* Error */
		goto not_found;
	} else if (rc == 0) {
		/*
		 * Iterator didn't find record with exactly the key requested.
		 *
		 * It is currently either
		 *
		 *     - positioned above record with key less than
		 *       requested - skip it.
		 *     - or not positioned at all (is in IAM_IT_SKEWED
		 *       state) - position it on the next item.
		 */
		rc = iops->next(&lqp->lqp_env, it);
		if (rc != 0)
			goto not_found;
	}
	while (offset--) {
		rc = iops->next(&lqp->lqp_env, it);
		if (rc != 0) /* Error or reach the end */
			goto not_found;
	}
	return it;

not_found:
	iops->put(&lqp->lqp_env, it);
	iops->fini(&lqp->lqp_env, it);
	return NULL;
}

static void lprocfs_quota_seq_stop(struct seq_file *p, void *v)
{
	struct lquota_procfs	*lqp = p->private;
	const struct dt_it_ops	*iops;
	struct dt_it		*it;

	if (lqp->lqp_obj == NULL || v == NULL || v == SEQ_START_TOKEN)
		return;

	iops = &lqp->lqp_obj->do_index_ops->dio_it;
	it = (struct dt_it *)v;
	/* if something wrong happened during ->seq_show, we need to release
	 * the iterator here */
	iops->put(&lqp->lqp_env, it);
	iops->fini(&lqp->lqp_env, it);
}

static void *lprocfs_quota_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct lquota_procfs	*lqp = p->private;
	const struct dt_it_ops	*iops;
	struct dt_it		*it;
	int			 rc;

	LASSERT(lqp);

	++*pos;
	if (lqp->lqp_obj == NULL)
		return NULL;

	if (v == SEQ_START_TOKEN)
		return lprocfs_quota_seq_start(p, pos);

	iops = &lqp->lqp_obj->do_index_ops->dio_it;
	it = (struct dt_it *)v;

	rc = iops->next(&lqp->lqp_env, it);
	if (rc == 0)
		return it;

	if (rc < 0)
		CERROR("%s: seq_next failed: rc = %d\n",
		       lqp->lqp_obj->do_lu.lo_dev->ld_obd->obd_name, rc);

	/* Reach the end or error */
	iops->put(&lqp->lqp_env, it);
	iops->fini(&lqp->lqp_env, it);
	return NULL;
}

/*
 * Output example:
 *
 * user_accounting:
 * - id:      0
 *   usage:   { inodes:                  209, bytes:             26161152 }
 * - id:      840000038
 *   usage:   { inodes:                    1, bytes:             10485760 }
 */
static int lprocfs_quota_seq_show(struct seq_file *p, void *v)
{
	struct lquota_procfs *lqp = p->private;
	const struct dt_it_ops *iops;
	struct dt_it           *it;
	struct dt_key          *key;
	struct acct_rec         rec;
	int                     rc;

	LASSERT(lqp);
	if (lqp->lqp_obj == NULL) {
		seq_printf(p, "not supported\n");
		return 0;
	}

	if (v == SEQ_START_TOKEN) {
		const struct lu_fid *fid = lu_object_fid(&lqp->lqp_obj->do_lu);

		LASSERT(fid_is_acct(fid));
		if (fid_oid(fid) == ACCT_USER_OID)
			seq_printf(p, "user_accounting:\n");
		else
			seq_printf(p, "group_accounting:\n");
		return 0;
	}

	iops = &lqp->lqp_obj->do_index_ops->dio_it;
	it = (struct dt_it *)v;

	key = iops->key(&lqp->lqp_env, it);
	if (IS_ERR(key)) {
		CERROR("%s: failed to get key: rc = %ld\n",
		       lqp->lqp_obj->do_lu.lo_dev->ld_obd->obd_name,
		       PTR_ERR(key));
		return PTR_ERR(key);
	}

	rc = iops->rec(&lqp->lqp_env, it, (struct dt_rec *)&rec, 0);
	if (rc) {
		CERROR("%s: failed to get rec: rc = %d\n",
		       lqp->lqp_obj->do_lu.lo_dev->ld_obd->obd_name, rc);
		return rc;
	}

	seq_printf(p, "- %-8s %llu\n", "id:", *((__u64 *)key));
	seq_printf(p, "  %-8s { inodes: %20"LPF64"u, bytes: %20"LPF64"u }\n",
		   "usage:", rec.ispace, rec.bspace);
	return 0;
}

struct seq_operations lprocfs_quota_seq_sops = {
	.start	= lprocfs_quota_seq_start,
	.stop	= lprocfs_quota_seq_stop,
	.next	= lprocfs_quota_seq_next,
	.show	= lprocfs_quota_seq_show,
};

static int lprocfs_quota_seq_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry	*dp = PDE(inode);
	struct seq_file		*seq;
	int			 rc;
	struct lquota_procfs	*lqp;

	/* Allocate quota procfs data. This structure will be passed to
	 * seq_start/stop/next/show via seq->private */
	OBD_ALLOC_PTR(lqp);
	if (lqp == NULL)
		return -ENOMEM;

	/* store pointer to object we would like to iterate over */
	lqp->lqp_obj = (struct dt_object *)dp->data;

	/* Initialize the common environment to be used in the seq operations */
	rc = lu_env_init(&lqp->lqp_env, LCT_LOCAL);
	if (rc) {
		CERROR("%s: error initializing procfs quota env: rc = %d\n",
		       lqp->lqp_obj->do_lu.lo_dev->ld_obd->obd_name, rc);
		goto out_lqp;
	}

	if (LPROCFS_ENTRY_AND_CHECK(dp)) {
		rc = -ENOENT;
		goto out_env;
	}

	rc = seq_open(file, &lprocfs_quota_seq_sops);
	if (rc)
		goto out_lprocfs;

	seq = file->private_data;
	seq->private = lqp;
	return 0;

out_lprocfs:
	LPROCFS_EXIT();
out_env:
	lu_env_fini(&lqp->lqp_env);
out_lqp:
	OBD_FREE_PTR(lqp);
	return rc;
}

static int lprocfs_quota_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file		*seq = file->private_data;
	struct lquota_procfs	*lqp = seq->private;

	LPROCFS_EXIT();

	LASSERT(lqp);
	lu_env_fini(&lqp->lqp_env);
	OBD_FREE_PTR(lqp);

	return seq_release(inode, file);
}

struct file_operations lprocfs_quota_seq_fops = {
	.owner		= THIS_MODULE,
	.open		= lprocfs_quota_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= lprocfs_quota_seq_release,
};

int lprocfs_quota_rd_type_dumb(char *page, char **start, off_t off, int count,
			       int *eof, void *data)
{
	return 0;
}
EXPORT_SYMBOL(lprocfs_quota_rd_type_dumb);

int lprocfs_quota_wr_type_dumb(struct file *file, const char *buffer,
			       unsigned long count, void *data)
{
	return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_type_dumb);

int lprocfs_quota_rd_bunit(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_bunit_sz);
}
EXPORT_SYMBOL(lprocfs_quota_rd_bunit);

int lprocfs_quota_wr_bunit(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val % QUOTABLOCK_SIZE ||
            val <= obd->u.obt.obt_qctxt.lqc_btune_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_bunit_sz = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_bunit);

int lprocfs_quota_rd_btune(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_btune_sz);
}
EXPORT_SYMBOL(lprocfs_quota_rd_btune);

int lprocfs_quota_wr_btune(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val <= QUOTABLOCK_SIZE * MIN_QLIMIT || val % QUOTABLOCK_SIZE ||
            val >= obd->u.obt.obt_qctxt.lqc_bunit_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_btune_sz = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_btune);

int lprocfs_quota_rd_iunit(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_iunit_sz);
}
EXPORT_SYMBOL(lprocfs_quota_rd_iunit);

int lprocfs_quota_wr_iunit(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val <= obd->u.obt.obt_qctxt.lqc_itune_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_iunit_sz = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_iunit);

int lprocfs_quota_rd_itune(char *page, char **start, off_t off, int count,
                           int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_itune_sz);
}
EXPORT_SYMBOL(lprocfs_quota_rd_itune);

int lprocfs_quota_wr_itune(struct file *file, const char *buffer,
                           unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val <= MIN_QLIMIT ||
            val >= obd->u.obt.obt_qctxt.lqc_iunit_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_itune_sz = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_itune);

#define USER_QUOTA      1
#define GROUP_QUOTA     2

#define MAX_STYPE_SIZE  5

int lprocfs_quota_rd_type(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        char stype[MAX_STYPE_SIZE + 1] = "";
        int oq_type;

        LASSERT(obd != NULL);

        /* Collect the needed information */
        oq_type = obd->u.obt.obt_qctxt.lqc_flags;

        /* Transform the collected data into a user-readable string */
        if (oq_type & LQC_USRQUOTA_FLAG)
                strcat(stype, "u");
        if (oq_type & LQC_GRPQUOTA_FLAG)
                strcat(stype, "g");

        strcat(stype, "3");

        return snprintf(page, count, "%s\n", stype);
}
EXPORT_SYMBOL(lprocfs_quota_rd_type);

/*
 * generic_quota_on is very lazy and tolerant about current quota settings
 * @global means to turn on quotas on each OST additionally to local quotas;
 * should not be called from filter_quota_ctl on MDS nodes (as it starts
 * admin quotas on MDS nodes).
 */
int generic_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl, int global)
{
        struct obd_device_target *obt = &obd->u.obt;
        struct lvfs_run_ctxt saved;
        int id, is_master, rc = 0, local; /* means we need a local quotaon */

        cfs_down(&obt->obt_quotachecking);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        id = UGQUOTA2LQC(oqctl->qc_type);
        local = (obt->obt_qctxt.lqc_flags & id) != id;

        oqctl->qc_cmd = Q_QUOTAON;
        oqctl->qc_id = obt->obt_qfmt;

        is_master = !strcmp(obd->obd_type->typ_name, LUSTRE_MDS_NAME);
        if (is_master) {
                cfs_down_write(&obd->u.mds.mds_qonoff_sem);
                if (local) {
                        /* turn on cluster wide quota */
                        rc = mds_admin_quota_on(obd, oqctl);
                        if (rc && rc != -ENOENT)
                                CERROR("%s: %s admin quotaon failed. rc=%d\n",
                                       obd->obd_name, global ? "global":"local",
                                       rc);
                }
        }

        if (rc == 0) {
                if (local) {
                        rc = fsfilt_quotactl(obd, obt->obt_sb, oqctl);
                        if (rc) {
                                if (rc != -ENOENT)
                                        CERROR("%s: %s quotaon failed with"
                                               " rc=%d\n", obd->obd_name,
                                               global ? "global" : "local", rc);
                        } else {
                                obt->obt_qctxt.lqc_flags |= UGQUOTA2LQC(oqctl->qc_type);
                                build_lqs(obd);
                        }
                }

                if (rc == 0 && global && is_master)
                        rc = obd_quotactl(obd->u.mds.mds_lov_exp, oqctl);
        }

        if (is_master)
                cfs_up_write(&obd->u.mds.mds_qonoff_sem);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        cfs_up(&obt->obt_quotachecking);

        CDEBUG(D_QUOTA, "%s: quotaon type:master:global:local:flags:rc "
               "%u:%d:%d:%d:%lu:%d\n",
               obd->obd_name, oqctl->qc_type, is_master, global, local,
               obt->obt_qctxt.lqc_flags, rc);

        return rc;
}

static int auto_quota_on(struct obd_device *obd, int type)
{
        struct obd_quotactl *oqctl;
        int rc;
        ENTRY;

        LASSERT(type == USRQUOTA || type == GRPQUOTA || type == UGQUOTA);

        OBD_ALLOC_PTR(oqctl);
        if (!oqctl)
                RETURN(-ENOMEM);

        oqctl->qc_type = type;

        rc = generic_quota_on(obd, oqctl, 0);

        OBD_FREE_PTR(oqctl);
        RETURN(rc);
}

int lprocfs_quota_wr_type(struct file *file, const char *buffer,
                          unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int type = 0;
        unsigned long i;
        char stype[MAX_STYPE_SIZE + 1] = "";

        LASSERT(obd != NULL);

        if (count > MAX_STYPE_SIZE)
                return -EINVAL;

        if (cfs_copy_from_user(stype, buffer, count))
                return -EFAULT;

        for (i = 0 ; i < count ; i++) {
                switch (stype[i]) {
                case 'u' :
                        type |= USER_QUOTA;
                        break;
                case 'g' :
                        type |= GROUP_QUOTA;
                        break;
                case '1' :
                case '2' :
                        CWARN("quota_type options 1 and 2 are obsolete, "
                              "they will be ignored\n");
                        break;
                case '3' : /* the only valid version spec, do nothing */
                default  : /* just skip stray symbols like \n */
                        break;
                }
        }

        if (type != 0) {
                int rc = auto_quota_on(obd, type - 1);

                if (rc && rc != -EALREADY && rc != -ENOENT)
                        return rc;
        }

        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_type);

int lprocfs_quota_rd_switch_seconds(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%d\n",
                        obd->u.obt.obt_qctxt.lqc_switch_seconds);
}
EXPORT_SYMBOL(lprocfs_quota_rd_switch_seconds);

int lprocfs_quota_wr_switch_seconds(struct file *file, const char *buffer,
                                    unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val <= 10)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_switch_seconds = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_switch_seconds);

int lprocfs_quota_rd_sync_blk(char *page, char **start, off_t off,
                              int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "%d\n",
                        obd->u.obt.obt_qctxt.lqc_sync_blk);
}
EXPORT_SYMBOL(lprocfs_quota_rd_sync_blk);

int lprocfs_quota_wr_sync_blk(struct file *file, const char *buffer,
                              unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < 0)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_sync_blk = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_sync_blk);

int lprocfs_quota_rd_switch_qs(char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);

        return snprintf(page, count, "changing qunit size is %s\n",
                        obd->u.obt.obt_qctxt.lqc_switch_qs ?
                        "enabled" : "disabled");
}
EXPORT_SYMBOL(lprocfs_quota_rd_switch_qs);

int lprocfs_quota_wr_switch_qs(struct file *file, const char *buffer,
                               unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val)
            obd->u.obt.obt_qctxt.lqc_switch_qs = 1;
        else
            obd->u.obt.obt_qctxt.lqc_switch_qs = 0;

        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_switch_qs);

int lprocfs_quota_rd_boundary_factor(char *page, char **start, off_t off,
                                     int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);


        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_cqs_boundary_factor);
}
EXPORT_SYMBOL(lprocfs_quota_rd_boundary_factor);

int lprocfs_quota_wr_boundary_factor(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < 2)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_cqs_boundary_factor = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_boundary_factor);

int lprocfs_quota_rd_least_bunit(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);


        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_cqs_least_bunit);
}
EXPORT_SYMBOL(lprocfs_quota_rd_least_bunit);

int lprocfs_quota_wr_least_bunit(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < PTLRPC_MAX_BRW_SIZE ||
            val >= obd->u.obt.obt_qctxt.lqc_bunit_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_cqs_least_bunit = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_least_bunit);

int lprocfs_quota_rd_least_iunit(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);


        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_cqs_least_iunit);
}
EXPORT_SYMBOL(lprocfs_quota_rd_least_iunit);

int lprocfs_quota_wr_least_iunit(struct file *file, const char *buffer,
                                 unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < 1 || val >= obd->u.obt.obt_qctxt.lqc_iunit_sz)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_cqs_least_iunit = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_least_iunit);

int lprocfs_quota_rd_qs_factor(char *page, char **start, off_t off,
                               int count, int *eof, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        LASSERT(obd != NULL);


        return snprintf(page, count, "%lu\n",
                        obd->u.obt.obt_qctxt.lqc_cqs_qs_factor);
}
EXPORT_SYMBOL(lprocfs_quota_rd_qs_factor);

int lprocfs_quota_wr_qs_factor(struct file *file, const char *buffer,
                               unsigned long count, void *data)
{
        struct obd_device *obd = (struct obd_device *)data;
        int val, rc;
        LASSERT(obd != NULL);

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val < 2)
                return -EINVAL;

        obd->u.obt.obt_qctxt.lqc_cqs_qs_factor = val;
        return count;
}
EXPORT_SYMBOL(lprocfs_quota_wr_qs_factor);

struct lprocfs_vars lprocfs_quota_common_vars[] = {
        { "quota_bunit_sz", lprocfs_quota_rd_bunit,
                            lprocfs_quota_wr_bunit, 0},
        { "quota_btune_sz", lprocfs_quota_rd_btune,
                            lprocfs_quota_wr_btune, 0},
        { "quota_iunit_sz", lprocfs_quota_rd_iunit,
                            lprocfs_quota_wr_iunit, 0},
        { "quota_itune_sz", lprocfs_quota_rd_itune,
                            lprocfs_quota_wr_itune, 0},
        { "quota_type",     lprocfs_quota_rd_type,
                            lprocfs_quota_wr_type, 0},
        { "quota_switch_seconds",  lprocfs_quota_rd_switch_seconds,
                                   lprocfs_quota_wr_switch_seconds, 0 },
        { "quota_sync_blk", lprocfs_quota_rd_sync_blk,
                            lprocfs_quota_wr_sync_blk, 0},
        { NULL }
};

struct lprocfs_vars lprocfs_quota_master_vars[] = {
        { "quota_switch_qs", lprocfs_quota_rd_switch_qs,
                             lprocfs_quota_wr_switch_qs, 0 },
        { "quota_boundary_factor", lprocfs_quota_rd_boundary_factor,
                                   lprocfs_quota_wr_boundary_factor, 0 },
        { "quota_least_bunit", lprocfs_quota_rd_least_bunit,
                               lprocfs_quota_wr_least_bunit, 0 },
        { "quota_least_iunit", lprocfs_quota_rd_least_iunit,
                               lprocfs_quota_wr_least_iunit, 0 },
        { "quota_qs_factor",   lprocfs_quota_rd_qs_factor,
                               lprocfs_quota_wr_qs_factor, 0 },
        { NULL }
};

int lquota_proc_setup(struct obd_device *obd, int is_master)
{
        struct lustre_quota_ctxt *qctxt = &obd->u.obt.obt_qctxt;
        int rc = 0;
        ENTRY;

        LASSERT(lquota_type_proc_dir && obd);
        qctxt->lqc_proc_dir = lprocfs_register(obd->obd_name,
                                               lquota_type_proc_dir,
                                               lprocfs_quota_common_vars, obd);
        if (IS_ERR(qctxt->lqc_proc_dir)) {
                rc = PTR_ERR(qctxt->lqc_proc_dir);
                CERROR("%s: error %d setting up lprocfs\n",
                       obd->obd_name, rc);
                qctxt->lqc_proc_dir = NULL;
                GOTO(out, rc);
        }

        if (is_master) {
                rc = lprocfs_add_vars(qctxt->lqc_proc_dir,
                                      lprocfs_quota_master_vars, obd);
                if (rc) {
                        CERROR("%s: error %d setting up lprocfs for "
                               "quota master\n", obd->obd_name, rc);
                        GOTO(out_free_proc, rc);
                }
        }

        qctxt->lqc_stats = lprocfs_alloc_stats(LQUOTA_LAST_STAT -
                                               LQUOTA_FIRST_STAT, 0);
        if (!qctxt->lqc_stats)
                GOTO(out_free_proc, rc = -ENOMEM);

        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_SYNC_ACQ,
                             LPROCFS_CNTR_AVGMINMAX, "sync_acq_req", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_SYNC_REL,
                             LPROCFS_CNTR_AVGMINMAX, "sync_rel_req", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_ASYNC_ACQ,
                             LPROCFS_CNTR_AVGMINMAX, "async_acq_req", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_ASYNC_REL,
                             LPROCFS_CNTR_AVGMINMAX, "async_rel_req", "us");

        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_WAIT_FOR_CHK_BLK,
                             LPROCFS_CNTR_AVGMINMAX,
                             "wait_for_blk_quota(lquota_chkquota)", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_WAIT_FOR_CHK_INO,
                             LPROCFS_CNTR_AVGMINMAX,
                             "wait_for_ino_quota(lquota_chkquota)", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_WAIT_FOR_COMMIT_BLK,
                             LPROCFS_CNTR_AVGMINMAX,
                             "wait_for_blk_quota(lquota_pending_commit)",
                             "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_WAIT_FOR_COMMIT_INO,
                             LPROCFS_CNTR_AVGMINMAX,
                             "wait_for_ino_quota(lquota_pending_commit)",
                             "us");

        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_WAIT_PENDING_BLK_QUOTA,
                             LPROCFS_CNTR_AVGMINMAX,
                             "wait_for_pending_blk_quota_req"
                             "(qctxt_wait_pending_dqacq)", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_WAIT_PENDING_INO_QUOTA,
                             LPROCFS_CNTR_AVGMINMAX,
                             "wait_for_pending_ino_quota_req"
                             "(qctxt_wait_pending_dqacq)", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_NOWAIT_PENDING_BLK_QUOTA,
                             LPROCFS_CNTR_AVGMINMAX,
                             "nowait_for_pending_blk_quota_req"
                             "(qctxt_wait_pending_dqacq)", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_NOWAIT_PENDING_INO_QUOTA,
                             LPROCFS_CNTR_AVGMINMAX,
                             "nowait_for_pending_ino_quota_req"
                             "(qctxt_wait_pending_dqacq)", "us");

        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_QUOTA_CTL,
                             LPROCFS_CNTR_AVGMINMAX, "quota_ctl", "us");
        lprocfs_counter_init(qctxt->lqc_stats, LQUOTA_ADJUST_QUNIT,
                             LPROCFS_CNTR_AVGMINMAX, "adjust_qunit", "us");

        lprocfs_register_stats(qctxt->lqc_proc_dir, "stats", qctxt->lqc_stats);

        RETURN(rc);

out_free_proc:
        lprocfs_remove(&qctxt->lqc_proc_dir);
out:
        RETURN(rc);
}

int lquota_proc_cleanup(struct lustre_quota_ctxt *qctxt)
{
        if (!qctxt || !qctxt->lqc_proc_dir)
                return -EINVAL;

        if (qctxt->lqc_stats != NULL)
                 lprocfs_free_stats(&qctxt->lqc_stats);

        lprocfs_remove(&qctxt->lqc_proc_dir);
        return 0;
}

#endif  /* LPROCFS */
