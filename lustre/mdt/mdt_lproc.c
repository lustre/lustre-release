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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_lproc.c
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
 * Author: Fan Yong <fanyong@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/version.h>
#include <asm/statfs.h>

#include <linux/module.h>
#include <lnet/nidstr.h>
/* LUSTRE_VERSION_CODE */
#include <lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * MDT_FAIL_CHECK
 */
#include <obd_support.h>
/* struct obd_export */
#include <lustre_export.h>
/* struct obd_device */
#include <obd.h>
#include <obd_class.h>
#include <lustre_mds.h>
#include <lprocfs_status.h>
#include "mdt_internal.h"

/**
 * The rename stats output would be YAML formats, like
 * rename_stats:
 * - snapshot_time: 1234567890.123456
 * - same_dir:
 *     4kB: { samples: 1230, pct: 33, cum_pct: 45 }
 *     8kB: { samples: 1242, pct: 33, cum_pct: 78 }
 *     16kB: { samples: 132, pct: 3, cum_pct: 81 }
 * - crossdir_src:
 *     4kB: { samples: 123, pct: 33, cum_pct: 45 }
 *     8kB: { samples: 124, pct: 33, cum_pct: 78 }
 *     16kB: { samples: 12, pct: 3, cum_pct: 81 }
 * - crossdir_tgt:
 *     4kB: { samples: 123, pct: 33, cum_pct: 45 }
 *     8kB: { samples: 124, pct: 33, cum_pct: 78 }
 *     16kB: { samples: 12, pct: 3, cum_pct: 81 }
 **/

#define pct(a, b) (b ? a * 100 / b : 0)

static void display_rename_stats(struct seq_file *seq, char *name,
                                 struct obd_histogram *hist)
{
        unsigned long tot, t, cum = 0;
        int i;

        tot = lprocfs_oh_sum(hist);
        if (tot > 0)
                seq_printf(seq, "- %-15s\n", name);
        /* dir size start from 4K, start i from 10(2^10) here */
        for (i = 0; i < OBD_HIST_MAX; i++) {
                t = hist->oh_buckets[i];
                cum += t;
                if (cum == 0)
                        continue;

                if (i < 10)
                        seq_printf(seq, "%6s%d%s", " ", 1<< i, "bytes:");
                else if (i < 20)
                        seq_printf(seq, "%6s%d%s", " ", 1<<(i-10), "KB:");
                else
                        seq_printf(seq, "%6s%d%s", " ", 1<<(i-20), "MB:");

                seq_printf(seq, " { sample: %3lu, pct: %3lu, cum_pct: %3lu }\n",
                           t, pct(t, tot), pct(cum, tot));

                if (cum == tot)
                        break;
        }
}

static void rename_stats_show(struct seq_file *seq,
                              struct rename_stats *rename_stats)
{
	struct timespec64 now;

	/* this sampling races with updates */
	ktime_get_real_ts64(&now);
	seq_printf(seq, "rename_stats:\n");
	seq_printf(seq, "- %-15s %llu.%9lu\n", "snapshot_time:",
		   (s64)now.tv_sec, now.tv_nsec);

        display_rename_stats(seq, "same_dir",
                             &rename_stats->hist[RENAME_SAMEDIR_SIZE]);
        display_rename_stats(seq, "crossdir_src",
                             &rename_stats->hist[RENAME_CROSSDIR_SRC_SIZE]);
        display_rename_stats(seq, "crossdir_tgt",
                             &rename_stats->hist[RENAME_CROSSDIR_TGT_SIZE]);
}

#undef pct

static int mdt_rename_stats_seq_show(struct seq_file *seq, void *v)
{
        struct mdt_device *mdt = seq->private;

        rename_stats_show(seq, &mdt->mdt_rename_stats);

        return 0;
}

static ssize_t
mdt_rename_stats_seq_write(struct file *file, const char __user *buf,
			   size_t len, loff_t *off)
{
        struct seq_file *seq = file->private_data;
        struct mdt_device *mdt = seq->private;
        int i;

        for (i = 0; i < RENAME_LAST; i++)
                lprocfs_oh_clear(&mdt->mdt_rename_stats.hist[i]);

        return len;
}
LPROC_SEQ_FOPS(mdt_rename_stats);

static int lproc_mdt_attach_rename_seqstat(struct mdt_device *mdt)
{
	int i;

	for (i = 0; i < RENAME_LAST; i++)
		spin_lock_init(&mdt->mdt_rename_stats.hist[i].oh_lock);

	return lprocfs_obd_seq_create(mdt2obd_dev(mdt), "rename_stats", 0644,
				      &mdt_rename_stats_fops, mdt);
}

void mdt_rename_counter_tally(struct mdt_thread_info *info,
			      struct mdt_device *mdt,
			      struct ptlrpc_request *req,
			      struct mdt_object *src,
			      struct mdt_object *tgt)
{
        struct md_attr *ma = &info->mti_attr;
        struct rename_stats *rstats = &mdt->mdt_rename_stats;
        int rc;

        ma->ma_need = MA_INODE;
        ma->ma_valid = 0;
        rc = mo_attr_get(info->mti_env, mdt_object_child(src), ma);
        if (rc) {
                CERROR("%s: "DFID" attr_get, rc = %d\n",
		       mdt_obd_name(mdt), PFID(mdt_object_fid(src)), rc);
                return;
        }

        if (src == tgt) {
		mdt_counter_incr(req, LPROC_MDT_SAMEDIR_RENAME);
                lprocfs_oh_tally_log2(&rstats->hist[RENAME_SAMEDIR_SIZE],
                                      (unsigned int)ma->ma_attr.la_size);
                return;
        }

	mdt_counter_incr(req, LPROC_MDT_CROSSDIR_RENAME);
        lprocfs_oh_tally_log2(&rstats->hist[RENAME_CROSSDIR_SRC_SIZE],
                              (unsigned int)ma->ma_attr.la_size);

        ma->ma_need = MA_INODE;
        ma->ma_valid = 0;
        rc = mo_attr_get(info->mti_env, mdt_object_child(tgt), ma);
        if (rc) {
                CERROR("%s: "DFID" attr_get, rc = %d\n",
		       mdt_obd_name(mdt), PFID(mdt_object_fid(tgt)), rc);
                return;
        }

        lprocfs_oh_tally_log2(&rstats->hist[RENAME_CROSSDIR_TGT_SIZE],
                              (unsigned int)ma->ma_attr.la_size);
}

static int mdt_identity_expire_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", mdt->mdt_identity_cache->uc_entry_expire);
	return 0;
}

static ssize_t
mdt_identity_expire_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	mdt->mdt_identity_cache->uc_entry_expire = val;

	return count;
}
LPROC_SEQ_FOPS(mdt_identity_expire);

static int mdt_identity_acquire_expire_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", mdt->mdt_identity_cache->uc_acquire_expire);
	return 0;
}

static ssize_t
mdt_identity_acquire_expire_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	mdt->mdt_identity_cache->uc_acquire_expire = val;

	return count;
}
LPROC_SEQ_FOPS(mdt_identity_acquire_expire);

static int mdt_identity_upcall_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct upcall_cache *hash = mdt->mdt_identity_cache;

	down_read(&hash->uc_upcall_rwsem);
	seq_printf(m, "%s\n", hash->uc_upcall);
	up_read(&hash->uc_upcall_rwsem);
	return 0;
}

static ssize_t
mdt_identity_upcall_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct mdt_device	*mdt = mdt_dev(obd->obd_lu_dev);
	struct upcall_cache	*hash = mdt->mdt_identity_cache;
	int			 rc;
	char			*kernbuf;

	if (count >= UC_CACHE_UPCALL_MAXPATH) {
		CERROR("%s: identity upcall too long\n", mdt_obd_name(mdt));
		return -EINVAL;
	}
	OBD_ALLOC(kernbuf, count + 1);
	if (kernbuf == NULL)
		GOTO(failed, rc = -ENOMEM);
	if (copy_from_user(kernbuf, buffer, count))
		GOTO(failed, rc = -EFAULT);

	/* Remove any extraneous bits from the upcall (e.g. linefeeds) */
	down_write(&hash->uc_upcall_rwsem);
	sscanf(kernbuf, "%s", hash->uc_upcall);
	up_write(&hash->uc_upcall_rwsem);

	if (strcmp(hash->uc_name, mdt_obd_name(mdt)) != 0)
		CWARN("%s: write to upcall name %s\n",
		      mdt_obd_name(mdt), hash->uc_upcall);

	if (strcmp(hash->uc_upcall, "NONE") == 0 && mdt->mdt_opts.mo_acl)
		CWARN("%s: disable \"identity_upcall\" with ACL enabled maybe "
		      "cause unexpected \"EACCESS\"\n", mdt_obd_name(mdt));

	CDEBUG(D_CONFIG, "%s: identity upcall set to %s\n", mdt_obd_name(mdt),
	       hash->uc_upcall);
	OBD_FREE(kernbuf, count + 1);
	RETURN(count);

 failed:
	if (kernbuf)
		OBD_FREE(kernbuf, count + 1);
	RETURN(rc);
}
LPROC_SEQ_FOPS(mdt_identity_upcall);

static ssize_t
lprocfs_identity_flush_seq_write(struct file *file, const char __user *buffer,
				 size_t count, void *data)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int rc;
	__s64 uid;

	rc = lprocfs_str_to_s64(buffer, count, &uid);
	if (rc)
		return rc;
	if (uid < INT_MIN || uid > INT_MAX)
		return -ERANGE;

	mdt_flush_identity(mdt->mdt_identity_cache, uid);
	return count;
}
LPROC_SEQ_FOPS_WO_TYPE(mdt, identity_flush);

static ssize_t
lprocfs_identity_info_seq_write(struct file *file, const char __user *buffer,
				size_t count, void *data)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct identity_downcall_data *param;
	int size = sizeof(*param), rc, checked = 0;

again:
	if (count < size) {
		CERROR("%s: invalid data count = %lu, size = %d\n",
		       mdt_obd_name(mdt), (unsigned long) count, size);
		return -EINVAL;
	}

	OBD_ALLOC(param, size);
	if (param == NULL)
		return -ENOMEM;

	if (copy_from_user(param, buffer, size)) {
		CERROR("%s: bad identity data\n", mdt_obd_name(mdt));
		GOTO(out, rc = -EFAULT);
	}

	if (checked == 0) {
		checked = 1;
		if (param->idd_magic != IDENTITY_DOWNCALL_MAGIC) {
			CERROR("%s: MDS identity downcall bad params\n",
			       mdt_obd_name(mdt));
			GOTO(out, rc = -EINVAL);
		}

		if (param->idd_nperms > N_PERMS_MAX) {
			CERROR("%s: perm count %d more than maximum %d\n",
			       mdt_obd_name(mdt), param->idd_nperms,
			       N_PERMS_MAX);
			GOTO(out, rc = -EINVAL);
		}

		if (param->idd_ngroups > NGROUPS_MAX) {
			CERROR("%s: group count %d more than maximum %d\n",
			       mdt_obd_name(mdt), param->idd_ngroups,
			       NGROUPS_MAX);
			GOTO(out, rc = -EINVAL);
		}

		if (param->idd_ngroups) {
			rc = param->idd_ngroups; /* save idd_ngroups */
			OBD_FREE(param, size);
			size = offsetof(struct identity_downcall_data,
					idd_groups[rc]);
			goto again;
		}
	}

	rc = upcall_cache_downcall(mdt->mdt_identity_cache, param->idd_err,
				   param->idd_uid, param);

out:
	if (param != NULL)
		OBD_FREE(param, size);

	return rc ? rc : count;
}
LPROC_SEQ_FOPS_WO_TYPE(mdt, identity_info);

static int mdt_site_stats_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return lu_site_stats_seq_print(mdt_lu_site(mdt), m);
}
LPROC_SEQ_FOPS_RO(mdt_site_stats);

#define BUFLEN (UUID_MAX + 4)

static ssize_t
lprocfs_mds_evict_client_seq_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	char *kbuf;
	char *tmpbuf;
	int rc = 0;

	OBD_ALLOC(kbuf, BUFLEN);
	if (kbuf == NULL)
		return -ENOMEM;

	/*
	 * OBD_ALLOC() will zero kbuf, but we only copy BUFLEN - 1
	 * bytes into kbuf, to ensure that the string is NUL-terminated.
	 * UUID_MAX should include a trailing NUL already.
	 */
	if (copy_from_user(kbuf, buf, min_t(unsigned long, BUFLEN - 1, count)))
		GOTO(out, rc = -EFAULT);
	tmpbuf = cfs_firststr(kbuf, min_t(unsigned long, BUFLEN - 1, count));

	if (strncmp(tmpbuf, "nid:", 4) != 0) {
		count = lprocfs_evict_client_seq_write(file, buf, count, off);
		goto out;
	}

	if (mdt->mdt_opts.mo_evict_tgt_nids) {
		rc = obd_set_info_async(NULL, mdt->mdt_child_exp,
					sizeof(KEY_EVICT_BY_NID),
					KEY_EVICT_BY_NID,
					strlen(tmpbuf + 4) + 1,
					tmpbuf + 4, NULL);
		if (rc)
			CERROR("Failed to evict nid %s from OSTs: rc %d\n",
			       tmpbuf + 4, rc);
	}

	/* See the comments in function lprocfs_wr_evict_client()
	 * in ptlrpc/lproc_ptlrpc.c for details. - jay */
	class_incref(obd, __func__, current);
	obd_export_evict_by_nid(obd, tmpbuf + 4);
	class_decref(obd, __func__, current);


out:
	OBD_FREE(kbuf, BUFLEN);
	return rc < 0 ? rc : count;
}

#undef BUFLEN

static int mdt_evict_tgt_nids_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", mdt->mdt_opts.mo_evict_tgt_nids);
	return 0;
}

static ssize_t
mdt_evict_tgt_nids_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	mdt->mdt_opts.mo_evict_tgt_nids = !!val;
	return count;
}
LPROC_SEQ_FOPS(mdt_evict_tgt_nids);

static int mdt_cos_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", mdt_cos_is_enabled(mdt));
	return 0;
}

static ssize_t
mdt_cos_seq_write(struct file *file, const char __user *buffer,
		  size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < INT_MIN || val > INT_MAX)
		return -ERANGE;

	mdt_enable_cos(mdt, val);
	return count;
}
LPROC_SEQ_FOPS(mdt_cos);

static int mdt_root_squash_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;

	seq_printf(m, "%u:%u\n", squash->rsi_uid,
		   squash->rsi_gid);
	return 0;
}

static ssize_t
mdt_root_squash_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;

	return lprocfs_wr_root_squash(buffer, count, squash,
				      mdt_obd_name(mdt));
}
LPROC_SEQ_FOPS(mdt_root_squash);

static int mdt_nosquash_nids_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;
	int len = 0;

	down_read(&squash->rsi_sem);
	if (!list_empty(&squash->rsi_nosquash_nids)) {
		len = cfs_print_nidlist(m->buf + m->count, m->size - m->count,
					&squash->rsi_nosquash_nids);
		m->count += len;
		seq_putc(m, '\n');
	} else
		seq_puts(m, "NONE\n");
	up_read(&squash->rsi_sem);

	return 0;
}

static ssize_t
mdt_nosquash_nids_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;

	return lprocfs_wr_nosquash_nids(buffer, count, squash,
					mdt_obd_name(mdt));
}
LPROC_SEQ_FOPS(mdt_nosquash_nids);

static int mdt_enable_remote_dir_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", mdt->mdt_enable_remote_dir);
	return 0;
}

static ssize_t
mdt_enable_remote_dir_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 1 || val < 0)
		return -ERANGE;

	mdt->mdt_enable_remote_dir = val;
	return count;
}
LPROC_SEQ_FOPS(mdt_enable_remote_dir);

static int mdt_enable_remote_dir_gid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%d\n",
		  (int)mdt->mdt_enable_remote_dir_gid);
	return 0;
}

static ssize_t
mdt_enable_remote_dir_gid_seq_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *off)
{
	struct seq_file   *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_remote_dir_gid = val;
	return count;
}
LPROC_SEQ_FOPS(mdt_enable_remote_dir_gid);

/**
 * Show MDT policy for handling dirty metadata under a lock being cancelled.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int mdt_slc_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct lu_target *tgt = obd->u.obt.obt_lut;
	char *slc_states[] = {"never", "blocking", "always" };

	seq_printf(m, "%s\n", slc_states[tgt->lut_sync_lock_cancel]);
	return 0;
}
LPROC_SEQ_FOPS_RO(mdt_slc);

/**
 * Show MDT async commit count.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int mdt_async_commit_count_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	seq_printf(m, "%d\n", atomic_read(&mdt->mdt_async_commit_count));
	return 0;
}

static ssize_t
mdt_async_commit_count_seq_write(struct file *file, const char __user *buffer,
				 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < INT_MIN || val > INT_MAX)
		return -ERANGE;

	atomic_set(&mdt->mdt_async_commit_count, val);

	return count;
}
LPROC_SEQ_FOPS(mdt_async_commit_count);

/**
 * Show MDT sync count.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int mdt_sync_count_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct lu_target *tgt = obd->u.obt.obt_lut;

	seq_printf(m, "%d\n", atomic_read(&tgt->lut_sync_count));
	return 0;
}

static ssize_t
mdt_sync_count_seq_write(struct file *file, const char __user *buffer,
			 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct lu_target *tgt = obd->u.obt.obt_lut;
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < INT_MIN || val > INT_MAX)
		return -ERANGE;

	atomic_set(&tgt->lut_sync_count, val);

	return count;
}
LPROC_SEQ_FOPS(mdt_sync_count);


LPROC_SEQ_FOPS_RO_TYPE(mdt, uuid);
LPROC_SEQ_FOPS_RO_TYPE(mdt, recovery_status);
LPROC_SEQ_FOPS_RO_TYPE(mdt, num_exports);
LPROC_SEQ_FOPS_RO_TYPE(mdt, target_instance);
LPROC_SEQ_FOPS_RO_TYPE(mdt, hash);
LPROC_SEQ_FOPS_WO_TYPE(mdt, mds_evict_client);
LPROC_SEQ_FOPS_RW_TYPE(mdt, job_interval);
LPROC_SEQ_FOPS_RW_TYPE(mdt, ir_factor);
LPROC_SEQ_FOPS_RW_TYPE(mdt, nid_stats_clear);
LPROC_SEQ_FOPS(mdt_hsm_cdt_control);

LPROC_SEQ_FOPS_RW_TYPE(mdt, recovery_time_hard);
LPROC_SEQ_FOPS_RW_TYPE(mdt, recovery_time_soft);

static struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
	{ .name =	"uuid",
	  .fops =	&mdt_uuid_fops				},
	{ .name =	"recovery_status",
	  .fops =	&mdt_recovery_status_fops		},
	{ .name =	"num_exports",
	  .fops =	&mdt_num_exports_fops			},
	{ .name =	"identity_expire",
	  .fops =	&mdt_identity_expire_fops		},
	{ .name =	"identity_acquire_expire",
	  .fops =	&mdt_identity_acquire_expire_fops	},
	{ .name =	"identity_upcall",
	  .fops =	&mdt_identity_upcall_fops		},
	{ .name =	"identity_flush",
	  .fops =	&mdt_identity_flush_fops		},
	{ .name =	"identity_info",
	  .fops =	&mdt_identity_info_fops			},
	{ .name =	"site_stats",
	  .fops =	&mdt_site_stats_fops			},
	{ .name =	"evict_client",
	  .fops =	&mdt_mds_evict_client_fops		},
	{ .name =	"evict_tgt_nids",
	  .fops =	&mdt_evict_tgt_nids_fops		},
	{ .name =	"hash_stats",
	  .fops =	&mdt_hash_fops				},
	{ .name =	"commit_on_sharing",
	  .fops =	&mdt_cos_fops				},
	{ .name =	"root_squash",
	  .fops =	&mdt_root_squash_fops			},
	{ .name =	"nosquash_nids",
	  .fops =	&mdt_nosquash_nids_fops			},
	{ .name =	"instance",
	  .fops =	&mdt_target_instance_fops		},
	{ .name =	"ir_factor",
	  .fops =	&mdt_ir_factor_fops			},
	{ .name =	"job_cleanup_interval",
	  .fops =	&mdt_job_interval_fops			},
	{ .name =	"enable_remote_dir",
	  .fops =	&mdt_enable_remote_dir_fops		},
	{ .name =	"enable_remote_dir_gid",
	  .fops =	&mdt_enable_remote_dir_gid_fops		},
	{ .name =	"hsm_control",
	  .fops =	&mdt_hsm_cdt_control_fops		},
	{ .name =	"recovery_time_hard",
	  .fops =	&mdt_recovery_time_hard_fops	},
	{ .name =	"recovery_time_soft",
	  .fops =	&mdt_recovery_time_soft_fops	},
	{ .name =	"sync_lock_cancel",
	  .fops =	&mdt_slc_fops				},
	{ .name =	"async_commit_count",
	  .fops =	&mdt_async_commit_count_fops		},
	{ .name =	"sync_count",
	  .fops =	&mdt_sync_count_fops			},
	{ NULL }
};

static int
lprocfs_mdt_print_open_files(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			     struct hlist_node *hnode, void *v)
{
	struct obd_export	*exp = cfs_hash_object(hs, hnode);
	struct seq_file		*seq = v;

	if (exp->exp_lock_hash != NULL) {
		struct mdt_export_data  *med = &exp->exp_mdt_data;
		struct mdt_file_data	*mfd;

		spin_lock(&med->med_open_lock);
		list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
			seq_printf(seq, DFID"\n",
				   PFID(mdt_object_fid(mfd->mfd_object)));
		}
		spin_unlock(&med->med_open_lock);
	}

	return 0;
}

static int lprocfs_mdt_open_files_seq_show(struct seq_file *seq, void *v)
{
	struct nid_stat *stats = seq->private;
	struct obd_device *obd = stats->nid_obd;

	cfs_hash_for_each_key(obd->obd_nid_hash, &stats->nid,
			      lprocfs_mdt_print_open_files, seq);

	return 0;
}

int lprocfs_mdt_open_files_seq_open(struct inode *inode, struct file *file)
{
	struct seq_file		*seq;
	int			rc;

	rc = single_open(file, &lprocfs_mdt_open_files_seq_show, NULL);
	if (rc != 0)
		return rc;

	seq = file->private_data;
	seq->private = PDE_DATA(inode);

	return 0;
}

void mdt_counter_incr(struct ptlrpc_request *req, int opcode)
{
	struct obd_export *exp = req->rq_export;

	if (exp->exp_obd && exp->exp_obd->obd_md_stats)
		lprocfs_counter_incr(exp->exp_obd->obd_md_stats, opcode);
	if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats != NULL)
		lprocfs_counter_incr(exp->exp_nid_stats->nid_stats, opcode);
	if (exp->exp_obd && exp->exp_obd->u.obt.obt_jobstats.ojs_hash &&
	    (exp_connect_flags(exp) & OBD_CONNECT_JOBSTATS))
		lprocfs_job_stats_log(exp->exp_obd,
				      lustre_msg_get_jobid(req->rq_reqmsg),
				      opcode, 1);
}

void mdt_stats_counter_init(struct lprocfs_stats *stats)
{
        lprocfs_counter_init(stats, LPROC_MDT_OPEN, 0, "open", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_CLOSE, 0, "close", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_MKNOD, 0, "mknod", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_LINK, 0, "link", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_UNLINK, 0, "unlink", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_MKDIR, 0, "mkdir", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_RMDIR, 0, "rmdir", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_RENAME, 0, "rename", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_GETATTR, 0, "getattr", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_SETATTR, 0, "setattr", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_GETXATTR, 0, "getxattr", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_SETXATTR, 0, "setxattr", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_STATFS, 0, "statfs", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_SYNC, 0, "sync", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_SAMEDIR_RENAME, 0,
                             "samedir_rename", "reqs");
        lprocfs_counter_init(stats, LPROC_MDT_CROSSDIR_RENAME, 0,
                             "crossdir_rename", "reqs");
}

int mdt_procfs_init(struct mdt_device *mdt, const char *name)
{
	struct obd_device		*obd = mdt2obd_dev(mdt);
	int				 rc;
	ENTRY;

	LASSERT(name != NULL);

	obd->obd_vars = lprocfs_mdt_obd_vars;
	rc = lprocfs_obd_setup(obd);
	if (rc) {
		CERROR("%s: cannot create proc entries: rc = %d\n",
		       mdt_obd_name(mdt), rc);
		return rc;
	}

	rc = hsm_cdt_procfs_init(mdt);
	if (rc) {
		CERROR("%s: cannot create hsm proc entries: rc = %d\n",
		       mdt_obd_name(mdt), rc);
		return rc;
	}

	obd->obd_proc_exports_entry = proc_mkdir("exports",
						 obd->obd_proc_entry);
	if (obd->obd_proc_exports_entry)
		lprocfs_add_simple(obd->obd_proc_exports_entry, "clear",
				   obd, &mdt_nid_stats_clear_fops);
	rc = lprocfs_alloc_md_stats(obd, LPROC_MDT_LAST);
	if (rc)
		return rc;
	mdt_stats_counter_init(obd->obd_md_stats);

	rc = lprocfs_job_stats_init(obd, LPROC_MDT_LAST,
				    mdt_stats_counter_init);

	rc = lproc_mdt_attach_rename_seqstat(mdt);
	if (rc)
		CERROR("%s: MDT can not create rename stats rc = %d\n",
		       mdt_obd_name(mdt), rc);

	RETURN(rc);
}

void mdt_procfs_fini(struct mdt_device *mdt)
{
	struct obd_device *obd = mdt2obd_dev(mdt);

	if (obd->obd_proc_exports_entry != NULL) {
		lprocfs_remove_proc_entry("clear", obd->obd_proc_exports_entry);
		obd->obd_proc_exports_entry = NULL;
	}

	lprocfs_free_per_client_stats(obd);
	hsm_cdt_procfs_fini(mdt);
	lprocfs_obd_cleanup(obd);
	lprocfs_free_md_stats(obd);
	lprocfs_free_obd_stats(obd);
	lprocfs_job_stats_fini(obd);
}
