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
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <uapi/linux/lnet/nidstr.h>
/* LUSTRE_VERSION_CODE */
#include <uapi/linux/lustre/lustre_ver.h>
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

		seq_printf(seq, " { sample: %3lu, pct: %3u, cum_pct: %3u }\n",
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
			      struct mdt_object *tgt, long count)
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
		mdt_counter_incr(req, LPROC_MDT_SAMEDIR_RENAME, count);
                lprocfs_oh_tally_log2(&rstats->hist[RENAME_SAMEDIR_SIZE],
                                      (unsigned int)ma->ma_attr.la_size);
                return;
        }

	mdt_counter_incr(req, LPROC_MDT_CROSSDIR_RENAME, count);
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

static ssize_t identity_expire_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 mdt->mdt_identity_cache->uc_entry_expire);
}

static ssize_t identity_expire_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 10, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -ERANGE;

	mdt->mdt_identity_cache->uc_entry_expire = val;

	return count;
}
LUSTRE_RW_ATTR(identity_expire);

static ssize_t identity_acquire_expire_show(struct kobject *kobj,
					    struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%lld\n",
			 mdt->mdt_identity_cache->uc_acquire_expire);
}

static ssize_t identity_acquire_expire_store(struct kobject *kobj,
					     struct attribute *attr,
					     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	time64_t val;
	int rc;

	rc = kstrtoll(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	mdt->mdt_identity_cache->uc_acquire_expire = val;

	return count;
}
LUSTRE_RW_ATTR(identity_acquire_expire);

static ssize_t identity_upcall_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct upcall_cache *hash = mdt->mdt_identity_cache;
	int rc;

	down_read(&hash->uc_upcall_rwsem);
	rc = scnprintf(buf, PAGE_SIZE, "%s\n", hash->uc_upcall);
	up_read(&hash->uc_upcall_rwsem);
	return rc;
}

static ssize_t identity_upcall_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct upcall_cache *hash = mdt->mdt_identity_cache;

	if (count >= UC_CACHE_UPCALL_MAXPATH) {
		CERROR("%s: identity upcall too long\n", mdt_obd_name(mdt));
		return -EINVAL;
	}

	/* Remove any extraneous bits from the upcall (e.g. linefeeds) */
	down_write(&hash->uc_upcall_rwsem);
	sscanf(buffer, "%s", hash->uc_upcall);
	up_write(&hash->uc_upcall_rwsem);

	if (strcmp(hash->uc_name, mdt_obd_name(mdt)) != 0)
		CWARN("%s: write to upcall name %s\n",
		      mdt_obd_name(mdt), hash->uc_upcall);

	if (strcmp(hash->uc_upcall, "NONE") == 0 && mdt->mdt_opts.mo_acl)
		CWARN("%s: disable \"identity_upcall\" with ACL enabled maybe "
		      "cause unexpected \"EACCESS\"\n", mdt_obd_name(mdt));

	CDEBUG(D_CONFIG, "%s: identity upcall set to %s\n", mdt_obd_name(mdt),
	       hash->uc_upcall);
	RETURN(count);
}
LUSTRE_RW_ATTR(identity_upcall);

static ssize_t identity_flush_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int uid;
	int rc;

	rc = kstrtoint(buffer, 0, &uid);
	if (rc)
		return rc;

	mdt_flush_identity(mdt->mdt_identity_cache, uid);
	return count;
}
LUSTRE_WO_ATTR(identity_flush);

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
LPROC_SEQ_FOPS_WR_ONLY(mdt, identity_info);

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
	tmpbuf = skip_spaces(kbuf);
	tmpbuf = strsep(&tmpbuf, " \t\n\f\v\r");

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

static ssize_t evict_tgt_nids_show(struct kobject *kobj,
				   struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 mdt->mdt_opts.mo_evict_tgt_nids);
}

static ssize_t evict_tgt_nids_store(struct kobject *kobj,
				    struct attribute *attr, const char *buffer,
				    size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_opts.mo_evict_tgt_nids = val;
	return count;
}
LUSTRE_RW_ATTR(evict_tgt_nids);

static ssize_t commit_on_sharing_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt_cos_is_enabled(mdt));
}

static ssize_t commit_on_sharing_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt_enable_cos(mdt, val);
	return count;
}
LUSTRE_RW_ATTR(commit_on_sharing);

static ssize_t local_recovery_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 obd->u.obt.obt_lut->lut_local_recovery);
}

static ssize_t local_recovery_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	obd->u.obt.obt_lut->lut_local_recovery = !!val;
	return count;
}
LUSTRE_RW_ATTR(local_recovery);

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

	spin_lock(&squash->rsi_lock);
	if (!list_empty(&squash->rsi_nosquash_nids)) {
		len = cfs_print_nidlist(m->buf + m->count, m->size - m->count,
					&squash->rsi_nosquash_nids);
		m->count += len;
		seq_putc(m, '\n');
	} else
		seq_puts(m, "NONE\n");
	spin_unlock(&squash->rsi_lock);

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

static ssize_t enable_remote_dir_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt->mdt_enable_remote_dir);
}

static ssize_t enable_remote_dir_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_remote_dir = val;
	return count;
}
LUSTRE_RW_ATTR(enable_remote_dir);

static ssize_t enable_remote_dir_gid_show(struct kobject *kobj,
					  struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 (int)mdt->mdt_enable_remote_dir_gid);
}

static ssize_t enable_remote_dir_gid_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int val;
	int rc;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_remote_dir_gid = val;
	return count;
}
LUSTRE_RW_ATTR(enable_remote_dir_gid);

static ssize_t enable_chprojid_gid_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 (int)mdt->mdt_enable_chprojid_gid);
}

static ssize_t enable_chprojid_gid_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int val;
	int rc;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_chprojid_gid = val;
	return count;
}
LUSTRE_RW_ATTR(enable_chprojid_gid);

static ssize_t enable_striped_dir_show(struct kobject *kobj,
				       struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt->mdt_enable_striped_dir);
}

static ssize_t enable_striped_dir_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_striped_dir = val;
	return count;
}
LUSTRE_RW_ATTR(enable_striped_dir);

static ssize_t enable_dir_migration_show(struct kobject *kobj,
					 struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt->mdt_enable_dir_migration);
}

static ssize_t enable_dir_migration_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_dir_migration = val;
	return count;
}
LUSTRE_RW_ATTR(enable_dir_migration);

static ssize_t enable_dir_restripe_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt->mdt_enable_dir_restripe);
}

static ssize_t enable_dir_restripe_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_dir_restripe = val;
	return count;
}
LUSTRE_RW_ATTR(enable_dir_restripe);

static ssize_t enable_dir_auto_split_show(struct kobject *kobj,
					  struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 mdt->mdt_enable_dir_auto_split);
}

static ssize_t enable_dir_auto_split_store(struct kobject *kobj,
					   struct attribute *attr,
					   const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_dir_auto_split = val;
	return count;
}
LUSTRE_RW_ATTR(enable_dir_auto_split);

/**
 * Show MDT async commit count.
 *
 * @m		seq_file handle
 * @data	unused for single entry
 *
 * Return:	0 on success
 *		negative value on error
 */
static ssize_t async_commit_count_show(struct kobject *kobj,
				       struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&mdt->mdt_async_commit_count));
}

static ssize_t async_commit_count_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int val;
	int rc;

	rc = kstrtoint(buffer, 10, &val);
	if (rc)
		return rc;

	atomic_set(&mdt->mdt_async_commit_count, val);

	return count;
}
LUSTRE_RW_ATTR(async_commit_count);

/**
 * Show MDT sync count.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static ssize_t sync_count_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *tgt = obd->u.obt.obt_lut;

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 atomic_read(&tgt->lut_sync_count));
}

static ssize_t sync_count_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *tgt = obd->u.obt.obt_lut;
	int val;
	int rc;

	rc = kstrtoint(buffer, 0, &val);
	if (rc)
		return rc;

	atomic_set(&tgt->lut_sync_count, val);

	return count;
}
LUSTRE_RW_ATTR(sync_count);

static const char *dom_open_lock_modes[NUM_DOM_LOCK_ON_OPEN_MODES] = {
	[NO_DOM_LOCK_ON_OPEN] = "never",
	[TRYLOCK_DOM_ON_OPEN] = "trylock",
	[ALWAYS_DOM_LOCK_ON_OPEN] = "always",
};

/* This must be longer than the longest string above */
#define DOM_LOCK_MODES_MAXLEN 16

/**
 * Show MDT policy for data prefetch on open for DoM files..
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static ssize_t dom_lock_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%s\n",
			 dom_open_lock_modes[mdt->mdt_opts.mo_dom_lock]);
}

/**
 * Change MDT policy for data prefetch on open for DoM files.
 *
 * This variable defines how DOM lock is taken at open enqueue.
 * There are three possible modes:
 * 1) never - never take DoM lock on open. DoM lock will be taken as separate
 *    IO lock with own enqueue.
 * 2) trylock - DoM lock will be taken only if non-blocked.
 * 3) always - DoM lock will be taken always even if it is blocking lock.
 *
 * If dom_read_open is enabled too then DoM lock is taken in PR mode and
 * is paired with LAYOUT lock when possible.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents policy
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t dom_lock_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int val = -1;
	int i, rc;

	if (count == 0 || count >= DOM_LOCK_MODES_MAXLEN)
		return -EINVAL;

	for (i = 0 ; i < NUM_DOM_LOCK_ON_OPEN_MODES; i++) {
		/* buffer might have '\n' but using strlen() avoids it */
		if (strncmp(buffer, dom_open_lock_modes[i],
			    strlen(dom_open_lock_modes[i])) == 0) {
			val = i;
			break;
		}
	}

	/* Legacy numeric codes */
	if (val == -1) {
		rc = kstrtoint(buffer, 0, &val);
		if (rc)
			return rc;
	}

	if (val == ALWAYS_DOM_LOCK_ON_OPEN)
		val = TRYLOCK_DOM_ON_OPEN;

	if (val < 0 || val >= NUM_DOM_LOCK_ON_OPEN_MODES)
		return -EINVAL;

	mdt->mdt_opts.mo_dom_lock = val;
	return count;
}
LUSTRE_RW_ATTR(dom_lock);

/**
 * Show MDT policy for data prefetch on open for DoM files..
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static ssize_t dom_read_open_show(struct kobject *kobj,
				  struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 !!mdt->mdt_opts.mo_dom_read_open);
}

/**
 * Modify MDT policy for data prefetch on open for DoM files.
 *
 * If enabled then Data-on-MDT file data may be read during open and
 * returned back in reply. It works only with mo_dom_lock enabled.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents policy
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t dom_read_open_store(struct kobject *kobj,
				   struct attribute *attr, const char *buffer,
				   size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_opts.mo_dom_read_open = !!val;
	return count;
}
LUSTRE_RW_ATTR(dom_read_open);

static ssize_t migrate_hsm_allowed_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 mdt->mdt_opts.mo_migrate_hsm_allowed);
}

static ssize_t migrate_hsm_allowed_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_opts.mo_migrate_hsm_allowed = val;
	return count;
}
LUSTRE_RW_ATTR(migrate_hsm_allowed);

static ssize_t readonly_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt->mdt_readonly);
}

static ssize_t readonly_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_readonly = val;
	return count;
}
LUSTRE_RW_ATTR(readonly);

static ssize_t enable_remote_rename_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 mdt->mdt_enable_remote_rename);
}

static ssize_t enable_remote_rename_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_remote_rename = val;
	return count;
}
LUSTRE_RW_ATTR(enable_remote_rename);

static ssize_t dir_split_count_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%llu\n",
			 mdt->mdt_restriper.mdr_dir_split_count);
}

static ssize_t dir_split_count_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	s64 val;
	int rc;

	rc = sysfs_memparse(buffer, count, &val, "B");
	if (rc < 0)
		return rc;

	if (val < 0)
		return -ERANGE;

	mdt->mdt_restriper.mdr_dir_split_count = val;

	return count;
}
LUSTRE_RW_ATTR(dir_split_count);

static ssize_t dir_split_delta_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 mdt->mdt_restriper.mdr_dir_split_delta);
}

static ssize_t dir_split_delta_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	u32 val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	mdt->mdt_restriper.mdr_dir_split_delta = val;

	return count;
}
LUSTRE_RW_ATTR(dir_split_delta);

static ssize_t dir_restripe_nsonly_show(struct kobject *kobj,
					struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", mdt->mdt_dir_restripe_nsonly);
}

static ssize_t dir_restripe_nsonly_store(struct kobject *kobj,
					 struct attribute *attr,
					 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_dir_restripe_nsonly = val;
	return count;
}
LUSTRE_RW_ATTR(dir_restripe_nsonly);

static ssize_t enable_remote_subdir_mount_show(struct kobject *kobj,
					       struct attribute *attr,
					       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 mdt->mdt_enable_remote_subdir_mount);
}

static ssize_t enable_remote_subdir_mount_store(struct kobject *kobj,
						struct attribute *attr,
						const char *buffer,
						size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_remote_subdir_mount = val;
	return count;
}
LUSTRE_RW_ATTR(enable_remote_subdir_mount);

/**
 * Show if the OFD enforces T10PI checksum.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static ssize_t checksum_t10pi_enforce_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd->u.obt.obt_lut;

	return scnprintf(buf, PAGE_SIZE, "%u\n", lut->lut_cksum_t10pi_enforce);
}

/**
 * Force specific T10PI checksum modes to be enabled
 *
 * If T10PI *is* supported in hardware, allow only the supported T10PI type
 * to be used. If T10PI is *not* supported by the OSD, setting the enforce
 * parameter forces all T10PI types to be enabled (even if slower) for
 * testing.
 *
 * The final determination of which algorithm to be used depends whether
 * the client supports T10PI or not, and is handled at client connect time.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents mode
 *			1: set T10PI checksums enforced
 *			0: unset T10PI checksums enforced
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t checksum_t10pi_enforce_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd->u.obt.obt_lut;
	bool enforce;
	int rc;

	rc = kstrtobool(buffer, &enforce);
	if (rc)
		return rc;

	spin_lock(&lut->lut_flags_lock);
	lut->lut_cksum_t10pi_enforce = enforce;
	spin_unlock(&lut->lut_flags_lock);
	return count;
}
LUSTRE_RW_ATTR(checksum_t10pi_enforce);

LPROC_SEQ_FOPS_RO_TYPE(mdt, hash);
LPROC_SEQ_FOPS_WR_ONLY(mdt, mds_evict_client);
LPROC_SEQ_FOPS_RW_TYPE(mdt, checksum_dump);
LUSTRE_RW_ATTR(job_cleanup_interval);
LPROC_SEQ_FOPS_RW_TYPE(mdt, nid_stats_clear);
LUSTRE_RW_ATTR(hsm_control);

LPROC_SEQ_FOPS_RO_TYPE(mdt, recovery_status);
LUSTRE_RW_ATTR(recovery_time_hard);
LUSTRE_RW_ATTR(recovery_time_soft);
LUSTRE_RW_ATTR(ir_factor);

LUSTRE_RO_ATTR(tot_dirty);
LUSTRE_RO_ATTR(tot_granted);
LUSTRE_RO_ATTR(tot_pending);
LUSTRE_RW_ATTR(grant_compat_disable);
LUSTRE_RO_ATTR(instance);

LUSTRE_RO_ATTR(num_exports);

static struct attribute *mdt_attrs[] = {
	&lustre_attr_tot_dirty.attr,
	&lustre_attr_tot_granted.attr,
	&lustre_attr_tot_pending.attr,
	&lustre_attr_grant_compat_disable.attr,
	&lustre_attr_instance.attr,
	&lustre_attr_recovery_time_hard.attr,
	&lustre_attr_recovery_time_soft.attr,
	&lustre_attr_ir_factor.attr,
	&lustre_attr_num_exports.attr,
	&lustre_attr_identity_expire.attr,
	&lustre_attr_identity_acquire_expire.attr,
	&lustre_attr_identity_upcall.attr,
	&lustre_attr_identity_flush.attr,
	&lustre_attr_evict_tgt_nids.attr,
	&lustre_attr_enable_remote_dir.attr,
	&lustre_attr_enable_remote_dir_gid.attr,
	&lustre_attr_enable_chprojid_gid.attr,
	&lustre_attr_enable_striped_dir.attr,
	&lustre_attr_enable_dir_migration.attr,
	&lustre_attr_enable_dir_restripe.attr,
	&lustre_attr_enable_dir_auto_split.attr,
	&lustre_attr_enable_remote_rename.attr,
	&lustre_attr_commit_on_sharing.attr,
	&lustre_attr_local_recovery.attr,
	&lustre_attr_async_commit_count.attr,
	&lustre_attr_sync_count.attr,
	&lustre_attr_dom_lock.attr,
	&lustre_attr_dom_read_open.attr,
	&lustre_attr_migrate_hsm_allowed.attr,
	&lustre_attr_hsm_control.attr,
	&lustre_attr_job_cleanup_interval.attr,
	&lustre_attr_readonly.attr,
	&lustre_attr_dir_split_count.attr,
	&lustre_attr_dir_split_delta.attr,
	&lustre_attr_dir_restripe_nsonly.attr,
	&lustre_attr_checksum_t10pi_enforce.attr,
	&lustre_attr_enable_remote_subdir_mount.attr,
	NULL,
};

static struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
	{ .name =	"recovery_status",
	  .fops =	&mdt_recovery_status_fops		},
	{ .name =	"identity_info",
	  .fops =	&mdt_identity_info_fops			},
	{ .name =	"site_stats",
	  .fops =	&mdt_site_stats_fops			},
	{ .name =	"evict_client",
	  .fops =	&mdt_mds_evict_client_fops		},
	{ .name =	"checksum_dump",
	  .fops =	&mdt_checksum_dump_fops			},
	{ .name =	"hash_stats",
	  .fops =	&mdt_hash_fops				},
	{ .name =	"root_squash",
	  .fops =	&mdt_root_squash_fops			},
	{ .name =	"nosquash_nids",
	  .fops =	&mdt_nosquash_nids_fops			},
	{ NULL }
};

static int
lprocfs_mdt_print_open_files(struct obd_export *exp, void *v)
{
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

	return obd_nid_export_for_each(stats->nid_obd, stats->nid,
				       lprocfs_mdt_print_open_files, seq);
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

void mdt_counter_incr(struct ptlrpc_request *req, int opcode, long amount)
{
	struct obd_export *exp = req->rq_export;

	if (exp->exp_obd && exp->exp_obd->obd_md_stats)
		lprocfs_counter_add(exp->exp_obd->obd_md_stats,
				    opcode + LPROC_MD_LAST_OPC, amount);
	if (exp->exp_nid_stats && exp->exp_nid_stats->nid_stats != NULL)
		lprocfs_counter_add(exp->exp_nid_stats->nid_stats, opcode,
				    amount);
	if (exp->exp_obd && exp->exp_obd->u.obt.obt_jobstats.ojs_hash &&
	    (exp_connect_flags(exp) & OBD_CONNECT_JOBSTATS))
		lprocfs_job_stats_log(exp->exp_obd,
				      lustre_msg_get_jobid(req->rq_reqmsg),
				      opcode, amount);
}

static const char * const mdt_stats[] = {
	[LPROC_MDT_OPEN]		= "open",
	[LPROC_MDT_CLOSE]		= "close",
	[LPROC_MDT_MKNOD]		= "mknod",
	[LPROC_MDT_LINK]		= "link",
	[LPROC_MDT_UNLINK]		= "unlink",
	[LPROC_MDT_MKDIR]		= "mkdir",
	[LPROC_MDT_RMDIR]		= "rmdir",
	[LPROC_MDT_RENAME]		= "rename",
	[LPROC_MDT_GETATTR]		= "getattr",
	[LPROC_MDT_SETATTR]		= "setattr",
	[LPROC_MDT_GETXATTR]		= "getxattr",
	[LPROC_MDT_SETXATTR]		= "setxattr",
	[LPROC_MDT_STATFS]		= "statfs",
	[LPROC_MDT_SYNC]		= "sync",
	[LPROC_MDT_SAMEDIR_RENAME]	= "samedir_rename",
	[LPROC_MDT_CROSSDIR_RENAME]	= "crossdir_rename",
	[LPROC_MDT_IO_READ]		= "read_bytes",
	[LPROC_MDT_IO_WRITE]		= "write_bytes",
	[LPROC_MDT_IO_PUNCH]		= "punch",
	[LPROC_MDT_MIGRATE]		= "migrate",
};

void mdt_stats_counter_init(struct lprocfs_stats *stats, unsigned int offset)
{
	int array_size = ARRAY_SIZE(mdt_stats);
	int oidx; /* obd_md_stats index */
	int midx; /* mdt_stats index */

	LASSERT(stats && stats->ls_num >= offset + array_size);

	for (midx = 0; midx < array_size; midx++) {
		oidx = midx + offset;
		if (midx == LPROC_MDT_IO_READ || midx == LPROC_MDT_IO_WRITE)
			lprocfs_counter_init(stats, oidx,
					     LPROCFS_TYPE_BYTES_FULL,
					     mdt_stats[midx], "bytes");
		else
			lprocfs_counter_init(stats, oidx,
					     LPROCFS_TYPE_LATENCY,
					     mdt_stats[midx], "usecs");
	}
}

int mdt_tunables_init(struct mdt_device *mdt, const char *name)
{
	struct obd_device *obd = mdt2obd_dev(mdt);
	int rc;

	ENTRY;
	LASSERT(name != NULL);

	obd->obd_ktype.default_attrs = mdt_attrs;
	obd->obd_vars = lprocfs_mdt_obd_vars;
	rc = lprocfs_obd_setup(obd, true);
	if (rc) {
		CERROR("%s: cannot create proc entries: rc = %d\n",
		       mdt_obd_name(mdt), rc);
		return rc;
	}

	rc = tgt_tunables_init(&mdt->mdt_lut);
	if (rc) {
		CERROR("%s: failed to init target tunables: rc = %d\n",
		       mdt_obd_name(mdt), rc);
		return rc;
	}

	rc = hsm_cdt_tunables_init(mdt);
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

	rc = lprocfs_alloc_md_stats(obd, ARRAY_SIZE(mdt_stats));
	if (rc)
		return rc;

	/* add additional MDT md_stats after the default ones */
	mdt_stats_counter_init(obd->obd_md_stats, LPROC_MD_LAST_OPC);
	rc = lprocfs_job_stats_init(obd, ARRAY_SIZE(mdt_stats),
				    mdt_stats_counter_init);

	rc = lproc_mdt_attach_rename_seqstat(mdt);
	if (rc)
		CERROR("%s: MDT can not create rename stats rc = %d\n",
		       mdt_obd_name(mdt), rc);

	RETURN(rc);
}

void mdt_tunables_fini(struct mdt_device *mdt)
{
	struct obd_device *obd = mdt2obd_dev(mdt);

	if (obd->obd_proc_exports_entry != NULL) {
		lprocfs_remove_proc_entry("clear", obd->obd_proc_exports_entry);
		obd->obd_proc_exports_entry = NULL;
	}

	lprocfs_free_per_client_stats(obd);
	/* hsm_cdt_tunables is disabled earlier than this to avoid
	 * coordinator restart.
	 */
	hsm_cdt_tunables_fini(mdt);
	tgt_tunables_fini(&mdt->mdt_lut);
	lprocfs_obd_cleanup(obd);
	lprocfs_free_md_stats(obd);
	lprocfs_free_obd_stats(obd);
	lprocfs_job_stats_fini(obd);
}
