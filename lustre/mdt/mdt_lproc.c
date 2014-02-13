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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2013, Intel Corporation.
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
#include <lnet/lib-lnet.h>

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
        struct timeval now;

        /* this sampling races with updates */
        do_gettimeofday(&now);
        seq_printf(seq, "rename_stats:\n");
        seq_printf(seq, "- %-15s %lu.%lu\n", "snapshot_time:",
                   now.tv_sec, now.tv_usec);

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

static ssize_t mdt_rename_stats_seq_write(struct file *file, const char *buf,
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

int mdt_procfs_init(struct mdt_device *mdt, const char *name)
{
	struct obd_device		*obd = mdt2obd_dev(mdt);
	struct lprocfs_static_vars	 lvars;
	int				 rc;
	ENTRY;

	LASSERT(name != NULL);

	lprocfs_mdt_init_vars(&lvars);
	rc = lprocfs_obd_setup(obd, lvars.obd_vars);
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
		lprocfs_add_simple(obd->obd_proc_exports_entry,
				   "clear", lprocfs_nid_stats_clear_read,
				   lprocfs_nid_stats_clear_write, obd, NULL);
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

static int lprocfs_rd_identity_expire(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%u\n",
                        mdt->mdt_identity_cache->uc_entry_expire);
}

static int lprocfs_wr_identity_expire(struct file *file,
				      const char __user *buffer,
				      unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_identity_cache->uc_entry_expire = val;
        return count;
}

static int lprocfs_rd_identity_acquire_expire(char *page, char **start,
                                              off_t off, int count, int *eof,
                                              void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        *eof = 1;
        return snprintf(page, count, "%u\n",
                        mdt->mdt_identity_cache->uc_acquire_expire);
}

static int lprocfs_wr_identity_acquire_expire(struct file *file,
					      const char __user *buffer,
					      unsigned long count,
					      void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_identity_cache->uc_acquire_expire = val;
        return count;
}

static int lprocfs_rd_identity_upcall(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct upcall_cache *hash = mdt->mdt_identity_cache;
        int len;

	*eof = 1;
	read_lock(&hash->uc_upcall_rwlock);
	len = snprintf(page, count, "%s\n", hash->uc_upcall);
	read_unlock(&hash->uc_upcall_rwlock);
	return len;
}

static int lprocfs_wr_identity_upcall(struct file *file,
				      const char __user *buffer,
				      unsigned long count, void *data)
{
	struct obd_device	*obd = data;
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
	write_lock(&hash->uc_upcall_rwlock);
	sscanf(kernbuf, "%s", hash->uc_upcall);
	write_unlock(&hash->uc_upcall_rwlock);

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

static int lprocfs_wr_identity_flush(struct file *file,
				     const char __user *buffer,
				     unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc, uid;

        rc = lprocfs_write_helper(buffer, count, &uid);
        if (rc)
                return rc;

        mdt_flush_identity(mdt->mdt_identity_cache, uid);
        return count;
}

static int lprocfs_wr_identity_info(struct file *file,
				    const char __user *buffer,
				    unsigned long count, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct identity_downcall_data *param;
	int size = sizeof(*param), rc, checked = 0;

again:
	if (count < size) {
		CERROR("%s: invalid data count = %lu, size = %d\n",
		       mdt_obd_name(mdt), count, size);
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

/* for debug only */
static int lprocfs_rd_capa(char *page, char **start, off_t off,
                           int count, int *eof, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return snprintf(page, count, "capability on: %s %s\n",
			mdt->mdt_lut.lut_oss_capa ? "oss" : "",
			mdt->mdt_lut.lut_mds_capa ? "mds" : "");
}

static int lprocfs_wr_capa(struct file *file, const char __user *buffer,
			   unsigned long count, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	int val, rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0 || val > 3) {
		CERROR("invalid capability mode, only 0/2/3 is accepted.\n"
		       " 0:  disable fid capability\n"
		       " 2:  enable MDS fid capability\n"
		       " 3:  enable both MDS and OSS fid capability\n");
		return -EINVAL;
	}

	/* OSS fid capability needs enable both MDS and OSS fid capability on
	 * MDS */
	if (val == 1) {
		CERROR("can't enable OSS fid capability only, you should use "
		       "'3' to enable both MDS and OSS fid capability.\n");
		return -EINVAL;
	}

	spin_lock(&mdt->mdt_lut.lut_flags_lock);
	mdt->mdt_lut.lut_oss_capa = !!(val & 0x1);
	mdt->mdt_lut.lut_mds_capa = !!(val & 0x2);
	spin_unlock(&mdt->mdt_lut.lut_flags_lock);
	mdt->mdt_capa_conf = 1;
	LCONSOLE_INFO("MDS %s %s MDS fid capability.\n",
		      mdt_obd_name(mdt),
		      mdt->mdt_lut.lut_mds_capa ? "enabled" : "disabled");
	LCONSOLE_INFO("MDS %s %s OSS fid capability.\n",
		      mdt_obd_name(mdt),
		      mdt->mdt_lut.lut_oss_capa ? "enabled" : "disabled");
	return count;
}

static int lprocfs_rd_capa_count(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        return snprintf(page, count, "%d %d\n",
                        capa_count[CAPA_SITE_CLIENT],
                        capa_count[CAPA_SITE_SERVER]);
}

static int lprocfs_rd_site_stats(char *page, char **start, off_t off,
                                 int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return lu_site_stats_print(mdt_lu_site(mdt), page, count);
}

static int lprocfs_rd_capa_timeout(char *page, char **start, off_t off,
                                   int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "%lu\n", mdt->mdt_capa_timeout);
}

static int lprocfs_wr_capa_timeout(struct file *file, const char __user *buffer,
				   unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_capa_timeout = (unsigned long)val;
        mdt->mdt_capa_conf = 1;
        return count;
}

static int lprocfs_rd_ck_timeout(char *page, char **start, off_t off, int count,
                                 int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "%lu\n", mdt->mdt_ck_timeout);
}

static int lprocfs_wr_ck_timeout(struct file *file, const char __user *buffer,
				 unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        mdt->mdt_ck_timeout = (unsigned long)val;
        mdt->mdt_capa_conf = 1;
        return count;
}

#define BUFLEN (UUID_MAX + 4)

static int lprocfs_mdt_wr_evict_client(struct file *file,
				       const char __user *buffer,
				       unsigned long count, void *data)
{
        char *kbuf;
        char *tmpbuf;

        OBD_ALLOC(kbuf, BUFLEN);
        if (kbuf == NULL)
                return -ENOMEM;

        /*
         * OBD_ALLOC() will zero kbuf, but we only copy BUFLEN - 1
         * bytes into kbuf, to ensure that the string is NUL-terminated.
         * UUID_MAX should include a trailing NUL already.
         */
	if (copy_from_user(kbuf, buffer,
			   min_t(unsigned long, BUFLEN - 1, count))) {
                count = -EFAULT;
                goto out;
        }
        tmpbuf = cfs_firststr(kbuf, min_t(unsigned long, BUFLEN - 1, count));

        if (strncmp(tmpbuf, "nid:", 4) != 0) {
                count = lprocfs_wr_evict_client(file, buffer, count, data);
                goto out;
        }

        CERROR("NOT implement evict client by nid %s\n", tmpbuf);

out:
        OBD_FREE(kbuf, BUFLEN);
        return count;
}

#undef BUFLEN

static int lprocfs_rd_sec_level(char *page, char **start, off_t off,
                                int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return snprintf(page, count, "%d\n", mdt->mdt_lut.lut_sec_level);
}

static int lprocfs_wr_sec_level(struct file *file, const char __user *buffer,
				unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;

        if (val > LUSTRE_SEC_ALL || val < LUSTRE_SEC_NONE)
                return -EINVAL;

        if (val == LUSTRE_SEC_SPECIFY) {
                CWARN("security level %d will be supported in future.\n",
                      LUSTRE_SEC_SPECIFY);
                return -EINVAL;
        }

	mdt->mdt_lut.lut_sec_level = val;
	return count;
}

static int lprocfs_rd_cos(char *page, char **start, off_t off,
                              int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "%u\n", mdt_cos_is_enabled(mdt));
}

static int lprocfs_wr_cos(struct file *file, const char __user *buffer,
			  unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int val, rc;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc)
                return rc;
        mdt_enable_cos(mdt, val);
        return count;
}

static int lprocfs_rd_mdt_root_squash(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;

	return snprintf(page, count, "%u:%u\n", squash->rsi_uid,
			squash->rsi_gid);
}

static int lprocfs_wr_mdt_root_squash(struct file *file,
				      const char __user *buffer,
				      unsigned long count, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;

	return lprocfs_wr_root_squash(buffer, count, squash,
				      mdt_obd_name(mdt));
}

static int lprocfs_rd_mdt_nosquash_nids(char *page, char **start, off_t off,
					int count, int *eof, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;
	int rc;

	down_read(&squash->rsi_sem);
	if (!list_empty(&squash->rsi_nosquash_nids)) {
		rc = cfs_print_nidlist(page, count, &squash->rsi_nosquash_nids);
		rc += snprintf(page + rc, count - rc, "\n");
	} else
		rc = snprintf(page, count, "NONE\n");
	up_read(&squash->rsi_sem);

	return rc;
}

static int lprocfs_wr_mdt_nosquash_nids(struct file *file,
					const char __user *buffer,
					unsigned long count, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	struct root_squash_info *squash = &mdt->mdt_squash;

	return lprocfs_wr_nosquash_nids(buffer, count, squash,
					mdt_obd_name(mdt));
}

static int lprocfs_rd_mdt_som(char *page, char **start, off_t off,
                              int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

        return snprintf(page, count, "%sabled\n",
                        mdt->mdt_som_conf ? "en" : "dis");
}

static int lprocfs_wr_mdt_som(struct file *file, const char __user *buffer,
			      unsigned long count, void *data)
{
        struct obd_export *exp;
        struct obd_device *obd = data;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        char kernbuf[16];
        unsigned long val = 0;

        if (count > (sizeof(kernbuf) - 1))
                return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
                return -EFAULT;

        kernbuf[count] = '\0';

        if (!strcmp(kernbuf, "enabled"))
                val = 1;
        else if (strcmp(kernbuf, "disabled"))
                return -EINVAL;

        if (mdt->mdt_som_conf == val)
                return count;

        if (!obd->obd_process_conf) {
                CERROR("Temporary SOM change is not supported, use lctl "
                       "conf_param for permanent setting\n");
                return count;
        }

        /* 1 stands for self export. */
        cfs_list_for_each_entry(exp, &obd->obd_exports, exp_obd_chain) {
                if (exp == obd->obd_self_export)
                        continue;
		if (exp_connect_flags(exp) & OBD_CONNECT_MDS_MDS)
			continue;
                /* Some clients are already connected, skip the change */
                LCONSOLE_INFO("%s is already connected, SOM will be %s on "
                              "the next mount\n", exp->exp_client_uuid.uuid,
                              val ? "enabled" : "disabled");
                return count;
        }

        mdt->mdt_som_conf = val;
        LCONSOLE_INFO("Enabling SOM\n");

        return count;
}

static int lprocfs_rd_enable_remote_dir(char *page, char **start, off_t off,
					int count, int *eof, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return snprintf(page, count, "%u\n", mdt->mdt_enable_remote_dir);
}

static int lprocfs_wr_enable_remote_dir(struct file *file,
					const char __user *buffer,
					unsigned long count, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	__u32 val;
	int rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 1)
		return -ERANGE;

	mdt->mdt_enable_remote_dir = val;
	return count;
}

static int lprocfs_rd_enable_remote_dir_gid(char *page, char **start, off_t off,
					    int count, int *eof, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);

	return snprintf(page, count, "%d\n",
			(int)mdt->mdt_enable_remote_dir_gid);
}

static int lprocfs_wr_enable_remote_dir_gid(struct file *file,
					    const char __user *buffer,
					    unsigned long count, void *data)
{
	struct obd_device *obd = data;
	struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
	__u32 val;
	int rc;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc)
		return rc;

	mdt->mdt_enable_remote_dir_gid = val;
	return count;
}

static struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
	{ "uuid",			lprocfs_rd_uuid, NULL,
					NULL, NULL, 0 },
	{ "recovery_status",		lprocfs_obd_rd_recovery_status, NULL,
					NULL, NULL, 0 },
	{ "num_exports",		lprocfs_rd_num_exports,	NULL,
					NULL, NULL, 0 },
	{ "identity_expire",		lprocfs_rd_identity_expire,
					lprocfs_wr_identity_expire,
					NULL, NULL, 0 },
	{ "identity_acquire_expire",    lprocfs_rd_identity_acquire_expire,
					lprocfs_wr_identity_acquire_expire,
					NULL, NULL, 0 },
	{ "identity_upcall",		lprocfs_rd_identity_upcall,
					lprocfs_wr_identity_upcall,
					NULL, NULL, 0 },
	{ "identity_flush",		NULL, lprocfs_wr_identity_flush,
					NULL, NULL, 0 },
	{ "identity_info",		NULL, lprocfs_wr_identity_info,
					NULL, NULL, 0 },
	{ "capa",			lprocfs_rd_capa,
					lprocfs_wr_capa,
					NULL, NULL, 0 },
	{ "capa_timeout",		lprocfs_rd_capa_timeout,
					lprocfs_wr_capa_timeout,
					NULL, NULL, 0 },
	{ "capa_key_timeout",		lprocfs_rd_ck_timeout,
					lprocfs_wr_ck_timeout,
					NULL, NULL, 0 },
	{ "capa_count",			lprocfs_rd_capa_count, NULL,
					NULL, NULL, 0 },
	{ "site_stats",			lprocfs_rd_site_stats, NULL,
					NULL, NULL, 0 },
	{ "evict_client",		NULL, lprocfs_mdt_wr_evict_client,
					NULL, NULL, 0 },
	{ "hash_stats",			lprocfs_obd_rd_hash, NULL,
					NULL, NULL, 0 },
	{ "sec_level",			lprocfs_rd_sec_level,
					lprocfs_wr_sec_level,
					NULL, NULL, 0 },
	{ "commit_on_sharing",		lprocfs_rd_cos, lprocfs_wr_cos,
					NULL, NULL, 0 },
	{ "root_squash",		lprocfs_rd_mdt_root_squash,
					lprocfs_wr_mdt_root_squash,
					NULL, NULL, 0 },
	{ "nosquash_nids",		lprocfs_rd_mdt_nosquash_nids,
					lprocfs_wr_mdt_nosquash_nids,
					NULL, NULL, 0 },
	{ "som",			lprocfs_rd_mdt_som,
					lprocfs_wr_mdt_som,
					NULL, NULL, 0 },
	{ "instance",			lprocfs_target_rd_instance, NULL,
					NULL, NULL, 0},
	{ "ir_factor",			lprocfs_obd_rd_ir_factor,
					lprocfs_obd_wr_ir_factor,
					NULL, NULL, 0 },
	{ "job_cleanup_interval",       lprocfs_rd_job_interval,
					lprocfs_wr_job_interval,
					NULL, NULL, 0 },
	{ "enable_remote_dir",		lprocfs_rd_enable_remote_dir,
					lprocfs_wr_enable_remote_dir,
					NULL, NULL, 0},
	{ "enable_remote_dir_gid",	lprocfs_rd_enable_remote_dir_gid,
					lprocfs_wr_enable_remote_dir_gid,
					NULL, NULL, 0},
	{ "hsm_control",		lprocfs_rd_hsm_cdt_control,
					lprocfs_wr_hsm_cdt_control,
					NULL, NULL, 0 },
	{ 0 }
};

static struct lprocfs_vars lprocfs_mdt_module_vars[] = {
	{ "num_refs",			lprocfs_rd_numrefs, NULL,
					NULL, NULL, 0 },
        { 0 }
};

void lprocfs_mdt_init_vars(struct lprocfs_static_vars *lvars)
{
	lvars->module_vars  = lprocfs_mdt_module_vars;
	lvars->obd_vars     = lprocfs_mdt_obd_vars;
}

struct lprocfs_vars lprocfs_mds_obd_vars[] = {
	{ "uuid",	lprocfs_rd_uuid, NULL, NULL, NULL, 0 },
	{ 0 }
};

struct lprocfs_vars lprocfs_mds_module_vars[] = {
	{ "num_refs",	lprocfs_rd_numrefs, NULL, NULL, NULL, 0 },
	{ 0 }
};

int lprocfs_mdt_print_open_files(cfs_hash_t *hs, cfs_hash_bd_t *bd,
				 cfs_hlist_node_t *hnode, void *v)
{
	struct obd_export	*exp = cfs_hash_object(hs, hnode);
	struct seq_file		*seq = v;

	if (exp->exp_lock_hash != NULL) {
		struct mdt_export_data  *med = &exp->exp_mdt_data;
		struct mdt_file_data	*mfd;

		spin_lock(&med->med_open_lock);
		cfs_list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
			seq_printf(seq, DFID"\n",
				   PFID(mdt_object_fid(mfd->mfd_object)));
		}
		spin_unlock(&med->med_open_lock);
	}

	return 0;
}

int lprocfs_mdt_open_files_seq_show(struct seq_file *seq, void *v)
{
	struct nid_stat *stats = seq->private;
	struct obd_device *obd = stats->nid_obd;

	cfs_hash_for_each_key(obd->obd_nid_hash, &stats->nid,
			      lprocfs_mdt_print_open_files, seq);

	return 0;
}

int lprocfs_mdt_open_files_seq_open(struct inode *inode, struct file *file)
{
	struct proc_dir_entry	*dp = PDE(inode);
	struct seq_file		*seq;
	struct nid_stat		*tmp;
	int			rc;

	if (LPROCFS_ENTRY_CHECK(dp))
		return -ENOENT;

	tmp = dp->data;
	rc = single_open(file, &lprocfs_mdt_open_files_seq_show, NULL);
	if (rc != 0)
		return rc;

	seq = file->private_data;
	seq->private = tmp;

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
