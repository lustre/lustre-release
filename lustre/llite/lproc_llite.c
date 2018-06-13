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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/version.h>
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
# include <linux/uidgid.h>
#endif
#include <uapi/linux/lustre_param.h>
#include <lprocfs_status.h>
#include <obd_support.h>

#include "llite_internal.h"
#include "vvp_internal.h"

struct proc_dir_entry *proc_lustre_fs_root;

#ifdef CONFIG_PROC_FS
/* /proc/lustre/llite mount point registration */
static const struct file_operations ll_rw_extents_stats_fops;
static const struct file_operations ll_rw_extents_stats_pp_fops;
static const struct file_operations ll_rw_offset_stats_fops;
static __s64 ll_stats_pid_write(const char __user *buf, size_t len);

static int ll_blksize_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct obd_statfs osfs;
	int rc;

	LASSERT(sb != NULL);
	rc = ll_statfs_internal(sb, &osfs,
				cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
				OBD_STATFS_NODELAY);
	if (!rc)
		seq_printf(m, "%u\n", osfs.os_bsize);
	return rc;
}
LPROC_SEQ_FOPS_RO(ll_blksize);

static int ll_stat_blksize_seq_show(struct seq_file *m, void *v)
{
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);

	seq_printf(m, "%u\n", sbi->ll_stat_blksize);

	return 0;
}

static ssize_t ll_stat_blksize_seq_write(struct file *file,
					 const char __user *buffer,
					 size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val != 0 && (val < PAGE_SIZE || (val & (val - 1))) != 0)
		return -ERANGE;

	sbi->ll_stat_blksize = val;

	return count;
}
LPROC_SEQ_FOPS(ll_stat_blksize);

static int ll_kbytestotal_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct obd_statfs osfs;
	int rc;

	LASSERT(sb != NULL);
	rc = ll_statfs_internal(sb, &osfs,
				cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
				OBD_STATFS_NODELAY);
	if (!rc) {
		__u32 blk_size = osfs.os_bsize >> 10;
		__u64 result = osfs.os_blocks;

		while (blk_size >>= 1)
			result <<= 1;

		seq_printf(m, "%llu\n", result);
	}
	return rc;
}
LPROC_SEQ_FOPS_RO(ll_kbytestotal);

static int ll_kbytesfree_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct obd_statfs osfs;
	int rc;

	LASSERT(sb != NULL);
	rc = ll_statfs_internal(sb, &osfs,
				cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
				OBD_STATFS_NODELAY);
	if (!rc) {
		__u32 blk_size = osfs.os_bsize >> 10;
		__u64 result = osfs.os_bfree;

		while (blk_size >>= 1)
			result <<= 1;

		seq_printf(m, "%llu\n", result);
	}
	return rc;
}
LPROC_SEQ_FOPS_RO(ll_kbytesfree);

static int ll_kbytesavail_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct obd_statfs osfs;
	int rc;

	LASSERT(sb != NULL);
	rc = ll_statfs_internal(sb, &osfs,
				cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
				OBD_STATFS_NODELAY);
	if (!rc) {
		__u32 blk_size = osfs.os_bsize >> 10;
		__u64 result = osfs.os_bavail;

		while (blk_size >>= 1)
			result <<= 1;

		seq_printf(m, "%llu\n", result);
	}
	return rc;
}
LPROC_SEQ_FOPS_RO(ll_kbytesavail);

static int ll_filestotal_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct obd_statfs osfs;
	int rc;

	LASSERT(sb != NULL);
	rc = ll_statfs_internal(sb, &osfs,
				cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
				OBD_STATFS_NODELAY);
	if (!rc)
		seq_printf(m, "%llu\n", osfs.os_files);
	return rc;
}
LPROC_SEQ_FOPS_RO(ll_filestotal);

static int ll_filesfree_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct obd_statfs osfs;
	int rc;

	LASSERT(sb != NULL);
	rc = ll_statfs_internal(sb, &osfs,
				cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS),
				OBD_STATFS_NODELAY);
	if (!rc)
		seq_printf(m, "%llu\n", osfs.os_ffree);
	return rc;
}
LPROC_SEQ_FOPS_RO(ll_filesfree);

static int ll_client_type_seq_show(struct seq_file *m, void *v)
{
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);

	LASSERT(sbi != NULL);

	seq_puts(m, "local client\n");
	return 0;
}
LPROC_SEQ_FOPS_RO(ll_client_type);

static int ll_fstype_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;

	LASSERT(sb != NULL);
	seq_printf(m, "%s\n", sb->s_type->name);
	return 0;
}
LPROC_SEQ_FOPS_RO(ll_fstype);

static int ll_sb_uuid_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;

	LASSERT(sb != NULL);
	seq_printf(m, "%s\n", ll_s2sbi(sb)->ll_sb_uuid.uuid);
	return 0;
}
LPROC_SEQ_FOPS_RO(ll_sb_uuid);

static int ll_xattr_cache_seq_show(struct seq_file *m, void *v)
{
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);

	seq_printf(m, "%u\n", sbi->ll_xattr_cache_enabled);
	return 0;
}

static ssize_t ll_xattr_cache_seq_write(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val != 0 && val != 1)
		return -ERANGE;

	if (val == 1 && !(sbi->ll_flags & LL_SBI_XATTR_CACHE))
		return -ENOTSUPP;

	sbi->ll_xattr_cache_enabled = val;
	sbi->ll_xattr_cache_set = 1;

	return count;
}
LPROC_SEQ_FOPS(ll_xattr_cache);

static int ll_site_stats_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;

	/*
	 * See description of statistical counters in struct cl_site, and
	 * struct lu_site.
	 */
	return cl_site_stats_print(lu2cl_site(ll_s2sbi(sb)->ll_site), m);
}
LPROC_SEQ_FOPS_RO(ll_site_stats);

static int ll_max_readahead_mb_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	long pages_number;
	int mult;

	spin_lock(&sbi->ll_lock);
	pages_number = sbi->ll_ra_info.ra_max_pages;
	spin_unlock(&sbi->ll_lock);

	mult = 1 << (20 - PAGE_SHIFT);
	return lprocfs_seq_read_frac_helper(m, pages_number, mult);
}

static ssize_t
ll_max_readahead_mb_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	__s64 pages_number;
	int rc;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &pages_number, 'M');
	if (rc)
		return rc;

	pages_number >>= PAGE_SHIFT;

	if (pages_number < 0 || pages_number > totalram_pages / 2) {
		/* 1/2 of RAM */
		CERROR("%s: can't set max_readahead_mb=%lu > %luMB\n",
		       ll_get_fsname(sb, NULL, 0),
		       (unsigned long)pages_number >> (20 - PAGE_SHIFT),
		       totalram_pages >> (20 - PAGE_SHIFT + 1));
		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_max_pages = pages_number;
	spin_unlock(&sbi->ll_lock);
	return count;
}
LPROC_SEQ_FOPS(ll_max_readahead_mb);

static int ll_max_readahead_per_file_mb_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	long pages_number;
	int mult;

	spin_lock(&sbi->ll_lock);
	pages_number = sbi->ll_ra_info.ra_max_pages_per_file;
	spin_unlock(&sbi->ll_lock);

	mult = 1 << (20 - PAGE_SHIFT);
	return lprocfs_seq_read_frac_helper(m, pages_number, mult);
}

static ssize_t
ll_max_readahead_per_file_mb_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	__s64 pages_number;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &pages_number, 'M');
	if (rc)
		return rc;

	pages_number >>= PAGE_SHIFT;

	if (pages_number < 0 || pages_number > sbi->ll_ra_info.ra_max_pages) {
		CERROR("%s: can't set max_readahead_per_file_mb=%lu > "
		       "max_read_ahead_mb=%lu\n", ll_get_fsname(sb, NULL, 0),
		       (unsigned long)pages_number >> (20 - PAGE_SHIFT),
		       sbi->ll_ra_info.ra_max_pages >> (20 - PAGE_SHIFT));
		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_max_pages_per_file = pages_number;
	spin_unlock(&sbi->ll_lock);
	return count;
}
LPROC_SEQ_FOPS(ll_max_readahead_per_file_mb);

static int ll_max_read_ahead_whole_mb_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	long pages_number;
	int mult;

	spin_lock(&sbi->ll_lock);
	pages_number = sbi->ll_ra_info.ra_max_read_ahead_whole_pages;
	spin_unlock(&sbi->ll_lock);

	mult = 1 << (20 - PAGE_SHIFT);
	return lprocfs_seq_read_frac_helper(m, pages_number, mult);
}

static ssize_t
ll_max_read_ahead_whole_mb_seq_write(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	__s64 pages_number;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &pages_number, 'M');
	if (rc)
		return rc;

	pages_number >>= PAGE_SHIFT;

	/* Cap this at the current max readahead window size, the readahead
	 * algorithm does this anyway so it's pointless to set it larger. */
	if (pages_number < 0 ||
	    pages_number > sbi->ll_ra_info.ra_max_pages_per_file) {
		int pages_shift = 20 - PAGE_SHIFT;
		CERROR("%s: can't set max_read_ahead_whole_mb=%lu > "
		       "max_read_ahead_per_file_mb=%lu\n",
		       ll_get_fsname(sb, NULL, 0),
		       (unsigned long)pages_number >> pages_shift,
		       sbi->ll_ra_info.ra_max_pages_per_file >> pages_shift);
		return -ERANGE;
	}

	spin_lock(&sbi->ll_lock);
	sbi->ll_ra_info.ra_max_read_ahead_whole_pages = pages_number;
	spin_unlock(&sbi->ll_lock);
	return count;
}
LPROC_SEQ_FOPS(ll_max_read_ahead_whole_mb);

static int ll_max_cached_mb_seq_show(struct seq_file *m, void *v)
{
	struct super_block     *sb    = m->private;
	struct ll_sb_info      *sbi   = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;
	int shift = 20 - PAGE_SHIFT;
	long max_cached_mb;
	long unused_mb;

	max_cached_mb = cache->ccc_lru_max >> shift;
	unused_mb = atomic_long_read(&cache->ccc_lru_left) >> shift;
	seq_printf(m, "users: %d\n"
		   "max_cached_mb: %ld\n"
		   "used_mb: %ld\n"
		   "unused_mb: %ld\n"
		   "reclaim_count: %u\n",
		   atomic_read(&cache->ccc_users),
		   max_cached_mb,
		   max_cached_mb - unused_mb,
		   unused_mb,
		   cache->ccc_lru_shrinkers);
	return 0;
}

static ssize_t
ll_max_cached_mb_seq_write(struct file *file, const char __user *buffer,
			   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct cl_client_cache *cache = sbi->ll_cache;
	struct lu_env *env;
	long diff = 0;
	long nrpages = 0;
	__u16 refcheck;
	__s64 pages_number;
	long rc;
	char kernbuf[128];
	ENTRY;

	if (count >= sizeof(kernbuf))
		RETURN(-EINVAL);

	if (copy_from_user(kernbuf, buffer, count))
		RETURN(-EFAULT);
	kernbuf[count] = 0;

	buffer += lprocfs_find_named_value(kernbuf, "max_cached_mb:", &count) -
		  kernbuf;
	rc = lprocfs_str_with_units_to_s64(buffer, count, &pages_number, 'M');
	if (rc)
		RETURN(rc);

	pages_number >>= PAGE_SHIFT;

	if (pages_number < 0 || pages_number > totalram_pages) {
		CERROR("%s: can't set max cache more than %lu MB\n",
		       ll_get_fsname(sb, NULL, 0),
		       totalram_pages >> (20 - PAGE_SHIFT));
		RETURN(-ERANGE);
	}
	/* Allow enough cache so clients can make well-formed RPCs */
	pages_number = max_t(long, pages_number, PTLRPC_MAX_BRW_PAGES);

	spin_lock(&sbi->ll_lock);
	diff = pages_number - cache->ccc_lru_max;
	spin_unlock(&sbi->ll_lock);

	/* easy - add more LRU slots. */
	if (diff >= 0) {
		atomic_long_add(diff, &cache->ccc_lru_left);
		GOTO(out, rc = 0);
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(rc);

	diff = -diff;
	while (diff > 0) {
		long tmp;

		/* reduce LRU budget from free slots. */
		do {
			long ov, nv;

			ov = atomic_long_read(&cache->ccc_lru_left);
			if (ov == 0)
				break;

			nv = ov > diff ? ov - diff : 0;
			rc = atomic_long_cmpxchg(&cache->ccc_lru_left, ov, nv);
			if (likely(ov == rc)) {
				diff -= ov - nv;
				nrpages += ov - nv;
				break;
			}
		} while (1);

		if (diff <= 0)
			break;

		if (sbi->ll_dt_exp == NULL) { /* being initialized */
			rc = -ENODEV;
			break;
		}

		/* difficult - have to ask OSCs to drop LRU slots. */
		tmp = diff << 1;
		rc = obd_set_info_async(env, sbi->ll_dt_exp,
				sizeof(KEY_CACHE_LRU_SHRINK),
				KEY_CACHE_LRU_SHRINK,
				sizeof(tmp), &tmp, NULL);
		if (rc < 0)
			break;
	}
	cl_env_put(env, &refcheck);

out:
	if (rc >= 0) {
		spin_lock(&sbi->ll_lock);
		cache->ccc_lru_max = pages_number;
		spin_unlock(&sbi->ll_lock);
		rc = count;
	} else {
		atomic_long_add(nrpages, &cache->ccc_lru_left);
	}
	return rc;
}
LPROC_SEQ_FOPS(ll_max_cached_mb);

static int ll_checksum_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n", (sbi->ll_flags & LL_SBI_CHECKSUM) ? 1 : 0);
	return 0;
}

static ssize_t ll_checksum_seq_write(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);
	int rc;
	__s64 val;

	if (!sbi->ll_dt_exp)
		/* Not set up yet */
		return -EAGAIN;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val)
		sbi->ll_flags |= LL_SBI_CHECKSUM;
	else
		sbi->ll_flags &= ~LL_SBI_CHECKSUM;

	rc = obd_set_info_async(NULL, sbi->ll_dt_exp, sizeof(KEY_CHECKSUM),
				KEY_CHECKSUM, sizeof(val), &val, NULL);
	if (rc)
		CWARN("Failed to set OSC checksum flags: %d\n", rc);

	return count;
}
LPROC_SEQ_FOPS(ll_checksum);

static int ll_rd_track_id(struct seq_file *m, enum stats_track_type type)
{
	struct super_block *sb = m->private;

	if (ll_s2sbi(sb)->ll_stats_track_type == type) {
		seq_printf(m, "%d\n",
			   ll_s2sbi(sb)->ll_stats_track_id);
	} else if (ll_s2sbi(sb)->ll_stats_track_type == STATS_TRACK_ALL) {
		seq_puts(m, "0 (all)\n");
	} else {
		seq_puts(m, "untracked\n");
	}
	return 0;
}

static int ll_wr_track_id(const char __user *buffer, unsigned long count,
			  void *data, enum stats_track_type type)
{
	struct super_block *sb = data;
	int rc;
	__s64 pid;

	rc = lprocfs_str_to_s64(buffer, count, &pid);
	if (rc)
		return rc;
	if (pid > INT_MAX || pid < 0)
		return -ERANGE;

	ll_s2sbi(sb)->ll_stats_track_id = pid;
	if (pid == 0)
		ll_s2sbi(sb)->ll_stats_track_type = STATS_TRACK_ALL;
	else
		ll_s2sbi(sb)->ll_stats_track_type = type;
	lprocfs_clear_stats(ll_s2sbi(sb)->ll_stats);
	return count;
}

static int ll_track_pid_seq_show(struct seq_file *m, void *v)
{
	return ll_rd_track_id(m, STATS_TRACK_PID);
}

static ssize_t ll_track_pid_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	return ll_wr_track_id(buffer, count, seq->private, STATS_TRACK_PID);
}
LPROC_SEQ_FOPS(ll_track_pid);

static int ll_track_ppid_seq_show(struct seq_file *m, void *v)
{
	return ll_rd_track_id(m, STATS_TRACK_PPID);
}

static ssize_t ll_track_ppid_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	return ll_wr_track_id(buffer, count, seq->private, STATS_TRACK_PPID);
}
LPROC_SEQ_FOPS(ll_track_ppid);

static int ll_track_gid_seq_show(struct seq_file *m, void *v)
{
	return ll_rd_track_id(m, STATS_TRACK_GID);
}

static ssize_t ll_track_gid_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	return ll_wr_track_id(buffer, count, seq->private, STATS_TRACK_GID);
}
LPROC_SEQ_FOPS(ll_track_gid);

static int ll_statahead_running_max_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n", sbi->ll_sa_running_max);
	return 0;
}

static ssize_t ll_statahead_running_max_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val >= 0 || val <= LL_SA_RUNNING_MAX)
		sbi->ll_sa_running_max = val;
	else
		CERROR("%s: bad statahead_running_max value %lld. Valid values "
		       "are in the range [0, %u]\n", ll_get_fsname(sb, NULL, 0),
		       val, LL_SA_RUNNING_MAX);

	return count;
}
LPROC_SEQ_FOPS(ll_statahead_running_max);

static int ll_statahead_max_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n", sbi->ll_sa_max);
	return 0;
}

static ssize_t ll_statahead_max_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val >= 0 && val <= LL_SA_RPC_MAX)
		sbi->ll_sa_max = val;
	else
		CERROR("%s: bad statahead_max value %lld. Valid values are in "
		       "are in the range [0, %u]\n", ll_get_fsname(sb, NULL, 0),
		       val, LL_SA_RPC_MAX);

	return count;
}
LPROC_SEQ_FOPS(ll_statahead_max);

static int ll_statahead_agl_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n",
		   sbi->ll_flags & LL_SBI_AGL_ENABLED ? 1 : 0);
	return 0;
}

static ssize_t ll_statahead_agl_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val)
		sbi->ll_flags |= LL_SBI_AGL_ENABLED;
	else
		sbi->ll_flags &= ~LL_SBI_AGL_ENABLED;

	return count;
}
LPROC_SEQ_FOPS(ll_statahead_agl);

static int ll_statahead_stats_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "statahead total: %u\n"
		    "statahead wrong: %u\n"
		    "agl total: %u\n",
		    atomic_read(&sbi->ll_sa_total),
		    atomic_read(&sbi->ll_sa_wrong),
		    atomic_read(&sbi->ll_agl_total));
	return 0;
}
LPROC_SEQ_FOPS_RO(ll_statahead_stats);

static int ll_lazystatfs_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n",
		   (sbi->ll_flags & LL_SBI_LAZYSTATFS) ? 1 : 0);
	return 0;
}

static ssize_t ll_lazystatfs_seq_write(struct file *file,
				       const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)m->private);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val)
		sbi->ll_flags |= LL_SBI_LAZYSTATFS;
	else
		sbi->ll_flags &= ~LL_SBI_LAZYSTATFS;

	return count;
}
LPROC_SEQ_FOPS(ll_lazystatfs);

static int ll_max_easize_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	unsigned int ealen;
	int rc;

	rc = ll_get_max_mdsize(sbi, &ealen);
	if (rc)
		return rc;

	seq_printf(m, "%u\n", ealen);
	return 0;
}
LPROC_SEQ_FOPS_RO(ll_max_easize);

/**
 * Get default_easize.
 *
 * \see client_obd::cl_default_mds_easize
 *
 * \param[in] m		seq_file handle
 * \param[in] v		unused for single entry
 *
 * \retval 0		on success
 * \retval negative	negated errno on failure
 */
static int ll_default_easize_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	unsigned int ealen;
	int rc;

	rc = ll_get_default_mdsize(sbi, &ealen);
	if (rc)
		return rc;

	seq_printf(m, "%u\n", ealen);
	return 0;
}

/**
 * Set default_easize.
 *
 * Range checking on the passed value is handled by
 * ll_set_default_mdsize().
 *
 * \see client_obd::cl_default_mds_easize
 *
 * \param[in] file	proc file
 * \param[in] buffer	string passed from user space
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval positive	\a count on success
 * \retval negative	negated errno on failure
 */
static ssize_t ll_default_easize_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *unused)
{
	struct seq_file	*seq = file->private_data;
	struct super_block *sb = (struct super_block *)seq->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	__s64 val;
	int rc;

	if (count == 0)
		return 0;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	rc = ll_set_default_mdsize(sbi, val);
	if (rc)
		return rc;

	return count;
}
LPROC_SEQ_FOPS(ll_default_easize);

static int ll_sbi_flags_seq_show(struct seq_file *m, void *v)
{
	const char *str[] = LL_SBI_FLAGS;
	struct super_block *sb = m->private;
	int flags = ll_s2sbi(sb)->ll_flags;
	int i = 0;

	while (flags != 0) {
		if (ARRAY_SIZE(str) <= i) {
			CERROR("%s: Revise array LL_SBI_FLAGS to match sbi "
				"flags please.\n", ll_get_fsname(sb, NULL, 0));
			return -EINVAL;
		}

		if (flags & 0x1)
			seq_printf(m, "%s ", str[i]);
		flags >>= 1;
		++i;
	}
	seq_printf(m, "\b\n");
	return 0;
}
LPROC_SEQ_FOPS_RO(ll_sbi_flags);

static int ll_fast_read_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n", !!(sbi->ll_flags & LL_SBI_FAST_READ));
	return 0;
}

static ssize_t
ll_fast_read_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val == 1)
		sbi->ll_flags |= LL_SBI_FAST_READ;
	else
		sbi->ll_flags &= ~LL_SBI_FAST_READ;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LPROC_SEQ_FOPS(ll_fast_read);

static int ll_pio_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	seq_printf(m, "%u\n", !!(sbi->ll_flags & LL_SBI_PIO));
	return 0;
}

static ssize_t ll_pio_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	spin_lock(&sbi->ll_lock);
	if (val == 1)
		sbi->ll_flags |= LL_SBI_PIO;
	else
		sbi->ll_flags &= ~LL_SBI_PIO;
	spin_unlock(&sbi->ll_lock);

	return count;
}
LPROC_SEQ_FOPS(ll_pio);

static int ll_unstable_stats_seq_show(struct seq_file *m, void *v)
{
	struct super_block	*sb    = m->private;
	struct ll_sb_info	*sbi   = ll_s2sbi(sb);
	struct cl_client_cache	*cache = sbi->ll_cache;
	long pages;
	int mb;

	pages = atomic_long_read(&cache->ccc_unstable_nr);
	mb    = (pages * PAGE_SIZE) >> 20;

	seq_printf(m, "unstable_check:     %8d\n"
		   "unstable_pages: %12ld\n"
		   "unstable_mb:        %8d\n",
		   cache->ccc_unstable_check, pages, mb);
	return 0;
}

static ssize_t ll_unstable_stats_seq_write(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *unused)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = ll_s2sbi((struct super_block *)seq->private);
	char kernbuf[128];
	int rc;
	__s64 val;

	if (count == 0)
		return 0;
	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	buffer += lprocfs_find_named_value(kernbuf, "unstable_check:", &count) -
		  kernbuf;
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc < 0)
		return rc;

	/* borrow lru lock to set the value */
	spin_lock(&sbi->ll_cache->ccc_lru_lock);
	sbi->ll_cache->ccc_unstable_check = !!val;
	spin_unlock(&sbi->ll_cache->ccc_lru_lock);

	return count;
}
LPROC_SEQ_FOPS(ll_unstable_stats);

static int ll_root_squash_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;

	seq_printf(m, "%u:%u\n", squash->rsi_uid, squash->rsi_gid);
	return 0;
}

static ssize_t ll_root_squash_seq_write(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;

	return lprocfs_wr_root_squash(buffer, count, squash,
				      ll_get_fsname(sb, NULL, 0));
}
LPROC_SEQ_FOPS(ll_root_squash);

static int ll_nosquash_nids_seq_show(struct seq_file *m, void *v)
{
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;
	int len;

	down_read(&squash->rsi_sem);
	if (!list_empty(&squash->rsi_nosquash_nids)) {
		len = cfs_print_nidlist(m->buf + m->count, m->size - m->count,
					&squash->rsi_nosquash_nids);
		m->count += len;
		seq_putc(m, '\n');
	} else {
		seq_puts(m, "NONE\n");
	}
	up_read(&squash->rsi_sem);

	return 0;
}

static ssize_t ll_nosquash_nids_seq_write(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct super_block *sb = m->private;
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct root_squash_info *squash = &sbi->ll_squash;
	int rc;

	rc = lprocfs_wr_nosquash_nids(buffer, count, squash,
				      ll_get_fsname(sb, NULL, 0));
	if (rc < 0)
		return rc;

	ll_compute_rootsquash_state(sbi);

	return rc;
}
LPROC_SEQ_FOPS(ll_nosquash_nids);

struct lprocfs_vars lprocfs_llite_obd_vars[] = {
	{ .name	=	"uuid",
	  .fops	=	&ll_sb_uuid_fops			},
	{ .name	=	"fstype",
	  .fops	=	&ll_fstype_fops				},
	{ .name	=	"site",
	  .fops	=	&ll_site_stats_fops			},
	{ .name	=	"blocksize",
	  .fops	=	&ll_blksize_fops			},
	{ .name	=	"stat_blocksize",
	  .fops	=	&ll_stat_blksize_fops			},
	{ .name	=	"kbytestotal",
	  .fops	=	&ll_kbytestotal_fops			},
	{ .name	=	"kbytesfree",
	  .fops	=	&ll_kbytesfree_fops			},
	{ .name	=	"kbytesavail",
	  .fops	=	&ll_kbytesavail_fops			},
	{ .name	=	"filestotal",
	  .fops	=	&ll_filestotal_fops			},
	{ .name	=	"filesfree",
	  .fops	=	&ll_filesfree_fops			},
	{ .name	=	"client_type",
	  .fops	=	&ll_client_type_fops			},
	{ .name	=	"max_read_ahead_mb",
	  .fops	=	&ll_max_readahead_mb_fops		},
	{ .name	=	"max_read_ahead_per_file_mb",
	  .fops	=	&ll_max_readahead_per_file_mb_fops	},
	{ .name	=	"max_read_ahead_whole_mb",
	  .fops	=	&ll_max_read_ahead_whole_mb_fops	},
	{ .name	=	"max_cached_mb",
	  .fops	=	&ll_max_cached_mb_fops			},
	{ .name	=	"checksum_pages",
	  .fops	=	&ll_checksum_fops			},
	{ .name	=	"stats_track_pid",
	  .fops	=	&ll_track_pid_fops			},
	{ .name	=	"stats_track_ppid",
	  .fops	=	&ll_track_ppid_fops			},
	{ .name	=	"stats_track_gid",
	  .fops	=	&ll_track_gid_fops			},
	{ .name	=	"statahead_max",
	  .fops	=	&ll_statahead_max_fops			},
	{ .name	=	"statahead_running_max",
	  .fops	=	&ll_statahead_running_max_fops		},
	{ .name	=	"statahead_agl",
	  .fops	=	&ll_statahead_agl_fops			},
	{ .name	=	"statahead_stats",
	  .fops	=	&ll_statahead_stats_fops		},
	{ .name	=	"lazystatfs",
	  .fops	=	&ll_lazystatfs_fops			},
	{ .name	=	"max_easize",
	  .fops	=	&ll_max_easize_fops			},
	{ .name	=	"default_easize",
	  .fops	=	&ll_default_easize_fops			},
	{ .name	=	"sbi_flags",
	  .fops	=	&ll_sbi_flags_fops			},
	{ .name	=	"xattr_cache",
	  .fops	=	&ll_xattr_cache_fops			},
	{ .name	=	"unstable_stats",
	  .fops	=	&ll_unstable_stats_fops			},
	{ .name	=	"root_squash",
	  .fops	=	&ll_root_squash_fops			},
	{ .name	=	"nosquash_nids",
	  .fops	=	&ll_nosquash_nids_fops			},
	{ .name =	"fast_read",
	  .fops =	&ll_fast_read_fops,			},
	{ .name =	"pio",
	  .fops =	&ll_pio_fops,				},
	{ NULL }
};

#define MAX_STRING_SIZE 128

static const struct llite_file_opcode {
        __u32       opcode;
        __u32       type;
        const char *opname;
} llite_opcode_table[LPROC_LL_FILE_OPCODES] = {
        /* file operation */
        { LPROC_LL_DIRTY_HITS,     LPROCFS_TYPE_REGS, "dirty_pages_hits" },
        { LPROC_LL_DIRTY_MISSES,   LPROCFS_TYPE_REGS, "dirty_pages_misses" },
        { LPROC_LL_READ_BYTES,     LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_BYTES,
                                   "read_bytes" },
        { LPROC_LL_WRITE_BYTES,    LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_BYTES,
                                   "write_bytes" },
        { LPROC_LL_BRW_READ,       LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "brw_read" },
        { LPROC_LL_BRW_WRITE,      LPROCFS_CNTR_AVGMINMAX|LPROCFS_TYPE_PAGES,
                                   "brw_write" },
        { LPROC_LL_IOCTL,          LPROCFS_TYPE_REGS, "ioctl" },
        { LPROC_LL_OPEN,           LPROCFS_TYPE_REGS, "open" },
        { LPROC_LL_RELEASE,        LPROCFS_TYPE_REGS, "close" },
        { LPROC_LL_MAP,            LPROCFS_TYPE_REGS, "mmap" },
	{ LPROC_LL_FAULT,          LPROCFS_TYPE_REGS, "page_fault" },
	{ LPROC_LL_MKWRITE,        LPROCFS_TYPE_REGS, "page_mkwrite" },
        { LPROC_LL_LLSEEK,         LPROCFS_TYPE_REGS, "seek" },
        { LPROC_LL_FSYNC,          LPROCFS_TYPE_REGS, "fsync" },
        { LPROC_LL_READDIR,        LPROCFS_TYPE_REGS, "readdir" },
        /* inode operation */
        { LPROC_LL_SETATTR,        LPROCFS_TYPE_REGS, "setattr" },
        { LPROC_LL_TRUNC,          LPROCFS_TYPE_REGS, "truncate" },
        { LPROC_LL_FLOCK,          LPROCFS_TYPE_REGS, "flock" },
        { LPROC_LL_GETATTR,        LPROCFS_TYPE_REGS, "getattr" },
        /* dir inode operation */
        { LPROC_LL_CREATE,         LPROCFS_TYPE_REGS, "create" },
        { LPROC_LL_LINK,           LPROCFS_TYPE_REGS, "link" },
        { LPROC_LL_UNLINK,         LPROCFS_TYPE_REGS, "unlink" },
        { LPROC_LL_SYMLINK,        LPROCFS_TYPE_REGS, "symlink" },
        { LPROC_LL_MKDIR,          LPROCFS_TYPE_REGS, "mkdir" },
        { LPROC_LL_RMDIR,          LPROCFS_TYPE_REGS, "rmdir" },
        { LPROC_LL_MKNOD,          LPROCFS_TYPE_REGS, "mknod" },
        { LPROC_LL_RENAME,         LPROCFS_TYPE_REGS, "rename" },
        /* special inode operation */
        { LPROC_LL_STAFS,          LPROCFS_TYPE_REGS, "statfs" },
        { LPROC_LL_ALLOC_INODE,    LPROCFS_TYPE_REGS, "alloc_inode" },
        { LPROC_LL_SETXATTR,       LPROCFS_TYPE_REGS, "setxattr" },
        { LPROC_LL_GETXATTR,       LPROCFS_TYPE_REGS, "getxattr" },
	{ LPROC_LL_GETXATTR_HITS,  LPROCFS_TYPE_REGS, "getxattr_hits" },
        { LPROC_LL_LISTXATTR,      LPROCFS_TYPE_REGS, "listxattr" },
        { LPROC_LL_REMOVEXATTR,    LPROCFS_TYPE_REGS, "removexattr" },
        { LPROC_LL_INODE_PERM,     LPROCFS_TYPE_REGS, "inode_permission" },
};

void ll_stats_ops_tally(struct ll_sb_info *sbi, int op, int count)
{
        if (!sbi->ll_stats)
                return;
        if (sbi->ll_stats_track_type == STATS_TRACK_ALL)
                lprocfs_counter_add(sbi->ll_stats, op, count);
        else if (sbi->ll_stats_track_type == STATS_TRACK_PID &&
                 sbi->ll_stats_track_id == current->pid)
                lprocfs_counter_add(sbi->ll_stats, op, count);
        else if (sbi->ll_stats_track_type == STATS_TRACK_PPID &&
                 sbi->ll_stats_track_id == current->parent->pid)
                lprocfs_counter_add(sbi->ll_stats, op, count);
	else if (sbi->ll_stats_track_type == STATS_TRACK_GID &&
		 sbi->ll_stats_track_id ==
			from_kgid(&init_user_ns, current_gid()))
		lprocfs_counter_add(sbi->ll_stats, op, count);
}
EXPORT_SYMBOL(ll_stats_ops_tally);

static const char *ra_stat_string[] = {
	[RA_STAT_HIT] = "hits",
	[RA_STAT_MISS] = "misses",
	[RA_STAT_DISTANT_READPAGE] = "readpage not consecutive",
	[RA_STAT_MISS_IN_WINDOW] = "miss inside window",
	[RA_STAT_FAILED_GRAB_PAGE] = "failed grab_cache_page",
	[RA_STAT_FAILED_MATCH] = "failed lock match",
	[RA_STAT_DISCARDED] = "read but discarded",
	[RA_STAT_ZERO_LEN] = "zero length file",
	[RA_STAT_ZERO_WINDOW] = "zero size window",
	[RA_STAT_EOF] = "read-ahead to EOF",
	[RA_STAT_MAX_IN_FLIGHT] = "hit max r-a issue",
	[RA_STAT_WRONG_GRAB_PAGE] = "wrong page from grab_cache_page",
	[RA_STAT_FAILED_REACH_END] = "failed to reach end"
};

LPROC_SEQ_FOPS_RO_TYPE(llite, name);
LPROC_SEQ_FOPS_RO_TYPE(llite, uuid);

int lprocfs_ll_register_mountpoint(struct proc_dir_entry *parent,
				   struct super_block *sb)
{
	struct lprocfs_vars lvars[2];
	struct lustre_sb_info *lsi = s2lsi(sb);
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	char name[MAX_STRING_SIZE + 1], *ptr;
	int err, id, len, rc;
	ENTRY;

	memset(lvars, 0, sizeof(lvars));

	name[MAX_STRING_SIZE] = '\0';
	lvars[0].name = name;

	LASSERT(sbi != NULL);

	/* Get fsname */
	len = strlen(lsi->lsi_lmd->lmd_profile);
	ptr = strrchr(lsi->lsi_lmd->lmd_profile, '-');
	if (ptr && (strcmp(ptr, "-client") == 0))
		len -= 7;

	/* Mount info */
	snprintf(name, MAX_STRING_SIZE, "%.*s-%p", len,
		 lsi->lsi_lmd->lmd_profile, sb);

	sbi->ll_proc_root = lprocfs_register(name, parent, NULL, NULL);
	if (IS_ERR(sbi->ll_proc_root)) {
		err = PTR_ERR(sbi->ll_proc_root);
		sbi->ll_proc_root = NULL;
		RETURN(err);
	}

	rc = lprocfs_seq_create(sbi->ll_proc_root, "dump_page_cache", 0444,
				&vvp_dump_pgcache_file_ops, sbi);
	if (rc)
		CWARN("Error adding the dump_page_cache file\n");

	rc = lprocfs_seq_create(sbi->ll_proc_root, "extents_stats", 0644,
				&ll_rw_extents_stats_fops, sbi);
	if (rc)
		CWARN("Error adding the extent_stats file\n");

	rc = lprocfs_seq_create(sbi->ll_proc_root, "extents_stats_per_process",
				0644, &ll_rw_extents_stats_pp_fops, sbi);
	if (rc)
		CWARN("Error adding the extents_stats_per_process file\n");

	rc = lprocfs_seq_create(sbi->ll_proc_root, "offset_stats", 0644,
				&ll_rw_offset_stats_fops, sbi);
	if (rc)
		CWARN("Error adding the offset_stats file\n");

	/* File operations stats */
	sbi->ll_stats = lprocfs_alloc_stats(LPROC_LL_FILE_OPCODES,
					    LPROCFS_STATS_FLAG_NONE);
	if (sbi->ll_stats == NULL)
		GOTO(out, err = -ENOMEM);
	/* do counter init */
	for (id = 0; id < LPROC_LL_FILE_OPCODES; id++) {
		__u32 type = llite_opcode_table[id].type;
		void *ptr = NULL;
		if (type & LPROCFS_TYPE_REGS)
			ptr = "regs";
		else if (type & LPROCFS_TYPE_BYTES)
			ptr = "bytes";
		else if (type & LPROCFS_TYPE_PAGES)
			ptr = "pages";
		lprocfs_counter_init(sbi->ll_stats,
				     llite_opcode_table[id].opcode,
				     (type & LPROCFS_CNTR_AVGMINMAX),
				     llite_opcode_table[id].opname, ptr);
	}
	err = lprocfs_register_stats(sbi->ll_proc_root, "stats", sbi->ll_stats);
	if (err)
		GOTO(out, err);

	sbi->ll_ra_stats = lprocfs_alloc_stats(ARRAY_SIZE(ra_stat_string),
					       LPROCFS_STATS_FLAG_NONE);
	if (sbi->ll_ra_stats == NULL)
		GOTO(out, err = -ENOMEM);

	for (id = 0; id < ARRAY_SIZE(ra_stat_string); id++)
		lprocfs_counter_init(sbi->ll_ra_stats, id, 0,
				     ra_stat_string[id], "pages");
	err = lprocfs_register_stats(sbi->ll_proc_root, "read_ahead_stats",
				     sbi->ll_ra_stats);
	if (err)
		GOTO(out, err);


	err = lprocfs_add_vars(sbi->ll_proc_root, lprocfs_llite_obd_vars, sb);
	if (err)
		GOTO(out, err);

out:
	if (err) {
		lprocfs_remove(&sbi->ll_proc_root);
		lprocfs_free_stats(&sbi->ll_ra_stats);
		lprocfs_free_stats(&sbi->ll_stats);
	}
	RETURN(err);
}

int lprocfs_ll_register_obd(struct super_block *sb, const char *obdname)
{
	struct lprocfs_vars lvars[2];
	struct ll_sb_info *sbi = ll_s2sbi(sb);
	struct obd_device *obd;
	struct proc_dir_entry *dir;
	char name[MAX_STRING_SIZE + 1];
	int err;
	ENTRY;

	memset(lvars, 0, sizeof(lvars));

	name[MAX_STRING_SIZE] = '\0';
	lvars[0].name = name;

	LASSERT(sbi != NULL);
	LASSERT(obdname != NULL);

	obd = class_name2obd(obdname);

	LASSERT(obd != NULL);
	LASSERT(obd->obd_magic == OBD_DEVICE_MAGIC);
	LASSERT(obd->obd_type->typ_name != NULL);

	dir = proc_mkdir(obd->obd_type->typ_name, sbi->ll_proc_root);
	if (dir == NULL)
		GOTO(out, err = -ENOMEM);

	snprintf(name, MAX_STRING_SIZE, "common_name");
	lvars[0].fops = &llite_name_fops;
	err = lprocfs_add_vars(dir, lvars, obd);
	if (err)
		GOTO(out, err);

	snprintf(name, MAX_STRING_SIZE, "uuid");
	lvars[0].fops = &llite_uuid_fops;
	err = lprocfs_add_vars(dir, lvars, obd);
	if (err)
		GOTO(out, err);

out:
	if (err) {
		lprocfs_remove(&sbi->ll_proc_root);
		lprocfs_free_stats(&sbi->ll_ra_stats);
		lprocfs_free_stats(&sbi->ll_stats);
	}
	RETURN(err);
}

void lprocfs_ll_unregister_mountpoint(struct ll_sb_info *sbi)
{
        if (sbi->ll_proc_root) {
                lprocfs_remove(&sbi->ll_proc_root);
                lprocfs_free_stats(&sbi->ll_ra_stats);
                lprocfs_free_stats(&sbi->ll_stats);
        }
}
#undef MAX_STRING_SIZE

#define pct(a,b) (b ? a * 100 / b : 0)

static void ll_display_extents_info(struct ll_rw_extents_info *io_extents,
                                   struct seq_file *seq, int which)
{
        unsigned long read_tot = 0, write_tot = 0, read_cum, write_cum;
        unsigned long start, end, r, w;
        char *unitp = "KMGTPEZY";
        int i, units = 10;
        struct per_process_info *pp_info = &io_extents->pp_extents[which];

        read_cum = 0;
        write_cum = 0;
        start = 0;

        for(i = 0; i < LL_HIST_MAX; i++) {
                read_tot += pp_info->pp_r_hist.oh_buckets[i];
                write_tot += pp_info->pp_w_hist.oh_buckets[i];
        }

        for(i = 0; i < LL_HIST_MAX; i++) {
                r = pp_info->pp_r_hist.oh_buckets[i];
                w = pp_info->pp_w_hist.oh_buckets[i];
                read_cum += r;
                write_cum += w;
                end = 1 << (i + LL_HIST_START - units);
                seq_printf(seq, "%4lu%c - %4lu%c%c: %14lu %4lu %4lu  | "
                           "%14lu %4lu %4lu\n", start, *unitp, end, *unitp,
                           (i == LL_HIST_MAX - 1) ? '+' : ' ',
                           r, pct(r, read_tot), pct(read_cum, read_tot),
                           w, pct(w, write_tot), pct(write_cum, write_tot));
                start = end;
                if (start == 1<<10) {
                        start = 1;
                        units += 10;
                        unitp++;
                }
                if (read_cum == read_tot && write_cum == write_tot)
                        break;
        }
}

static int ll_rw_extents_stats_pp_seq_show(struct seq_file *seq, void *v)
{
	struct timespec64 now;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *io_extents = &sbi->ll_rw_extents_info;
	int k;

	ktime_get_real_ts64(&now);

	if (!sbi->ll_rw_stats_on) {
		seq_puts(seq, "disabled\n write anything to this file to activate, then '0' or 'disable' to deactivate\n");
		return 0;
	}
	seq_printf(seq, "snapshot_time:         %llu.%09lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);
        seq_printf(seq, "%15s %19s       | %20s\n", " ", "read", "write");
        seq_printf(seq, "%13s   %14s %4s %4s  | %14s %4s %4s\n",
                   "extents", "calls", "%", "cum%",
                   "calls", "%", "cum%");
	spin_lock(&sbi->ll_pp_extent_lock);
	for (k = 0; k < LL_PROCESS_HIST_MAX; k++) {
		if (io_extents->pp_extents[k].pid != 0) {
			seq_printf(seq, "\nPID: %d\n",
				   io_extents->pp_extents[k].pid);
			ll_display_extents_info(io_extents, seq, k);
		}
	}
	spin_unlock(&sbi->ll_pp_extent_lock);
	return 0;
}

static ssize_t ll_rw_extents_stats_pp_seq_write(struct file *file,
						const char __user *buf,
						size_t len,
						loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *io_extents = &sbi->ll_rw_extents_info;
	int i;
	__s64 value;

	if (len == 0)
		return -EINVAL;

	value = ll_stats_pid_write(buf, len);

	if (value == 0)
		sbi->ll_rw_stats_on = 0;
	else
		sbi->ll_rw_stats_on = 1;

	spin_lock(&sbi->ll_pp_extent_lock);
	for (i = 0; i < LL_PROCESS_HIST_MAX; i++) {
		io_extents->pp_extents[i].pid = 0;
		lprocfs_oh_clear(&io_extents->pp_extents[i].pp_r_hist);
		lprocfs_oh_clear(&io_extents->pp_extents[i].pp_w_hist);
	}
	spin_unlock(&sbi->ll_pp_extent_lock);
	return len;
}

LPROC_SEQ_FOPS(ll_rw_extents_stats_pp);

static int ll_rw_extents_stats_seq_show(struct seq_file *seq, void *v)
{
	struct timespec64 now;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *io_extents = &sbi->ll_rw_extents_info;

	ktime_get_real_ts64(&now);

	if (!sbi->ll_rw_stats_on) {
		seq_puts(seq, "disabled\n write anything to this file to activate, then '0' or 'disable' to deactivate\n");
		return 0;
	}
	seq_printf(seq, "snapshot_time:         %llu.%09lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);

	seq_printf(seq, "%15s %19s       | %20s\n", " ", "read", "write");
	seq_printf(seq, "%13s   %14s %4s %4s  | %14s %4s %4s\n",
		   "extents", "calls", "%", "cum%",
		   "calls", "%", "cum%");
	spin_lock(&sbi->ll_lock);
	ll_display_extents_info(io_extents, seq, LL_PROCESS_HIST_MAX);
	spin_unlock(&sbi->ll_lock);

	return 0;
}

static ssize_t ll_rw_extents_stats_seq_write(struct file *file,
					     const char __user *buf,
					     size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_extents_info *io_extents = &sbi->ll_rw_extents_info;
	int i;
	__s64 value;

	if (len == 0)
		return -EINVAL;

	value = ll_stats_pid_write(buf, len);

	if (value == 0)
		sbi->ll_rw_stats_on = 0;
	else
		sbi->ll_rw_stats_on = 1;

	spin_lock(&sbi->ll_pp_extent_lock);
	for (i = 0; i <= LL_PROCESS_HIST_MAX; i++) {
		io_extents->pp_extents[i].pid = 0;
		lprocfs_oh_clear(&io_extents->pp_extents[i].pp_r_hist);
		lprocfs_oh_clear(&io_extents->pp_extents[i].pp_w_hist);
	}
	spin_unlock(&sbi->ll_pp_extent_lock);

	return len;
}
LPROC_SEQ_FOPS(ll_rw_extents_stats);

void ll_rw_stats_tally(struct ll_sb_info *sbi, pid_t pid,
                       struct ll_file_data *file, loff_t pos,
                       size_t count, int rw)
{
        int i, cur = -1;
        struct ll_rw_process_info *process;
        struct ll_rw_process_info *offset;
        int *off_count = &sbi->ll_rw_offset_entry_count;
        int *process_count = &sbi->ll_offset_process_count;
        struct ll_rw_extents_info *io_extents = &sbi->ll_rw_extents_info;

        if(!sbi->ll_rw_stats_on)
                return;
        process = sbi->ll_rw_process_info;
        offset = sbi->ll_rw_offset_info;

	spin_lock(&sbi->ll_pp_extent_lock);
        /* Extent statistics */
        for(i = 0; i < LL_PROCESS_HIST_MAX; i++) {
                if(io_extents->pp_extents[i].pid == pid) {
                        cur = i;
                        break;
                }
        }

        if (cur == -1) {
                /* new process */
                sbi->ll_extent_process_count =
                        (sbi->ll_extent_process_count + 1) % LL_PROCESS_HIST_MAX;
                cur = sbi->ll_extent_process_count;
                io_extents->pp_extents[cur].pid = pid;
                lprocfs_oh_clear(&io_extents->pp_extents[cur].pp_r_hist);
                lprocfs_oh_clear(&io_extents->pp_extents[cur].pp_w_hist);
        }

        for(i = 0; (count >= (1 << LL_HIST_START << i)) &&
             (i < (LL_HIST_MAX - 1)); i++);
        if (rw == 0) {
                io_extents->pp_extents[cur].pp_r_hist.oh_buckets[i]++;
                io_extents->pp_extents[LL_PROCESS_HIST_MAX].pp_r_hist.oh_buckets[i]++;
        } else {
                io_extents->pp_extents[cur].pp_w_hist.oh_buckets[i]++;
                io_extents->pp_extents[LL_PROCESS_HIST_MAX].pp_w_hist.oh_buckets[i]++;
        }
	spin_unlock(&sbi->ll_pp_extent_lock);

	spin_lock(&sbi->ll_process_lock);
        /* Offset statistics */
        for (i = 0; i < LL_PROCESS_HIST_MAX; i++) {
                if (process[i].rw_pid == pid) {
                        if (process[i].rw_last_file != file) {
                                process[i].rw_range_start = pos;
                                process[i].rw_last_file_pos = pos + count;
                                process[i].rw_smallest_extent = count;
                                process[i].rw_largest_extent = count;
                                process[i].rw_offset = 0;
                                process[i].rw_last_file = file;
				spin_unlock(&sbi->ll_process_lock);
                                return;
                        }
                        if (process[i].rw_last_file_pos != pos) {
                                *off_count =
                                    (*off_count + 1) % LL_OFFSET_HIST_MAX;
                                offset[*off_count].rw_op = process[i].rw_op;
                                offset[*off_count].rw_pid = pid;
                                offset[*off_count].rw_range_start =
                                        process[i].rw_range_start;
                                offset[*off_count].rw_range_end =
                                        process[i].rw_last_file_pos;
                                offset[*off_count].rw_smallest_extent =
                                        process[i].rw_smallest_extent;
                                offset[*off_count].rw_largest_extent =
                                        process[i].rw_largest_extent;
                                offset[*off_count].rw_offset =
                                        process[i].rw_offset;
                                process[i].rw_op = rw;
                                process[i].rw_range_start = pos;
                                process[i].rw_smallest_extent = count;
                                process[i].rw_largest_extent = count;
                                process[i].rw_offset = pos -
                                        process[i].rw_last_file_pos;
                        }
                        if(process[i].rw_smallest_extent > count)
                                process[i].rw_smallest_extent = count;
                        if(process[i].rw_largest_extent < count)
                                process[i].rw_largest_extent = count;
                        process[i].rw_last_file_pos = pos + count;
			spin_unlock(&sbi->ll_process_lock);
                        return;
                }
        }
        *process_count = (*process_count + 1) % LL_PROCESS_HIST_MAX;
        process[*process_count].rw_pid = pid;
        process[*process_count].rw_op = rw;
        process[*process_count].rw_range_start = pos;
        process[*process_count].rw_last_file_pos = pos + count;
        process[*process_count].rw_smallest_extent = count;
        process[*process_count].rw_largest_extent = count;
        process[*process_count].rw_offset = 0;
        process[*process_count].rw_last_file = file;
	spin_unlock(&sbi->ll_process_lock);
}

static int ll_rw_offset_stats_seq_show(struct seq_file *seq, void *v)
{
	struct timespec64 now;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_process_info *offset = sbi->ll_rw_offset_info;
	struct ll_rw_process_info *process = sbi->ll_rw_process_info;
	int i;

	ktime_get_real_ts64(&now);

	if (!sbi->ll_rw_stats_on) {
		seq_puts(seq, "disabled\n write anything to this file to activate, then '0' or 'disable' to deactivate\n");
		return 0;
	}
	spin_lock(&sbi->ll_process_lock);

	seq_printf(seq, "snapshot_time:         %llu.%09lu (secs.nsecs)\n",
		   (s64)now.tv_sec, now.tv_nsec);
	seq_printf(seq, "%3s %10s %14s %14s %17s %17s %14s\n",
		   "R/W", "PID", "RANGE START", "RANGE END",
		   "SMALLEST EXTENT", "LARGEST EXTENT", "OFFSET");

	/* We stored the discontiguous offsets here; print them first */
	for (i = 0; i < LL_OFFSET_HIST_MAX; i++) {
		if (offset[i].rw_pid != 0)
			seq_printf(seq,
				   "%3c %10d %14Lu %14Lu %17lu %17lu %14Lu",
				   offset[i].rw_op == READ ? 'R' : 'W',
				   offset[i].rw_pid,
				   offset[i].rw_range_start,
				   offset[i].rw_range_end,
				   (unsigned long)offset[i].rw_smallest_extent,
				   (unsigned long)offset[i].rw_largest_extent,
				   offset[i].rw_offset);
	}

	/* Then print the current offsets for each process */
	for (i = 0; i < LL_PROCESS_HIST_MAX; i++) {
		if (process[i].rw_pid != 0)
			seq_printf(seq,
				   "%3c %10d %14Lu %14Lu %17lu %17lu %14Lu",
				   process[i].rw_op == READ ? 'R' : 'W',
				   process[i].rw_pid,
				   process[i].rw_range_start,
				   process[i].rw_last_file_pos,
				   (unsigned long)process[i].rw_smallest_extent,
				   (unsigned long)process[i].rw_largest_extent,
				   process[i].rw_offset);
	}
	spin_unlock(&sbi->ll_process_lock);

	return 0;
}

static ssize_t ll_rw_offset_stats_seq_write(struct file *file,
					    const char __user *buf,
					    size_t len, loff_t *off)
{
	struct seq_file *seq = file->private_data;
	struct ll_sb_info *sbi = seq->private;
	struct ll_rw_process_info *process_info = sbi->ll_rw_process_info;
	struct ll_rw_process_info *offset_info = sbi->ll_rw_offset_info;
	__s64 value;

	if (len == 0)
		return -EINVAL;

	value = ll_stats_pid_write(buf, len);

	if (value == 0)
		sbi->ll_rw_stats_on = 0;
	else
		sbi->ll_rw_stats_on = 1;

	spin_lock(&sbi->ll_process_lock);
	sbi->ll_offset_process_count = 0;
	sbi->ll_rw_offset_entry_count = 0;
	memset(process_info, 0, sizeof(struct ll_rw_process_info) *
	       LL_PROCESS_HIST_MAX);
	memset(offset_info, 0, sizeof(struct ll_rw_process_info) *
	       LL_OFFSET_HIST_MAX);
	spin_unlock(&sbi->ll_process_lock);

	return len;
}

/**
 * ll_stats_pid_write() - Determine if stats collection should be enabled
 * @buf: Buffer containing the data written
 * @len: Number of bytes in the buffer
 *
 * Several proc files begin collecting stats when a value is written, and stop
 * collecting when either '0' or 'disable' is written. This function checks the
 * written value to see if collection should be enabled or disabled.
 *
 * Return: If '0' or 'disable' is provided, 0 is returned. If the text
 * equivalent of a number is written, that number is returned. Otherwise,
 * 1 is returned. Non-zero return values indicate collection should be enabled.
 */
static __s64 ll_stats_pid_write(const char __user *buf, size_t len)
{
	__s64 value = 1;
	int rc;
	char kernbuf[16];

	rc = lprocfs_str_to_s64(buf, len, &value);

	if (rc < 0 && len < sizeof(kernbuf)) {

		if (copy_from_user(kernbuf, buf, len))
			return -EFAULT;
		kernbuf[len] = 0;

		if (kernbuf[len - 1] == '\n')
			kernbuf[len - 1] = 0;

		if (strncasecmp(kernbuf, "disable", 7) == 0)
			value = 0;
	}

	return value;
}

LPROC_SEQ_FOPS(ll_rw_offset_stats);
#endif /* CONFIG_PROC_FS */
